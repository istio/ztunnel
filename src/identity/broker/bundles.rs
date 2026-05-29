// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Background subscription to the SPIFFE Broker `SubscribeToX509Bundles`
//! RPC.
//!
//! Workload SVID responses already carry their own trust-domain bundle (see
//! [`crate::identity::broker::client::SpiffeBrokerClient::fetch_certificate`]),
//! but in a federated mesh the broker may serve additional bundles that the
//! workload should trust without ever having requested an SVID for those
//! identities. This module maintains a process-wide cache of those extra
//! bundles, refreshed by a long-lived background task that re-subscribes
//! on disconnect with capped exponential backoff. The cache is consulted
//! every time the broker client mints a `WorkloadCertificate`, so updates
//! propagate to new SVIDs without any cross-component plumbing.
//!
//! The subscription is attested using ztunnel's own PID; this requires the
//! broker agent to be reachable from a process that the broker can resolve
//! to an identity (the standard inpod deployment satisfies this).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use tonic::metadata::MetadataValue;
use tracing::{debug, info, warn};

use crate::identity::broker::attestor::{WORKLOAD_PID_REFERENCE_TYPE, pack_any};
use crate::identity::broker::channel::UdsGrpcChannel;
use crate::identity::broker_proto::spiffe::broker::{
    SubscribeToX509BundlesRequest, WorkloadPidReference, WorkloadReference,
    api_client::ApiClient,
};

/// Required broker metadata header — see
/// [`crate::identity::broker::client`] for the rationale.
const BROKER_SECURITY_HEADER: &str = "broker.spiffe.io";
const BROKER_SECURITY_HEADER_VALUE: &str = "true";

const RECONNECT_BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Process-wide cache of trust-domain bundles streamed from the broker.
///
/// Keyed by trust-domain SPIFFE ID (e.g. `spiffe://td.example`), value is
/// the ASN.1 DER-encoded bundle for that trust domain. May contain multiple
/// DER certificates concatenated for a single trust domain.
#[derive(Debug, Default)]
pub struct TrustBundleStore {
    bundles: RwLock<HashMap<String, Bytes>>,
}

impl TrustBundleStore {
    /// Build an empty store wrapped in `Arc` for shared ownership.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Overwrite the cache with `bundles`.
    pub fn replace(&self, bundles: HashMap<String, Bytes>) {
        let mut guard = self.bundles.write().expect("trust bundle store poisoned");
        *guard = bundles;
    }

    /// Snapshot all bundle DERs currently known. The returned `Vec` is
    /// disconnected from the cache; later updates are not reflected.
    pub fn snapshot(&self) -> Vec<Bytes> {
        self.bundles
            .read()
            .expect("trust bundle store poisoned")
            .values()
            .cloned()
            .collect()
    }
}

/// Spawn a detached task that keeps `store` populated from the broker's
/// `SubscribeToX509Bundles` stream. Reconnects on disconnect with capped
/// exponential backoff; never panics on stream errors.
pub fn spawn_bundle_subscriber(channel: UdsGrpcChannel, store: Arc<TrustBundleStore>) {
    tokio::spawn(async move {
        let mut backoff = RECONNECT_BACKOFF_INITIAL;
        loop {
            match run_once(&channel, &store).await {
                Ok(()) => {
                    debug!("bundle stream ended cleanly; reconnecting");
                    backoff = RECONNECT_BACKOFF_INITIAL;
                }
                Err(e) => {
                    warn!(
                        error = %e,
                        backoff_secs = backoff.as_secs(),
                        "bundle stream errored; reconnecting after backoff"
                    );
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = std::cmp::min(backoff.saturating_mul(2), RECONNECT_BACKOFF_MAX);
        }
    });
}

/// Open one subscription and drain it. Returns once the stream completes
/// (the broker shut it down) or errors (transport / status). The caller
/// is responsible for reconnecting.
async fn run_once(
    channel: &UdsGrpcChannel,
    store: &Arc<TrustBundleStore>,
) -> Result<(), tonic::Status> {
    // Attest ztunnel itself by PID. The broker is expected to resolve
    // ztunnel's PID to an identity via its own attestation pipeline; we
    // do not pre-validate this here because failures show up as a stream
    // error and we retry with backoff.
    let pid_ref = WorkloadPidReference {
        pid: std::process::id() as i32,
    };
    let any = pack_any(WORKLOAD_PID_REFERENCE_TYPE, &pid_ref);
    let mut req = tonic::Request::new(SubscribeToX509BundlesRequest {
        reference: Some(WorkloadReference {
            reference: Some(any),
        }),
    });
    req.metadata_mut().insert(
        BROKER_SECURITY_HEADER,
        MetadataValue::from_static(BROKER_SECURITY_HEADER_VALUE),
    );

    let mut client = ApiClient::new(channel.clone());
    let mut stream = client.subscribe_to_x509_bundles(req).await?.into_inner();

    while let Some(msg) = stream.next().await {
        let resp = msg?;
        let count = resp.bundles.len();
        let bundles: HashMap<String, Bytes> = resp
            .bundles
            .into_iter()
            .map(|(td, b)| (td, Bytes::from(b)))
            .collect();
        info!(count, "received trust bundle update from broker");
        store.replace(bundles);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_and_replace_round_trip() {
        let store = TrustBundleStore::new();
        assert!(store.snapshot().is_empty(), "new store starts empty");

        let mut input = HashMap::new();
        input.insert("spiffe://a.example".to_string(), Bytes::from_static(b"AA"));
        input.insert("spiffe://b.example".to_string(), Bytes::from_static(b"BB"));
        store.replace(input);

        let mut got = store.snapshot();
        got.sort();
        assert_eq!(
            got,
            vec![Bytes::from_static(b"AA"), Bytes::from_static(b"BB")]
        );
    }

    #[test]
    fn replace_overwrites() {
        let store = TrustBundleStore::new();
        let mut first = HashMap::new();
        first.insert("spiffe://a.example".to_string(), Bytes::from_static(b"AA"));
        store.replace(first);

        let mut second = HashMap::new();
        second.insert("spiffe://c.example".to_string(), Bytes::from_static(b"CC"));
        store.replace(second);

        let got = store.snapshot();
        assert_eq!(got, vec![Bytes::from_static(b"CC")]);
    }
}
