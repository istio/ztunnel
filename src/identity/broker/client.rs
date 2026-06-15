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

//! SPIFFE Broker [`CaClientTrait`] implementation.
//!
//! Performs the workload-attested side of `SubscribeToX509SVID` over a
//! local UDS connection to the broker agent:
//!
//! 1. Run the configured [`WorkloadAttestor`] over the [`CertRequest`] to
//!    obtain a `WorkloadReference` (the wire-level identity of the
//!    requesting pod).
//! 2. Open the server-streaming RPC and pull the first response. The
//!    broker streams updates as SVIDs rotate; we surface the first one
//!    and let [`crate::identity::SecretManager`] re-fetch on expiry.
//! 3. Locate the SVID whose `spiffe_id` matches what we asked for and
//!    pack it into a [`tls::WorkloadCertificate`], merging in any
//!    federated bundles delivered out of band by
//!    [`SubscribeToX509Bundles`](crate::identity::broker::bundles).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use tonic::metadata::MetadataValue;
use tracing::{debug, instrument};

use crate::identity::Error;
use crate::identity::broker::attestor::WorkloadAttestor;
use crate::identity::broker::bundles::TrustBundleStore;
use crate::identity::broker::channel::UdsGrpcChannel;
use crate::identity::broker_proto::spiffe::broker::{
    SubscribeToX509svidRequest, api_client::ApiClient,
};
use crate::identity::manager::{CaClientTrait, CertRequest};
use crate::tls;

/// Required broker metadata header. The broker rejects any request that
/// is missing this header to defend against accidental cross-protocol
/// calls (e.g. a Workload-API-aware client dialling the broker socket by
/// mistake).
const BROKER_SECURITY_HEADER: &str = "broker.spiffe.io";
const BROKER_SECURITY_HEADER_VALUE: &str = "true";

/// CA client backed by a SPIFFE Broker agent reachable over a local UDS.
pub struct SpiffeBrokerClient {
    attestor: Arc<dyn WorkloadAttestor>,
    channel: UdsGrpcChannel,
    /// Shared federated bundle cache populated by the background
    /// `SubscribeToX509Bundles` task; merged into the per-workload bundle
    /// every time we mint a `WorkloadCertificate`.
    bundle_store: Arc<TrustBundleStore>,
    /// Cap on how long we wait for the broker to deliver the first SVID
    /// of a fresh subscription before erroring out.
    request_timeout: Duration,
}

impl std::fmt::Debug for SpiffeBrokerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeBrokerClient")
            .field("attestor", &self.attestor)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

impl SpiffeBrokerClient {
    /// Build a client that opens its own plain UDS channel and runs
    /// without any federated bundle cache. Suitable for tests and minimal
    /// setups where the broker is not gated on mTLS.
    #[cfg(any(test, feature = "testing"))]
    pub fn new(
        attestor: Arc<dyn WorkloadAttestor>,
        socket_path: std::path::PathBuf,
        request_timeout: Duration,
    ) -> Result<Self, Error> {
        let channel = UdsGrpcChannel::new_plain(socket_path)?;
        Ok(Self::with_channel(
            attestor,
            channel,
            TrustBundleStore::new(),
            request_timeout,
        ))
    }

    /// Build a client around an already-constructed channel and bundle
    /// store. Used by [`crate::identity::SecretManager::new`] so the same
    /// channel can be shared with the background bundles subscriber and so
    /// federated bundles are visible to every minted cert.
    pub fn with_channel(
        attestor: Arc<dyn WorkloadAttestor>,
        channel: UdsGrpcChannel,
        bundle_store: Arc<TrustBundleStore>,
        request_timeout: Duration,
    ) -> Self {
        Self {
            attestor,
            channel,
            bundle_store,
            request_timeout,
        }
    }
}

#[async_trait]
impl CaClientTrait for SpiffeBrokerClient {
    #[instrument(skip_all, fields(identity = %req.identity))]
    async fn fetch_certificate(
        &self,
        req: &CertRequest,
    ) -> Result<tls::WorkloadCertificate, Error> {
        let reference = self.attestor.attest(req)?;

        let mut client = ApiClient::new(self.channel.clone());
        let mut grpc_req = tonic::Request::new(SubscribeToX509svidRequest {
            reference: Some(reference),
        });
        grpc_req.metadata_mut().insert(
            BROKER_SECURITY_HEADER,
            MetadataValue::from_static(BROKER_SECURITY_HEADER_VALUE),
        );
        let rpc = client.subscribe_to_x509svid(grpc_req);

        // First response on a fresh subscription is what we hand back to
        // `SecretManager`; subsequent rotations are picked up on the next
        // refresh cycle. Bound the wait so a broken broker doesn't pin us
        // here forever.
        let mut stream = tokio::time::timeout(self.request_timeout, rpc)
            .await
            .map_err(|_| Error::BrokerTimeout)?
            .map_err(transport_err)?
            .into_inner();

        let resp = tokio::time::timeout(self.request_timeout, stream.next())
            .await
            .map_err(|_| Error::BrokerTimeout)?
            .ok_or(Error::BrokerStreamEmpty)?
            .map_err(transport_err)?;

        if resp.svids.is_empty() {
            return Err(Error::BrokerNoSvids);
        }

        // Pick the SVID matching the SPIFFE ID we asked for. Brokers may
        // return multiple SVIDs (e.g. when a workload is entitled to
        // several identities); we only care about the one this fetch was
        // launched for.
        let want = req.identity.to_string();
        let svid = resp
            .svids
            .into_iter()
            .find(|s| s.spiffe_id == want)
            .ok_or_else(|| Error::BrokerSpiffeIdMismatch {
                expected: req.identity.clone(),
                actual: "(none matched)".to_string(),
            })?;

        debug!(spiffe_id = %svid.spiffe_id, "received SVID from broker");

        let extras = self.bundle_store.snapshot();
        tls::WorkloadCertificate::from_spiffe_svid(
            &svid.x509_svid_key,
            &svid.x509_svid,
            &svid.bundle,
            &extras,
        )
        .map_err(Error::from)
    }
}

fn transport_err(s: tonic::Status) -> Error {
    Error::BrokerTransport(Arc::from(s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::identity::broker_proto::spiffe::broker::WorkloadReference;
    use std::path::PathBuf;

    /// Minimal attestor whose `attest` outcome tests can control, used to
    /// confirm the broker client invokes the trait at the right point.
    #[derive(Debug, Default)]
    struct SpyAttestor {
        attest_err: Option<Error>,
    }

    impl WorkloadAttestor for SpyAttestor {
        fn attest(&self, _req: &CertRequest) -> Result<WorkloadReference, Error> {
            if let Some(e) = &self.attest_err {
                return Err(e.clone());
            }
            Ok(WorkloadReference { reference: None })
        }
    }

    fn identity() -> Identity {
        Identity::Spiffe {
            trust_domain: "test".into(),
            namespace: "test".into(),
            service_account: "broker-client".into(),
        }
    }

    #[tokio::test]
    async fn attestor_error_short_circuits() {
        // If attestation fails we must never touch the channel; the
        // socket path is intentionally bogus to prove we never connect.
        let spy = Arc::new(SpyAttestor {
            attest_err: Some(Error::BrokerMissingWorkload),
            ..Default::default()
        });
        let client = SpiffeBrokerClient::new(
            spy.clone(),
            PathBuf::from("/nonexistent/spiffe-broker.sock"),
            Duration::from_secs(1),
        )
        .expect("client builds");

        let err = client
            .fetch_certificate(&CertRequest::new(identity()))
            .await
            .expect_err("attestation error must surface");
        assert!(matches!(err, Error::BrokerMissingWorkload), "got {err:?}");
    }

    #[tokio::test]
    async fn missing_socket_surfaces_transport_error() {
        let spy = Arc::new(SpyAttestor::default());
        let client = SpiffeBrokerClient::new(
            spy.clone(),
            PathBuf::from("/nonexistent/spiffe-broker.sock"),
            Duration::from_secs(1),
        )
        .expect("client builds");

        let err = client
            .fetch_certificate(&CertRequest::new(identity()))
            .await
            .expect_err("missing socket must error");
        assert!(
            matches!(err, Error::BrokerTransport(_) | Error::BrokerTimeout),
            "got {err:?}"
        );
    }
}
