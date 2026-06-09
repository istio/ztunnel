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

//! Minimal SPIFFE Workload API client used by the Broker provider to
//! bootstrap ztunnel's own SVID before opening the mTLS-gated broker
//! channel.
//!
//! Only `FetchX509SVID` is implemented; that is enough to obtain a key
//! pair, leaf chain, and trust-domain bundle for ztunnel itself. The
//! result is fed into [`super::svid_source::SvidSource`] which the
//! broker channel consults on every connection to build its rustls
//! client config.
//!
//! The Workload API uses a flat (no-package) gRPC service path
//! (`/SpiffeWorkloadAPI/FetchX509SVID`) which `tonic-prost-build` does
//! not generate idiomatically, so we drive the streaming call by hand
//! against [`tonic::client::Grpc`].

use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use http::uri::PathAndQuery;
use tonic::metadata::MetadataValue;
use tracing::{debug, info};

use crate::identity::Error;
use crate::identity::broker::channel::UdsGrpcChannel;
use crate::identity::workload_api_proto::spiffe::workloadapi::{
    X509svidRequest, X509svidResponse,
};

/// Canonical fully-qualified gRPC path for the Workload API streaming
/// FetchX509SVID method. The leading slash is required by tonic.
const FETCH_X509_SVID_PATH: &str = "/SpiffeWorkloadAPI/FetchX509SVID";

/// Required metadata header that gates Workload API calls; SPIRE rejects
/// requests without this header to guard against clients that aren't aware
/// they're talking to a SPIFFE Workload API endpoint.
const SECURITY_HEADER: &str = "workload.spiffe.io";
const SECURITY_HEADER_VALUE: &str = "true";

/// One SVID returned by the Workload API, projected into ztunnel's
/// internal shape (raw DER buffers, no PEM hand-holding).
#[derive(Clone, Debug)]
pub struct WorkloadSvid {
    /// SPIFFE ID this SVID asserts.
    pub spiffe_id: String,
    /// X.509 leaf + intermediate chain, DER ASN.1, concatenated.
    pub cert_chain_der: Bytes,
    /// PKCS#8 DER private key matching the leaf in `cert_chain_der`.
    pub key_der: Bytes,
    /// Trust-domain bundle for this SVID, DER ASN.1, concatenated.
    pub bundle_der: Bytes,
}

/// gRPC client for the SPIFFE Workload API. Holds a single shared UDS
/// channel; cheap to clone.
#[derive(Clone)]
pub struct WorkloadApiClient {
    channel: UdsGrpcChannel,
}

impl WorkloadApiClient {
    /// Build a client rooted at `socket_path`. No connection is opened
    /// until the first RPC.
    pub fn new(socket_path: PathBuf) -> Result<Self, Error> {
        let channel = UdsGrpcChannel::new_plain(socket_path)?;
        Ok(Self { channel })
    }

    /// Subscribe to the Workload API and pull the first SVID snapshot.
    ///
    /// The Workload API streams updates as SVIDs rotate; callers that
    /// need to keep an up-to-date copy should drive [`Self::stream`]
    /// instead. This helper exists for bootstrap and one-shot fetches.
    pub async fn fetch_first(&self, timeout: Duration) -> Result<Vec<WorkloadSvid>, Error> {
        let mut stream = self.subscribe().await?;
        match tokio::time::timeout(timeout, stream.next()).await {
            Ok(Some(Ok(resp))) => Ok(into_svids(resp)),
            Ok(Some(Err(s))) => Err(transport_err(s)),
            Ok(None) => Err(Error::BrokerStreamEmpty),
            Err(_) => Err(Error::BrokerTimeout),
        }
    }

    /// Open a streaming subscription. Each yielded value is one
    /// `Vec<WorkloadSvid>` snapshot.
    pub async fn stream(
        &self,
    ) -> Result<impl futures_util::Stream<Item = Result<Vec<WorkloadSvid>, Error>>, Error>
    {
        let stream = self.subscribe().await?;
        Ok(stream.map(|msg| match msg {
            Ok(resp) => Ok(into_svids(resp)),
            Err(s) => Err(transport_err(s)),
        }))
    }

    /// Drive the raw `FetchX509SVID` streaming RPC. Sets the SPIFFE
    /// security header on the outgoing metadata.
    async fn subscribe(
        &self,
    ) -> Result<tonic::codec::Streaming<X509svidResponse>, Error> {
        let mut inner = tonic::client::Grpc::new(self.channel.clone());
        inner
            .ready()
            .await
            .map_err(|e| Error::BrokerTransport(format!("workload api not ready: {e}").into()))?;
        let codec = tonic_prost::ProstCodec::<X509svidRequest, X509svidResponse>::default();
        let path = PathAndQuery::from_static(FETCH_X509_SVID_PATH);
        let mut req = tonic::Request::new(X509svidRequest {});
        req.metadata_mut().insert(
            SECURITY_HEADER,
            MetadataValue::from_static(SECURITY_HEADER_VALUE),
        );
        let resp = inner
            .server_streaming(req, path, codec)
            .await
            .map_err(transport_err)?;
        debug!("opened SPIFFE Workload API FetchX509SVID stream");
        Ok(resp.into_inner())
    }
}

fn into_svids(resp: X509svidResponse) -> Vec<WorkloadSvid> {
    let total = resp.svids.len();
    let svids: Vec<_> = resp
        .svids
        .into_iter()
        .map(|s| WorkloadSvid {
            spiffe_id: s.spiffe_id,
            cert_chain_der: Bytes::from(s.x509_svid),
            key_der: Bytes::from(s.x509_svid_key),
            bundle_der: Bytes::from(s.bundle),
        })
        .collect();
    info!(count = total, "received SVID update from SPIFFE Workload API");
    svids
}

fn transport_err(s: tonic::Status) -> Error {
    Error::BrokerTransport(format!("workload api: {s}").into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test]
    async fn missing_socket_surfaces_transport_error() {
        let client = WorkloadApiClient::new(PathBuf::from("/nonexistent/spiffe-wapi.sock"))
            .expect("client builds even when the socket is missing");
        let err = client
            .fetch_first(Duration::from_secs(1))
            .await
            .expect_err("missing socket must error");
        assert!(
            matches!(err, Error::BrokerTransport(_) | Error::BrokerTimeout),
            "got {err:?}"
        );
    }
}
