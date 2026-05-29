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

//! Process-wide cache for ztunnel's own SVID, refreshed in the background
//! from the SPIFFE Workload API and consulted by the broker channel on
//! every connection to build a fresh rustls [`ClientConfig`].
//!
//! The cache holds DER buffers exactly as the Workload API delivered
//! them; conversion into rustls types happens lazily in
//! [`SvidSource::client_config`] so that we can rebuild after rotation
//! without holding rustls-shaped state.

use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use futures_util::StreamExt;
use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, TrustAnchor, UnixTime,
};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tracing::{debug, info, warn};

use crate::identity::Error;
use crate::identity::broker::workload_api::{WorkloadApiClient, WorkloadSvid};
use crate::tls::provider;

/// How long to wait for the Workload API to deliver a first SVID at startup.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(30);
/// Backoff between retries when the Workload API stream errors or ends.
const RECONNECT_BACKOFF: Duration = Duration::from_secs(5);

/// SPIFFE Workload API-backed source of ztunnel's own SVID. Wraps a
/// background refresher and exposes [`Self::client_config`] which returns
/// a fresh rustls [`ClientConfig`] suitable for an mTLS broker dial.
///
/// The source rebuilds its `ClientConfig` on every connection rather than
/// caching it because rustls configs are immutable by value; this trades
/// a bit of CPU per connection for not needing a swap/rotate protocol.
pub struct SvidSource {
    expected_spiffe_id: String,
    current: RwLock<Option<WorkloadSvid>>,
}

impl std::fmt::Debug for SvidSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SvidSource")
            .field("expected_spiffe_id", &self.expected_spiffe_id)
            .field("has_svid", &self.current.read().unwrap().is_some())
            .finish_non_exhaustive()
    }
}

impl SvidSource {
    /// Bootstrap from `workload_api_socket`, blocking until either an SVID
    /// for `expected_spiffe_id` arrives or `BOOTSTRAP_TIMEOUT` elapses.
    /// Spawns a detached background task that keeps the SVID up to date.
    pub async fn bootstrap(
        workload_api_socket: PathBuf,
        expected_spiffe_id: String,
    ) -> Result<Arc<Self>, Error> {
        let client = WorkloadApiClient::new(workload_api_socket)?;
        let initial = client.fetch_first(BOOTSTRAP_TIMEOUT).await?;
        let svid = pick_svid(&initial, &expected_spiffe_id).ok_or_else(|| {
            Error::BrokerSpiffeIdMismatch {
                expected: dummy_identity(&expected_spiffe_id),
                actual: format!(
                    "Workload API returned {} SVID(s), none matched",
                    initial.len()
                ),
            }
        })?;
        info!(spiffe_id = %svid.spiffe_id, "bootstrapped ztunnel SVID from Workload API");

        let source = Arc::new(Self {
            expected_spiffe_id,
            current: RwLock::new(Some(svid)),
        });
        Self::spawn_refresher(source.clone(), client);
        Ok(source)
    }

    /// Snapshot the currently cached SVID, or `None` if the refresher has
    /// not yet delivered the first one (only possible if
    /// [`Self::bootstrap`] was not used).
    pub fn current(&self) -> Option<WorkloadSvid> {
        self.current.read().expect("svid source poisoned").clone()
    }

    /// Build a fresh rustls [`ClientConfig`] from the currently cached
    /// SVID. Errors if no SVID has been cached yet or if the DER buffers
    /// fail to parse.
    pub fn client_config(&self) -> Result<ClientConfig, Error> {
        let svid = self
            .current()
            .ok_or_else(|| Error::BrokerTransport("svid source not yet bootstrapped".into()))?;

        let chain = parse_cert_chain(&svid.cert_chain_der)?;
        let key = parse_private_key(&svid.key_der)?;
        let bundle = parse_cert_chain(&svid.bundle_der)?;
        let trust_domain = trust_domain_from_spiffe_id(&svid.spiffe_id).ok_or_else(|| {
            Error::BrokerTransport(
                format!("SVID id {} is not a valid SPIFFE URI", svid.spiffe_id).into(),
            )
        })?;

        let cfg = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(crate::tls::tls_versions())
            .map_err(|e| Error::BrokerTransport(format!("tls versions: {e}").into()))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SpiffeServerVerifier {
                bundle,
                trust_domain,
            }))
            .with_client_auth_cert(chain, key)
            .map_err(|e| Error::BrokerTransport(format!("client auth cert: {e}").into()))?;

        let mut cfg = cfg;
        // tonic / hyper-rustls require ALPN to advertise h2 so the broker
        // gRPC server picks the HTTP/2 endpoint after the TLS handshake.
        // Without this the server falls back to HTTP/1.1 (or in tonic's
        // case, it just sees a non-h2 connection and closes it), which
        // surfaces to us as `client error (SendRequest): connection
        // error`.
        cfg.alpn_protocols = vec![b"h2".to_vec()];

        Ok(cfg)
    }

    fn spawn_refresher(self: Arc<Self>, client: WorkloadApiClient) {
        tokio::spawn(async move {
            loop {
                match client.stream().await {
                    Ok(mut stream) => {
                        while let Some(item) = stream.next().await {
                            match item {
                                Ok(svids) => {
                                    if let Some(svid) = pick_svid(&svids, &self.expected_spiffe_id)
                                    {
                                        debug!(spiffe_id = %svid.spiffe_id, "refreshed ztunnel SVID");
                                        *self.current.write().expect("svid source poisoned") =
                                            Some(svid);
                                    } else {
                                        warn!(
                                            "Workload API snapshot did not include {}; ignoring",
                                            self.expected_spiffe_id
                                        );
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "Workload API stream error; reconnecting");
                                    break;
                                }
                            }
                        }
                        debug!("Workload API stream ended; reconnecting");
                    }
                    Err(e) => {
                        warn!(error = %e, "Workload API subscribe failed; backing off");
                    }
                }
                tokio::time::sleep(RECONNECT_BACKOFF).await;
            }
        });
    }
}

fn pick_svid(svids: &[WorkloadSvid], expected: &str) -> Option<WorkloadSvid> {
    svids.iter().find(|s| s.spiffe_id == expected).cloned()
}

fn dummy_identity(spiffe_id: &str) -> crate::identity::Identity {
    // Only used to populate the `expected` field of a mismatch error; we
    // don't have a parsed Identity at this point and the value is purely
    // diagnostic, so synthesise a placeholder rather than threading a
    // real one through the bootstrap.
    crate::identity::Identity::Spiffe {
        trust_domain: "unknown".into(),
        namespace: "unknown".into(),
        service_account: spiffe_id.into(),
    }
}

fn parse_cert_chain(der: &[u8]) -> Result<Vec<CertificateDer<'static>>, Error> {
    use x509_parser::der_parser::ber::parse_ber_sequence;
    // The Workload API concatenates multiple DER-encoded X.509 certs into
    // a single byte buffer with no length prefix. Each cert is itself an
    // ASN.1 SEQUENCE, so we can split by parsing one SEQUENCE at a time
    // off the front of the buffer until empty.
    let mut out = Vec::new();
    let mut remaining = der;
    while !remaining.is_empty() {
        let (rest, _seq) = parse_ber_sequence(remaining)
            .map_err(|e| Error::BrokerTransport(format!("der parse: {e}").into()))?;
        let consumed = remaining.len() - rest.len();
        let cert_bytes = remaining[..consumed].to_vec();
        out.push(CertificateDer::from(cert_bytes));
        remaining = rest;
    }
    Ok(out)
}

fn parse_private_key(der: &[u8]) -> Result<PrivateKeyDer<'static>, Error> {
    // SPIFFE Workload API delivers PKCS#8 DER per the spec.
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        der.to_vec(),
    )))
}

fn trust_domain_from_spiffe_id(id: &str) -> Option<String> {
    let rest = id.strip_prefix("spiffe://")?;
    let (td, _) = rest.split_once('/').unwrap_or((rest, ""));
    if td.is_empty() {
        return None;
    }
    Some(td.to_string())
}

/// Custom rustls server-certificate verifier that accepts any peer whose
/// leaf SVID asserts a SPIFFE ID within `trust_domain` and chains back to
/// `bundle`. Mirrors go-spiffe's `tlsconfig.AuthorizeMemberOf`.
#[derive(Debug)]
struct SpiffeServerVerifier {
    bundle: Vec<CertificateDer<'static>>,
    trust_domain: String,
}

impl ServerCertVerifier for SpiffeServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 1. Validate the chain against the bundle. We let rustls-webpki
        //    handle the heavy lifting; SPIFFE peers always present a
        //    self-contained chain so EE + intermediates + bundle roots
        //    is enough.
        let webpki_roots: Vec<TrustAnchor<'_>> = self
            .bundle
            .iter()
            .map(webpki::anchor_from_trusted_cert)
            .collect::<Result<_, _>>()
            .map_err(|e| rustls::Error::General(format!("bundle parse: {e}")))?;
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|e| rustls::Error::General(format!("peer cert parse: {e}")))?;
        let algs = provider().signature_verification_algorithms.all;
        cert.verify_for_usage(
            algs,
            &webpki_roots,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| rustls::Error::General(format!("peer chain invalid: {e}")))?;

        // 2. Pull the URI SAN and confirm it asserts a SPIFFE ID under
        //    our trust domain. Without this the broker's TLS cert from a
        //    foreign trust domain would still pass once it chained — we
        //    must enforce SPIFFE membership ourselves.
        let (_, parsed) = x509_parser::parse_x509_certificate(end_entity)
            .map_err(|e| rustls::Error::General(format!("peer x509 parse: {e}")))?;
        let mut matched = false;
        for ext in parsed.extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::URI(uri) = name
                        && let Some(td) = trust_domain_from_spiffe_id(uri)
                        && td == self.trust_domain
                    {
                        matched = true;
                        break;
                    }
                }
            }
            if matched {
                break;
            }
        }
        if !matched {
            return Err(rustls::Error::General(format!(
                "peer SVID is not in trust domain {}",
                self.trust_domain
            )));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_domain_extraction() {
        assert_eq!(
            trust_domain_from_spiffe_id("spiffe://cluster.local/ns/x/sa/y").as_deref(),
            Some("cluster.local")
        );
        assert_eq!(
            trust_domain_from_spiffe_id("spiffe://only.td").as_deref(),
            Some("only.td")
        );
        assert_eq!(trust_domain_from_spiffe_id("not-spiffe://x/y"), None);
        assert_eq!(trust_domain_from_spiffe_id("spiffe://"), None);
    }

    #[test]
    fn pick_svid_filters_by_id() {
        let svids = vec![
            WorkloadSvid {
                spiffe_id: "spiffe://td/a".into(),
                cert_chain_der: bytes::Bytes::from_static(b""),
                key_der: bytes::Bytes::from_static(b""),
                bundle_der: bytes::Bytes::from_static(b""),
            },
            WorkloadSvid {
                spiffe_id: "spiffe://td/b".into(),
                cert_chain_der: bytes::Bytes::from_static(b""),
                key_der: bytes::Bytes::from_static(b""),
                bundle_der: bytes::Bytes::from_static(b""),
            },
        ];
        assert_eq!(
            pick_svid(&svids, "spiffe://td/b").unwrap().spiffe_id,
            "spiffe://td/b"
        );
        assert!(pick_svid(&svids, "spiffe://td/c").is_none());
    }
}
