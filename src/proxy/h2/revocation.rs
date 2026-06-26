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

use std::sync::Arc;

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{CertificateError, CommonState, RootCertStore};
use tokio::sync::watch;
use webpki::KeyUsage;

use crate::identity::Identity;
use crate::proxy::Metrics;
use crate::proxy::metrics::Reporter;
use crate::tls::crl::CrlManager;
use crate::tls::verifier::verify_cert_chain;

/// Per-connection CRL revocation enforcement for an HBONE connection, shared by both directions:
///
/// - inbound server ([`super::server::serve_connection`]) checks the peer (client) chain
/// - outbound client connection driver ([`super::client::drive_connection`]) checks the upstream
/// server chain.
/// - In both cases, the connection's serving task watches for CRL updates and, on
/// revocation, tears the connection down abruptly (a security event) while attributing the
/// termination as `CERT_REVOKED` in the access log.
///
/// Boxed by callers and held off to the side so it adds only a pointer to the (size-sensitive)
/// per-connection driver future — it is cold state, touched only on a CRL update.
pub struct ConnectionRevocation {
    crl_manager: Arc<CrlManager>,
    metrics: Arc<Metrics>,
    /// The peer chain (leaf first), captured at handshake time since it is no longer retrievable
    /// once the stream is handed to h2. Re-verified via [`verify_cert_chain`] — the same webpki
    /// path used at handshake time — on every CRL update.
    chain: Vec<CertificateDer<'static>>,
    /// Trust anchors the peer chain is verified against, matching what was used at handshake time.
    roots: Arc<RootCertStore>,
    /// `client_auth` for the inbound peer (client) chain, `server_auth` for the outbound peer
    /// (server) chain — matches the usage the handshake-time verifier required.
    key_usage: KeyUsage,
    /// The connection's establishment time, used as the verification "now" for every re-check
    /// instead of the wall clock. The chain was already proven valid at handshake, so pinning to
    /// this instant means expiry/not-yet-valid can never spuriously trip the re-check — the only
    /// thing a later CRL reload can newly change is revocation status. Without this, a long-lived
    /// HBONE tunnel whose peer cert has since expired (sessions outlive cert rotation) would return
    /// `CertExpired` rather than `Revoked`, silently letting a revoked-but-expired cert escape
    /// existing-connection enforcement.
    established: UnixTime,
    crl_rx: watch::Receiver<u64>,
    /// Peer identity (client cert inbound, server cert outbound), retained only so a revocation
    /// termination is attributable in logs.
    peer_identity: Option<Identity>,
    /// Flipped to `true` when this connection's cert is revoked, so the per-connection serving
    /// future(s) resolve to `Error::CertificateRevoked` and the access log attributes the
    /// termination. Receivers are obtained via [`Self::subscribe_revoked`].
    revoked_tx: watch::Sender<bool>,
}

impl ConnectionRevocation {
    /// Captures the peer chain, trust anchors, and identity from the established TLS connection
    /// and subscribes to CRL updates. Call before the `TlsStream` is moved into the connection
    /// driver. `conn_state` is the rustls connection state — `&ServerConnection` (inbound) or
    /// `&ClientConnection` (outbound) both deref-coerce to [`CommonState`]. `roots` and
    /// `key_usage` must match what the handshake-time verifier used to validate this peer.
    pub fn new(
        conn_state: &CommonState,
        crl_manager: Arc<CrlManager>,
        metrics: Arc<Metrics>,
        roots: Arc<RootCertStore>,
        key_usage: KeyUsage,
    ) -> Box<Self> {
        let chain = conn_state
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.clone().into_owned()).collect())
            .unwrap_or_default();
        let peer_identity = crate::tls::identity_from_connection(conn_state);
        let crl_rx = crl_manager.subscribe();
        let (revoked_tx, _) = watch::channel(false);
        Box::new(Self {
            crl_manager,
            metrics,
            chain,
            roots,
            key_usage,
            established: UnixTime::now(),
            crl_rx,
            peer_identity,
            revoked_tx,
        })
    }

    /// A receiver for this connection's revocation signal
    pub fn subscribe_revoked(&self) -> watch::Receiver<bool> {
        self.revoked_tx.subscribe()
    }

    /// Records the revocation as a security event and returns the peer identity string for logging:
    /// bumps the rejection metric with the caller's reporter direction (`destination` inbound,
    /// `source` outbound) and signals the serving future(s) — done *before* the caller tears the
    /// connection down, so the signal wins the attribution race against the generic teardown error.
    pub fn record_revocation(&self, reporter: Reporter) -> String {
        self.metrics.record_crl_rejection(reporter);
        let _ = self.revoked_tx.send(true);
        self.peer_identity
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), |id| id.to_string())
    }

    /// Re-runs the shared webpki chain-validation path against the peer chain captured at
    /// handshake time. For a chain that was already accepted at handshake, the only thing a CRL
    /// update can newly change is revocation status — so only a `CertificateError::Revoked`
    /// result counts here; any other error is out of scope for this check.
    ///
    /// Verification is done at `now`; callers pass [`Self::established`] (the connection's
    /// handshake time) rather than the wall clock: the chain was valid then, so expiry/not-yet-valid
    /// can never spuriously trip the re-check, leaving revocation status — evaluated against the
    /// *current* CRL via `get_crls()` — as the only thing that can change the outcome. This matters
    /// because an HBONE session can outlive its peer's (short) cert lifetime; checking against the
    /// wall clock would return `CertExpired` and let a revoked-but-expired cert slip past enforcement.
    fn is_revoked_at(&self, now: UnixTime) -> bool {
        let Some((end_entity, intermediates)) = self.chain.split_first() else {
            return false;
        };
        matches!(
            verify_cert_chain(
                end_entity,
                intermediates,
                &self.roots,
                now,
                self.key_usage,
                Some(self.crl_manager.as_ref()),
            ),
            Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
        )
    }
}

/// Resolves only when a CRL update actually revokes a cert in this connection's chain.
/// CRL reloads that don't affect this chain are ignored (keep waiting),
/// so the connection is torn down strictly on revocation.
/// With no CRL configured (`None`), or once the watcher's sender is gone, it never resolves —
/// so the corresponding `select!` arm stays dormant rather than busy-looping.
pub async fn wait_for_revocation(state: Option<&mut Box<ConnectionRevocation>>) {
    match state {
        None => std::future::pending().await,
        Some(s) => loop {
            if s.is_revoked_at(s.established) {
                return;
            }
            if s.crl_rx.changed().await.is_err() {
                // Sender dropped (shutdown); never resolve again.
                std::future::pending::<()>().await;
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::helpers::{initialize_telemetry, test_proxy_metrics};
    use crate::tls::WorkloadCertificate;
    use crate::tls::mock::{TEST_ROOT, TEST_ROOT_KEY, TestIdentity, crl_pem_revoking_cert};
    use std::io::Write;
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};
    use tempfile::NamedTempFile;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    /// Re-checking an existing connection re-runs the shared webpki chain-validation path against
    /// the peer chain captured at handshake time. `wait_for_revocation` must not resolve while the
    /// CRL doesn't cover the peer's cert, and must resolve once a reload revokes it.
    #[tokio::test]
    async fn wait_for_revocation_resolves_on_webpki_revocation() {
        initialize_telemetry();

        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();
        let (server_key, server_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let server_wl = WorkloadCertificate::new(
            server_key.as_bytes(),
            server_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();
        let (client_key, client_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let client_wl = WorkloadCertificate::new(
            client_key.as_bytes(),
            client_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // Start with an empty (non-revoking) CRL so the handshake succeeds.
        let mut crl_file = NamedTempFile::new().unwrap();
        let crl_mgr = Arc::new(CrlManager::new(crl_file.path().to_path_buf()).unwrap());

        let server_tls = TlsAcceptor::from(Arc::new(server_wl.server_config(None).unwrap()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_tls.accept(stream).await.unwrap()
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = client_wl.outbound_connector(vec![id], None).unwrap();
        let client_tls = connector.connect(stream).await.unwrap();
        let _server_tls_stream = accept.await.unwrap();

        let (_, ssl) = client_tls.get_ref();
        let mut revocation = Some(ConnectionRevocation::new(
            ssl,
            crl_mgr.clone(),
            test_proxy_metrics(),
            server_wl.root_store(),
            KeyUsage::server_auth(),
        ));

        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                wait_for_revocation(revocation.as_mut())
            )
            .await
            .is_err(),
            "must not resolve before the CRL revokes the peer cert"
        );

        // Revoke the server (peer) cert and reload — bypassing the file-watcher debounce by
        // calling `load_crl` directly, so the test is deterministic.
        use std::io::{Seek, SeekFrom};
        crl_file.as_file_mut().set_len(0).unwrap();
        crl_file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        crl_file
            .write_all(crl_pem_revoking_cert(&server_wl.cert.serial_bytes()).as_bytes())
            .unwrap();
        crl_file.flush().unwrap();
        crl_mgr.load_crl().unwrap();

        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_revocation(revocation.as_mut()),
        )
        .await
        .expect("must resolve once the CRL revokes the peer cert");

        // Regression guard for expiry masking revocation. An HBONE session can outlive its peer's
        // cert lifetime, so the re-check pins verification to the handshake time. Demonstrate why:
        let rev = revocation.as_ref().unwrap();
        let past_expiry = UnixTime::since_unix_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                + Duration::from_secs(7200), // well past the cert's 3600s not_after
        );
        assert!(
            !rev.is_revoked_at(past_expiry),
            "checking past the cert's not_after yields CertExpired, not Revoked — this is the \
             masking a wall-clock re-check would suffer"
        );
        assert!(
            rev.is_revoked_at(rev.established),
            "checking at the handshake time still detects the revocation despite later expiry"
        );
    }
}
