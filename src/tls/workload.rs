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

use crate::identity::Identity;
use std::error::Error;
use std::fmt::{Debug, Display};

use crate::tls::lib::provider;
use crate::tls::{ServerCertProvider, TlsError};
use futures_util::TryFutureExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme,
};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use webpki::{ExpirationPolicy, KeyUsage, OwnedCertRevocationList, RevocationOptionsBuilder};

use crate::strng::Strng;
use crate::tls;
use crate::tls::crl::CrlManager;
use tokio::net::TcpStream;
use tokio_rustls::client;
use tracing::{debug, trace};

#[derive(Clone, Debug)]
pub struct InboundAcceptor<F: ServerCertProvider> {
    provider: F,
}

impl<F: ServerCertProvider> InboundAcceptor<F> {
    pub fn new(provider: F) -> Self {
        Self { provider }
    }
}

#[derive(Debug)]
pub(super) struct TrustDomainVerifier {
    trust_domain: Option<Strng>,
    crl_manager: Option<Arc<CrlManager>>,
    root_store: Arc<RootCertStore>,
}

impl TrustDomainVerifier {
    pub fn new(
        trust_domain: Option<Strng>,
        crl_manager: Option<Arc<CrlManager>>,
        root_store: Arc<RootCertStore>,
    ) -> Arc<Self> {
        Arc::new(Self {
            trust_domain,
            crl_manager,
            root_store,
        })
    }

    fn verify_trust_domain(&self, client_cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        use x509_parser::prelude::*;
        let Some(want_trust_domain) = &self.trust_domain else {
            // No need to verify
            return Ok(());
        };
        let (_, c) = X509Certificate::from_der(client_cert).map_err(|_e| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let ids = tls::certificate::identities(c).map_err(|_e| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;
        trace!(
            "verifying client identities {ids:?} against trust domain {:?}",
            want_trust_domain
        );
        ids.iter()
            .find(|id| match id {
                Identity::Spiffe { trust_domain, .. } => trust_domain == want_trust_domain,
            })
            .ok_or_else(|| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::Other(
                    rustls::OtherError(Arc::new(TlsError::SanTrustDomainError(
                        want_trust_domain.to_string(),
                        ids.clone(),
                    ))),
                ))
            })
            .map(|_| ())
    }

    /// verifies the certificate chain using webpki's verify_for_usage.
    fn verify_cert_chain(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        crls: Option<Vec<OwnedCertRevocationList>>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        use rustls::pki_types::TrustAnchor;
        use webpki::EndEntityCert;

        let cert = EndEntityCert::try_from(end_entity).map_err(|e| {
            debug!(error = ?e, "failed to parse end entity certificate");
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // convert root store to trust anchors
        let trust_anchors: Vec<TrustAnchor<'_>> = self
            .root_store
            .roots
            .iter()
            .map(|ta| TrustAnchor {
                subject: ta.subject.clone(),
                subject_public_key_info: ta.subject_public_key_info.clone(),
                name_constraints: ta.name_constraints.clone(),
            })
            .collect();

        if trust_anchors.is_empty() {
            debug!("no trust anchors available for certificate verification");
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }

        let sig_algs = provider().signature_verification_algorithms.all;

        // convert CRLs if provided - keep in scope for lifetime
        let crl_refs: Vec<webpki::CertRevocationList<'_>> = crls
            .map(|c| {
                c.into_iter()
                    .map(webpki::CertRevocationList::from)
                    .collect()
            })
            .unwrap_or_default();
        let crl_ref_refs: Vec<&webpki::CertRevocationList<'_>> = crl_refs.iter().collect();

        // build revocation options if CRLs are available
        let revocation = if crl_ref_refs.is_empty() {
            None
        } else {
            Some(
                RevocationOptionsBuilder::new(&crl_ref_refs)
                    .map_err(|_| {
                        debug!("failed to build revocation options");
                        rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
                    })?
                    .with_expiration_policy(ExpirationPolicy::Enforce)
                    .build(),
            )
        };

        // verify_for_usage performs:
        // - certificate chain validation
        // - signature verification for certs (and CRLs if provided)
        // - time bounds validation for certs (and CRLs if provided)
        // - revocation status checking (if CRLs provided)
        // - KeyUsage validation (cRLSign for CRL issuers if CRLs provided)
        cert.verify_for_usage(
            sig_algs,
            &trust_anchors,
            intermediates,
            now,
            KeyUsage::client_auth(),
            revocation,
            None,
        )
        .map_err(|e| {
            debug!(error = ?e, "certificate verification failed");
            match e {
                webpki::Error::CertRevoked => {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked)
                }
                webpki::Error::UnknownRevocationStatus => {
                    debug!("no authoritative crl found for certificate - issuer dn mismatch");
                    rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    )
                }
                webpki::Error::CrlExpired { .. } => {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
                }
                webpki::Error::InvalidCrlSignatureForPublicKey => {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
                }
                webpki::Error::UnknownIssuer => {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
                }
                webpki::Error::CertExpired { .. } => {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
                }
                webpki::Error::CertNotValidYet { .. } => {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet)
                }
                webpki::Error::InvalidSignatureForPublicKey => {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature)
                }
                _ => rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ),
            }
        })?;

        Ok(())
    }
}

// Implement our custom ClientCertVerifier logic. We only want to add an extra check, but
// need a decent amount of boilerplate to do so.
impl ClientCertVerifier for TrustDomainVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // return distinguished names from root store for client cert hints
        static EMPTY: &[DistinguishedName] = &[];
        EMPTY
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        // get CRLs if CRL manager is enabled
        let crls = self.crl_manager.as_ref().map(|m| m.get_crls());

        // use verify_for_usage for all certificate verification
        // this validates certificate chain, signatures, time bounds, and CRL (if provided)
        match self.verify_cert_chain(end_entity, intermediates, crls, now) {
            Ok(()) => {
                if self.crl_manager.is_some() {
                    debug!("client certificate chain is valid via verify_for_usage");
                } else {
                    debug!("client certificate chain is valid (crl checking disabled)");
                }
            }
            Err(e) => {
                // fail-open for CRL-related errors only, fail-closed for cert errors
                match &e {
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked) => {
                        debug!("client certificate is revoked, rejecting connection");
                        return Err(e);
                    }
                    // fail-open for CRL expiration - CRL might be stale but cert could be valid
                    rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
                        if self.crl_manager.is_some() =>
                    {
                        debug!(error = ?e, "crl expired, allowing connection (fail-open)");
                    }
                    // all other errors should be propagated (unknown issuer, bad signature, etc.)
                    _ => {
                        debug!(error = ?e, "certificate verification failed");
                        return Err(e);
                    }
                }
            }
        }

        // trust domain verification
        self.verify_trust_domain(end_entity)?;

        Ok(ClientCertVerified::assertion())
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

impl<F> tls_listener::AsyncTls<TcpStream> for InboundAcceptor<F>
where
    F: ServerCertProvider + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<TcpStream>;
    type Error = TlsError;
    type AcceptFuture = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn accept(&self, conn: TcpStream) -> Self::AcceptFuture {
        let mut acceptor = self.provider.clone();
        Box::pin(async move {
            let tls = acceptor.fetch_cert().await?;
            tokio_rustls::TlsAcceptor::from(tls)
                .accept(conn)
                .map_err(TlsError::Handshake)
                .await
        })
    }
}

#[derive(Clone, Debug)]
pub struct OutboundConnector {
    pub(super) client_config: Arc<ClientConfig>,
}

impl OutboundConnector {
    pub async fn connect<IO>(self, stream: IO) -> Result<client::TlsStream<IO>, io::Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let c = tokio_rustls::TlsConnector::from(self.client_config);
        // Use dummy value for domain because it doesn't matter.
        c.connect(
            ServerName::IpAddress(std::net::Ipv4Addr::new(0, 0, 0, 0).into()),
            stream,
        )
        .await
    }
}

#[derive(Debug)]
pub struct IdentityVerifier {
    pub(super) roots: Arc<RootCertStore>,
    pub(super) identity: Vec<Identity>,
}

impl IdentityVerifier {
    fn verify_full_san(&self, server_cert: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        use x509_parser::prelude::*;
        let (_, c) = X509Certificate::from_der(server_cert).map_err(|_e| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let id = tls::certificate::identities(c).map_err(|_e| {
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;
        trace!(
            "verifying server identities {id:?} against {:?}",
            self.identity
        );
        for ident in id.iter() {
            if let Some(_i) = self.identity.iter().find(|id| id == &ident) {
                return Ok(());
            }
        }
        debug!("identity mismatch {id:?} != {:?}", self.identity);
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Other(rustls::OtherError(Arc::new(DebugAsDisplay(
                TlsError::SanError(self.identity.clone(), id),
            )))),
        ))
    }
}

/// DebugAsDisplay is a shim to make an object implement Debug with its Display format
/// This is to workaround rustls only using Debug which makes our errors worse.
struct DebugAsDisplay<T>(T);

impl<T: Display> Debug for DebugAsDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}
impl<T: Display> Display for DebugAsDisplay<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<T: Error + Display> Error for DebugAsDisplay<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

// Rustls doesn't natively validate URI SAN.
// Build our own verifier, inspired by https://github.com/rustls/rustls/blob/ccb79947a4811412ee7dcddcd0f51ea56bccf101/rustls/src/webpki/server_verifier.rs#L239.
impl ServerCertVerifier for IdentityVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a  trusted `RootCertStore` CA
    /// - Not Expired
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _sn: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        use rustls::pki_types::TrustAnchor;
        use webpki::EndEntityCert;

        let cert = EndEntityCert::try_from(end_entity).map_err(|e| {
            debug!(error = ?e, "failed to parse end entity certificate");
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // convert root store to trust anchors
        let trust_anchors: Vec<TrustAnchor<'_>> = self
            .roots
            .roots
            .iter()
            .map(|ta| TrustAnchor {
                subject: ta.subject.clone(),
                subject_public_key_info: ta.subject_public_key_info.clone(),
                name_constraints: ta.name_constraints.clone(),
            })
            .collect();

        if trust_anchors.is_empty() {
            debug!("no trust anchors available for server cert verification");
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }

        let sig_algs = provider().signature_verification_algorithms.all;

        // verify_for_usage performs certificate chain validation and signature verification
        cert.verify_for_usage(
            sig_algs,
            &trust_anchors,
            intermediates,
            now,
            KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| {
            debug!(error = ?e, "server certificate verification failed");
            rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            )
        })?;

        if !ocsp_response.is_empty() {
            trace!("Unvalidated OCSP response: {ocsp_response:?}");
        }

        self.verify_full_san(end_entity)?;

        Ok(ServerCertVerified::assertion())
    }

    // Rest use the default implementations

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
