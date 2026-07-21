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
    CertRevocationListError, ClientConfig, DigitallySignedStruct, DistinguishedName, OtherError,
    RootCertStore, SignatureScheme,
};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use webpki::{CertRevocationList, KeyUsage};

use crate::strng::Strng;
use crate::tls;
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
    base: Arc<dyn ClientCertVerifier>,
    trust_domain: Option<Strng>,
}

impl TrustDomainVerifier {
    pub fn new(base: Arc<dyn ClientCertVerifier>, trust_domain: Option<Strng>) -> Arc<Self> {
        Arc::new(Self { base, trust_domain })
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
}

// Implement our custom ClientCertVerifier logic. We only want to add an extra check, but
// need a decent amount of boilerplate to do so.
impl ClientCertVerifier for TrustDomainVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.base.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let res = self
            .base
            .verify_client_cert(end_entity, intermediates, now)?;
        self.verify_trust_domain(end_entity)?;
        Ok(res)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.base.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.base.supported_verify_schemes()
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
    pub(super) crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
}

/// Maps `rustls-webpki` errors to `rustls::Error`.
///
/// We map the variants that carry structured `CertificateError` / CRL types used by rustls for
/// handshake reporting; everything else (signature-algorithm context, uncommon path failures, and
/// future `#[non_exhaustive]` variants) is wrapped in [`CertificateError::Other`] while preserving
/// the original `webpki::Error` for logs.
fn webpki_error_to_rustls(error: webpki::Error) -> rustls::Error {
    use rustls::CertificateError;
    use webpki::Error;

    match error {
        Error::BadDer | Error::BadDerTime | Error::TrailingData(_) => {
            CertificateError::BadEncoding.into()
        }
        Error::CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        Error::CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        Error::UnknownIssuer => CertificateError::UnknownIssuer.into(),
        Error::CertNotValidForName(ctx) => CertificateError::NotValidForNameContext {
            expected: ctx.expected,
            presented: ctx.presented,
        }
        .into(),
        Error::CertRevoked => CertificateError::Revoked.into(),
        Error::UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        Error::CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        Error::IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),
        Error::InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        #[allow(deprecated)]
        Error::RequiredEkuNotFound | Error::RequiredEkuNotFoundContext(_) => {
            CertificateError::InvalidPurpose.into()
        }
        e => CertificateError::Other(OtherError(std::sync::Arc::new(e))).into(),
    }
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
    /// - Signed by a trusted `RootCertStore` CA
    /// - Not expired
    /// - Optional CRL checking (same webpki policy as inbound `WebPkiClientVerifier` when enabled)
    /// - SPIFFE URI SAN matches expected identities (not DNS `ServerName`)
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _sn: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let crls: Arc<Vec<CertRevocationList<'static>>> = self
            .crl_manager
            .as_deref()
            .map(|mgr| mgr.get_crls())
            .unwrap_or_default();

        // Shared cert chain + CRL-revocation verification
        crate::tls::revocation::verify_cert_chain(
            end_entity,
            intermediates,
            &self.roots,
            now,
            KeyUsage::server_auth(),
            &crls,
        )
        .map_err(webpki_error_to_rustls)?;

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
