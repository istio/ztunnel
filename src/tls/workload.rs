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

use crate::tls::lib::provider;
use crate::tls::{ServerCertProvider, TlsError};
use futures_util::TryFutureExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme,
};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

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
    trust_domain: Option<String>,
}

impl TrustDomainVerifier {
    pub fn new(base: Arc<dyn ClientCertVerifier>, trust_domain: Option<String>) -> Arc<Self> {
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
            let tls = acceptor.fetch_cert(&conn).await?;
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
    pub async fn connect(
        self,
        stream: TcpStream,
    ) -> Result<client::TlsStream<TcpStream>, io::Error> {
        let dest = ServerName::IpAddress(stream.peer_addr().unwrap().ip().into());
        let c = tokio_rustls::TlsConnector::from(self.client_config);
        c.connect(dest, stream).await
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
        debug!("identity mismatch");
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
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
        let cert = ParsedCertificate::try_from(end_entity)?;

        let algs = provider().signature_verification_algorithms;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            algs.all,
        )?;

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
