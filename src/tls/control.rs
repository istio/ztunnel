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

use crate::config::RootCert;
use crate::identity::AuthSource;
use crate::tls::lib::provider;
use crate::tls::{ControlPlaneClientCertProvider, Error, WorkloadCertificate};
use hyper::body::Incoming;
use hyper::Uri;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use itertools::Itertools;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tonic::body::BoxBody;
use tracing::debug;

async fn root_to_store(root_cert: &RootCert) -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    match root_cert {
        RootCert::File(f) => {
            let certfile = tokio::fs::read(f)
                .await
                .map_err(|e| Error::InvalidRootCert(e.to_string()))?;
            let mut reader = std::io::BufReader::new(Cursor::new(certfile));
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidRootCert(e.to_string()))?;
            roots.add_parsable_certificates(certs);
        }
        RootCert::Static(b) => {
            let mut reader = std::io::BufReader::new(Cursor::new(b));
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidRootCert(e.to_string()))?;
            roots.add_parsable_certificates(certs);
        }
        RootCert::Default => {
            let certs = {
                let rustls_native_certs::CertificateResult { certs, errors, .. } =
                    rustls_native_certs::load_native_certs();
                if !errors.is_empty() {
                    return Err(Error::InvalidRootCert(
                        errors.into_iter().map(|e| e.to_string()).join(","),
                    ));
                }
                certs
            };
            roots.add_parsable_certificates(certs);
        }
    };
    Ok(roots)
}

#[derive(Debug)]
pub enum ControlPlaneAuthentication {
    RootCert(RootCert),
    ClientBundle(WorkloadCertificate),
}

#[async_trait::async_trait]
impl ControlPlaneClientCertProvider for ControlPlaneAuthentication {
    async fn fetch_cert(&self, alt_hostname: Option<String>) -> Result<ClientConfig, Error> {
        match self {
            ControlPlaneAuthentication::RootCert(root_cert) => {
                control_plane_client_config(root_cert, alt_hostname).await
            }
            ControlPlaneAuthentication::ClientBundle(_bundle) => {
                // TODO: implement this. Its is not currently used so no need.
                unimplemented!();
            }
        }
    }
}

#[derive(Debug)]
struct AltHostnameVerifier {
    roots: Arc<rustls::RootCertStore>,
    alt_server_name: ServerName<'static>,
}

// A custom verifier that allows alternative server names to be accepted.
// Build our own verifier, inspired by https://github.com/rustls/rustls/blob/ccb79947a4811412ee7dcddcd0f51ea56bccf101/rustls/src/webpki/server_verifier.rs#L239.
impl ServerCertVerifier for AltHostnameVerifier {
    /// Will verify the certificate is valid in the following ways:
    /// - Signed by a  trusted `RootCertStore` CA
    /// - Not Expired
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        sn: &ServerName,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let cert = rustls::server::ParsedCertificate::try_from(end_entity)?;

        let algs = provider().signature_verification_algorithms;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            algs.all,
        )?;

        if !ocsp_response.is_empty() {
            tracing::trace!("Unvalidated OCSP response: {ocsp_response:?}");
        }

        // First attempt to verify the original server name...
        if let Err(err) = rustls::client::verify_server_name(&cert, sn) {
            tracing::debug!(
                "failed to verify {sn:?} ({err}), attempting alt name {:?}",
                self.alt_server_name
            );
            // That failed, lets try the alternative one
            rustls::client::verify_server_name(&cert, &self.alt_server_name)?;
        }

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

async fn control_plane_client_config(
    root_cert: &RootCert,
    alt_hostname: Option<String>,
) -> Result<ClientConfig, Error> {
    let roots = root_to_store(root_cert).await?;
    let c = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(crate::tls::TLS_VERSIONS)?;
    if let Some(alt_hostname) = alt_hostname {
        debug!("using alternate hostname {alt_hostname} for TLS verification");
        Ok(c.dangerous()
            .with_custom_certificate_verifier(Arc::new(AltHostnameVerifier {
                roots: Arc::new(roots),
                alt_server_name: ServerName::try_from(alt_hostname)?,
            }))
            .with_no_client_auth())
    } else {
        Ok(c.with_root_certificates(roots).with_no_client_auth())
    }
}

#[derive(Clone, Debug)]
pub struct TlsGrpcChannel {
    uri: Uri,
    client: hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, BoxBody>,
    auth: Arc<AuthSource>,
}

/// grpc_connector provides a client TLS channel for gRPC requests.
pub fn grpc_connector(
    uri: String,
    auth: AuthSource,
    cc: ClientConfig,
) -> Result<TlsGrpcChannel, Error> {
    let uri = Uri::try_from(uri)?;
    let _is_localhost_call = uri.host() == Some("localhost");
    let mut http: HttpConnector = HttpConnector::new();
    // Set keepalives to match istio's Envoy bootstrap configuration:
    // https://github.com/istio/istio/blob/a29d5c9c27d80bff31f218936f5a96759d8911c8/tools/packaging/common/envoy_bootstrap.json#L322C14-L322C28
    //
    // keepalive_interval and keepalive_retries match the linux default per Envoy docs:
    // https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/address.proto#config-core-v3-tcpkeepalive
    http.set_keepalive(Some(Duration::from_secs(300)));
    http.set_keepalive_interval(Some(Duration::from_secs(75)));
    http.set_keepalive_retries(Some(9));
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    http.enforce_http(false);
    let https: HttpsConnector<HttpConnector> = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cc)
        .https_only()
        .enable_http2()
        .wrap_connector(http);

    // Configure hyper's client to be h2 only and build with the
    // correct https connector.
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .timer(crate::hyper_util::TokioTimer)
        .build(https);

    Ok(TlsGrpcChannel {
        uri,
        auth: Arc::new(auth),
        client,
    })
}

impl tower::Service<http::Request<BoxBody>> for TlsGrpcChannel {
    type Response = http::Response<Incoming>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, mut req: http::Request<BoxBody>) -> Self::Future {
        let mut uri = Uri::builder();
        if let Some(scheme) = self.uri.scheme() {
            uri = uri.scheme(scheme.to_owned());
        }
        if let Some(authority) = self.uri.authority() {
            uri = uri.authority(authority.to_owned());
        }
        if let Some(path_and_query) = req.uri().path_and_query() {
            uri = uri.path_and_query(path_and_query.to_owned());
        }
        let uri = uri.build().expect("uri must be valid");
        *req.uri_mut() = uri;

        let client = self.client.clone();
        let auth = self.auth.clone();
        Box::pin(async move {
            auth.insert_headers(req.headers_mut()).await?;
            Ok(client.request(req).await?)
        })
    }
}
