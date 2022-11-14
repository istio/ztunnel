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

use core::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::Poll;

use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey;
use boring::pkey::PKey;
use boring::ssl;
use boring::stack::Stack;
use boring::x509::{self, X509StoreContextRef, X509StoreContext};
use boring::x509::extension::SubjectAlternativeName;
use hyper::client::ResponseFuture;
use hyper::{Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::body::BoxBody;
use tower::Service;
use tracing::{error, info};

use crate::identity::{self, Identity};

use super::Error;

pub fn cert_from(key: &[u8], cert: &[u8]) -> Certs {
    let cert = x509::X509::from_pem(cert).unwrap();
    let key = pkey::PKey::private_key_from_pem(key).unwrap();
    Certs { cert, key }
}

pub struct CertSign {
    pub csr: Vec<u8>,
    pub pkey: Vec<u8>,
}

pub struct CsrOptions {
    pub san: String,
}

impl CsrOptions {
    pub fn generate(&self) -> Result<CertSign, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let ec_key = EcKey::generate(&group)?;
        let pkey = PKey::from_ec_key(ec_key)?;

        let mut csr = x509::X509ReqBuilder::new()?;
        csr.set_pubkey(&pkey)?;
        let mut extensions = Stack::new()?;
        let subject_alternative_name = SubjectAlternativeName::new()
            .uri(&self.san)
            .critical()
            .build(&csr.x509v3_context(None))
            .unwrap();
        extensions.push(subject_alternative_name)?;
        csr.add_extensions(&extensions)?;
        csr.sign(&pkey, MessageDigest::sha256())?;

        let csr = csr.build();
        let pkey_pem = pkey.private_key_to_pem_pkcs8()?;
        let csr_pem = csr.to_pem()?;
        Ok(CertSign {
            csr: csr_pem,
            pkey: pkey_pem,
        })
    }
}

#[derive(Debug)]
pub struct Certs {
    // TODO: pretty sure this needs the full chain at some point
    cert: x509::X509,
    // root: x509::X509,
    key: pkey::PKey<pkey::Private>,
}

#[derive(Clone, Debug)]
pub struct TlsGrpcChannel {
    uri: Uri,
    client: hyper::Client<hyper_boring::HttpsConnector<hyper::client::HttpConnector>, BoxBody>,
}

/// grpc_connector provides a client TLS channel for gRPC requests.
pub fn grpc_connector(uri: &'static str) -> Result<TlsGrpcChannel, Error> {
    let mut conn = ssl::SslConnector::builder(ssl::SslMethod::tls_client())?;

    conn.set_verify(ssl::SslVerifyMode::NONE);
    conn.set_verify_callback(ssl::SslVerifyMode::NONE, |_, x509| {
        info!("ssl: {:?}", x509.error());
        // TODO: this MUST verify before upstreaming
        true
    });

    conn.set_alpn_protos(Alpn::H2.encode())?;
    conn.set_min_proto_version(Some(ssl::SslVersion::TLS1_2))?;
    conn.set_max_proto_version(Some(ssl::SslVersion::TLS1_3))?;
    let mut http = hyper::client::HttpConnector::new();
    http.enforce_http(false);
    let mut https = hyper_boring::HttpsConnector::with_connector(http, conn)?;
    https.set_callback(|cc, _| {
        // TODO: this MUST verify before upstreaming
        cc.set_verify_hostname(false);
        Ok(())
    });

    // Configure hyper's client to be h2 only and build with the
    // correct https connector.
    let hyper = hyper::Client::builder().http2_only(true).build(https);

    let uri = Uri::from_static(uri);

    Ok(TlsGrpcChannel { uri, client: hyper })
}


impl Certs {
    fn verify_mode()  -> ssl::SslVerifyMode {
        ssl::SslVerifyMode::PEER | ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT
    }

    pub fn acceptor(&self) -> Result<ssl::SslAcceptor, Error> {
        let _ctx = ssl::SslContext::builder(ssl::SslMethod::tls_server())?;
        // mozilla_intermediate_v5 is the only variant that enables TLSv1.3, so we use that.
        let mut conn = ssl::SslAcceptor::mozilla_intermediate_v5(ssl::SslMethod::tls_server())?;

        // Force use of TLSv1.3.
        conn.set_min_proto_version(Some(ssl::SslVersion::TLS1_3))?;
        conn.set_max_proto_version(Some(ssl::SslVersion::TLS1_3))?;
        conn.set_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
        )?;

        conn.set_private_key(&self.key)?;
        conn.set_certificate(&self.cert)?;
        conn.check_private_key()?;

        // Ensure that client certificates are validated when present.
        conn.set_verify_callback(Self::verify_mode(), |_, _| {
            // TODO: this MUST verify before upstreaming
            true
        });
        conn.set_alpn_protos(Alpn::H2.encode())?;

        Ok(conn.build())
    }
    pub fn connector(&self, id: Identity) -> Result<ssl::SslConnector, Error> {
        let mut conn = ssl::SslConnector::builder(ssl::SslMethod::tls_client())?;

        conn.set_private_key(&self.key)?;
        conn.set_certificate(&self.cert)?;
        conn.set_ca_file("./var/run/secrets/istio/root-cert.pem")?;
        conn.check_private_key()?;

        conn.set_verify_callback(Self::verify_mode(), Verifier::Exact(id).build());

        conn.set_alpn_protos(Alpn::H2.encode())?;
        conn.set_min_proto_version(Some(ssl::SslVersion::TLS1_3))?;
        conn.set_max_proto_version(Some(ssl::SslVersion::TLS1_3))?;

        Ok(conn.build())
    }
}

#[derive(Clone)]
enum Verifier {
    // Does not verify the identity.
    None,

    // Allows exactly one identity
    Exact(Identity),
    // TODO other types could be allowlist/denylist or some combo for RBAC
}

impl Verifier {
    // TODO other logic from 
    fn build(self) -> impl Fn(bool, &mut X509StoreContextRef) -> bool { 
        move |verified,ctx| {
            if !verified {
                // log errs from ctx? definitely increment counters
                return false;
            }
            let v = self.clone(); // TODO appease borrow checking in a cleaner way 
            match v {
                Verifier::None => true, 
                Verifier::Exact(id) => {
                    let ssl_idx = X509StoreContext::ssl_idx().expect("BUG: store context ssl index missing");
                    let ssl = ctx.ex_data(ssl_idx).expect("BUG: ssl data missing");
                    let cert =  ssl.peer_certificate().expect("BUG: missing peer cert");
                    let  Some(sans) = cert.subject_alt_names() else {
                        return false;
                    };
                    for san in sans {
                        if let Some(uri_san) = san.uri() {
                            let want_san = format!("{id}");
                            if uri_san ==  want_san{
                                info!("verified SAN {}", want_san);
                                return true;
                            }
                        }
                    }           
                   false 
                }, 
            }
        }
    }
}

impl Service<Request<BoxBody>> for TlsGrpcChannel {
    type Response = hyper::Response<hyper::Body>;
    type Error = hyper::Error;
    type Future = ResponseFuture;

    fn poll_ready(&mut self, _: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, mut req: Request<BoxBody>) -> Self::Future {
        let uri = Uri::builder()
            .scheme(self.uri.scheme().unwrap().clone())
            .authority(self.uri.authority().unwrap().clone())
            .path_and_query(req.uri().path_and_query().unwrap().clone())
            .build()
            .unwrap();
        *req.uri_mut() = uri;
        self.client.request(req)
    }
}

enum Alpn {
    H2,
}

impl Alpn {
    fn encode(&self) -> &[u8] {
        match self {
            Alpn::H2 => b"\x02h2",
        }
    }
}

#[async_trait::async_trait]
pub trait CertProvider: Send + Sync + Clone {
    async fn fetch_cert(&self, fd: RawFd) -> Result<ssl::SslAcceptor, TlsError>;
}

#[derive(Clone)]
pub struct BoringTlsAcceptor<F: CertProvider> {
    /// Acceptor is a function that determines the TLS context to use. As input, the FD of the client
    /// connection is provided.
    pub acceptor: F,
}

#[derive(thiserror::Error, Debug)]
pub enum TlsError {
    #[error("tls handshake error")]
    Handshake,
    #[error("certificate lookup error: {0} is not a known destination")]
    CertificateLookup(IpAddr),
    #[error("destination lookup error")]
    DestinationLookup(#[source] io::Error),
    #[error("signing error: {0}")]
    SigningError(#[from] identity::Error),
    #[error("ssl error: {0}")]
    SslError(#[from] Error),
}

impl<C, F> tls_listener::AsyncTls<C> for BoringTlsAcceptor<F>
where
    C: AsRawFd + AsyncRead + AsyncWrite + Unpin + Send + fmt::Debug + 'static,
    F: CertProvider + 'static,
{
    type Stream = tokio_boring::SslStream<C>;
    type Error = TlsError;
    type AcceptFuture = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn accept(&self, conn: C) -> Self::AcceptFuture {
        let fd = conn.as_raw_fd();
        let acceptor = self.acceptor.clone();
        Box::pin(async move {
            let tls = acceptor.fetch_cert(fd).await?;
            tokio_boring::accept(&tls, conn)
                .await
                .map_err(|_| TlsError::Handshake)
        })
    }
}

#[test]
#[cfg(feature = "fips")]
fn is_fips_enabled() {
    assert!(boring::fips::enabled());
}

#[test]
#[cfg(not(feature = "fips"))]
fn is_fips_disabled() {
    assert_eq!(false, boring::fips::enabled());
}
