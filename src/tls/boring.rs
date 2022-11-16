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
use std::time::Duration;

use boring::asn1::{Asn1Time, Asn1TimeRef};
use boring::ec::{EcGroup, EcKey};
use boring::hash::MessageDigest;
use boring::nid::Nid;
use boring::pkey;
use boring::pkey::PKey;
use boring::ssl::{self, SslContextBuilder};
use boring::stack::Stack;
use boring::x509::extension::SubjectAlternativeName;
use boring::x509::{self, GeneralName, X509StoreContext, X509StoreContextRef, X509VerifyResult};
use hyper::client::ResponseFuture;
use hyper::{Request, Uri};
use tokio::io::{AsyncRead, AsyncWrite};
use tonic::body::BoxBody;
use tower::Service;
use tracing::{error, info};

use crate::identity::{self, Identity};

use super::Error;

pub fn cert_from(key: &[u8], cert: &[u8], chain: Vec<&[u8]>) -> Certs {
    let key = pkey::PKey::private_key_from_pem(key).unwrap();
    let cert = x509::X509::from_pem(cert).unwrap();
    let chain = chain
        .into_iter()
        .map(|pem| x509::X509::from_pem(pem).unwrap())
        .collect();
    Certs { cert, chain, key }
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

#[derive(Clone, Debug)]
pub struct Certs {
    // the leaf cert
    cert: x509::X509,
    // the remainder of the chain, not including the leaf cert
    chain: Vec<x509::X509>,
    key: pkey::PKey<pkey::Private>,
}

impl PartialEq for Certs {
    fn eq(&self, other: &Self) -> bool {
        self.cert.to_der().iter().eq(other.cert.to_der().iter())
            && self
                .key
                .private_key_to_der()
                .iter()
                .eq(other.key.private_key_to_der().iter())
    }
}

impl Certs {
    pub fn is_expired(&self) -> bool {
        let current = Asn1Time::days_from_now(0).unwrap();
        let end: &Asn1TimeRef = self.cert.not_after();
        let time_until_expired = current.diff(end).unwrap();
        if time_until_expired.secs > 0 {
            return false;
        }
        true
    }

    pub fn get_duration_until_refresh(&self) -> Duration {
        let current = Asn1Time::days_from_now(0).unwrap();
        let start: &Asn1TimeRef = self.cert.not_before();
        let end: &Asn1TimeRef = self.cert.not_after();

        let total_lifetime = start.diff(end).unwrap();
        let total_lifetime_secs = total_lifetime.days * 86400 + total_lifetime.secs;
        let halflife = total_lifetime_secs / 2;
        let elapsed = start.diff(&current).unwrap();
        let elapsed_secs = elapsed.days * 86400 + elapsed.secs; // 86400 secs/day
        let returnval: i32 = halflife - elapsed_secs;
        if returnval < 0 {
            return Duration::from_secs(0);
        }
        Duration::from_secs(u64::try_from(returnval).unwrap())
    }
}

#[derive(Clone, Debug)]
pub struct TlsGrpcChannel {
    uri: Uri,
    client: hyper::Client<hyper_boring::HttpsConnector<hyper::client::HttpConnector>, BoxBody>,
}

/// grpc_connector provides a client TLS channel for gRPC requests.
pub fn grpc_connector(uri: String) -> Result<TlsGrpcChannel, Error> {
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

    let uri = Uri::try_from(uri)?;

    Ok(TlsGrpcChannel { uri, client: hyper })
}

impl Certs {
    fn verify_mode() -> ssl::SslVerifyMode {
        ssl::SslVerifyMode::PEER | ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT
    }

    pub fn acceptor(&self) -> Result<ssl::SslAcceptor, Error> {
        let _ctx = ssl::SslContext::builder(ssl::SslMethod::tls_server())?;
        // mozilla_intermediate_v5 is the only variant that enables TLSv1.3, so we use that.
        let mut conn = ssl::SslAcceptor::mozilla_intermediate_v5(ssl::SslMethod::tls_server())?;
        self.setup_ctx(&mut conn)?;

        Ok(conn.build())
    }
    pub fn connector(&self, dest_id: &Option<Identity>) -> Result<ssl::SslConnector, Error> {
        let mut conn = ssl::SslConnector::builder(ssl::SslMethod::tls_client())?;
        self.setup_ctx(&mut conn)?;

        // client verifies SAN
        if let Some(dest_id) = dest_id {
            conn.set_verify_callback(
                Self::verify_mode(),
                Verifier::San(dest_id.clone()).callback(),
            );
        }

        Ok(conn.build())
    }

    fn setup_ctx(&self, conn: &mut SslContextBuilder) -> Result<(), Error> {
        // general TLS options
        conn.set_alpn_protos(Alpn::H2.encode())?;
        conn.set_min_proto_version(Some(ssl::SslVersion::TLS1_3))?;
        conn.set_max_proto_version(Some(ssl::SslVersion::TLS1_3))?;
        conn.set_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
        )?;
        // key and certs
        conn.set_private_key(&self.key)?;
        conn.set_certificate(&self.cert)?;
        for chain_cert in self.chain.iter() {
            conn.cert_store_mut().add_cert(chain_cert.clone())?;
        }
        conn.check_private_key()?;

        // by default, allow boringssl to do standard validation
        conn.set_verify_callback(Self::verify_mode(), Verifier::None.callback());

        Ok(())
    }
}

enum Verifier {
    // Does not verify an individual identity.
    None,

    // Allows exactly one identity, making sure at least one of the presented certs
    San(Identity),
}

impl Verifier {
    fn base_verifier(verified: bool, ctx: &mut X509StoreContextRef) -> Result<(), TlsError> {
        if !verified {
            return Err(TlsError::Verification(ctx.error()));
        };
        Ok(())
    }

    fn verifiy_san(&self, ctx: &mut X509StoreContextRef) -> Result<(), TlsError> {
        let Self::San(identity) = self else {
            // not verifying san
            return Ok(());
        };

        // internally, openssl tends to .expect the results of these methods.
        // TODO bubble up better error message
        let ssl_idx = X509StoreContext::ssl_idx().map_err(Error::SslError)?;
        let cert = ctx
            .ex_data(ssl_idx)
            .ok_or(TlsError::SanError)?
            .peer_certificate()
            .ok_or(TlsError::SanError)?;

        let want_san = format!("{identity}");
        cert.subject_alt_names()
            .unwrap_or(boring::stack::Stack::<GeneralName>::new().map_err(Error::SslError)?)
            .iter()
            .find(|san| san.uri().unwrap_or("<non-uri>") == want_san)
            .ok_or(TlsError::SanError)
            .map(|_| ())
    }

    fn verifiy(&self, verified: bool, ctx: &mut X509StoreContextRef) -> Result<(), TlsError> {
        Self::base_verifier(verified, ctx)?;
        self.verifiy_san(ctx)?;
        Ok(())
    }

    fn callback(self) -> impl Fn(bool, &mut X509StoreContextRef) -> bool {
        move |verified, ctx| match self.verifiy(verified, ctx) {
            Ok(_) => true,
            Err(e) => {
                // TODO metrics/counters; info would be too noisy
                info!("failed verifying TLS: {e}");
                false
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
    async fn fetch_cert(&mut self, fd: RawFd) -> Result<ssl::SslAcceptor, TlsError>;
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
    #[error("tls verification error: {0}")]
    Verification(X509VerifyResult),
    #[error("certificate lookup error: {0} is not a known destination")]
    CertificateLookup(IpAddr),
    #[error("destination lookup error")]
    DestinationLookup(#[source] io::Error),
    #[error("signing error: {0}")]
    SigningError(#[from] identity::Error),
    #[error("san verification error: remote did not present the expected SAN")]
    SanError,
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
        let mut acceptor = self.acceptor.clone();
        Box::pin(async move {
            let tls = acceptor.fetch_cert(fd).await?;
            tokio_boring::accept(&tls, conn)
                .await
                .map_err(|_| TlsError::Handshake)
        })
    }
}


#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    const CERT: &[u8] = include_bytes!("cert.crt");
    const PKEY: &[u8] = include_bytes!("cert.key");

    pub fn test_certs() -> Certs {
        let cert = x509::X509::from_pem(CERT).unwrap();
        let key = pkey::PKey::private_key_from_pem(PKEY).unwrap();
        Certs { cert, key, chain: unimplemented!() }
    }

    // Creates an invalid dummy cert with overridden expire time
    pub fn generate_test_certs(seconds_until_expiry: Duration) -> Certs {
        let mut tmp = x509::X509::builder().unwrap();
        let current = Asn1Time::days_from_now(0).unwrap();
        let expire_time: i64 = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + seconds_until_expiry.as_secs())
        .try_into()
        .unwrap();
        tmp.set_not_before(&current)
            .expect("error setting cert 'not_before'");
        tmp.set_not_after(&Asn1Time::from_unix(expire_time).unwrap())
            .expect("error setting cert 'not_after'");

        let cert = tmp.build();
        let key = pkey::PKey::private_key_from_pem(PKEY).unwrap();
        Certs { cert, key, chain: unimplemented!() }
    }

    #[test]
    fn is_fips_enabled() {
        assert!(boring::fips::enabled());
    }
}

#[test]
#[cfg(not(feature = "fips"))]
fn is_fips_disabled() {
    assert_eq!(false, boring::fips::enabled());
}
