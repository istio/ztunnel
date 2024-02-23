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

use super::Error;

use crate::identity::{self, Identity};
use crate::state::workload::NetworkAddress;

use std::fmt::Debug;

use std::sync::Arc;

use rustls;
use rustls::crypto::CryptoProvider;

use rustls::ClientConfig;
use rustls::ServerConfig;

use tokio::net::TcpStream;

use tracing::error;

#[async_trait::async_trait]
pub trait ClientCertProvider: Send + Sync {
    async fn fetch_cert(&self) -> Result<ClientConfig, Error>;
}

#[async_trait::async_trait]
pub trait ServerCertProvider: Send + Sync + Clone {
    async fn fetch_cert(&mut self, fd: &TcpStream) -> Result<Arc<ServerConfig>, TlsError>;
}

pub(super) static TLS_VERSIONS: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

// Ztunnel use `rustls` with pluggable crypto modules.
// All crypto MUST be done via the below providers.
//
// One exception is CSR generation which doesn't currently have a plugin mechanism (https://github.com/rustls/rcgen/issues/228);
// In that case, and any future ones, it is critical to guard the code with appropriate `cfg` guards.

#[cfg(feature = "tls-boring")]
pub(super) fn provider() -> Arc<CryptoProvider> {
    // Due to 'fips-only' feature on the boring provider, this will use only AES_256_GCM_SHA384
    // and AES_128_GCM_SHA256
    // In later code we select to only use TLS 1.3
    Arc::new(boring_rustls_provider::provider())
}

#[cfg(feature = "tls-ring")]
pub(super) fn provider() -> Arc<CryptoProvider> {
    Arc::new(CryptoProvider {
        // Limit to only the subset of ciphers that are FIPS compatible
        cipher_suites: vec![
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ],
        ..rustls::crypto::ring::default_provider()
    })
}

#[derive(thiserror::Error, Debug)]
pub enum TlsError {
    #[error("tls handshake error: {0:?}")]
    Handshake(std::io::Error),
    #[error("certificate lookup error: {0} is not a known destination")]
    CertificateLookup(NetworkAddress),
    #[error("signing error: {0}")]
    SigningError(#[from] identity::Error),
    #[error("san verification error: remote did not present the expected SAN ({0:?}), got {1:?}")]
    SanError(Vec<Identity>, Vec<Identity>),
    #[error(
        "san verification error: remote did not present the expected trustdomain ({0}), got {1:?}"
    )]
    SanTrustDomainError(String, Vec<Identity>),
    #[error("failed getting ex data")]
    ExDataError,
    #[error("failed getting peer cert")]
    PeerCertError,
    #[error("ssl error: {0}")]
    SslError(#[from] Error),
}

#[cfg(test)]
pub mod tests {
    use std::time::Duration;

    use crate::identity::Identity;
    use crate::tls::WorkloadCertificate;

    use crate::tls::mock::*;

    #[test]
    #[cfg(feature = "tls-boring")]
    fn is_fips_enabled() {
        assert!(boring::fips::enabled());
    }

    #[test]
    fn test_workload_cert() {
        // note that TEST_CERT contains more than one cert - this is how istiod serves it when
        // intermediary cert is used..
        let roots: Vec<String> = std::str::from_utf8(TEST_CERT)
            .unwrap()
            .to_string()
            .split("-----END CERTIFICATE-----")
            .filter(|x| !x.trim().is_empty())
            .map(|x| format!("{}{}", x, "-----END CERTIFICATE-----"))
            .collect();
        let roots: Vec<&[u8]> = roots.iter().map(|x| x.as_bytes()).collect();
        let certs = WorkloadCertificate::new(TEST_PKEY, TEST_WORKLOAD_CERT, roots).unwrap();

        // 3 certs that should be here are the istiod cert, intermediary cert and the root cert.
        assert_eq!(certs.chain.len(), 3);
        assert_eq!(
            certs.cert.names(),
            vec![
                "commonName/default.default.svc.cluster.local",
                "URI(spiffe://cluster.local/ns/default/sa/default)",
            ]
        );

        assert_eq!(
            certs.chain[0].names(),
            vec!["organizationName/istiod.cluster.local".to_string()]
        );

        assert_eq!(
            certs.chain[1].names(),
            vec!["organizationName/intermediary.cluster.local".to_string(),]
        );
    }

    #[test]
    fn cert_expiration() {
        let expiry_seconds = 1000;
        let id: TestIdentity = Identity::default().into();
        let zero_dur = Duration::from_secs(0);
        let certs_not_expired = generate_test_certs(
            &id,
            Duration::from_secs(0),
            Duration::from_secs(expiry_seconds),
        );
        assert!(!certs_not_expired.is_expired());
        let seconds_until_refresh = certs_not_expired.get_duration_until_refresh().as_secs();
        // Give a couple second window to avoid flakiness in the test.
        assert!(
            seconds_until_refresh <= expiry_seconds / 2
                && seconds_until_refresh >= expiry_seconds / 2 - 1
        );

        let certs_expired = generate_test_certs(&id, zero_dur, zero_dur);
        assert!(certs_expired.is_expired());
        assert_eq!(certs_expired.get_duration_until_refresh(), zero_dur);

        let future_certs = generate_test_certs(
            &id,
            Duration::from_secs(1000),
            Duration::from_secs(expiry_seconds),
        );
        assert!(!future_certs.is_expired());
        assert_eq!(future_certs.get_duration_until_refresh(), zero_dur);
    }
}
