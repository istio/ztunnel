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

#[allow(unused_imports)]
use crate::PQC_ENABLED;
use crate::TLS12_ENABLED;
use crate::identity::{self, Identity};

use std::fmt::Debug;

use std::sync::Arc;

use rustls;
use rustls::crypto::CryptoProvider;

use rustls::ClientConfig;
use rustls::ServerConfig;

#[async_trait::async_trait]
pub trait ControlPlaneClientCertProvider: Send + Sync {
    async fn fetch_cert(&self, alt_hostname: Option<String>) -> Result<ClientConfig, Error>;
}

#[async_trait::async_trait]
pub trait ServerCertProvider: Send + Sync + Clone {
    async fn fetch_cert(&mut self) -> Result<Arc<ServerConfig>, TlsError>;
}

static TLS_VERSIONS_13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
static TLS_VERSIONS_12_AND_13: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

pub fn tls_versions() -> &'static [&'static rustls::SupportedProtocolVersion] {
    if *TLS12_ENABLED {
        TLS_VERSIONS_12_AND_13
    } else {
        TLS_VERSIONS_13_ONLY
    }
}

#[cfg(feature = "tls-aws-lc")]
pub static CRYPTO_PROVIDER: &str = "tls-aws-lc";
#[cfg(feature = "tls-ring")]
pub static CRYPTO_PROVIDER: &str = "tls-ring";
#[cfg(feature = "tls-boring")]
pub static CRYPTO_PROVIDER: &str = "tls-boring";
#[cfg(feature = "tls-openssl")]
pub static CRYPTO_PROVIDER: &str = "tls-openssl";

// Ztunnel use `rustls` with pluggable crypto modules.
// All crypto MUST be done via the below providers.
//
// One exception is CSR generation which doesn't currently have a plugin mechanism (https://github.com/rustls/rcgen/issues/228);
// In that case, and any future ones, it is critical to guard the code with appropriate `cfg` guards.

#[cfg(feature = "tls-boring")]
pub(super) fn provider() -> Arc<CryptoProvider> {
    // Due to 'fips-only' feature on the boring provider, this will use only AES_256_GCM_SHA384
    // and AES_128_GCM_SHA256
    Arc::new(boring_rustls_provider::provider())
}

#[cfg(feature = "tls-ring")]
pub(super) fn provider() -> Arc<CryptoProvider> {
    let mut cipher_suites = vec![
        rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    if *TLS12_ENABLED {
        // Add TLS 1.2 FIPS-compatible cipher suites
        cipher_suites.extend([
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]);
    }
    Arc::new(CryptoProvider {
        cipher_suites,
        ..rustls::crypto::ring::default_provider()
    })
}

#[cfg(feature = "tls-aws-lc")]
pub(super) fn provider() -> Arc<CryptoProvider> {
    let mut cipher_suites = vec![
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    if *TLS12_ENABLED {
        // Add TLS 1.2 FIPS-compatible cipher suites
        cipher_suites.extend([
            rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]);
    }
    let mut provider = CryptoProvider {
        cipher_suites,
        ..rustls::crypto::aws_lc_rs::default_provider()
    };

    if *PQC_ENABLED {
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768]
    }

    Arc::new(provider)
}

#[cfg(feature = "tls-openssl")]
pub(super) fn provider() -> Arc<CryptoProvider> {
    let mut cipher_suites = vec![
        rustls_openssl::cipher_suite::TLS13_AES_256_GCM_SHA384,
        rustls_openssl::cipher_suite::TLS13_AES_128_GCM_SHA256,
    ];
    if *TLS12_ENABLED {
        // Add TLS 1.2 FIPS-compatible cipher suites
        cipher_suites.extend([
            rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]);
    }

    let kx_groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup> = if *PQC_ENABLED {
        // To use PQC with OpenSSL provider the binary needs to be
        // both compiled and used with OpenSSL >= 3.5.0.
        #[cfg(ossl350)]
        {
            if openssl::version::number() >= 0x30500000 {
                vec![rustls_openssl::kx_group::X25519MLKEM768]
            } else {
                panic!("COMPLIANCE_POLICY=pqc requires OpenSSL >=3.5.0");
            }
        }
        #[cfg(not(ossl350))]
        {
            panic!("COMPLIANCE_POLICY=pqc requires compilation with OpenSSL >=3.5.0");
        }
    } else {
        vec![
            rustls_openssl::kx_group::SECP256R1,
            rustls_openssl::kx_group::SECP384R1,
        ]
    };

    Arc::new(CryptoProvider {
        cipher_suites,
        kx_groups,
        ..rustls_openssl::default_provider()
    })
}

#[derive(thiserror::Error, Debug)]
pub enum TlsError {
    #[error("tls handshake error: {0:?}")]
    Handshake(std::io::Error),
    #[error("signing error: {0}")]
    SigningError(#[from] identity::Error),
    #[error(
        "identity verification error: peer did not present the expected SAN ({}), got {}",
        display_list(.0),
        display_list(.1)
    )]
    SanError(Vec<Identity>, Vec<Identity>),
    #[error(
        "identity verification error: peer did not present the expected trustdomain ({}), got {}",
        .0,
        display_list(.1)
    )]
    SanTrustDomainError(String, Vec<Identity>),
    #[error("ssl error: {0}")]
    SslError(#[from] Error),
}

fn display_list<T: ToString>(i: &[T]) -> String {
    i.iter()
        .map(|id| id.to_string())
        .collect::<Vec<String>>()
        .join(",")
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
            .split("-----END CERTIFICATE-----")
            .filter(|x| !x.trim().is_empty())
            .map(|x| format!("{}{}", x, "-----END CERTIFICATE-----"))
            .collect();
        let roots: Vec<&[u8]> = roots.iter().map(|x| x.as_bytes()).collect();
        let certs = WorkloadCertificate::new(TEST_PKEY, TEST_WORKLOAD_CERT, roots).unwrap();

        // 3 certs that should be here are the istiod cert, intermediary cert and the root cert.
        assert_eq!(certs.chain.len(), 2);
        assert_eq!(certs.roots.len(), 1);
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

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_openssl_provider_created_successfully() {
        // Test that provider can be created without panicking
        let provider = super::provider();
        assert!(
            !provider.kx_groups.is_empty(),
            "kx_groups should not be empty"
        );
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_openssl_provider_kx_groups_valid() {
        // Provider must have valid key exchange groups regardless of PQC state
        let provider = super::provider();
        let expected_len = if *crate::PQC_ENABLED { 1 } else { 2 };
        assert_eq!(
            provider.kx_groups.len(),
            expected_len,
            "PQC={} should have {} kx groups",
            *crate::PQC_ENABLED,
            expected_len
        );
    }

    #[test]
    #[cfg(all(feature = "tls-openssl", not(ossl350)))]
    fn test_pqc_panic_expected_without_ossl350() {
        // Without ossl350 cfg, PQC cannot be enabled (would panic in provider())
        if *crate::PQC_ENABLED {
            panic!("PQC_ENABLED=true without ossl350 cfg - provider() will panic");
        }
    }
}
