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
use crate::strng::Strng;

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

/// TLS version for runtime configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TlsVersion {
    Tls12,
    Tls13,
}

/// TLS configuration from MeshConfig.meshMTLS.
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TlsConfig {
    pub min_protocol_version: Option<TlsVersion>,
    pub cipher_suites: Vec<String>,
    pub ecdh_curves: Vec<String>,
}

/// Runtime mesh settings from xDS (maps to MeshConfig fields).
#[derive(Debug, Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MeshSettings {
    pub trust_domain: Strng,
    pub trust_domain_aliases: Vec<Strng>,
    pub tls: Option<TlsConfig>,
}

/// Check if TLS 1.2 is enabled (xDS settings > env var).
fn is_tls12_enabled(settings: Option<&MeshSettings>) -> bool {
    if let Some(ms) = settings {
        if let Some(ref tls) = ms.tls {
            if let Some(min_version) = tls.min_protocol_version {
                return min_version == TlsVersion::Tls12;
            }
        }
    }
    *TLS12_ENABLED
}

static TLS_VERSIONS_13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
static TLS_VERSIONS_12_AND_13: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

pub fn tls_versions(
    settings: Option<&MeshSettings>,
) -> &'static [&'static rustls::SupportedProtocolVersion] {
    if is_tls12_enabled(settings) {
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

/// Macro to generate cipher suite parsing functions for each crypto provider.
/// All providers support the same cipher suite names, only the module path differs.
macro_rules! impl_parse_cipher_suites {
    ($fn_name:ident, $provider_mod:path) => {
        fn $fn_name(
            settings: Option<&MeshSettings>,
        ) -> Option<Vec<rustls::SupportedCipherSuite>> {
            use $provider_mod as provider_cs;
            let tls = settings?.tls.as_ref()?;
            if tls.cipher_suites.is_empty() {
                return None;
            }

            let mut suites = Vec::new();
            for name in &tls.cipher_suites {
                match name.as_str() {
                    "TLS_AES_256_GCM_SHA384" => suites.push(provider_cs::TLS13_AES_256_GCM_SHA384),
                    "TLS_AES_128_GCM_SHA256" => suites.push(provider_cs::TLS13_AES_128_GCM_SHA256),
                    "TLS_CHACHA20_POLY1305_SHA256" => {
                        suites.push(provider_cs::TLS13_CHACHA20_POLY1305_SHA256)
                    }
                    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
                        suites.push(provider_cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
                    }
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
                        suites.push(provider_cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                    }
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
                        suites.push(provider_cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
                    }
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
                        suites.push(provider_cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
                    }
                    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => {
                        suites.push(provider_cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)
                    }
                    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => {
                        suites.push(provider_cs::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256)
                    }
                    unknown => tracing::warn!("Unknown cipher suite '{}', ignoring", unknown),
                }
            }

            if suites.is_empty() {
                tracing::warn!(
                    "all configured cipher suites were unrecognized ({:?}), falling back to defaults",
                    tls.cipher_suites
                );
                None
            } else {
                Some(suites)
            }
        }
    };
}

#[cfg(feature = "tls-boring")]
pub(crate) fn provider(_settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
    if let Some(ms) = _settings {
        if ms.tls.is_some() {
            tracing::warn!("MeshSettings TLS configuration ignored: BoringSSL FIPS uses fixed cipher suites");
        }
    }
    Arc::new(boring_rustls_provider::provider())
}

#[cfg(feature = "tls-ring")]
impl_parse_cipher_suites!(parse_cipher_suites_ring, rustls::crypto::ring::cipher_suite);

#[cfg(feature = "tls-ring")]
pub(crate) fn provider(settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
    let cipher_suites = if let Some(suites) = parse_cipher_suites_ring(settings) {
        suites
    } else {
        let mut suites = vec![
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ];
        if is_tls12_enabled(settings) {
            suites.extend([
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]);
        }
        suites
    };
    Arc::new(CryptoProvider {
        cipher_suites,
        ..rustls::crypto::ring::default_provider()
    })
}

#[cfg(feature = "tls-aws-lc")]
impl_parse_cipher_suites!(parse_cipher_suites_aws_lc, rustls::crypto::aws_lc_rs::cipher_suite);

#[cfg(feature = "tls-aws-lc")]
pub(crate) fn provider(settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
    let cipher_suites = if let Some(suites) = parse_cipher_suites_aws_lc(settings) {
        suites
    } else {
        let mut suites = vec![
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ];
        if is_tls12_enabled(settings) {
            suites.extend([
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls::crypto::aws_lc_rs::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]);
        }
        suites
    };

    let mut provider = CryptoProvider {
        cipher_suites,
        ..rustls::crypto::aws_lc_rs::default_provider()
    };

    // Key exchange groups: xDS settings override PQC_ENABLED env var
    if let Some(kx_groups) = parse_kx_groups_aws_lc(settings) {
        provider.kx_groups = kx_groups;
    } else if *PQC_ENABLED {
        provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768];
    }

    Arc::new(provider)
}

#[cfg(feature = "tls-aws-lc")]
fn parse_kx_groups_aws_lc(
    settings: Option<&MeshSettings>,
) -> Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>> {
    let tls = settings?.tls.as_ref()?;
    if tls.ecdh_curves.is_empty() {
        return None;
    }

    let mut groups = Vec::new();
    for name in &tls.ecdh_curves {
        match name.as_str() {
            "X25519MLKEM768" => groups.push(rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768),
            "X25519" => groups.push(rustls::crypto::aws_lc_rs::kx_group::X25519),
            "P-256" | "SECP256R1" => groups.push(rustls::crypto::aws_lc_rs::kx_group::SECP256R1),
            "P-384" | "SECP384R1" => groups.push(rustls::crypto::aws_lc_rs::kx_group::SECP384R1),
            unknown => tracing::warn!("Unknown ECDH curve '{}', ignoring", unknown),
        }
    }

    if groups.is_empty() {
        tracing::warn!(
            "all configured ECDH curves were unrecognized ({:?}), falling back to defaults",
            tls.ecdh_curves
        );
        None
    } else {
        Some(groups)
    }
}

#[cfg(feature = "tls-openssl")]
impl_parse_cipher_suites!(parse_cipher_suites_openssl, rustls_openssl::cipher_suite);

#[cfg(feature = "tls-openssl")]
pub(crate) fn provider(settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
    let cipher_suites = if let Some(suites) = parse_cipher_suites_openssl(settings) {
        suites
    } else {
        let mut suites = vec![
            rustls_openssl::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls_openssl::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ];
        if is_tls12_enabled(settings) {
            suites.extend([
                rustls_openssl::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                rustls_openssl::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                rustls_openssl::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]);
        }
        suites
    };

    // Key exchange groups: xDS settings > PQC_ENABLED env var > defaults
    let kx_groups = if let Some(groups) = parse_kx_groups_openssl(settings) {
        groups
    } else if *PQC_ENABLED {
        #[cfg(ossl350)]
        if openssl::version::number() >= 0x30500000 {
            vec![rustls_openssl::kx_group::X25519MLKEM768]
        } else {
            panic!("COMPLIANCE_POLICY=pqc requires OpenSSL >=3.5.0");
        }
        #[cfg(not(ossl350))]
        panic!("COMPLIANCE_POLICY=pqc requires OpenSSL >=3.5.0");
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

#[cfg(feature = "tls-openssl")]
fn parse_kx_groups_openssl(
    settings: Option<&MeshSettings>,
) -> Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>> {
    let tls = settings?.tls.as_ref()?;
    if tls.ecdh_curves.is_empty() {
        return None;
    }

    let mut groups = Vec::new();
    for name in &tls.ecdh_curves {
        match name.as_str() {
            #[cfg(ossl350)]
            "X25519MLKEM768" if openssl::version::number() >= 0x30500000 => {
                groups.push(rustls_openssl::kx_group::X25519MLKEM768);
            }
            "X25519" => groups.push(rustls_openssl::kx_group::X25519),
            "P-256" | "SECP256R1" => groups.push(rustls_openssl::kx_group::SECP256R1),
            "P-384" | "SECP384R1" => groups.push(rustls_openssl::kx_group::SECP384R1),
            unknown => {
                tracing::warn!("Unknown ECDH curve '{}', ignoring", unknown);
            }
        }
    }

    if groups.is_empty() {
        tracing::warn!(
            "all configured ECDH curves were unrecognized ({:?}), falling back to defaults",
            tls.ecdh_curves
        );
        None
    } else {
        Some(groups)
    }
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
        let provider = super::provider(None);
        assert!(
            !provider.kx_groups.is_empty(),
            "kx_groups should not be empty"
        );
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_openssl_provider_kx_groups_valid() {
        let provider = super::provider(None);
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
        if *crate::PQC_ENABLED {
            panic!("PQC_ENABLED=true without ossl350 cfg - provider() will panic");
        }
    }

    #[test]
    fn test_mesh_settings_default() {
        let settings = super::MeshSettings::default();
        assert!(settings.trust_domain.is_empty());
        assert!(settings.trust_domain_aliases.is_empty());
        assert!(settings.tls.is_none());
    }

    #[test]
    fn test_is_tls12_enabled_none_settings() {
        let result = super::is_tls12_enabled(None);
        assert_eq!(result, *crate::TLS12_ENABLED);
    }

    #[test]
    fn test_is_tls12_enabled_with_tls13() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls13),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        assert!(!super::is_tls12_enabled(Some(&settings)));
    }

    #[test]
    fn test_is_tls12_enabled_with_tls12() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls12),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        assert!(super::is_tls12_enabled(Some(&settings)));
    }

    #[test]
    fn test_is_tls12_enabled_no_tls_config() {
        let settings = super::MeshSettings {
            trust_domain: "cluster.local".into(),
            trust_domain_aliases: vec![],
            tls: None,
        };
        assert_eq!(super::is_tls12_enabled(Some(&settings)), *crate::TLS12_ENABLED);
    }

    #[test]
    fn test_tls_versions_with_tls13() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls13),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        let versions = super::tls_versions(Some(&settings));
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0], &rustls::version::TLS13);
    }

    #[test]
    fn test_tls_versions_with_tls12() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls12),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        let versions = super::tls_versions(Some(&settings));
        assert_eq!(versions.len(), 2);
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_provider_with_mesh_settings_tls13() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls13),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        let provider = super::provider(Some(&settings));
        assert_eq!(provider.cipher_suites.len(), 2);
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_provider_with_mesh_settings_tls12() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls12),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        let provider = super::provider(Some(&settings));
        assert_eq!(provider.cipher_suites.len(), 6);
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_provider_with_custom_cipher_suites() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls13),
                cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
                ecdh_curves: vec![],
            }),
        };
        let provider = super::provider(Some(&settings));
        assert_eq!(provider.cipher_suites.len(), 1);
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_provider_with_custom_ecdh_curves() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls13),
                cipher_suites: vec![],
                ecdh_curves: vec!["P-256".to_string(), "P-384".to_string()],
            }),
        };
        let provider = super::provider(Some(&settings));
        assert_eq!(provider.kx_groups.len(), 2);
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_provider_ignores_unknown_cipher_suites() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls13),
                cipher_suites: vec![
                    "UNKNOWN_CIPHER".to_string(),
                    "TLS_AES_256_GCM_SHA384".to_string(),
                ],
                ecdh_curves: vec![],
            }),
        };
        let provider = super::provider(Some(&settings));
        assert_eq!(provider.cipher_suites.len(), 1);
    }

    #[test]
    #[cfg(feature = "tls-openssl")]
    fn test_provider_all_unknown_cipher_suites_falls_back() {
        let settings = super::MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(super::TlsConfig {
                min_protocol_version: Some(super::TlsVersion::Tls13),
                cipher_suites: vec!["UNKNOWN_CIPHER".to_string()],
                ecdh_curves: vec![],
            }),
        };
        let provider = super::provider(Some(&settings));
        assert_eq!(provider.cipher_suites.len(), 2);
    }
}
