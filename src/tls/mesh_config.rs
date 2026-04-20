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

use once_cell::sync::Lazy;
use rustls::crypto::CryptoProvider;

#[allow(unused_imports)]
use crate::PQC_ENABLED;
use crate::TLS12_ENABLED;
use crate::strng::Strng;

/// Default resolved config computed from env vars at startup.
/// Used by control plane connections and signature verification.
static DEFAULT_CONFIG: Lazy<Arc<ResolvedMeshConfig>> =
    Lazy::new(|| Arc::new(resolve_mesh_config(None)));

/// Returns the default resolved config (env var defaults, no xDS).
pub fn default_mesh_config() -> Arc<ResolvedMeshConfig> {
    DEFAULT_CONFIG.clone()
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

/// Pre-resolved mesh configuration ready for use by TLS setup code.
/// Computed once when MeshSettings arrives via xDS (or at startup from env var defaults),
/// so call sites don't need to repeat the fallback logic.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedMeshConfig {
    pub trust_domain: Option<Strng>,
    pub trust_domain_aliases: Vec<Strng>,
    pub min_tls_version: TlsVersion,
    pub cipher_suites: Vec<String>,
    pub ecdh_curves: Vec<String>,
    #[serde(skip)]
    pub provider: Arc<CryptoProvider>,
}

static TLS_VERSIONS_13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];
static TLS_VERSIONS_12_AND_13: &[&rustls::SupportedProtocolVersion] =
    &[&rustls::version::TLS13, &rustls::version::TLS12];

impl ResolvedMeshConfig {
    pub fn tls_versions(&self) -> &'static [&'static rustls::SupportedProtocolVersion] {
        match self.min_tls_version {
            TlsVersion::Tls12 => TLS_VERSIONS_12_AND_13,
            TlsVersion::Tls13 => TLS_VERSIONS_13_ONLY,
        }
    }
}

pub fn resolve_mesh_config(settings: Option<&MeshSettings>) -> ResolvedMeshConfig {
    let trust_domain = settings
        .filter(|ms| !ms.trust_domain.is_empty())
        .map(|ms| ms.trust_domain.clone());
    let trust_domain_aliases = settings
        .map(|ms| ms.trust_domain_aliases.clone())
        .unwrap_or_default();
    let min_tls_version = if is_tls12_enabled(settings) {
        TlsVersion::Tls12
    } else {
        TlsVersion::Tls13
    };
    let resolved_provider = provider(settings);
    let cipher_suites = resolved_provider
        .cipher_suites
        .iter()
        .map(|cs| format!("{:?}", cs.suite()))
        .collect();
    let ecdh_curves = resolved_provider
        .kx_groups
        .iter()
        .map(|kx| format!("{:?}", kx.name()))
        .collect();
    ResolvedMeshConfig {
        trust_domain,
        trust_domain_aliases,
        min_tls_version,
        cipher_suites,
        ecdh_curves,
        provider: resolved_provider,
    }
}

// ============================================================================
// Crypto Provider
// ============================================================================
//
// Ztunnel uses `rustls` with pluggable crypto modules.
// All crypto MUST be done via the below providers.
//
// One exception is CSR generation which doesn't currently have a plugin
// mechanism (https://github.com/rustls/rcgen/issues/228); in that case,
// and any future ones, it is critical to guard the code with appropriate
// `cfg` guards.

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
fn provider(_settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
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
fn provider(settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
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
fn provider(settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
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
fn provider(settings: Option<&MeshSettings>) -> Arc<CryptoProvider> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_settings_default() {
        let settings = MeshSettings::default();
        assert!(settings.trust_domain.is_empty());
        assert!(settings.trust_domain_aliases.is_empty());
        assert!(settings.tls.is_none());
    }

    #[test]
    fn test_resolve_defaults() {
        let resolved = resolve_mesh_config(None);
        assert!(resolved.trust_domain.is_none());
        assert!(resolved.trust_domain_aliases.is_empty());
        assert!(!resolved.cipher_suites.is_empty());
        assert!(!resolved.ecdh_curves.is_empty());
    }

    #[test]
    fn test_resolve_trust_domain_from_settings() {
        let settings = MeshSettings {
            trust_domain: "cluster.local".into(),
            trust_domain_aliases: vec!["old.cluster.local".into()],
            tls: None,
        };
        let resolved = resolve_mesh_config(Some(&settings));
        assert_eq!(resolved.trust_domain, Some("cluster.local".into()));
        assert_eq!(resolved.trust_domain_aliases, vec![Strng::from("old.cluster.local")]);
    }

    #[test]
    fn test_resolve_empty_trust_domain_is_none() {
        let settings = MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: None,
        };
        let resolved = resolve_mesh_config(Some(&settings));
        assert!(resolved.trust_domain.is_none());
    }

    #[test]
    fn test_resolve_tls13() {
        let settings = MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(TlsConfig {
                min_protocol_version: Some(TlsVersion::Tls13),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        let resolved = resolve_mesh_config(Some(&settings));
        assert_eq!(resolved.min_tls_version, TlsVersion::Tls13);
        assert_eq!(resolved.tls_versions().len(), 1);
    }

    #[test]
    fn test_resolve_tls12() {
        let settings = MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(TlsConfig {
                min_protocol_version: Some(TlsVersion::Tls12),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        let resolved = resolve_mesh_config(Some(&settings));
        assert_eq!(resolved.min_tls_version, TlsVersion::Tls12);
        assert_eq!(resolved.tls_versions().len(), 2);
        // TLS 1.2 adds additional cipher suites beyond the TLS 1.3 defaults
        assert!(resolved.cipher_suites.len() > 2);
    }

    #[test]
    fn test_resolve_tls13_has_tls13_only_cipher_suites() {
        let settings = MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(TlsConfig {
                min_protocol_version: Some(TlsVersion::Tls13),
                cipher_suites: vec![],
                ecdh_curves: vec![],
            }),
        };
        let resolved = resolve_mesh_config(Some(&settings));
        assert_eq!(resolved.cipher_suites.len(), 2);
        assert!(resolved.cipher_suites.iter().all(|cs| cs.starts_with("TLS13_")));
    }

    #[test]
    fn test_resolve_custom_cipher_suites() {
        let settings = MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(TlsConfig {
                min_protocol_version: Some(TlsVersion::Tls13),
                cipher_suites: vec!["TLS_AES_256_GCM_SHA384".to_string()],
                ecdh_curves: vec![],
            }),
        };
        let resolved = resolve_mesh_config(Some(&settings));
        assert_eq!(resolved.cipher_suites.len(), 1);
    }

    #[test]
    fn test_resolve_custom_ecdh_curves() {
        let settings = MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(TlsConfig {
                min_protocol_version: Some(TlsVersion::Tls13),
                cipher_suites: vec![],
                ecdh_curves: vec!["P-256".to_string(), "P-384".to_string()],
            }),
        };
        let resolved = resolve_mesh_config(Some(&settings));
        assert_eq!(resolved.ecdh_curves.len(), 2);
    }

    #[test]
    fn test_resolve_unknown_cipher_suites_falls_back() {
        let settings = MeshSettings {
            trust_domain: Default::default(),
            trust_domain_aliases: vec![],
            tls: Some(TlsConfig {
                min_protocol_version: Some(TlsVersion::Tls13),
                cipher_suites: vec!["UNKNOWN_CIPHER".to_string()],
                ecdh_curves: vec![],
            }),
        };
        let resolved = resolve_mesh_config(Some(&settings));
        // All unknown = fall back to defaults (2 for TLS 1.3)
        assert_eq!(resolved.cipher_suites.len(), 2);
    }
}
