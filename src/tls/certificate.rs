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
use crate::tls::{Error, IdentityVerifier, OutboundConnector};
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use itertools::Itertools;

use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use rustls::server::WebPkiClientVerifier;
use rustls::{server, ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::Item;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::tls;
use x509_parser::certificate::X509Certificate;

#[derive(Clone, Debug)]
pub struct Certificate {
    pub(in crate::tls) expiry: Expiration,
    der: CertificateDer<'static>,
}

#[derive(Clone, Debug)]
pub struct Expiration {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

#[derive(Debug)]
pub struct WorkloadCertificate {
    /// cert is the leaf certificate
    pub cert: Certificate,
    /// chain is the entire trust chain, excluding the leaf
    pub chain: Vec<Certificate>,
    pub private_key: PrivateKeyDer<'static>,

    /// precomputed roots
    roots: Arc<RootCertStore>,
}

pub fn identity_from_connection(conn: &server::ServerConnection) -> Option<Identity> {
    use x509_parser::prelude::*;
    conn.peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| match X509Certificate::from_der(cert) {
            Ok((_, a)) => Some(a),
            Err(e) => {
                warn!("invalid certificate: {e}");
                None
            }
        })
        .and_then(|cert| match identities(cert) {
            Ok(ids) => ids.into_iter().next(),
            Err(e) => {
                warn!("failed to extract identity: {}", e);
                None
            }
        })
}

pub fn identities(cert: X509Certificate) -> Result<Vec<Identity>, Error> {
    use x509_parser::prelude::*;
    let names = cert
        .subject_alternative_name()?
        .map(|x| &x.value.general_names);

    if let Some(names) = names {
        return Ok(names
            .iter()
            .filter_map(|n| {
                let id = match n {
                    GeneralName::URI(uri) => Identity::from_str(uri),
                    _ => return None,
                };

                match id {
                    Ok(id) => Some(id),
                    Err(err) => {
                        warn!("SAN {n} could not be parsed: {err}");
                        None
                    }
                }
            })
            .collect());
    }
    Ok(Vec::default())
}

impl Certificate {
    // TOOD: I would love to parse this once, but ran into lifetime issues.
    fn parsed(&self) -> X509Certificate {
        x509_parser::parse_x509_certificate(&self.der).unwrap().1
    }

    pub fn as_pem(&self) -> String {
        der_to_pem(&self.der, CERTIFICATE)
    }

    pub fn identity(&self) -> Option<Identity> {
        self.parsed()
            .subject_alternative_name()
            .ok()
            .flatten()
            .and_then(|ext| {
                ext.value
                    .general_names
                    .iter()
                    .filter_map(|n| match n {
                        x509_parser::extensions::GeneralName::URI(uri) => Some(uri),
                        _ => None,
                    })
                    .next()
            })
            .and_then(|san| Identity::from_str(san).ok())
    }

    #[cfg(test)]
    pub fn names(&self) -> Vec<String> {
        let reg = oid_registry::OidRegistry::default().with_x509();

        self.parsed()
            .subject
            .iter()
            .flat_map(|dn| {
                dn.iter().map(|x| {
                    reg.get(x.attr_type()).unwrap().sn().to_string() + "/" + x.as_str().unwrap()
                })
            })
            .chain(
                self.parsed()
                    .subject_alternative_name()
                    .ok()
                    .flatten()
                    .iter()
                    .flat_map(|ext| ext.value.general_names.iter().map(|n| n.to_string())),
            )
            .collect()
    }

    pub fn serial(&self) -> String {
        self.parsed().serial.to_string()
    }

    pub fn expiration(&self) -> Expiration {
        self.expiry.clone()
    }
}

fn expiration(cert: X509Certificate) -> Expiration {
    Expiration {
        not_before: UNIX_EPOCH
            + Duration::from_secs(
                cert.validity
                    .not_before
                    .timestamp()
                    .try_into()
                    .unwrap_or_default(),
            ),
        not_after: UNIX_EPOCH
            + Duration::from_secs(
                cert.validity
                    .not_after
                    .timestamp()
                    .try_into()
                    .unwrap_or_default(),
            ),
    }
}

fn parse_cert(mut cert: Vec<u8>) -> Result<Certificate, Error> {
    let mut reader = std::io::BufReader::new(Cursor::new(&mut cert));
    let parsed = rustls_pemfile::read_one(&mut reader)
        .map_err(|e| Error::CertificateParseError(e.to_string()))?
        .ok_or_else(|| Error::CertificateParseError("no certificate".to_string()))?;
    let Item::X509Certificate(der) = parsed else {
        return Err(Error::CertificateParseError("no certificate".to_string()));
    };

    let (_, cert) = x509_parser::parse_x509_certificate(&der)?;
    Ok(Certificate {
        der: der.clone(),
        expiry: expiration(cert),
    })
}

fn parse_key(mut key: &[u8]) -> Result<PrivateKeyDer<'static>, Error> {
    let mut reader = std::io::BufReader::new(Cursor::new(&mut key));
    let parsed = rustls_pemfile::read_one(&mut reader)
        .map_err(|e| Error::CertificateParseError(e.to_string()))?
        .ok_or_else(|| Error::CertificateParseError("no key".to_string()))?;
    match parsed {
        Item::Pkcs8Key(c) => Ok(PrivateKeyDer::Pkcs8(c)),
        _ => Err(Error::CertificateParseError("no key".to_string())),
    }
}

impl WorkloadCertificate {
    pub fn new(key: &[u8], cert: &[u8], chain: Vec<&[u8]>) -> Result<WorkloadCertificate, Error> {
        let cert = parse_cert(cert.to_vec())?;
        let chain = chain
            .into_iter()
            .map(|x| x.to_vec())
            .map(parse_cert)
            .collect::<Result<Vec<_>, _>>()?;
        let key: PrivateKeyDer = parse_key(key)?;

        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(chain.iter().last().map(|c| c.der.clone()));
        Ok(WorkloadCertificate {
            cert,
            chain,
            private_key: key,
            roots: Arc::new(roots),
        })
    }

    // TODO: can we precompute some or all of this?

    pub(in crate::tls) fn cert_and_intermediates(&self) -> Vec<CertificateDer<'static>> {
        std::iter::once(self.cert.der.clone())
            .chain(
                self.chain[..self.chain.len() - 1]
                    .iter()
                    .map(|x| x.der.clone()),
            )
            .collect()
    }

    pub fn server_config(&self) -> Result<ServerConfig, Error> {
        let td = self.cert.identity().map(|i| match i {
            Identity::Spiffe { trust_domain, .. } => trust_domain,
        });
        let raw_client_cert_verifier = WebPkiClientVerifier::builder_with_provider(
            self.roots.clone(),
            crate::tls::lib::provider(),
        )
        .build()?;

        let client_cert_verifier =
            crate::tls::workload::TrustDomainVerifier::new(raw_client_cert_verifier, td);
        let mut sc = ServerConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::TLS_VERSIONS)
            .expect("server config must be valid")
            .with_client_cert_verifier(client_cert_verifier)
            .with_single_cert(self.cert_and_intermediates(), self.private_key.clone_key())?;
        sc.alpn_protocols = vec![b"h2".into()];
        Ok(sc)
    }

    pub fn outbound_connector(&self, identity: Vec<Identity>) -> Result<OutboundConnector, Error> {
        let roots = self.roots.clone();
        let verifier = IdentityVerifier { roots, identity };
        let mut cc = ClientConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(tls::TLS_VERSIONS)
            .expect("client config must be valid")
            .dangerous() // Customer verifier is requires "dangerous" opt-in
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(self.cert_and_intermediates(), self.private_key.clone_key())?;
        cc.alpn_protocols = vec![b"h2".into()];
        cc.resumption = Resumption::disabled();
        cc.enable_sni = false;
        Ok(OutboundConnector {
            client_config: Arc::new(cc),
        })
    }

    pub fn dump_chain(&self) -> Bytes {
        self.chain.iter().map(|c| c.as_pem()).join("\n").into()
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.cert.expiry.not_after
    }

    pub fn refresh_at(&self) -> SystemTime {
        let expiry = &self.cert.expiry;
        match expiry.not_after.duration_since(expiry.not_before) {
            Ok(valid_for) => expiry.not_before + valid_for / 2,
            Err(_) => expiry.not_after,
        }
    }

    pub fn get_duration_until_refresh(&self) -> Duration {
        let expiry = &self.cert.expiry;
        let halflife = expiry
            .not_after
            .duration_since(expiry.not_before)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            / 2;
        // If now() is earlier than not_before, we need to refresh ASAP, so return 0.
        let elapsed = SystemTime::now()
            .duration_since(expiry.not_before)
            .unwrap_or(halflife);
        halflife
            .checked_sub(elapsed)
            .unwrap_or_else(|| Duration::from_secs(0))
    }
}

const CERTIFICATE: &str = "CERTIFICATE";

/// Converts DER encoded data to PEM.
fn der_to_pem(der: &[u8], label: &str) -> String {
    use base64::Engine;
    let mut ans = String::from("-----BEGIN ");
    ans.push_str(label);
    ans.push_str("-----\n");
    let b64 = STANDARD.encode(der);
    let line_length = 60;
    for chunk in b64.chars().collect::<Vec<_>>().chunks(line_length) {
        ans.extend(chunk);
        ans.push('\n');
    }
    ans.push_str("-----END ");
    ans.push_str(label);
    ans.push_str("-----\n");
    ans
}
