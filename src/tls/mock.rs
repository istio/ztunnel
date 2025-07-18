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
use std::fmt::{Display, Formatter};

use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::SmallRng;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use crate::tls::TLS_VERSIONS;
use rustls::ServerConfig;

use super::{ServerCertProvider, TlsError, WorkloadCertificate};

pub const TEST_CERT: &[u8] = include_bytes!("cert-chain.pem");
pub const TEST_WORKLOAD_CERT: &[u8] = include_bytes!("cert.pem");
pub const TEST_PKEY: &[u8] = include_bytes!("key.pem");
pub const TEST_ROOT: &[u8] = include_bytes!("root-cert.pem");
pub const TEST_ROOT_KEY: &[u8] = include_bytes!("ca-key.pem");
pub const TEST_ROOT2: &[u8] = include_bytes!("root-cert2.pem");
pub const TEST_ROOT2_KEY: &[u8] = include_bytes!("ca-key2.pem");

/// TestIdentity is an identity used for testing. This extends the Identity with test-only types
#[derive(Debug)]
pub enum TestIdentity {
    Identity(Identity),
    Ip(IpAddr),
}

impl Display for TestIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TestIdentity::Identity(i) => std::fmt::Display::fmt(&i, f),
            TestIdentity::Ip(i) => std::fmt::Display::fmt(&i, f),
        }
    }
}

impl From<Identity> for TestIdentity {
    fn from(i: Identity) -> Self {
        Self::Identity(i)
    }
}

impl From<IpAddr> for TestIdentity {
    fn from(i: IpAddr) -> Self {
        Self::Ip(i)
    }
}

/// Allows generating test certificates in a deterministic manner.
pub struct CertGenerator {
    rng: SmallRng,
}

impl CertGenerator {
    /// Returns a new test certificate generator. The seed parameter sets the seed for any
    /// randomized operations. Multiple CertGenerator instances created with the same seed will
    /// return the same successive certificates, if same arguments to new_certs are given.
    pub fn new(seed: u64) -> Self {
        Self {
            rng: SmallRng::seed_from_u64(seed),
        }
    }

    pub fn new_certs(
        &mut self,
        id: &TestIdentity,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> WorkloadCertificate {
        generate_test_certs_at(id, not_before, not_after, Some(&mut self.rng))
    }
}

impl Default for CertGenerator {
    fn default() -> Self {
        // Use arbitrary seed.
        Self::new(427)
    }
}

// TODO: Move towards code that doesn't rely on SystemTime::now() for easier time control with
// tokio. Ideally we'll be able to also get rid of the sub-second timestamps on certificates
// (since right now they are there only for testing).
pub fn generate_test_certs_at(
    id: &TestIdentity,
    not_before: SystemTime,
    not_after: SystemTime,
    rng: Option<&mut dyn rand::RngCore>,
) -> WorkloadCertificate {
    let (key, cert) = generate_test_certs_with_root(id, not_before, not_after, rng, TEST_ROOT_KEY);
    let mut workload =
        WorkloadCertificate::new(key.as_bytes(), cert.as_bytes(), vec![TEST_ROOT]).unwrap();
    // Certificates do not allow sub-millisecond, but we need this for tests.
    workload.cert.expiry.not_before = not_before;
    workload.cert.expiry.not_after = not_after;
    workload
}

pub fn generate_test_certs_with_root(
    id: &TestIdentity,
    not_before: SystemTime,
    not_after: SystemTime,
    rng: Option<&mut dyn rand::RngCore>,
    ca_key: &[u8],
) -> (String, String) {
    use rcgen::*;
    let serial_number = {
        let mut data = [0u8; 20];
        match rng {
            None => rand::rng().fill_bytes(&mut data),
            Some(rng) => rng.fill_bytes(&mut data),
        }
        // Clear the most significant bit to make the resulting bignum effectively 159 bit long.
        data[0] &= 0x7f;
        data
    };
    let mut p = CertificateParams::default();
    p.not_before = not_before.into();
    p.not_after = not_after.into();
    p.serial_number = Some(SerialNumber::from_slice(&serial_number));
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "cluster.local");
    p.distinguished_name = dn;
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    p.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    p.subject_alt_names = vec![match id {
        TestIdentity::Identity(i) => {
            SanType::URI(string::Ia5String::try_from(i.to_string()).unwrap())
        }
        TestIdentity::Ip(i) => SanType::IpAddress(*i),
    }];

    let kp = KeyPair::from_pem(std::str::from_utf8(TEST_PKEY).unwrap()).unwrap();
    let ca_kp = KeyPair::from_pem(std::str::from_utf8(ca_key).unwrap()).unwrap();
    let key = kp.serialize_pem();
    let issuer = Issuer::from_params(&p, &ca_kp);
    let cert = p.signed_by(&kp, &issuer).unwrap();
    let cert = cert.pem();
    (key, cert)
}

pub fn generate_test_certs(
    id: &TestIdentity,
    duration_until_valid: Duration,
    duration_until_expiry: Duration,
) -> WorkloadCertificate {
    let not_before = SystemTime::now() + duration_until_valid;
    generate_test_certs_at(id, not_before, not_before + duration_until_expiry, None)
}

#[derive(Debug, Clone)]
pub struct MockServerCertProvider(Arc<WorkloadCertificate>);

impl MockServerCertProvider {
    pub fn new(w: WorkloadCertificate) -> Self {
        MockServerCertProvider(Arc::new(w))
    }
}

#[async_trait::async_trait]
impl ServerCertProvider for MockServerCertProvider {
    async fn fetch_cert(&mut self) -> Result<Arc<ServerConfig>, TlsError> {
        let mut sc = ServerConfig::builder_with_provider(crate::tls::lib::provider())
            .with_protocol_versions(TLS_VERSIONS)
            .expect("server config must be valid")
            .with_no_client_auth()
            .with_single_cert(
                self.0.cert_and_intermediates_der(),
                self.0.private_key.clone_key(),
            )
            .unwrap();
        sc.alpn_protocols = vec![b"h2".into()];
        Ok(Arc::new(sc))
    }
}
