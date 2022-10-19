use crate::identity::caclient::CaClient;
use std::fmt;

use crate::tls;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Identity {
    Spiffe {
        trust_domain: String,
        namespace: String,
        service_account: String,
    },
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Identity::Spiffe {
                trust_domain,
                namespace,
                service_account,
            } => write!(
                f,
                "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"
            ),
        }
    }
}

pub struct SecretManager {
    client: CaClient,
}

impl SecretManager {
    pub fn new() -> SecretManager {
        todo!()
    }
    pub fn fetch_certificate(_id: Identity) -> tls::Certs {
        todo!()
    }
}
