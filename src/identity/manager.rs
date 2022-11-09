use std::fmt;
use tracing::instrument;

use super::CaClient;
use super::Error;
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

#[derive(Clone)]
pub struct SecretManager {
    client: CaClient,
}

impl SecretManager {
    pub fn new(cfg: crate::config::Config) -> SecretManager {
        let client = CaClient::new(cfg.auth);
        SecretManager { client }
    }

    #[instrument(skip_all, fields(%id))]
    pub async fn fetch_certificate(&self, id: Identity) -> Result<tls::Certs, Error> {
        self.client.clone().fetch_certificate(id).await
    }
}
