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
    pub async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
        self.client.clone().fetch_certificate(id).await
    }
}
