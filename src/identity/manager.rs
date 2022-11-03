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
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};
use tracing::instrument;

use super::CaClient;
use super::Error;
use crate::tls;
use tracing::{info, warn};

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
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
    cache: Arc<Mutex<HashMap<Identity, tls::Certs>>>,
}

impl SecretManager {
    pub fn new(cfg: crate::config::Config) -> SecretManager {
        let client = CaClient::new(cfg.auth);
        let cache: HashMap<Identity, tls::Certs> = Default::default();
        return SecretManager { client: client, cache: Arc::new(Mutex::new(cache)) };
    }

    pub async fn refresh_handler(id: Identity, ctx: SecretManager, initial_sleep_time: u64) {
        info!("refreshing certs for id {} in {:?} seconds", id, initial_sleep_time);
        sleep(Duration::from_secs(initial_sleep_time)).await;
        loop {
            match ctx.client.clone().fetch_certificate(&id.clone()).await {
                Err(e) => {
                    // Cert refresh has failed. Drop cert from the cache.
                    warn!("Failed cert refresh for id {:?}: {:?}", id, e);
                    { // lock cache
                        let mut locked_cache = ctx.cache.lock().unwrap();
                        locked_cache.remove(&id.clone());
                    } // unlock cache
                    return;
                }
                Ok(fetched_certs) => {
                    info!("refreshed certs {:?}", fetched_certs);
                    { // lock cache
                        let mut locked_cache = ctx.cache.lock().unwrap();
                        locked_cache.insert(id.clone(), fetched_certs.clone());
                    } // unlock cache
                    let sleep_dur = Duration::from_secs(fetched_certs.get_seconds_until_refresh());
                    info!("refreshing certs for id {} in {:?} seconds", id, sleep_dur);
                    sleep(sleep_dur).await;
                }
            }
        }
    }

    #[instrument(skip_all, fields(%id))]
    pub async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error> {
        // Check cache first
        { // lock cache
            let locked_cache = self.cache.lock().unwrap();
            let cache_certs: std::option::Option<&tls::Certs> = locked_cache.get(id);
            info!("cache certs for req: {:?}", cache_certs);
            if cache_certs.is_some() {
                return Ok(cache_certs.unwrap().clone())
            }
        } // unlock cache

        // No cache entry, fetch it and spawn refresh handler
        let fetched_certs = self.client.clone().fetch_certificate(id).await?;
        info!("fetched certs {:?}", fetched_certs);
        { // lock cache
            let mut locked_cache = self.cache.lock().unwrap();
            locked_cache.insert(id.clone(), fetched_certs.clone());
        } // unlock cache

        tokio::spawn(SecretManager::refresh_handler(id.clone(),
                                                        self.clone(),
                                                        fetched_certs.get_seconds_until_refresh()));

        Ok(fetched_certs.clone())
    }
}
