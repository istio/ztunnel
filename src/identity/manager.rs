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
use std::sync::{Arc, RwLock};
use tokio::time::{sleep, Duration};
use tracing::instrument;
use tokio::sync::watch;

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
    cache: Arc<RwLock<HashMap<Identity, watch::Receiver<Option<tls::Certs>>>>>,
}

impl SecretManager {
    pub fn new(cfg: crate::config::Config) -> SecretManager {
        let caclient = CaClient::new(cfg.auth);
        let cache: HashMap<Identity, watch::Receiver<Option<tls::Certs>>> = Default::default();
        SecretManager {
            client: caclient,
            cache: Arc::new(RwLock::new(cache))
        }
    }

    pub async fn refresh_handler(id: Identity, mut ctx: SecretManager,
                                 initial_sleep_time: Duration,
                                 tx: watch::Sender<Option<tls::Certs>>) {
        sleep(initial_sleep_time).await;
        loop {
            match ctx.client.fetch_certificate(&id).await {
                Err(e) => {
                    // Cert refresh has failed. Drop cert from the cache.
                    warn!("Failed cert refresh for id {:?}: {:?}", id, e);
                    {
                        let mut locked_cache = ctx.cache.write().unwrap();
                        locked_cache.remove(&id.clone());
                    }
                    return;
                }
                Ok(fetched_certs) => {

                    let sleep_dur = fetched_certs.get_duration_until_refresh();
                    match tx.send(Some(fetched_certs.clone())) {
                        Err(_) => {
                            let mut locked_cache = ctx.cache.write().unwrap();
                            locked_cache.remove(&id.clone());
                        },
                        Ok(_) => {
                            info!("refreshed certs for id: {:?}", id);
                        }
                    }
                    info!("refreshing certs for id {} in {:?} seconds", id, sleep_dur);
                    sleep(sleep_dur).await;
                }
            }
        }
    }

    #[instrument(skip_all, fields(%id))]
    pub async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error> {
        loop {
            let mut tx_option: Option<watch::Sender<Option<tls::Certs>>> = None;
            let mut cache_rx = None;
            {
                let read_locked_cache = self.cache.read().unwrap();
                match read_locked_cache.get(id) {
                    None => {
                        drop(read_locked_cache);
                        let mut write_locked_cache = self.cache.write().unwrap();
                        match write_locked_cache.get(id) {

                            Some(cert_rx) => {
                                // A different thread got here before us and is handling the fetch.
                                // Take a copy of the receiver.
                                cache_rx = Some(cert_rx.clone());
                            },
                            None => {
                                let (tx, rx) = watch::channel(None);
                                write_locked_cache.insert(id.clone(), rx);
                                tx_option = Some(tx);
                            }
                        };
                    }
                    Some(cert_rcvr) => {
                        info!("Got cached cert receiver.");
                        cache_rx = Some(cert_rcvr.clone());
                    }
                }
            }

            // We made a transmitter, so fetch the cert and send the result.
            if tx_option.is_some() {
                let certs = self.client.fetch_certificate(id).await;
                match certs {
                    Ok(c) => {
                        let tx = tx_option.unwrap();
                        match tx.send(Some(c.clone())) {
                            Ok(_) => {
                                tokio::spawn(SecretManager::refresh_handler(
                                    id.clone(),
                                    self.clone(),
                                    c.get_duration_until_refresh(),
                                    tx));
                            },
                            Err(e) => {
                                warn!("Failed to send fetched certs on channel: {:?}", e);
                                let mut locked_cache = self.cache.write().unwrap();
                                locked_cache.remove(id);
                            }
                        }

                        return Ok(c);
                    },
                    Err(e) => {
                        let mut locked_cache = self.cache.write().unwrap();
                        locked_cache.remove(id);
                        return Err(e);
                    }
                }
            }

            // We found a channel receiver in the cache, so use it to get the cert.
            loop {
                let current_cert_info = cache_rx.as_mut().unwrap();
                {
                    let current_cert = current_cert_info.borrow_and_update();
                    if current_cert.is_some() {
                        return Ok(current_cert.clone().unwrap());
                    }
                }
                // "None" means CA request in progress.  Wait for it.
                match current_cert_info.changed().await {
                    Err(_) => {
                        // CA request failed or other error.
                        warn!("Cert sender has been dropped.");
                        break;
                    }
                    Ok(_) => {
                        continue;
                    }
                }
            }
        }
    }
}
