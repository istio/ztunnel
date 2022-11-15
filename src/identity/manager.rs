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

use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use tokio::sync::watch;
use tokio::time::{sleep, Duration};
use tracing::instrument;

use super::Error;
use super::{CaClient, CertificateProvider};
use crate::tls;
use tracing::{info, warn};

const CERT_REFRESH_FAILURE_RETRY_DELAY: Duration = Duration::from_secs(60);

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
pub struct SecretManager<T: CertificateProvider> {
    client: T,
    cache: Arc<RwLock<HashMap<Identity, watch::Receiver<Option<tls::Certs>>>>>,
}

impl SecretManager<CaClient> {
    pub fn new(cfg: crate::config::Config) -> SecretManager<CaClient> {
        let caclient = CaClient::new(cfg.auth);
        let cache: HashMap<Identity, watch::Receiver<Option<tls::Certs>>> = Default::default();
        SecretManager {
            client: caclient,
            cache: Arc::new(RwLock::new(cache)),
        }
    }
}

impl<T: CertificateProvider> SecretManager<T> {
    pub async fn refresh_handler(
        id: Identity,
        cache: Arc<RwLock<HashMap<Identity, watch::Receiver<Option<tls::Certs>>>>>,
        mut ca_client: T,
        initial_sleep_time: Duration,
        tx: watch::Sender<Option<tls::Certs>>,
    ) {
        info!("refreshing certs for id {} in {:?}", id, initial_sleep_time);
        sleep(initial_sleep_time).await;
        loop {
            let sleep_dur;
            match ca_client.fetch_certificate(&id).await {
                Err(e) => {
                    // Cert refresh has failed. Drop cert from the cache.
                    warn!("Failed cert refresh for id {:?}: {:?}", id, e);
                    let mut write_locked_cache = cache.write().unwrap();
                    match write_locked_cache.get(&id) {
                        Some(certs_rx) => {
                            if certs_rx.borrow().clone().unwrap().is_expired() {
                                write_locked_cache.remove(&id.clone());
                            }
                            sleep_dur = CERT_REFRESH_FAILURE_RETRY_DELAY;
                        }
                        None => {
                            return;
                        }
                    }
                    {
                        let mut locked_cache = cache.write().unwrap();
                        locked_cache.remove(&id);
                    }
                }
                Ok(fetched_certs) => {
                    sleep_dur = fetched_certs.get_duration_until_refresh();
                    match tx.send(Some(fetched_certs.clone())) {
                        Err(_) => {
                            // This means no receivers left. Should not be possible.
                            let mut locked_cache = cache.write().unwrap();
                            locked_cache.remove(&id);
                            return;
                        }
                        Ok(_) => {
                            info!("refreshed certs for id: {:?}", id);
                        }
                    }
                    info!("refreshing certs for id {} in {:?}", id, sleep_dur);
                }
            }
            sleep(sleep_dur).await;
        }
    }
}

#[async_trait]
impl<T: CertificateProvider + Clone + Send + 'static> CertificateProvider for SecretManager<T> {
    #[instrument(skip_all, fields(%id))]
    #[instrument(skip_all, fields(%id))]
    async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error> {
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
                            }
                            None => {
                                let (tx, rx) = watch::channel(None);
                                write_locked_cache.insert(id.clone(), rx);
                                tx_option = Some(tx);
                            }
                        };
                    }
                    Some(cert_rcvr) => {
                        cache_rx = Some(cert_rcvr.clone());
                    }
                }
            }

            // We made a transmitter, so fetch the cert and send the result.
            if let Some(tx) = tx_option {
                info!("Fetching cert.");
                let certs = self.client.fetch_certificate(id).await;
                match certs {
                    Ok(c) => {
                        match tx.send(Some(c.clone())) {
                            Ok(_) => {
                                tokio::spawn(SecretManager::refresh_handler(
                                    id.clone(),
                                    self.cache.clone(),
                                    self.client.clone(),
                                    c.get_duration_until_refresh(),
                                    tx,
                                ));
                            }
                            Err(e) => {
                                warn!("Failed to send fetched certs on channel: {:?}", e);
                                let mut locked_cache = self.cache.write().unwrap();
                                locked_cache.remove(id);
                            }
                        }

                        return Ok(c);
                    }
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
                        info!("Got cached cert.");
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::{self, *},
        tls::tests::generate_test_certs,
    };

    #[derive(Clone, Debug)]
    struct MockCaClient;

    #[async_trait]
    impl CertificateProvider for MockCaClient {
        async fn fetch_certificate(&mut self, _id: &Identity) -> Result<tls::Certs, Error> {
            let certs: tls::Certs = generate_test_certs(10);
            return Ok(certs);
        }
    }

    impl SecretManager<MockCaClient> {
        pub fn new_mock() -> SecretManager<MockCaClient> {
            let cache: HashMap<Identity, watch::Receiver<Option<tls::Certs>>> = Default::default();
            let ca_client = MockCaClient;
            SecretManager {
                client: ca_client,
                cache: Arc::new(RwLock::new(cache)),
            }
        }
    }

    async fn stress(mut sm: SecretManager<MockCaClient>, iterations: u32) {
        for i in 0..iterations {
            let id = identity::Identity::Spiffe {
                trust_domain: "cluster.local".to_string(),
                namespace: "istio-system".to_string(),
                service_account: format!("ztunnel{}", i),
            };
            sm.fetch_certificate(&id).await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_stress_caching() {
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let secret_manager = SecretManager::new_mock();
        for _n in 0..8 {
            tasks.push(tokio::spawn(stress(secret_manager.clone(), 5000)));
        }
        futures::future::join_all(tasks).await;
        assert_eq!(5000, secret_manager.cache.read().unwrap().len());
    }
}
