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
use std::io::Write;
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

impl prometheus_client::encoding::text::Encode for Identity {
    fn encode(&self, writer: &mut dyn Write) -> Result<(), std::io::Error> {
        writer.write_all(self.to_string().as_bytes())
    }
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

impl Default for Identity {
    fn default() -> Self {
        Identity::Spiffe {
            trust_domain: "cluster.local".to_string(),
            namespace: "istio-system".to_string(),
            service_account: "ztunnel".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct SecretManager<C: CertificateProvider>
where
    C: Clone,
{
    client: C,
    cache: Arc<RwLock<HashMap<Identity, watch::Receiver<Option<tls::Certs>>>>>,
}

impl SecretManager<CaClient> {
    pub fn new(cfg: crate::config::Config) -> SecretManager<CaClient> {
        let caclient = CaClient::new(cfg.ca_address.unwrap(), cfg.auth);
        let cache: HashMap<Identity, watch::Receiver<Option<tls::Certs>>> = Default::default();
        SecretManager {
            client: caclient,
            cache: Arc::new(RwLock::new(cache)),
        }
    }
}

impl<T: CertificateProvider + Clone> SecretManager<T> {
    pub async fn refresh_handler(
        id: Identity,
        cache: Arc<RwLock<HashMap<Identity, watch::Receiver<Option<tls::Certs>>>>>,
        mut ca_client: T,
        tx: watch::Sender<Option<tls::Certs>>,
    ) {
        loop {
            let sleep_dur = match ca_client.fetch_certificate(&id).await {
                Err(e) => {
                    warn!("Failed cert refresh for id {:?}: {:?}", id, e);
                    let mut write_locked_cache = cache.write().unwrap();
                    let Some(certs_rx) = write_locked_cache.get(&id) else {
                        // Should not be possible, but if there is no receiver
                        // in the cache, then no one is using these certs that
                        // are being refreshed, so let's stop refreshing them.
                        return;
                    };

                    let certs_op = certs_rx.borrow().clone();
                    if certs_op.is_none() || certs_op.unwrap().is_expired() {
                        write_locked_cache.remove(&id);
                        return;
                    }
                    CERT_REFRESH_FAILURE_RETRY_DELAY
                }
                Ok(fetched_certs) => {
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
                    fetched_certs.get_duration_until_refresh()
                }
            };
            sleep(sleep_dur).await;
        }
    }
}

#[async_trait]
impl<T: CertificateProvider + Clone + Send + 'static> CertificateProvider for SecretManager<T> {
    #[instrument(skip_all, fields(%id))]
    async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error> {
        let mut cache_rx;
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
                            cache_rx = cert_rx.clone();
                        }
                        None => {
                            let (tx, rx) = watch::channel(None);
                            write_locked_cache.insert(id.clone(), rx.clone());
                            drop(write_locked_cache);
                            tokio::spawn(SecretManager::refresh_handler(
                                id.clone(),
                                self.cache.clone(),
                                self.client.clone(),
                                tx,
                            ));
                            cache_rx = rx;
                        }
                    };
                }
                Some(cert_rcvr) => {
                    cache_rx = cert_rcvr.clone();
                }
            }
        }

        // We have a channel receiver, so use it to get the cert.
        match cache_rx.changed().await {
            Err(_) => {
                // CA request failed or other error.
                warn!("Cert sender has been dropped.");
                return Err(Error::EmptyResponse(id.clone()));
            }
            Ok(_) => {
                let current_cert = cache_rx.borrow().clone();
                if let Some(cert) = current_cert {
                    info!("Got cached cert.");
                    return Ok(cert);
                }
                return Err(Error::EmptyResponse(id.clone()));
            }
        }
    }
}

pub mod mock {
    use super::*;
    use crate::identity::{CertificateProvider, Identity, SecretManager};
    use crate::tls::{generate_test_certs, Certs};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;
    use tokio::sync::watch;

    #[derive(Clone, Debug)]
    pub struct MockCaClient {
        pub cert_lifetime: Duration,
    }

    #[async_trait]
    impl CertificateProvider for MockCaClient {
        async fn fetch_certificate(&mut self, id: &Identity) -> Result<Certs, Error> {
            let certs = generate_test_certs(id, Duration::from_secs(0), self.cert_lifetime);
            return Ok(certs);
        }
    }

    impl MockCaClient {
        pub fn new(cert_lifetime: Duration) -> SecretManager<MockCaClient> {
            let cache: HashMap<Identity, watch::Receiver<Option<Certs>>> = Default::default();
            let ca_client = MockCaClient { cert_lifetime };
            SecretManager {
                client: ca_client,
                cache: Arc::new(RwLock::new(cache)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use super::*;
    use crate::identity::{self, *};

    async fn stress_many_ids(mut sm: SecretManager<mock::MockCaClient>, iterations: u32) {
        for i in 0..iterations {
            let id = identity::Identity::Spiffe {
                trust_domain: "cluster.local".to_string(),
                namespace: "istio-system".to_string(),
                service_account: format!("ztunnel{}", i),
            };
            sm.fetch_certificate(&id)
                .await
                .unwrap_or_else(|_| panic!("Didn't get a cert as expected."));
        }
    }

    async fn stress_single_id(
        mut sm: SecretManager<mock::MockCaClient>,
        id: Identity,
        dur: Duration,
    ) {
        let start_time = time::Instant::now();
        loop {
            let current_time = time::Instant::now();
            if current_time - start_time > dur {
                break;
            }
            sm.fetch_certificate(&id)
                .await
                .unwrap_or_else(|_| panic!("Didn't get a cert as expected."));
            sleep(Duration::from_micros(500)).await;
        }
    }

    async fn verify_cert_updates(
        mut sm: SecretManager<mock::MockCaClient>,
        id: Identity,
        dur: Duration,
    ) {
        let start_time = time::Instant::now();
        let expected_update_interval = sm.client.cert_lifetime.as_millis() / 2;
        let mut total_updates = 0;
        let mut current_cert = sm
            .fetch_certificate(&id)
            .await
            .unwrap_or_else(|_| panic!("Didn't get a cert as expected."));
        loop {
            let new_cert = sm
                .fetch_certificate(&id)
                .await
                .unwrap_or_else(|_| panic!("Didn't get a cert as expected."));

            if current_cert != new_cert {
                total_updates += 1;
                current_cert = new_cert;
            }
            if time::Instant::now() - start_time > dur {
                break;
            }
            sleep(Duration::from_micros(100)).await;
        }
        assert_eq!(total_updates, dur.as_millis() / expected_update_interval);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_stress_caching() {
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let secret_manager = mock::MockCaClient::new(Duration::from_millis(50));

        for _n in 0..8 {
            tasks.push(tokio::spawn(stress_many_ids(secret_manager.clone(), 100)));
        }
        let results = futures::future::join_all(tasks).await;
        for result in results.iter() {
            assert!(result.is_ok());
        }
        assert_eq!(100, secret_manager.cache.read().unwrap().len());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_cache_refresh() {
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let test_dur = Duration::from_millis(200);

        let id: Identity = Default::default();

        // Certs added to the cache should be refreshed every 80 millis
        let secret_manager = mock::MockCaClient::new(Duration::from_millis(160));

        // Spawn task that verifies cert updates.
        tasks.push(tokio::spawn(verify_cert_updates(
            secret_manager.clone(),
            id.clone(),
            test_dur,
        )));

        // Start spamming fetches for that cert.
        for _n in 0..7 {
            tasks.push(tokio::spawn(stress_single_id(
                secret_manager.clone(),
                id.clone(),
                test_dur,
            )));
        }

        let results = futures::future::join_all(tasks).await;
        for result in results.iter() {
            assert!(result.is_ok());
        }
    }
}
