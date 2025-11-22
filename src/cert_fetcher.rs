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

use crate::config;
use crate::config::ProxyMode;
use crate::identity::Priority::Warmup;
use crate::identity::{CompositeId, Request, RequestKeyEnum, SecretManager};
use crate::inpod::WorkloadUid;
use crate::state::workload::{InboundProtocol, Workload};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Responsible for pre-fetching certs for workloads.
pub trait CertFetcher: Send + Sync {
    fn prefetch_cert(&self, w: &Workload);
    fn clear_cert(&self, id: &CompositeId<RequestKeyEnum>);
}

/// A no-op implementation of [CertFetcher].
pub struct NoCertFetcher();

impl CertFetcher for NoCertFetcher {
    fn prefetch_cert(&self, _: &Workload) {}
    fn clear_cert(&self, _: &CompositeId<RequestKeyEnum>) {}
}

/// Constructs an appropriate [CertFetcher] for the proxy config.
pub fn new(cfg: &config::Config, cert_manager: Arc<SecretManager>) -> Arc<dyn CertFetcher> {
    match cfg.proxy_mode {
        ProxyMode::Dedicated => Arc::new(NoCertFetcher()),
        ProxyMode::Shared => Arc::new(CertFetcherImpl::new(cfg, cert_manager)),
    }
}

/// A real [CertFetcher] that asynchronously forwards cert pre-fetch requests to a [SecretManager].
struct CertFetcherImpl {
    proxy_mode: ProxyMode,
    local_node: Option<String>,
    tx: mpsc::Sender<Request>,
}

impl CertFetcherImpl {
    fn new(cfg: &config::Config, cert_manager: Arc<SecretManager>) -> Self {
        let (tx, mut rx) = mpsc::channel::<Request>(256);

        // Spawn a task for handling the pre-fetch requests asynchronously.
        tokio::spawn(async move {
            while let Some(req) = rx.recv().await {
                match req {
                    Request::Fetch(workload_identity, priority) => {
                        match cert_manager
                            .fetch_certificate_pri(&workload_identity, priority)
                            .await
                        {
                            Ok(_) => {
                                debug!("prefetched cert for {:?}", workload_identity.to_string())
                            }
                            Err(e) => error!(
                                "unable to prefetch cert for {:?}, skipping, {:?}",
                                workload_identity.to_string(),
                                e
                            ),
                        }
                    }
                    Request::Forget(workload_identity) => {
                        cert_manager.forget_certificate(&workload_identity).await;
                    }
                }
            }
        });

        Self {
            proxy_mode: cfg.proxy_mode,
            local_node: cfg.local_node.clone(),
            tx,
        }
    }

    // Determine if we should prefetch a certificate for this workload. Being "wrong" is not
    // too bad; a missing cert will be fetched on-demand when we get a request, so will just
    // result in some extra latency.
    fn should_prefetch_certificate(&self, w: &Workload) -> bool {
        // Only shared mode fetches other workloads's certs
        self.proxy_mode == ProxyMode::Shared &&
            // We only get certs for our own node
            Some(w.node.as_ref()) == self.local_node.as_deref() &&
            // If it doesn't support HBONE it *probably* doesn't need a cert.
            (w.native_tunnel || w.protocol == InboundProtocol::HBONE)
    }
}

impl CertFetcher for CertFetcherImpl {
    fn prefetch_cert(&self, w: &Workload) {
        if self.should_prefetch_certificate(w) {
            let comp_key = CompositeId::new(w.identity(), RequestKeyEnum::Workload(WorkloadUid::new(w.uid.to_string())));
            if let Err(e) = self.tx.try_send(Request::Fetch(comp_key, Warmup)) {
                info!("couldn't prefetch: {:?}", e)
            }
        }
    }

    fn clear_cert(&self, id: &CompositeId<RequestKeyEnum>) {
        if let Err(e) = self.tx.try_send(Request::Forget(id.clone())) {
            info!("couldn't clear identity: {:?}", e)
        }
    }
}
