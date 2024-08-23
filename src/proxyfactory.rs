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
use crate::identity::SecretManager;
use crate::state::{DemandProxyState, WorkloadInfo};
use std::sync::Arc;
use tracing::error;

use crate::dns;
use crate::drain::DrainWatcher;

use crate::proxy::connection_manager::ConnectionManager;
use crate::proxy::{Error, Metrics};

use crate::proxy::Proxy;

// Proxy factory creates ztunnel proxies using a socket factory.
// this allows us to create our proxies the same way in regular mode and in inpod mode.
pub struct ProxyFactory {
    config: Arc<config::Config>,
    state: DemandProxyState,
    cert_manager: Arc<SecretManager>,
    proxy_metrics: Arc<Metrics>,
    dns_metrics: Option<Arc<dns::Metrics>>,
    drain: DrainWatcher,
}

impl ProxyFactory {
    pub fn new(
        config: Arc<config::Config>,
        state: DemandProxyState,
        cert_manager: Arc<SecretManager>,
        proxy_metrics: Arc<Metrics>,
        dns_metrics: Option<dns::Metrics>,
        drain: DrainWatcher,
    ) -> std::io::Result<Self> {
        let dns_metrics = match dns_metrics {
            Some(metrics) => Some(Arc::new(metrics)),
            None => {
                if config.dns_proxy {
                    error!("dns proxy configured but no dns metrics provided")
                }
                None
            }
        };

        Ok(ProxyFactory {
            config,
            state,
            cert_manager,
            proxy_metrics,
            dns_metrics,
            drain,
        })
    }

    pub async fn new_proxies_for_dedicated(
        &self,
        proxy_workload_info: WorkloadInfo,
    ) -> Result<ProxyResult, Error> {
        let factory: Arc<dyn crate::proxy::SocketFactory + Send + Sync> =
            if let Some(mark) = self.config.packet_mark {
                Arc::new(crate::proxy::MarkSocketFactory(mark))
            } else {
                Arc::new(crate::proxy::DefaultSocketFactory)
            };
        self.new_proxies_from_factory(None, proxy_workload_info, factory)
            .await
    }

    pub async fn new_proxies_from_factory(
        &self,
        proxy_drain: Option<DrainWatcher>,
        proxy_workload_info: WorkloadInfo,
        socket_factory: Arc<dyn crate::proxy::SocketFactory + Send + Sync>,
    ) -> Result<ProxyResult, Error> {
        let mut result: ProxyResult = Default::default();
        let drain = proxy_drain.unwrap_or_else(|| self.drain.clone());

        let mut resolver = None;
        // Optionally create the DNS proxy.
        if self.config.dns_proxy {
            let server = dns::Server::new(
                self.config.cluster_domain.clone(),
                self.config.dns_proxy_addr,
                self.config.network.clone(),
                self.state.clone(),
                dns::forwarder_for_mode(
                    self.config.proxy_mode,
                    self.config.cluster_domain.clone(),
                )?,
                self.dns_metrics.clone().unwrap(),
                drain.clone(),
                socket_factory.as_ref(),
                false,
            )
            .await?;
            resolver = Some(server.resolver());
            result.dns_proxy = Some(server);
        }

        // Optionally create the HBONE proxy.
        if self.config.proxy {
            let cm = ConnectionManager::default();
            let pi = crate::proxy::ProxyInputs::new(
                self.config.clone(),
                self.cert_manager.clone(),
                cm.clone(),
                self.state.clone(),
                self.proxy_metrics.clone(),
                socket_factory.clone(),
                proxy_workload_info,
                resolver,
            );
            result.connection_manager = Some(cm);
            result.proxy = Some(Proxy::from_inputs(pi, drain).await?);
        }

        Ok(result)
    }
}

#[derive(Default)]
pub struct ProxyResult {
    pub proxy: Option<Proxy>,
    pub dns_proxy: Option<dns::Server>,
    pub connection_manager: Option<ConnectionManager>,
}
