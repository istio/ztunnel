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
use crate::state::DemandProxyState;
use drain::Watch;
use std::sync::Arc;
use tracing::error;

use crate::dns;

use crate::proxy::{Error, Metrics};

#[mockall_double::double]
use crate::proxy::Proxy;

#[cfg(test)]
use mockall::automock;

// Proxy factory creates ztunnel proxies using a socket factory.
// this allows us to create our proxies the same way in regular mode and in inpod mode.
pub struct ProxyFactory {
    config: config::Config,
    state: DemandProxyState,
    cert_manager: Arc<SecretManager>,
    proxy_metrics: Option<Arc<Metrics>>,
    dns_metrics: Option<Arc<dns::Metrics>>,
    drain: Watch,
}

#[cfg_attr(test, automock)]
impl ProxyFactory {
    pub fn new(
        config: config::Config,
        state: DemandProxyState,
        cert_manager: Arc<SecretManager>,
        proxy_metrics: Option<Metrics>,
        dns_metrics: Option<dns::Metrics>,
        drain: Watch,
    ) -> std::io::Result<Self> {
        let proxy_metrics = match proxy_metrics {
            Some(metrics) => Some(Arc::new(metrics)),
            None => {
                if config.proxy {
                    error!("proxy configured but no metrics provided")
                }
                None
            }
        };
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

    pub async fn new_proxies(&self) -> Result<ProxyResult, Error> {
        self.new_proxies_from_factory(None, Arc::new(crate::proxy::DefaultSocketFactory))
            .await
    }

    pub async fn new_proxies_from_factory(
        &self,
        proxy_drain: Option<Watch>,
        socket_factory: Arc<dyn crate::proxy::SocketFactory + Send + Sync>,
    ) -> Result<ProxyResult, Error> {
        let mut result: ProxyResult = Default::default();
        let drain = proxy_drain.unwrap_or_else(|| self.drain.clone());

        // Optionally create the HBONE proxy.
        if self.config.proxy {
            let pi = crate::proxy::ProxyInputs::new(
                self.config.clone(),
                self.cert_manager.clone(),
                self.state.clone(),
                self.proxy_metrics.clone().unwrap(),
                socket_factory.clone(),
            );
            result.proxy = Some(Proxy::from_inputs(pi, drain.clone()).await?);
        }

        // Optionally create the DNS proxy.
        if self.config.dns_proxy {
            result.dns_proxy = Some(
                dns::Server::new(
                    self.config.cluster_domain.clone(),
                    self.config.dns_proxy_addr,
                    self.config.network.clone(),
                    self.state.clone(),
                    dns::forwarder_for_mode(self.config.proxy_mode)?,
                    self.dns_metrics.clone().unwrap(),
                    drain,
                    socket_factory.as_ref(),
                )
                .await?,
            );
        }
        Ok(result)
    }
}

#[derive(Default)]
pub struct ProxyResult {
    pub proxy: Option<Proxy>,
    pub dns_proxy: Option<dns::Server>,
}
