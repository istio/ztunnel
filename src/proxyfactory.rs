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
use crate::tls;
use std::sync::Arc;
use tracing::error;

use crate::dns;
use crate::drain::DrainWatcher;

use crate::proxy::connection_manager::ConnectionManager;
use crate::proxy::{DefaultSocketFactory, Proxy, inbound::Inbound};
use crate::proxy::{Error, LocalWorkloadInformation, Metrics};

// Proxy factory creates ztunnel proxies using a socket factory.
// this allows us to create our proxies the same way in regular mode and in inpod mode.
pub struct ProxyFactory {
    config: Arc<config::Config>,
    state: DemandProxyState,
    cert_manager: Arc<SecretManager>,
    proxy_metrics: Arc<Metrics>,
    dns_metrics: Option<Arc<dns::Metrics>>,
    drain: DrainWatcher,
    crl_manager: Option<Arc<tls::crl::CrlManager>>,
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

        // Initialize CRL manager if crl_path is set
        let crl_manager = if let Some(crl_path) = &config.crl_path {
            match tls::crl::CrlManager::new(crl_path.clone()) {
                Ok(manager) => {
                    let manager_arc = Arc::new(manager);

                    if let Err(e) = manager_arc.start_file_watcher() {
                        tracing::warn!(
                            "crl file watcher could not be started: {}. \
                            crl validation will continue with current file, but \
                            crl updates will require restarting ztunnel.",
                            e
                        );
                    }

                    Some(manager_arc)
                }
                Err(e) => {
                    tracing::warn!(
                        path = ?crl_path,
                        error = %e,
                        "failed to initialize crl manager"
                    );
                    None
                }
            }
        } else {
            None
        };

        Ok(ProxyFactory {
            config,
            state,
            cert_manager,
            proxy_metrics,
            dns_metrics,
            drain,
            crl_manager,
        })
    }

    pub async fn new_proxies_for_dedicated(
        &self,
        proxy_workload_info: WorkloadInfo,
    ) -> Result<ProxyResult, Error> {
        let base = crate::proxy::DefaultSocketFactory(self.config.socket_config);
        let factory: Arc<dyn crate::proxy::SocketFactory + Send + Sync> =
            if let Some(mark) = self.config.packet_mark {
                Arc::new(crate::proxy::MarkSocketFactory { inner: base, mark })
            } else {
                Arc::new(base)
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

        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(proxy_workload_info),
            self.state.clone(),
            self.cert_manager.clone(),
            self.config.clone(),
        ));

        // Optionally create the DNS proxy.
        if self.config.dns_proxy {
            let server = dns::Server::new(
                self.config.cluster_domain.clone(),
                self.config.dns_proxy_addr,
                self.state.clone(),
                dns::forwarder_for_mode(
                    self.config.proxy_mode,
                    self.config.cluster_domain.clone(),
                    socket_factory.clone(),
                )?,
                self.dns_metrics.clone().unwrap(),
                drain.clone(),
                socket_factory.as_ref(),
                local_workload_information.as_fetcher(),
                self.config.prefered_service_namespace.clone(),
                self.config.ipv6_enabled,
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
                cm.clone(),
                self.state.clone(),
                self.proxy_metrics.clone(),
                socket_factory.clone(),
                resolver,
                local_workload_information,
                false,
                self.crl_manager.clone(),
            );
            result.connection_manager = Some(cm);
            result.proxy = Some(Proxy::from_inputs(pi, drain).await?);
        }

        Ok(result)
    }

    /// Creates an inbound listener specifically for ztunnel's own internal endpoints (metrics).
    /// This allows ztunnel to act as its own workload, enforcing policies on traffic directed to itself.
    /// This is distinct from the main inbound listener which handles traffic for other workloads proxied by ztunnel.
    pub async fn create_ztunnel_self_proxy_listener(
        &self,
    ) -> Result<Option<crate::proxy::inbound::Inbound>, Error> {
        if self.config.proxy_mode != config::ProxyMode::Shared {
            return Ok(None);
        }

        if let (Some(ztunnel_identity), Some(ztunnel_workload)) =
            (&self.config.ztunnel_identity, &self.config.ztunnel_workload)
        {
            tracing::info!(
                "creating ztunnel self-proxy listener with identity: {:?}",
                ztunnel_identity
            );

            let local_workload_information = Arc::new(LocalWorkloadInformation::new(
                Arc::new(ztunnel_workload.clone()),
                self.state.clone(),
                self.cert_manager.clone(),
                self.config.clone(),
            ));

            let socket_factory = Arc::new(DefaultSocketFactory(self.config.socket_config));

            let cm = ConnectionManager::default();

            let pi = crate::proxy::ProxyInputs::new(
                self.config.clone(),
                cm.clone(),
                self.state.clone(),
                self.proxy_metrics.clone(),
                socket_factory,
                None,
                local_workload_information,
                true,
                self.crl_manager.clone(),
            );

            let inbound = Inbound::new(pi, self.drain.clone()).await?;
            Ok(Some(inbound))
        } else {
            Ok(None)
        }
    }
}

#[derive(Default)]
pub struct ProxyResult {
    pub proxy: Option<Proxy>,
    pub dns_proxy: Option<dns::Server>,
    pub connection_manager: Option<ConnectionManager>,
}
