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

use crate::config::ConfigSource;
use crate::state::service::{Endpoint, Service};
use crate::state::workload::{gatewayaddress, Workload};
use crate::test_helpers::app::TestApp;
use crate::test_helpers::netns::{Namespace, Resolver};
use crate::test_helpers::*;
use crate::xds::{LocalConfig, LocalWorkload};
use crate::{config, identity, proxy};
use bytes::BufMut;
use itertools::Itertools;
use std::net::IpAddr;
use std::time::Duration;
use tracing::info;

/// WorkloadManager provides an interface to deploy "workloads" as part of a test. Each workload
/// runs in its own isolated network namespace, simulating a real environment. Redirection in the "host network"
/// namespace is configured, which can redirect traffic to a ztunnel.
/// Note: at this time, only a single "node" (and therefor, ztunnel), is supported.
pub struct WorkloadManager {
    namespaces: netns::NamespaceManager,
    /// workloads that we have constructed
    workloads: Vec<LocalWorkload>,
    /// services that we have constructed. VIP -> SVC
    services: HashMap<NamespacedHostname, Service>,
    /// Node to IPs on the node that are captured
    captured_workloads: HashMap<String, Vec<IpAddr>>,
    waypoints: Vec<IpAddr>,
}

impl WorkloadManager {
    /// new instantiates a manager with the given name. Using a unique name between tests is critical.
    pub fn new(name: &str) -> anyhow::Result<Self> {
        Ok(Self {
            namespaces: netns::NamespaceManager::new(name)?,
            workloads: vec![],
            services: HashMap::new(),
            captured_workloads: Default::default(),
            waypoints: vec![],
        })
    }

    /// deploy_ztunnel runs a ztunnel instance and configures redirection on the "node".
    ///
    /// Warning: currently, workloads are not dynamically update; they are snapshotted at the time
    /// deploy_ztunnel is called. As such, you must ensure this is called after all other workloads are created.
    pub fn deploy_ztunnel(&mut self, node: &str) -> anyhow::Result<TestApp> {
        let ns = TestWorkloadBuilder::new(&format!("ztunnel-{node}"), self)
            .on_node(node)
            .uncaptured()
            .register()?;
        let ip = ns.ip();
        let veth = ns.interface();
        let lc = LocalConfig {
            workloads: self.workloads.clone(),
            policies: vec![],
            services: self.services.values().cloned().collect_vec(),
        };
        let mut b = bytes::BytesMut::new().writer();
        serde_yaml::to_writer(&mut b, &lc)?;

        let cfg = config::Config {
            xds_address: None,
            dns_proxy: true,
            fake_ca: true,
            local_xds_config: Some(ConfigSource::Static(b.into_inner().freeze())),
            local_node: Some(node.to_string()),
            local_ip: Some(ns.ip()),
            ..config::parse_config().unwrap()
        };
        let waypoints = self.waypoints.iter().map(|i| i.to_string()).join(" ");
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        // Setup the ztunnel...
        ns.run_ready(move |ready| async move {
            helpers::run_command(&format!("scripts/ztunnel-redirect.sh {ip} {waypoints}"))?;
            let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
            let app = crate::app::build_with_cert(cfg, cert_manager.clone()).await?;

            let ta = TestApp {
                // Not actually accessible
                admin_address: helpers::with_ip(app.admin_address, ip),
                stats_address: helpers::with_ip(app.stats_address, ip),
                proxy_addresses: proxy::Addresses {
                    outbound: helpers::with_ip(app.proxy_addresses.outbound, ip),
                    inbound: helpers::with_ip(app.proxy_addresses.inbound, ip),
                    socks5: helpers::with_ip(app.proxy_addresses.socks5, ip),
                    dns_proxy: app
                        .proxy_addresses
                        .dns_proxy
                        .map(|dns_proxy| helpers::with_ip(dns_proxy, ip)),
                },
                readiness_address: helpers::with_ip(app.readiness_address, ip),
                cert_manager,
            };
            ta.ready().await;
            info!("ready");
            ready.set_ready();
            tx.send(ta)?;

            app.wait_termination().await
        })?;
        // Setup the node...
        let captured = self
            .captured_workloads
            .get(node)
            .unwrap_or(&vec![])
            .iter()
            .map(|i| i.to_string())
            .join(" ");
        self.namespaces.run_in_node(node, || {
            helpers::run_command(&format!("scripts/node-redirect.sh {ip} {veth} {captured}"))
        })?;
        Ok(rx.recv()?)
    }

    /// workload_builder allows creating a new workload. It will run in its own network namespace.
    pub fn workload_builder(&mut self, name: &str, node: &str) -> TestWorkloadBuilder {
        TestWorkloadBuilder::new(name, self).on_node(node)
    }

    /// service_builder allows creating a new service
    pub fn service_builder(&mut self, name: &str) -> TestServiceBuilder {
        TestServiceBuilder::new(name, self)
    }

    /// register_waypoint builds a new waypoint. This must be used for waypoints, rather than workload_builder,
    /// or the redirection will not work properly
    pub fn register_waypoint(&mut self, name: &str, node: &str) -> anyhow::Result<Namespace> {
        let ns = TestWorkloadBuilder::new(name, self)
            .hbone()
            .on_node(node)
            .register()?;
        self.waypoints.push(ns.ip());
        Ok(ns)
    }

    pub fn resolver(&self) -> Resolver {
        self.namespaces.resolver()
    }

    /// resolve acts as a "DNS lookup", converting a workload name to an IP address.
    pub fn resolve(&self, name: &str) -> anyhow::Result<IpAddr> {
        self.namespaces.resolve(name)
    }
}

pub struct TestServiceBuilder<'a> {
    s: Service,
    manager: &'a mut WorkloadManager,
}

impl<'a> TestServiceBuilder<'a> {
    pub fn new(name: &str, manager: &'a mut WorkloadManager) -> TestServiceBuilder<'a> {
        TestServiceBuilder {
            s: Service {
                name: name.to_string(),
                namespace: "default".to_string(),
                hostname: format!("default.{}-svc.svc.cluster.local", name),
                vips: vec![],
                ports: Default::default(),
                endpoints: Default::default(), // populated later when workloads are added
            },
            manager,
        }
    }

    /// Set the service addresses
    pub fn addresses(mut self, addrs: Vec<NetworkAddress>) -> Self {
        self.s.vips = addrs;
        self
    }

    /// Set the service ports
    pub fn ports(mut self, ports: HashMap<u16, u16>) -> Self {
        self.s.ports = ports;
        self
    }

    /// Finish building the service.
    pub fn register(self) -> anyhow::Result<()> {
        self.manager
            .services
            .insert(self.s.namespaced_hostname(), self.s);
        Ok(())
    }
}

pub struct TestWorkloadBuilder<'a> {
    w: LocalWorkload,
    captured: bool,
    manager: &'a mut WorkloadManager,
}

impl<'a> TestWorkloadBuilder<'a> {
    pub fn new(name: &str, manager: &'a mut WorkloadManager) -> TestWorkloadBuilder<'a> {
        TestWorkloadBuilder {
            captured: true, // workload has redirection enabled
            w: LocalWorkload {
                workload: Workload {
                    name: name.to_string(),
                    namespace: "default".to_string(),
                    service_account: "default".to_string(),
                    node: "not-local".to_string(),
                    ..test_default_workload()
                },
                services: Default::default(),
            },
            manager,
        }
    }

    /// Set the workload to use HBONE
    pub fn hbone(mut self) -> Self {
        self.w.workload.protocol = HBONE;
        self
    }

    pub fn identity(mut self, identity: identity::Identity) -> Self {
        match identity {
            identity::Identity::Spiffe {
                trust_domain,
                namespace,
                service_account,
            } => {
                self.w.workload.service_account = service_account;
                self.w.workload.namespace = namespace;
                self.w.workload.trust_domain = trust_domain;
            }
        }
        self
    }

    /// Set a waypoint to the workload
    pub fn waypoint(mut self, waypoint: IpAddr) -> Self {
        self.w.workload.waypoint = Some(GatewayAddress {
            destination: gatewayaddress::Destination::Address(NetworkAddress {
                network: "".to_string(),
                address: waypoint,
            }),
            port: 15008,
        });
        self
    }

    /// Append a service to the workload
    pub fn service(mut self, service: &str, server_port: u16, target_port: u16) -> Self {
        self.w
            .services
            .entry(service.to_string())
            .or_default()
            .insert(server_port, target_port);
        self
    }

    /// Configure the workload to run a given node
    pub fn on_node(mut self, node: &str) -> Self {
        self.w.workload.node = node.to_string();
        self
    }

    /// Opt out of redirection
    pub fn uncaptured(mut self) -> Self {
        self.captured = false;
        self
    }

    /// Finish building the workload.
    pub fn register(mut self) -> anyhow::Result<Namespace> {
        let node = self.w.workload.node.clone();
        let network_namespace = self
            .manager
            .namespaces
            .child(&self.w.workload.node, &self.w.workload.name)?;
        self.w.workload.workload_ips = vec![network_namespace.ip()];
        self.w.workload.uid = format!(
            "cluster1//v1/Pod/{}/{}",
            self.w.workload.namespace, self.w.workload.name,
        );

        // update the endpoints for the service.
        for (service, ports) in &self.w.services {
            let service_name = service.parse::<NamespacedHostname>()?;

            for wip in self.w.workload.workload_ips.iter() {
                let ep_network_addr = NetworkAddress {
                    network: "".to_string(),
                    address: *wip,
                };

                let ep = Endpoint {
                    service: service_name.clone(),
                    address: ep_network_addr.clone(),
                    port: ports.to_owned(),
                };
                let mut svc = self.manager.services.get(&service_name).unwrap().clone();
                svc.endpoints.insert(ep_network_addr.clone(), ep.clone());
            }
        }

        info!("registered {}", self.w.workload.uid);
        self.manager.workloads.push(self.w);
        if self.captured {
            self.manager
                .captured_workloads
                .entry(node)
                .or_default()
                .push(network_namespace.ip());
        }
        Ok(network_namespace)
    }
}
