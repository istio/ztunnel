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
use crate::rbac::Authorization;
use crate::state::service::{endpoint_uid, Endpoint, Service};
use crate::state::workload::{gatewayaddress, Workload};
use crate::test_helpers::app::TestApp;
use crate::test_helpers::netns::{Namespace, Resolver};
use crate::test_helpers::*;
use crate::xds::{LocalConfig, LocalWorkload};
use crate::{config, identity, proxy, strng};

use itertools::Itertools;
use nix::unistd::mkdtemp;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::Duration;

use crate::test_helpers::inpod::start_ztunnel_server;
use crate::test_helpers::linux::TestMode::InPod;
use tokio::sync::Mutex;
use tracing::info;

/// WorkloadManager provides an interface to deploy "workloads" as part of a test. Each workload
/// runs in its own isolated network namespace, simulating a real environment. Redirection in the "host network"
/// namespace is configured, which can redirect traffic to a ztunnel.
/// Note: at this time, only a single "node" (and therefor, ztunnel), is supported.
pub struct WorkloadManager {
    namespaces: netns::NamespaceManager,
    /// set of nodes that have ztunnel deployed on them
    ztunnels: HashMap<String, LocalZtunnel>,
    /// workloads that we have constructed
    workloads: Vec<LocalWorkload>,
    /// services that we have constructed. VIP -> SVC
    services: HashMap<NamespacedHostname, Service>,
    /// Configured policies
    policies: Vec<Authorization>,
    mode: TestMode,
    tmp_dir: PathBuf,
}

pub struct LocalZtunnel {
    fd_sender: Option<MpscAckSender<(String, i32)>>,
    config_sender: MpscAckSender<LocalConfig>,
    ip: IpAddr,
    veth: String,
}

impl Drop for WorkloadManager {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.tmp_dir).unwrap()
    }
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub enum TestMode {
    InPod,
    SharedNode,
}

impl WorkloadManager {
    /// new instantiates a manager with the given name. Using a unique name between tests is critical.
    pub fn new(name: &str, mode: TestMode) -> anyhow::Result<Self> {
        // Temporary directory will hold all our mounts
        let tp = std::env::temp_dir().join("ztunnel_namespaced.XXXXXX");
        let tmp_dir = mkdtemp(&tp).expect("tmp dir");
        Ok(Self {
            mode,
            tmp_dir,
            ztunnels: Default::default(),
            namespaces: netns::NamespaceManager::new(name)?,
            workloads: vec![],
            services: HashMap::new(),
            policies: vec![],
        })
    }

    /// deploy_ztunnel runs a ztunnel instance and configures redirection on the "node".
    ///
    /// Warning: currently, workloads are not dynamically update; they are snapshotted at the time
    /// deploy_ztunnel is called. As such, you must ensure this is called after all other workloads are created.
    pub async fn deploy_ztunnel(&mut self, node: &str) -> anyhow::Result<TestApp> {
        let mut inpod_uds: PathBuf = "/dev/null".into();
        let ztunnel_server = if self.mode == InPod {
            inpod_uds = self.tmp_dir.join(node);
            Some(start_ztunnel_server(inpod_uds.clone()))
        } else {
            None
        };
        let ns = TestWorkloadBuilder::new(&format!("ztunnel-{node}"), self)
            .on_node(node)
            .uncaptured()
            .register()
            .await?;
        let ip = ns.ip();
        let veth = ns.interface();
        let initial_config = LocalConfig {
            workloads: self.workloads.clone(),
            policies: self.policies.clone(),
            services: self.services.values().cloned().collect_vec(),
        };
        let inpod_enabled = ztunnel_server.is_some();
        let (mut tx_cfg, rx_cfg) = mpsc_ack(1);
        tx_cfg.send(initial_config).await?;
        let local_xds_config = Some(ConfigSource::Dynamic(Arc::new(Mutex::new(rx_cfg))));
        let cfg = config::Config {
            xds_address: None,
            dns_proxy: true,
            fake_ca: true,
            local_xds_config,
            local_node: Some(node.to_string()),
            local_ip: Some(ns.ip()),
            inpod_uds,
            inpod_enabled,
            ..config::parse_config().unwrap()
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        // Setup the ztunnel...
        let cloned_ns = ns.clone();
        ns.run_ready(move |ready| async move {
            if !inpod_enabled {
                // not needed in inpod mode. In in pod mode we run `ztunnel-redirect-inpod.sh`
                // inside the pod's netns
                helpers::run_command(&format!("scripts/ztunnel-redirect.sh {ip}"))?;
            }
            let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
            let app = crate::app::build_with_cert(Arc::new(cfg), cert_manager.clone()).await?;

            // inpod mode doesn't have ore need these, so just put bogus values.
            let proxy_addresses = app.proxy_addresses.unwrap_or(proxy::Addresses {
                inbound: "0.0.0.0:0".parse()?,
                outbound: "0.0.0.0:0".parse()?,
                socks5: Some("0.0.0.0:0".parse()?),
            });

            let ta = TestApp {
                // Not actually accessible
                admin_address: helpers::with_ip(app.admin_address, ip),
                metrics_address: helpers::with_ip(app.metrics_address, ip),
                readiness_address: helpers::with_ip(app.readiness_address, ip),
                proxy_addresses: proxy::Addresses {
                    outbound: helpers::with_ip(proxy_addresses.outbound, ip),
                    inbound: helpers::with_ip(proxy_addresses.inbound, ip),
                    socks5: proxy_addresses.socks5.map(|i| helpers::with_ip(i, ip)),
                },
                tcp_dns_proxy_address: Some(helpers::with_ip(
                    app.tcp_dns_proxy_address.unwrap_or("0.0.0.0:0".parse()?),
                    ip,
                )),
                udp_dns_proxy_address: Some(helpers::with_ip(
                    app.udp_dns_proxy_address.unwrap_or("0.0.0.0:0".parse()?),
                    ip,
                )),
                cert_manager,

                namespace: Some(cloned_ns),
            };
            ta.ready().await;
            info!("ready");
            ready.set_ready();
            tx.send(ta)?;

            app.wait_termination().await
        })?;
        // Make sure our initial config is ACKed
        tx_cfg.wait().await?;
        let zt_info = LocalZtunnel {
            fd_sender: ztunnel_server,
            config_sender: tx_cfg,
            ip,
            veth: veth.clone(),
        };
        self.ztunnels.insert(node.to_string(), zt_info);
        Ok(rx.recv()?)
    }

    async fn refresh_config(&mut self) -> anyhow::Result<()> {
        for node in self.ztunnels.values_mut() {
            let new_config = LocalConfig {
                workloads: self.workloads.clone(),
                policies: self.policies.clone(),
                services: self.services.values().cloned().collect_vec(),
            };
            node.config_sender.send_and_wait(new_config).await?;
        }
        Ok(())
    }

    /// workload_builder allows creating a new workload. It will run in its own network namespace.
    pub fn workload_builder(&mut self, name: &str, node: &str) -> TestWorkloadBuilder {
        TestWorkloadBuilder::new(name, self)
            .on_node(node)
            .identity(identity::Identity::Spiffe {
                trust_domain: "cluster.local".into(),
                namespace: "default".into(),
                service_account: name.into(),
            })
    }

    /// service_builder allows creating a new service
    pub fn service_builder(&mut self, name: &str) -> TestServiceBuilder {
        TestServiceBuilder::new(name, self)
    }

    /// register_waypoint builds a new waypoint. This must be used for waypoints, rather than workload_builder,
    /// or the redirection will not work properly
    pub async fn register_waypoint(&mut self, name: &str, node: &str) -> anyhow::Result<Namespace> {
        TestWorkloadBuilder::new(name, self)
            .on_node(node)
            .uncaptured() // Waypoints are not captured.
            .identity(identity::Identity::Spiffe {
                trust_domain: "cluster.local".into(),
                namespace: "default".into(),
                service_account: name.into(),
            })
            .register()
            .await
    }

    pub async fn add_policy(&mut self, p: Authorization) -> anyhow::Result<()> {
        self.policies.push(p);
        self.refresh_config().await?;
        Ok(())
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
                name: name.into(),
                namespace: "default".into(),
                hostname: strng::format!("{name}.default.svc.cluster.local"),
                vips: vec![],
                ports: Default::default(),
                endpoints: Default::default(), // populated later when workloads are added
                subject_alt_names: vec![],
                waypoint: None,
                load_balancer: None,
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

    /// Set the service waypoint
    pub fn waypoint(mut self, waypoint: IpAddr) -> Self {
        self.s.waypoint = Some(GatewayAddress {
            destination: gatewayaddress::Destination::Address(NetworkAddress {
                network: "".to_string(),
                address: waypoint,
            }),
            hbone_mtls_port: 15008,
            hbone_single_tls_port: Some(15003),
        });
        self
    }

    /// Finish building the service.
    pub async fn register(self) -> anyhow::Result<()> {
        self.manager
            .services
            .insert(self.s.namespaced_hostname(), self.s);
        self.manager.refresh_config().await?;
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
            captured: false,
            w: LocalWorkload {
                workload: Workload {
                    name: name.into(),
                    namespace: "default".into(),
                    service_account: "default".into(),
                    node: "".into(),
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
            hbone_mtls_port: 15008,
            hbone_single_tls_port: Some(15003),
        });
        self
    }

    /// Set a waypoint to the workload
    pub fn mutate_workload(mut self, f: impl FnOnce(&mut Workload)) -> Self {
        f(&mut self.w.workload);
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
        self.w.workload.node = node.into();
        if self.manager.ztunnels.contains_key(node) {
            self.captured = true;
            self.w.workload.protocol = HBONE;
        }
        self
    }

    /// Opt out of redirection
    pub fn uncaptured(mut self) -> Self {
        self.captured = false;
        self.w.workload.protocol = TCP;
        self
    }

    /// Finish building the workload.
    pub async fn register(mut self) -> anyhow::Result<Namespace> {
        let node = self.w.workload.node.clone();
        let network_namespace = self
            .manager
            .namespaces
            .child(&self.w.workload.node, &self.w.workload.name)?;
        self.w.workload.workload_ips = vec![network_namespace.ip()];
        self.w.workload.uid = format!(
            "cluster1//v1/Pod/{}/{}",
            self.w.workload.namespace, self.w.workload.name,
        ).into();
        let uid = self.w.workload.uid.clone();

        // update the endpoints for the service.
        for (service, ports) in &self.w.services {
            let service_name = service.parse::<NamespacedHostname>()?;

            for wip in self.w.workload.workload_ips.iter() {
                let ep_network_addr = NetworkAddress {
                    network: "".to_string(),
                    address: *wip,
                };

                let ep = Endpoint {
                    workload_uid: self.w.workload.uid.as_str().into(),
                    service: service_name.clone(),
                    address: Some(ep_network_addr.clone()),
                    port: ports.to_owned(),
                };
                let mut svc = self.manager.services.get(&service_name).unwrap().clone();
                let ep_uid = endpoint_uid(&self.w.workload.uid, Some(&ep_network_addr));
                svc.endpoints.insert(ep_uid, ep.clone());
            }
        }

        info!("registered {}", &self.w.workload.uid);
        self.manager.workloads.push(self.w);
        if self.captured {
            // Setup redirection
            let zt_info = self.manager.ztunnels.get_mut(node.as_str()).unwrap();
            if self.manager.mode == InPod {
                // In the new pod network
                network_namespace
                    .netns()
                    .run(|_| helpers::run_command("scripts/ztunnel-redirect-inpod.sh"))??;
                let fd = network_namespace.netns().file().as_raw_fd();
                zt_info
                    .fd_sender
                    .as_mut()
                    .unwrap()
                    .send_and_wait((uid.to_string(), fd))
                    .await?;
            } else {
                let our_ip = network_namespace.ip();
                // Setup in the ztunnel network namespace
                let ip = zt_info.ip;
                let veth = &zt_info.veth;
                self.manager.namespaces.run_in_node(&node, || {
                    helpers::run_command(&format!("scripts/node-redirect.sh {ip} {veth} {our_ip}"))
                })?;
            }
        }
        self.manager.refresh_config().await?;
        Ok(network_namespace)
    }
}
