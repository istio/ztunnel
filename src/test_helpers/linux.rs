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

use crate::config::{ConfigSource, ProxyMode};
use crate::rbac::Authorization;
use crate::state::service::{Endpoint, Service};
use crate::state::workload::{HealthStatus, Workload, gatewayaddress};
use crate::test_helpers::app::TestApp;
use crate::test_helpers::netns::{Namespace, Resolver};
use crate::test_helpers::*;
use crate::xds::{LocalConfig, LocalWorkload};
use crate::{config, identity, proxy, strng};

use crate::inpod::istio::zds::WorkloadInfo;
use crate::signal::ShutdownTrigger;
use crate::test_helpers::inpod::start_ztunnel_server;
use crate::test_helpers::linux::TestMode::{Dedicated, Shared};
use itertools::Itertools;
use nix::unistd::mkdtemp;
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;
use std::time::Duration;
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
    drops: Vec<ShutdownTrigger>,
}

#[derive(Debug)]
pub struct LocalZtunnel {
    fd_sender: Option<MpscAckSender<inpod::Message>>,
    config_sender: MpscAckSender<LocalConfig>,
    namespace: Namespace,
}

impl Drop for WorkloadManager {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.tmp_dir).unwrap();
        for d in &self.drops {
            let d = d.clone();
            thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move { d.shutdown_now().await });
            });
        }
    }
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub enum TestMode {
    Shared,
    Dedicated,
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
            drops: vec![],
        })
    }

    pub fn mode(&self) -> TestMode {
        self.mode
    }

    /// deploy_ztunnel runs a ztunnel instance and configures redirection on the "node".
    ///
    /// Warning: currently, workloads are not dynamically update; they are snapshotted at the time
    /// deploy_ztunnel is called. As such, you must ensure this is called after all other workloads are created.
    pub async fn deploy_ztunnel(&mut self, node: &str) -> anyhow::Result<TestApp> {
        self.deploy_dedicated_ztunnel(node, None).await
    }

    /// deploy_ztunnel runs a ztunnel instance for dedicated mode.
    pub async fn deploy_dedicated_ztunnel(
        &mut self,
        node: &str,
        wli: Option<state::WorkloadInfo>,
    ) -> anyhow::Result<TestApp> {
        let mut inpod_uds: PathBuf = "/dev/null".into();
        let ztunnel_server = if self.mode == Shared {
            inpod_uds = self.tmp_dir.join(node);
            Some(start_ztunnel_server(inpod_uds.clone()).await)
        } else {
            None
        };
        let ns = TestWorkloadBuilder::new(&format!("ztunnel-{node}"), self)
            .on_node(node)
            .uncaptured()
            .register()
            .await?;
        let ip = ns.ip();
        let initial_config = LocalConfig {
            workloads: self.workloads.clone(),
            policies: self.policies.clone(),
            services: self.services.values().cloned().collect_vec(),
        };
        let proxy_mode = if ztunnel_server.is_some() {
            ProxyMode::Shared
        } else {
            ProxyMode::Dedicated
        };
        let (mut tx_cfg, rx_cfg) = mpsc_ack(1);
        tx_cfg.send(initial_config).await?;
        let local_xds_config = Some(ConfigSource::Dynamic(Arc::new(Mutex::new(rx_cfg))));
        let cfg = config::Config {
            xds_address: None,
            dns_proxy: true,
            fake_ca: true,
            local_xds_config,
            local_node: Some(node.to_string()),
            proxy_workload_information: wli,
            inpod_uds,
            proxy_mode,
            // We use packet mark even in dedicated to distinguish proxy from application
            packet_mark: Some(1337),
            require_original_source: if proxy_mode == ProxyMode::Dedicated {
                Some(false)
            } else {
                Some(true)
            },
            ..config::parse_config().unwrap()
        };
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        // Setup the ztunnel...
        let cloned_ns = ns.clone();
        let cloned_ns2 = ns.clone();
        // run_ready will spawn a thread and block on it. Run with spawn_blocking so it doesn't block the runtime.
        tokio::task::spawn_blocking(move || {
            ns.run_ready(move |ready| async move {
                if proxy_mode == ProxyMode::Dedicated {
                    // not needed in "inpod" (shared proxy) mode. In shared mode we run `ztunnel-redirect-inpod.sh`
                    // inside the pod's netns
                    helpers::run_command("scripts/ztunnel-redirect.sh")?;
                }
                let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
                let app = crate::app::build_with_cert(Arc::new(cfg), cert_manager.clone()).await?;
                let shutdown = app.shutdown.trigger();

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
                    shutdown,
                };
                ta.ready().await;
                info!("ready");
                ready.set_ready();
                tx.send(ta)?;

                app.wait_termination().await
            })
        })
        .await
        .unwrap()?;

        // Make sure our initial config is ACKed
        tx_cfg.wait().await?;
        let zt_info = LocalZtunnel {
            fd_sender: ztunnel_server,
            config_sender: tx_cfg,
            namespace: cloned_ns2,
        };
        self.ztunnels.insert(node.to_string(), zt_info);
        let ta = rx.recv()?;
        self.drops.push(ta.shutdown.clone());
        Ok(ta)
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

    pub async fn delete_workload(&mut self, name: &str) -> anyhow::Result<()> {
        let mut workloads = vec![];
        std::mem::swap(&mut self.workloads, &mut workloads);
        let (keep, drop) = workloads.into_iter().partition(|w| w.workload.name != name);
        self.workloads = keep;
        for d in drop {
            if let Some(zt) = self.ztunnels.get_mut(&d.workload.node.to_string()).as_mut() {
                let msg = inpod::Message::Stop(d.workload.uid.to_string());
                zt.fd_sender
                    .as_mut()
                    .unwrap()
                    .send_and_wait(msg)
                    .await
                    .unwrap();
            }
        }
        self.refresh_config().await?;
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
                ip_families: None,
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
                network: strng::EMPTY,
                address: waypoint,
            }),
            hbone_mtls_port: 15008,
        });
        self
    }

    /// Set the service waypoint by hostname
    pub fn waypoint_hostname(mut self, hostname: &str) -> Self {
        self.s.waypoint = Some(GatewayAddress {
            destination: gatewayaddress::Destination::Hostname(NamespacedHostname {
                namespace: strng::literal!("default"),
                hostname: hostname.into(),
            }),
            hbone_mtls_port: 15008,
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
                network: strng::EMPTY,
                address: waypoint,
            }),
            hbone_mtls_port: 15008,
        });
        self
    }

    /// Set the service waypoint by hostname
    pub fn waypoint_hostname(mut self, hostname: &str) -> Self {
        self.w.workload.waypoint = Some(GatewayAddress {
            destination: gatewayaddress::Destination::Hostname(NamespacedHostname {
                namespace: strng::literal!("default"),
                hostname: hostname.into(),
            }),
            hbone_mtls_port: 15008,
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
        self.w
            .workload
            .services
            .push(NamespacedHostname::from_str(service).unwrap());
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
        let zt = self.manager.ztunnels.get(self.w.workload.node.as_str());
        let node = self.w.workload.node.clone();
        let network_namespace = if self.manager.mode == Dedicated && zt.is_some() {
            // This is a bit of hack. For dedicated mode, we run the app and ztunnel in the same namespace
            // We probably should express this more natively in the framework, but for now we just detect it
            // and re-use the namespace.
            tracing::info!("node already has ztunnel and dedicate mode, sharing");
            zt.as_ref().unwrap().namespace.clone()
        } else {
            self.manager
                .namespaces
                .child(&self.w.workload.node, &self.w.workload.name)?
        };
        self.w.workload.workload_ips = vec![network_namespace.ip()];
        self.w.workload.uid = format!(
            "cluster1//v1/Pod/{}/{}",
            self.w.workload.namespace, self.w.workload.name,
        )
        .into();
        let uid = self.w.workload.uid.clone();

        // update the endpoints for the service.
        for (service, ports) in &self.w.services {
            let service_name = service.parse::<NamespacedHostname>()?;

            let ep = Endpoint {
                workload_uid: self.w.workload.uid.as_str().into(),
                port: ports.to_owned(),
                status: HealthStatus::Healthy,
            };
            let mut svc = self.manager.services.get(&service_name).unwrap().clone();
            svc.endpoints
                .insert(self.w.workload.uid.clone(), ep.clone());
        }

        info!("registered {}", &self.w.workload.uid);
        let wli = WorkloadInfo {
            name: self.w.workload.name.to_string(),
            namespace: self.w.workload.namespace.to_string(),
            service_account: self.w.workload.service_account.to_string(),
        };
        self.manager.workloads.push(self.w);
        if self.captured {
            // Setup redirection
            let zt_info = self.manager.ztunnels.get_mut(node.as_str()).unwrap();
            if self.manager.mode == Shared {
                // In the new pod network
                network_namespace
                    .netns()
                    .run(|_| helpers::run_command("scripts/ztunnel-redirect-inpod.sh"))??;
                let fd = network_namespace.netns().file().as_raw_fd();
                let msg = inpod::Message::Start(inpod::StartZtunnelMessage {
                    uid: uid.to_string(),
                    workload_info: Some(wli),
                    fd,
                });
                zt_info
                    .fd_sender
                    .as_mut()
                    .unwrap()
                    .send_and_wait(msg)
                    .await?;
            }
        }
        self.manager.refresh_config().await?;
        Ok(network_namespace)
    }
}
