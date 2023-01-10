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

use std::net::IpAddr;
use std::time::Duration;

use bytes::BufMut;
use itertools::Itertools;
use tracing::info;

use crate::config::ConfigSource;
use crate::test_helpers::app::TestApp;
use crate::test_helpers::netns::{Namespace, Resolver};
use crate::test_helpers::*;
use crate::workload::{LocalConfig, LocalWorkload, Workload};
use crate::{config, identity, proxy};

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
                vips: Default::default(),
            },
            manager,
        }
    }

    pub fn hbone(mut self) -> Self {
        self.w.workload.protocol = HBONE;
        self
    }

    pub fn waypoint(mut self, waypoint: IpAddr) -> Self {
        self.w.workload.waypoint_addresses.push(waypoint);
        self
    }

    pub fn vip(mut self, ip: &str, server_port: u16, target_port: u16) -> Self {
        self.w
            .vips
            .entry(ip.to_string())
            .or_default()
            .insert(server_port, target_port);
        self
    }

    pub fn on_local_node(mut self) -> Self {
        self.w.workload.node = "local".to_string();
        self
    }

    pub fn uncaptured(mut self) -> Self {
        self.captured = false;
        self
    }

    pub fn register(mut self) -> anyhow::Result<Namespace> {
        let network_namespace = self.manager.namespaces.child(&self.w.workload.name)?;
        self.w.workload.workload_ip = network_namespace.ip();
        info!(
            "registered {}/{} at {}",
            self.w.workload.namespace, self.w.workload.name, self.w.workload.workload_ip
        );
        self.manager.workloads.push(self.w);
        if self.captured {
            self.manager.captured_workloads.push(network_namespace.ip());
        }
        Ok(network_namespace)
    }
}

pub struct WorkloadManager {
    namespaces: netns::NamespaceManager,
    /// workloads that we have constructed
    workloads: Vec<LocalWorkload>,
    captured_workloads: Vec<IpAddr>,
    waypoints: Vec<IpAddr>,
}

impl WorkloadManager {
    pub fn new(name: &str) -> anyhow::Result<Self> {
        Ok(Self {
            namespaces: netns::NamespaceManager::new(name)?,
            workloads: vec![],
            captured_workloads: vec![],
            waypoints: vec![],
        })
    }

    pub fn deploy_ztunnel(&mut self) -> anyhow::Result<TestApp> {
        let ns = TestWorkloadBuilder::new("ztunnel", self).register()?;
        let ip = ns.ip();
        let veth = ns.interface();
        let _count = self.namespaces.count();
        let lc = LocalConfig {
            workloads: self.workloads.clone(),
            policies: vec![],
        };
        let mut b = bytes::BytesMut::new().writer();
        serde_yaml::to_writer(&mut b, &lc)?;

        let cfg = crate::config::Config {
            xds_address: None,
            fake_ca: true,
            local_xds_config: Some(ConfigSource::Static(b.into_inner().freeze())),
            local_node: Some("local".to_string()),
            ..config::parse_config().unwrap()
        };
        let waypoints = self.waypoints.iter().map(|i| i.to_string()).join(" ");
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        // Setup the ztunnel...
        ns.run_ready(move |ready| async move {
            helpers::run_command(&format!("scripts/ztunnel-redirect.sh {ip} {waypoints}"))?;
            let cert_manager = identity::mock::MockCaClient::new(Duration::from_secs(10));
            let app = crate::app::build_with_cert(cfg, cert_manager.clone()).await?;

            let ta = TestApp {
                admin_address: helpers::with_ip(app.admin_address, ip),
                proxy_addresses: proxy::Addresses {
                    outbound: helpers::with_ip(app.proxy_addresses.outbound, ip),
                    inbound: helpers::with_ip(app.proxy_addresses.inbound, ip),
                    socks5: helpers::with_ip(app.proxy_addresses.socks5, ip),
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
            .iter()
            .map(|i| i.to_string())
            .join(" ");
        self.namespaces.run_in_root_namespace(|| {
            helpers::run_command(&format!("scripts/node-redirect.sh {ip} {veth} {captured}"))
        })?;
        Ok(rx.recv()?)
    }

    pub fn workload_builder(&mut self, name: &str) -> TestWorkloadBuilder {
        TestWorkloadBuilder::new(name, self)
    }

    pub fn register_waypoint(&mut self, name: &str) -> anyhow::Result<Namespace> {
        let ns = TestWorkloadBuilder::new(name, self).hbone().register()?;
        self.waypoints.push(ns.ip());
        Ok(ns)
    }

    pub fn resolver(&self) -> Resolver {
        self.namespaces.resolver()
    }

    pub fn resolve(&self, name: &str) -> Option<IpAddr> {
        self.namespaces.resolve(name)
    }
}
// TODO: all threads must terminate... somehow.
