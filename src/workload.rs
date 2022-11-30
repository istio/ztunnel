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

use std::collections::{HashMap, HashSet};
use std::convert::Into;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::{fmt, net};

use prometheus_client::registry::Registry;
use rand::prelude::IteratorRandom;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use xds::istio::workload::Workload as XdsWorkload;

use crate::identity::Identity;
use crate::workload::WorkloadError::ProtocolParse;
use crate::xds::{AdsClient, Demander, HandlerContext, XdsUpdate};
use crate::{admin, config, xds};

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum Protocol {
    TCP,
    HBONE,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::TCP
    }
}

impl TryFrom<Option<xds::istio::workload::Protocol>> for Protocol {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::workload::Protocol>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::workload::Protocol::Http) => Ok(Protocol::HBONE),
            Some(xds::istio::workload::Protocol::Direct) => Ok(Protocol::TCP),
            None => Err(ProtocolParse("unknown type".into())),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workload {
    pub workload_ip: IpAddr,
    #[serde(default)]
    pub waypoint_addresses: Vec<IpAddr>,
    #[serde(default)]
    pub gateway_address: Option<SocketAddr>,
    #[serde(default)]
    pub protocol: Protocol,

    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub service_account: String,

    #[serde(default)]
    pub workload_name: String,
    #[serde(default)]
    pub workload_type: String,
    #[serde(default)]
    pub canonical_name: String,
    #[serde(default)]
    pub canonical_revision: String,

    #[serde(default)]
    pub node: String,

    #[serde(default)]
    pub native_hbone: bool,
}

impl Workload {
    pub fn identity(&self) -> Identity {
        Identity::Spiffe {
            /// TODO: don't hardcode
            trust_domain: "cluster.local".to_string(),
            namespace: self.namespace.clone(),
            service_account: self.service_account.clone(),
        }
    }
    pub fn choose_waypoint_address(&self) -> Option<IpAddr> {
        self.waypoint_addresses
            .iter()
            .choose(&mut rand::thread_rng())
            .copied()
    }
}

impl fmt::Display for Workload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Workload{{{} at {} via {} ({:?})}}",
            self.name,
            self.workload_ip,
            self.gateway_address
                .map(|x| format!("{}", x))
                .unwrap_or_else(|| "None".into()),
            self.protocol
        )
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize)]
pub struct Upstream {
    pub workload: Workload,
    pub port: u16,
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Upstream{{{} at {}:{} via {} ({:?})}}",
            self.workload.name,
            self.workload.workload_ip,
            self.port,
            self.workload
                .gateway_address
                .map(|x| format!("{}", x))
                .unwrap_or_else(|| "None".into()),
            self.workload.protocol
        )
    }
}

fn byte_to_ip(b: &bytes::Bytes) -> Result<IpAddr, WorkloadError> {
    match b.len() {
        0 => Err(WorkloadError::ByteAddressParse(0)),
        4 => {
            let v: [u8; 4] = b.deref().try_into().expect("size already proven");
            Ok(IpAddr::from(v))
        }
        16 => {
            let v: [u8; 16] = b.deref().try_into().expect("size already proven");
            Ok(IpAddr::from(v))
        }
        n => Err(WorkloadError::ByteAddressParse(n)),
    }
}

impl TryFrom<&XdsWorkload> for Workload {
    type Error = WorkloadError;
    fn try_from(resource: &XdsWorkload) -> Result<Self, Self::Error> {
        let resource: XdsWorkload = resource.to_owned();

        let mut waypoint_addresses: Vec<IpAddr> = Vec::new();
        for addr in &resource.waypoint_addresses {
            waypoint_addresses.push(byte_to_ip(addr)?)
        }
        let address = byte_to_ip(&resource.address)?;
        let workload_type = resource.workload_type().as_str_name().to_lowercase();
        Ok(Workload {
            workload_ip: address,
            waypoint_addresses,
            gateway_address: None,

            protocol: Protocol::try_from(xds::istio::workload::Protocol::from_i32(
                resource.protocol,
            ))?,

            name: resource.name,
            namespace: resource.namespace,
            service_account: {
                let result = resource.service_account;
                if result.is_empty() {
                    "default".into()
                } else {
                    result
                }
            },
            node: resource.node,

            workload_name: resource.workload_name,
            workload_type,
            canonical_name: resource.canonical_name,
            canonical_revision: resource.canonical_revision,

            native_hbone: resource.native_hbone,
        })
    }
}

pub struct WorkloadManager {
    workloads: WorkloadInformation,
    xds_client: Option<xds::AdsClient>,
}

fn handle_xds<F: FnOnce() -> anyhow::Result<()>>(ctx: &mut HandlerContext, name: String, f: F) {
    debug!("handling update {}", name);
    let result: anyhow::Result<()> = f();
    if let Err(e) = result {
        warn!("rejecting workload {name}: {e}");
        ctx.reject(name, e)
    }
}

impl xds::Handler<XdsWorkload> for Arc<Mutex<WorkloadStore>> {
    fn handle(&self, ctx: &mut HandlerContext, updates: Vec<XdsUpdate<XdsWorkload>>) {
        let mut wli = self.lock().unwrap();
        for res in updates {
            let name = res.name();
            handle_xds(ctx, name, || {
                match res {
                    XdsUpdate::Update(w) => {
                        // TODO: we process each item on its own, this may lead to heavy lock contention.
                        // Need batch updates?
                        wli.insert_xds_workload(w.resource)?
                    }
                    XdsUpdate::Remove(name) => {
                        info!("handling delete {}", name);
                        wli.remove(name);
                    }
                }
                Ok(())
            });
        }
    }
}

impl WorkloadManager {
    pub async fn new(
        config: config::Config,
        registry: &mut Registry,
        awaiting_ready: admin::BlockReady,
    ) -> anyhow::Result<WorkloadManager> {
        let workloads: Arc<Mutex<WorkloadStore>> = Arc::new(Mutex::new(WorkloadStore::default()));
        let xds_workloads = workloads.clone();
        let xds_client = if config.xds_address.is_some() {
            Some(
                xds::Config::new(config.clone())
                    .with_workload_handler(xds_workloads)
                    .watch(xds::WORKLOAD_TYPE.into())
                    .build(registry, awaiting_ready.subtask("ads client")),
            )
        } else {
            None
        };
        if let Some(path) = config.local_xds_path {
            let local_client = LocalClient {
                path,
                workloads: workloads.clone(),
            };
            local_client.run().await?;
        }
        let demand = xds_client.as_ref().and_then(AdsClient::demander);
        let workloads = WorkloadInformation {
            info: workloads,
            demand,
        };
        Ok(WorkloadManager {
            xds_client,
            workloads,
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        match self.xds_client {
            Some(xds) => xds.run().await.map_err(|e| anyhow::anyhow!(e)),
            None => Ok(()),
        }
    }

    pub fn workloads(&self) -> WorkloadInformation {
        self.workloads.clone()
    }
}

/// LocalClient serves as a local file reader alternative for XDS. This is intended for testing.
struct LocalClient {
    path: String,
    workloads: Arc<Mutex<WorkloadStore>>,
}

impl LocalClient {
    async fn run(self) -> Result<(), anyhow::Error> {
        info!("running local client");
        // Currently, we just load the file once. In the future, we could dynamically reload.
        let data = tokio::fs::read_to_string(self.path).await?;
        let r: Vec<Workload> = serde_yaml::from_str(&data)?;
        let mut wli = self.workloads.lock().unwrap();
        for wl in r {
            info!("inserting local workloads {wl}");
            wli.insert(wl);
        }
        Ok(())
    }
}

/// WorkloadInformation wraps WorkloadStore, but is able to additionally request resources on-demand.
/// It is designed to be cheap to clone.
#[derive(serde::Serialize, Debug, Clone)]
pub struct WorkloadInformation {
    #[serde(flatten)]
    pub info: Arc<Mutex<WorkloadStore>>,

    /// demand, if present, is used to request on-demand updates for workloads.
    #[serde(skip_serializing)]
    pub demand: Option<Demander>,
}

impl WorkloadInformation {
    pub async fn fetch_workload(&self, addr: &IpAddr) -> Option<Workload> {
        // Wait for it on-demand, *if* needed
        debug!("lookup workload for {addr}");
        match self.find_workload(addr) {
            None => {
                if let Some(demand) = &self.demand {
                    info!("workload not found, sending on-demand request for {addr}");
                    demand.demand(addr.to_string()).await.recv().await;
                    debug!("on demand ready: {addr}");
                    self.find_workload(addr)
                } else {
                    None
                }
            }
            wl @ Some(_) => wl,
        }
    }

    pub fn find_workload(&self, addr: &IpAddr) -> Option<Workload> {
        let wi = self.info.lock().unwrap();
        wi.find_workload(addr).cloned()
    }

    pub async fn find_upstream(&self, addr: SocketAddr, hbone_port: u16) -> Option<Upstream> {
        let _ = self.fetch_workload(&addr.ip()).await;
        let wi = self.info.lock().unwrap();
        wi.find_upstream(addr, hbone_port)
    }
}

/// A WorkloadStore encapsulates all information about workloads in the mesh
#[derive(serde::Serialize, Default, Debug)]
pub struct WorkloadStore {
    workloads: HashMap<IpAddr, Workload>,
    // workload_to_vip maintains a mapping of workload IP to VIP. This is used only to handle removals.
    workload_to_vip: HashMap<IpAddr, HashSet<(SocketAddr, u16)>>,
    // vips maintains a mapping of socket address with service port to workload ip and socket address
    // with target ports in hashset.
    vips: HashMap<SocketAddr, HashSet<(IpAddr, u16)>>,
}

impl WorkloadStore {
    #[cfg(test)]
    pub fn test_store(workloads: Vec<XdsWorkload>) -> anyhow::Result<WorkloadStore> {
        let mut store = WorkloadStore::default();
        for w in workloads {
            store.insert_xds_workload(w)?;
        }
        Ok(store)
    }

    fn insert_xds_workload(&mut self, w: XdsWorkload) -> anyhow::Result<()> {
        let workload = Workload::try_from(&w)?;
        let wip = workload.workload_ip;
        self.insert(workload);
        for (vip, pl) in &w.virtual_ips {
            let ip = vip.parse::<IpAddr>()?;
            for port in &pl.ports {
                let service_sock_addr = SocketAddr::from((ip, port.service_port as u16));
                self.vips
                    .entry(service_sock_addr)
                    .or_default()
                    .insert((wip, port.target_port as u16));
                self.workload_to_vip
                    .entry(wip)
                    .or_default()
                    .insert((service_sock_addr, port.target_port as u16));
            }
        }
        Ok(())
    }

    fn insert(&mut self, w: Workload) {
        let wip = w.workload_ip;
        self.workloads.insert(wip, w);
    }

    fn remove(&mut self, ip: String) {
        use std::str::FromStr;
        let ip: IpAddr = match IpAddr::from_str(&ip) {
            Err(e) => {
                error!("received invalid resource removal {}, ignoring: {}", ip, e);
                return;
            }
            Ok(i) => i,
        };
        if let Some(prev) = self.workloads.remove(&ip) {
            if let Some(vips) = self.workload_to_vip.remove(&prev.workload_ip) {
                for (vip, target_port) in vips {
                    if let Some(wls) = self.vips.get_mut(&vip) {
                        let vip_hash_entry = (prev.workload_ip, target_port);
                        wls.remove(&vip_hash_entry);
                        if wls.is_empty() {
                            self.vips.remove(&vip);
                        }
                    }
                }
            }
        }
    }

    fn find_workload(&self, addr: &IpAddr) -> Option<&Workload> {
        self.workloads.get(addr)
    }

    fn find_upstream(&self, addr: SocketAddr, hbone_port: u16) -> Option<Upstream> {
        if let Some(wl_vips) = self.vips.get(&addr) {
            // Randomly pick an upstream
            // TODO: do this more efficiently, and not just randomly
            let (workload_ip, target_port) =
                wl_vips.iter().choose(&mut rand::thread_rng()).unwrap();
            if let Some(wl) = self.workloads.get(workload_ip) {
                let mut us = Upstream {
                    workload: wl.clone(),
                    port: *target_port,
                };
                Self::set_gateway_address(&mut us, hbone_port);
                debug!("found upstream from VIP: {}", us);
                return Some(us);
            }
        }
        if let Some(wl) = self.workloads.get(&addr.ip()) {
            let mut us = Upstream {
                workload: wl.clone(),
                port: addr.port(),
            };
            Self::set_gateway_address(&mut us, hbone_port);
            debug!("found upstream: {}", us);
            return Some(us);
        }
        None
    }

    fn set_gateway_address(us: &mut Upstream, hbone_port: u16) {
        if us.workload.gateway_address.is_none() {
            us.workload.gateway_address = Some(match us.workload.protocol {
                Protocol::HBONE => {
                    let ip = us
                        .workload
                        .choose_waypoint_address()
                        .unwrap_or(us.workload.workload_ip);
                    SocketAddr::from((ip, hbone_port))
                }
                Protocol::TCP => SocketAddr::from((us.workload.workload_ip, us.port)),
            });
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum WorkloadError {
    #[error("failed to parse address: {0}")]
    AddressParse(#[from] net::AddrParseError),
    #[error("failed to parse address, had {0} bytes")]
    ByteAddressParse(usize),
    #[error("unknown protocol {0}")]
    ProtocolParse(String),
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use crate::xds::istio::workload::Port as XdsPort;
    use crate::xds::istio::workload::PortList as XdsPortList;

    use super::*;

    #[test]
    fn byte_to_ipaddr_garbage() {
        let garbage = "not_an_ip";
        let bytes = Bytes::from(garbage);
        let result = byte_to_ip(&bytes);
        assert!(result.is_err());
        let actual_error: WorkloadError = result.unwrap_err();
        let expected_error = WorkloadError::ByteAddressParse(garbage.len());
        assert_eq!(actual_error, expected_error);
    }

    #[test]
    fn byte_to_ipaddr_empty() {
        let empty = "";
        let bytes = Bytes::from(empty);
        let result = byte_to_ip(&bytes);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), WorkloadError::ByteAddressParse(0));
    }

    #[test]
    fn byte_to_ipaddr_unspecified() {
        let unspecified: Vec<u8> = Ipv4Addr::UNSPECIFIED.octets().to_vec();
        let bytes = Bytes::from(unspecified);
        let result = byte_to_ip(&bytes);
        assert!(result.is_ok());
        let ip_addr = result.unwrap();
        assert!(ip_addr.is_unspecified(), "was not unspecified")
    }

    #[test]
    fn byte_to_ipaddr_v4_loopback() {
        let loopback: Vec<u8> = Ipv4Addr::LOCALHOST.octets().to_vec();
        let bytes = Bytes::from(loopback);
        let result = byte_to_ip(&bytes);
        assert!(result.is_ok());
        let maybe_loopback_ip = result.unwrap();
        assert_eq!(maybe_loopback_ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn byte_to_ipaddr_v4_happy() {
        let addr_vec: Vec<u8> = Vec::from([1, 1, 1, 1]);
        let bytes = &Bytes::from(addr_vec);
        let result = byte_to_ip(bytes);
        assert!(result.is_ok());
        let ip_addr = result.unwrap();
        assert!(ip_addr.is_ipv4(), "was not ipv4");
        assert!(!ip_addr.is_ipv6(), "was ipv6");
        assert!(!ip_addr.is_unspecified(), "was unspecified");
        assert_eq!(ip_addr.to_string(), "1.1.1.1");
    }

    #[test]
    fn byte_to_ipaddr_v6_happy() {
        let addr: Vec<u8> = Vec::from([
            32, 1, 13, 184, 133, 163, 0, 0, 0, 0, 138, 46, 3, 112, 115, 52,
        ]);
        let bytes = &Bytes::from(addr);
        let result = byte_to_ip(bytes);
        assert!(result.is_ok());
        let ip_addr = result.unwrap();
        assert!(ip_addr.is_ipv6(), "was not ipv6");
        assert!(!ip_addr.is_ipv4(), "was ipv4");
        assert!(!ip_addr.is_unspecified());
        assert_eq!(ip_addr.to_string(), "2001:db8:85a3::8a2e:370:7334");
    }

    #[test]
    fn byte_to_ipaddr_v6_loopback() {
        let addr_vec: Vec<u8> = Ipv6Addr::LOCALHOST.octets().to_vec();
        let bytes = &Bytes::from(addr_vec);
        let result = byte_to_ip(bytes);
        assert!(result.is_ok());
        let maybe_loopback_ip = result.unwrap();
        assert_eq!(maybe_loopback_ip.to_string(), "::1");
    }

    #[test]
    fn workload_information() {
        let default = Workload {
            workload_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            waypoint_addresses: Vec::new(),
            gateway_address: None,
            protocol: Default::default(),
            name: "".to_string(),
            namespace: "".to_string(),
            service_account: "default".to_string(),
            workload_name: "".to_string(),
            workload_type: "deployment".to_string(),
            canonical_name: "".to_string(),
            canonical_revision: "".to_string(),
            node: "".to_string(),

            native_hbone: false,
        };
        let mut wi = WorkloadStore::default();
        assert_eq!((wi.workloads.len()), 0);
        assert_eq!((wi.vips.len()), 0);

        let xds_ip1 = Bytes::copy_from_slice(&[127, 0, 0, 1]);
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let xds_ip2 = Bytes::copy_from_slice(&[127, 0, 0, 2]);

        wi.insert_xds_workload(XdsWorkload {
            address: xds_ip1.clone(),
            name: "some name".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((wi.workloads.len()), 1);
        assert_eq!(
            wi.find_workload(&ip1),
            Some(&Workload {
                workload_ip: ip1,
                name: "some name".to_string(),
                ..default.clone()
            })
        );

        wi.remove("invalid".to_string());
        assert_eq!(
            wi.find_workload(&ip1),
            Some(&Workload {
                workload_ip: ip1,
                name: "some name".to_string(),
                ..default.clone()
            })
        );

        wi.remove("127.0.0.2".to_string());
        assert_eq!(
            wi.find_workload(&ip1),
            Some(&Workload {
                workload_ip: ip1,
                name: "some name".to_string(),
                ..default
            })
        );

        wi.remove("127.0.0.1".to_string());
        assert_eq!(wi.find_workload(&ip1), None);
        assert_eq!(wi.workloads.len(), 0);

        // Add two workloads into the VIP
        wi.insert_xds_workload(XdsWorkload {
            address: xds_ip1,
            name: "some name".to_string(),
            virtual_ips: HashMap::from([(
                "127.0.1.1".to_string(),
                XdsPortList {
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            ..Default::default()
        })
        .unwrap();
        wi.insert_xds_workload(XdsWorkload {
            address: xds_ip2,
            name: "some name2".to_string(),
            virtual_ips: HashMap::from([(
                "127.0.1.1".to_string(),
                XdsPortList {
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            ..Default::default()
        })
        .unwrap();

        assert_vips(&wi, vec!["some name", "some name2"]);
        wi.remove("127.0.0.2".to_string());
        assert_vips(&wi, vec!["some name"]);
        wi.remove("127.0.0.1".to_string());
        assert_vips(&wi, vec![]);
    }

    #[track_caller]
    fn assert_vips(wi: &WorkloadStore, want: Vec<&str>) {
        let mut wants: HashSet<String> = HashSet::from_iter(want.iter().map(|x| x.to_string()));
        let mut found: HashSet<String> = HashSet::new();
        // VIP has randomness. We will try to fetch the VIP 1k times and assert the we got the expected results
        // at least once, and no unexpected results
        for _ in 0..1000 {
            if let Some(us) = wi.find_upstream("127.0.1.1:80".parse().unwrap(), 15008) {
                let n = us.workload.name.clone();
                found.insert(n.clone());
                wants.remove(&n);
            }
        }
        if !wants.is_empty() {
            panic!("expected all names to be found, but missed {want:?} (found {found:?})");
        }
        if found.len() != want.len() {
            panic!("found unexpected items: {found:?}");
        }
    }

    #[tokio::test]
    async fn local_client() {
        let dir = std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
            .join("examples")
            .join("localhost.yaml")
            .to_str()
            .unwrap()
            .to_string();
        let workloads: Arc<Mutex<WorkloadStore>> = Arc::new(Mutex::new(WorkloadStore::default()));

        let local_client = LocalClient {
            path: dir,
            workloads: workloads.clone(),
        };
        local_client.run().await.expect("client should run");
        let store = workloads.lock().unwrap();
        let wl = store.find_workload(&"127.0.0.1".parse().unwrap());
        // Make sure we get a valid workload
        assert!(wl.is_some());
        assert_eq!(wl.unwrap().service_account, "default");
    }
}
