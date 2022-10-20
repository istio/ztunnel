use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::{fmt, net};

use futures::future::TryFutureExt;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use xds::istio::workload::Workload as XdsWorkload;

use crate::workload::WorkloadError::ProtocolParse;
use crate::xds::{HandlerContext, XdsUpdate};
use crate::{config, xds};

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum Protocol {
    Tcp,
    Hbone,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Tcp
    }
}

impl TryFrom<Option<xds::istio::workload::Protocol>> for Protocol {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::workload::Protocol>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::workload::Protocol::Http) => Ok(Protocol::Hbone),
            Some(xds::istio::workload::Protocol::Direct) => Ok(Protocol::Hbone),
            None => Err(ProtocolParse("unknown type".into())),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub workload_ip: IpAddr,
    #[serde(default)]
    pub waypoint_address: Option<IpAddr>,
    #[serde(default)]
    pub gateway_ip: Option<SocketAddr>,
    #[serde(default)]
    pub protocol: Protocol,

    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,

    #[serde(default)]
    pub node: String,

    #[serde(default)]
    pub native_hbone: bool,
}

impl Workload {
    fn resource_name(&self) -> String {
        self.name.to_owned() + "/" + self.namespace.as_str()
    }
}

impl fmt::Display for Workload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Workload{{{} at {} via {} ({:?})}}",
            self.name,
            self.workload_ip,
            self.gateway_ip
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
                .gateway_ip
                .map(|x| format!("{}", x))
                .unwrap_or_else(|| "None".into()),
            self.workload.protocol
        )
    }
}

fn byte_to_ip(b: bytes::Bytes) -> Result<Option<IpAddr>, WorkloadError> {
    Ok(match b.len() {
        0 => None,
        4 => {
            let v: [u8; 4] = (&*b).try_into().expect("size already proven");
            Some(IpAddr::V4(Ipv4Addr::from(v)))
        }
        16 => {
            let v: [u8; 16] = (&*b).try_into().expect("size already proven");
            Some(IpAddr::V6(Ipv6Addr::from(v)))
        }
        n => return Err(WorkloadError::ByteAddressParse(n)),
    })
}

impl TryFrom<&XdsWorkload> for Workload {
    type Error = WorkloadError;
    fn try_from(resource: &XdsWorkload) -> Result<Self, Self::Error> {
        let waypoint = byte_to_ip(resource.waypoint_address.clone())?;
        let address =
            byte_to_ip(resource.address.clone())?.ok_or(WorkloadError::ByteAddressParse(0))?;
        // TODO can we borrow instead of clone everywhere?
        Ok(Workload {
            workload_ip: address,
            waypoint_address: waypoint,
            gateway_ip: None,

            protocol: Protocol::try_from(xds::istio::workload::Protocol::from_i32(
                resource.protocol,
            ))?,

            name: resource.name.clone(),
            namespace: resource.namespace.clone(),
            node: resource.node.clone(),

            native_hbone: resource.native_hbone,
        })
    }
}

pub struct WorkloadManager {
    workloads: Arc<Mutex<WorkloadInformation>>,
    xds_client: xds::AdsClient,
    local_client: LocalClient,
}

fn handle_xds<F: FnOnce() -> anyhow::Result<()>>(ctx: &mut HandlerContext, name: String, f: F) {
    debug!("handling update {}", name);
    let result: anyhow::Result<()> = f();
    if let Err(e) = result {
        warn!("rejecting workload {name}: {e}");
        ctx.reject(name, e)
    }
}

impl xds::Handler<XdsWorkload> for Arc<Mutex<WorkloadInformation>> {
    fn handle(&self, ctx: &mut HandlerContext, updates: Vec<XdsUpdate<XdsWorkload>>) {
        let mut wli = self.lock().unwrap();
        for res in updates {
            let name = res.name();
            handle_xds(ctx, name, || {
                match res {
                    XdsUpdate::Update(w) => {
                        let workload = Workload::try_from(&w.resource)?;
                        // TODO: we process each item on its own, this may lead to heavy lock contention.
                        // Need batch updates?
                        wli.insert(workload.clone());
                        for (vip, pl) in &w.resource.virtual_ips {
                            let ip = vip.parse::<IpAddr>()?;
                            for port in &pl.ports {
                                let addr = SocketAddr::from((ip, port.service_port as u16));
                                let us = Upstream {
                                    workload: workload.clone(), // TODO avoid clones
                                    port: port.target_port as u16,
                                };
                                wli.vips.entry(addr).or_default().insert(us);
                            }
                        }
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
    pub fn new(config: config::Config) -> WorkloadManager {
        let workloads: Arc<Mutex<WorkloadInformation>> = Default::default();
        let xds_workloads = workloads.clone();
        let xds_client = xds::Config::new()
            .with_workload_handler(xds_workloads)
            .watch(xds::WORKLOAD_TYPE.into())
            .build();
        let local_workloads = workloads.clone();
        let local_client = LocalClient {
            path: config.local_xds_path,
            workloads: local_workloads,
        };
        WorkloadManager {
            xds_client,
            workloads,
            local_client,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        tokio::try_join!(
            self.xds_client.run().map_err(|e| anyhow::anyhow!(e)),
            self.local_client.run()
        )?;
        Ok(())
    }

    pub fn workloads(&self) -> Arc<Mutex<WorkloadInformation>> {
        self.workloads.clone()
    }
}

/// LocalClient serves as a local file reader alternative for XDS. This is intended for testing.
struct LocalClient {
    path: Option<String>,
    workloads: Arc<Mutex<WorkloadInformation>>,
}

impl LocalClient {
    async fn run(self) -> Result<(), anyhow::Error> {
        let path = match self.path {
            Some(p) => p,
            None => return Ok(()),
        };
        info!("running local client");
        // Currently, we just load the file once. In the future, we could dynamically reload.
        let data = tokio::fs::read_to_string(path).await?;
        let r: Vec<Workload> = serde_yaml::from_str(&data)?;
        let mut wli = self.workloads.lock().unwrap();
        for wl in r {
            info!("inserting local workloads {wl}");
            wli.insert(wl);
        }
        Ok(())
    }
}

#[derive(serde::Serialize, Default)]
/// A WorkloadInformation encapsulates all information about workloads in the mesh
pub struct WorkloadInformation {
    workloads: HashMap<IpAddr, Workload>,
    name_index: HashMap<String, IpAddr>,
    vips: HashMap<SocketAddr, HashSet<Upstream>>,
}

impl WorkloadInformation {
    fn insert(&mut self, w: Workload) {
        let wip = w.workload_ip;
        let wname = w.resource_name();
        self.workloads.insert(wip, w);
        self.name_index.insert(wname, wip);
    }

    fn remove(&mut self, name: String) {
        if let Some(ip) = self.name_index.remove(&name) {
            if let Some(_workload) = self.workloads.remove(&ip) {
                // TODO: store VIPs in workload so we can remove them
            } else {
                panic!(
                    "removed name {} with ip {}, but was not found in workload map",
                    name, ip
                )
            }
        }
    }

    pub fn find_workload(&self, addr: &IpAddr) -> Option<&Workload> {
        self.workloads.get(addr)
    }

    pub fn find_upstream(&self, addr: SocketAddr) -> (Upstream, bool) {
        if let Some(upstream) = self.vips.get(&addr) {
            let us: &Upstream = upstream.iter().next().unwrap();
            // TODO: avoid clone
            let mut us: Upstream = us.clone();
            Self::set_gateway_ip(&mut us);
            debug!("found upstream from VIP: {}", us);
            return (us, true);
        }
        if let Some(wl) = self.workloads.get(&addr.ip()) {
            let mut us = Upstream {
                workload: wl.clone(),
                port: addr.port(),
            };
            Self::set_gateway_ip(&mut us);
            debug!("found upstream: {}", us);
            return (us, false);
        }
        (
            Upstream {
                port: addr.port(),
                workload: Workload {
                    workload_ip: addr.ip(),
                    waypoint_address: None,
                    gateway_ip: Some(addr),
                    protocol: Protocol::Tcp,

                    name: "".to_string(),
                    namespace: "".to_string(),
                    node: "".to_string(),

                    native_hbone: false,
                },
            },
            false,
        )
    }

    fn set_gateway_ip(us: &mut Upstream) {
        let mut ip = us.workload.workload_ip;
        if us.workload.waypoint_address.is_some() {
            ip = us.workload.waypoint_address.unwrap();
        }
        if us.workload.gateway_ip.is_none() {
            us.workload.gateway_ip = Some(match us.workload.protocol {
                Protocol::Hbone => SocketAddr::from((ip, 15008)),
                Protocol::Tcp => SocketAddr::from((us.workload.workload_ip, us.port)),
            });
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug)]
pub enum WorkloadError {
    #[error("failed to parse address: {0}")]
    AddressParse(#[from] net::AddrParseError),
    #[error("failed to parse address, had {0} bytes")]
    ByteAddressParse(usize),
    #[error("unknown protocol {0}")]
    ProtocolParse(String),
}
