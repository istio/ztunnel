use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::{fmt, net};

use thiserror::Error;
use tracing::{debug, error, info};

use xds::istio::workload::Workload as XdsWorkload;

use crate::workload::WorkloadError::ProtocolParseError;
use crate::xds;
use crate::xds::{HandlerContext, XdsUpdate};

#[derive(Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize)]
pub enum Protocol {
    Hbone,
    Tcp,
}

impl TryFrom<Option<xds::istio::workload::Protocol>> for Protocol {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::workload::Protocol>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::workload::Protocol::Http2connect) => Ok(Protocol::Hbone),
            Some(xds::istio::workload::Protocol::Direct) => Ok(Protocol::Hbone),
            None => Err(ProtocolParseError("unknown type".into())),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize)]
pub struct Workload {
    pub workload_ip: IpAddr,
    pub remote_proxy: Option<IpAddr>,
    pub gateway_ip: Option<SocketAddr>,
    pub identity: String,
    // TODO: optional?
    pub protocol: Protocol,

    pub name: String,
    pub namespace: String,
    pub canonical_name: String,
    pub canonical_revision: String,
    pub workload_type: String,
    pub workload_name: String,
    pub uid: String,
    pub node: String,

    pub enforce: bool,
    pub native_hbone: bool,
    // RBAC:        *uproxyapi.Authorization,
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
            "Workload{{{}{} at {} via {} ({:?})}}",
            self.name,
            self.identity,
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
            "Upstream{{{}{} at {}:{} via {} ({:?})}}",
            self.workload.name,
            self.workload.identity,
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

fn non_empty_string(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

impl TryFrom<&XdsWorkload> for Workload {
    type Error = WorkloadError;
    fn try_from(resource: &XdsWorkload) -> Result<Self, Self::Error> {
        let remote = non_empty_string(resource.remote_proxy.as_str())
            .map(|r| r.parse::<IpAddr>())
            .transpose()?;
        // TODO can we borrow instead of clone everywhere?
        Ok(Workload {
            workload_ip: resource.address.parse::<IpAddr>()?,
            remote_proxy: remote,
            gateway_ip: None,

            identity: resource.identity.clone(),
            protocol: Protocol::try_from(xds::istio::workload::Protocol::from_i32(
                resource.protocol,
            ))?,

            name: resource.name.clone(),
            namespace: resource.namespace.clone(),
            canonical_name: resource.canonical_name.clone(),
            canonical_revision: resource.canonical_revision.clone(),
            workload_type: resource.workload_type.clone(),
            workload_name: resource.workload_name.clone(),
            uid: resource.uid.clone(),
            node: resource.node.clone(),

            enforce: resource.enforce,
            native_hbone: resource.native_hbone,
        })
    }
}

pub struct WorkloadManager {
    pub workloads: Arc<Mutex<WorkloadInformation>>,
    pub xds_client: xds::AdsClient,
}

fn handle_xds<F: FnOnce() -> Result<(), anyhow::Error>>(
    ctx: &mut HandlerContext,
    name: String,
    f: F,
) {
    let result: Result<(), anyhow::Error> = f();
    if let Err(e) = result {
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
                        // TODO: use name
                        // info!("handling update {}", res.name);
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
    pub fn new() -> WorkloadManager {
        let workloads: Arc<Mutex<WorkloadInformation>> = Default::default();
        let xds_workloads = workloads.clone();
        let xds_client = xds::Config::new()
            .with_workload_handler(xds_workloads)
            .watch(xds::WORKLOAD_TYPE.into())
            .build();
        WorkloadManager {
            xds_client,
            workloads,
        }
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
                    remote_proxy: None,
                    gateway_ip: Some(addr),
                    identity: "".to_string(),
                    protocol: Protocol::Tcp,

                    name: "".to_string(),
                    namespace: "".to_string(),
                    canonical_name: "".to_string(),
                    canonical_revision: "".to_string(),
                    workload_type: "".to_string(),
                    workload_name: "".to_string(),
                    uid: "".to_string(),
                    node: "".to_string(),

                    enforce: false,
                    native_hbone: false,
                },
            },
            false,
        )
    }

    fn set_gateway_ip(us: &mut Upstream) {
        let mut ip = us.workload.workload_ip;
        if us.workload.remote_proxy.is_some() {
            ip = us.workload.remote_proxy.unwrap();
        }
        if us.workload.gateway_ip.is_none() {
            us.workload.gateway_ip = Some(match us.workload.protocol {
                Protocol::Hbone => SocketAddr::from((ip, 15008)),
                Protocol::Tcp => SocketAddr::from((us.workload.workload_ip, us.port)),
            });
        }
    }
}

#[derive(Error, Debug)]
pub enum WorkloadError {
    #[error("failed to parse address")]
    AddressParseError(#[from] net::AddrParseError),
    #[error("unknown protocol {0}")]
    ProtocolParseError(String),
}
