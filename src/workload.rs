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

use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::convert::Into;
use std::default::Default;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::{fmt, net};

use rand::prelude::IteratorRandom;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, trace};

use xds::istio::security::Authorization as XdsAuthorization;
use xds::istio::workload::address::Type as XdsType;
use xds::istio::workload::Address as XdsAddress;
use xds::istio::workload::GatewayAddress as XdsGatewayAddress;
use xds::istio::workload::Service as XdsService;
use xds::istio::workload::Workload as XdsWorkload;

use crate::config::{ConfigSource, ProxyMode};
use crate::identity::{Identity, SecretManager};
use crate::metrics::Metrics;
use crate::rbac::{Authorization, RbacScope};
use crate::workload::address::Address;
use crate::workload::WorkloadError::EnumParse;
use crate::xds::istio::workload::PortList;
use crate::xds::{AdsClient, Demander, RejectedConfig, XdsUpdate};
use crate::{config, rbac, readiness, xds};

#[derive(
    Default, Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
pub enum Protocol {
    #[default]
    TCP,
    HBONE,
}

impl TryFrom<Option<xds::istio::workload::TunnelProtocol>> for Protocol {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::workload::TunnelProtocol>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::workload::TunnelProtocol::Hbone) => Ok(Protocol::HBONE),
            Some(xds::istio::workload::TunnelProtocol::None) => Ok(Protocol::TCP),
            None => Err(EnumParse("unknown type".into())),
        }
    }
}

#[derive(
    Default, Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
pub enum HealthStatus {
    #[default]
    Healthy,
    Unhealthy,
}

impl TryFrom<Option<xds::istio::workload::WorkloadStatus>> for HealthStatus {
    type Error = WorkloadError;

    fn try_from(value: Option<xds::istio::workload::WorkloadStatus>) -> Result<Self, Self::Error> {
        match value {
            Some(xds::istio::workload::WorkloadStatus::Healthy) => Ok(HealthStatus::Healthy),
            Some(xds::istio::workload::WorkloadStatus::Unhealthy) => Ok(HealthStatus::Unhealthy),
            None => Err(EnumParse("unknown type".into())),
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayAddress {
    pub destination: gatewayaddress::Destination,
    pub port: u16,
}

pub mod gatewayaddress {
    use super::{NamespacedHostname, NetworkAddress};
    #[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "address", content = "content")]
    pub enum Destination {
        Hostname(NamespacedHostname),
        Address(NetworkAddress),
    }
}

pub mod address {
    use crate::workload::{Service, Workload};

    #[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
    #[serde(tag = "address", content = "content")]
    pub enum Address {
        Workload(Box<Workload>),
        Service(Box<Service>),
    }
}
#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workload {
    pub workload_ip: IpAddr,
    pub waypoint: Option<GatewayAddress>,
    pub network_gateway: Option<GatewayAddress>,
    #[serde(default)]
    pub gateway_address: Option<SocketAddr>,
    #[serde(default)]
    pub protocol: Protocol,

    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub trust_domain: String,
    #[serde(default)]
    pub service_account: String,
    #[serde(default)]
    pub network: String,

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
    pub native_tunnel: bool,

    #[serde(default)]
    pub authorization_policies: Vec<String>,

    #[serde(default)]
    pub status: HealthStatus,

    #[serde(default)]
    pub cluster_id: String,
}

impl Workload {
    pub fn identity(&self) -> Identity {
        Identity::Spiffe {
            trust_domain: self.trust_domain.to_string(),
            namespace: self.namespace.clone(),
            service_account: self.service_account.clone(),
        }
    }
    pub fn waypoint_svc_ip_address(&self) -> Result<Option<IpAddr>, WaypointError> {
        if let Some(gw_address) = self.waypoint.as_ref() {
            match &gw_address.destination {
                gatewayaddress::Destination::Hostname(_) => {
                    return Err(WaypointError::UnsupportedFeature(
                        "hostname lookup not supported yet".to_string(),
                    ))
                }
                gatewayaddress::Destination::Address(ip) => return Ok(Some(ip.address)),
            }
        }
        Ok(None)
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
                .map(|x| format!("{x}"))
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
                .map(|x| format!("{x}"))
                .unwrap_or_else(|| "None".into()),
            self.workload.protocol
        )
    }
}

pub fn byte_to_ip(b: &bytes::Bytes) -> Result<IpAddr, WorkloadError> {
    match b.len() {
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

impl From<&PortList> for HashMap<u16, u16> {
    fn from(value: &PortList) -> Self {
        value
            .ports
            .iter()
            .map(|p| (p.service_port as u16, p.target_port as u16))
            .collect()
    }
}

impl TryFrom<&XdsGatewayAddress> for GatewayAddress {
    type Error = WorkloadError;

    fn try_from(value: &xds::istio::workload::GatewayAddress) -> Result<Self, Self::Error> {
        let gw_addr: GatewayAddress = match &value.destination {
            Some(a) => match a {
                xds::istio::workload::gateway_address::Destination::Address(addr) => {
                    GatewayAddress {
                        destination: gatewayaddress::Destination::Address(network_addr(
                            &addr.network,
                            byte_to_ip(&Bytes::copy_from_slice(&addr.address))?,
                        )),
                        port: value.port as u16,
                    }
                }
                xds::istio::workload::gateway_address::Destination::Hostname(hn) => {
                    GatewayAddress {
                        destination: gatewayaddress::Destination::Hostname(NamespacedHostname {
                            namespace: hn.namespace.clone(),
                            hostname: hn.hostname.clone(),
                        }),
                        port: value.port as u16,
                    }
                }
            },
            None => return Err(WorkloadError::MissingGatewayAddress),
        };
        Ok(gw_addr)
    }
}

impl TryFrom<&XdsWorkload> for Workload {
    type Error = WorkloadError;
    fn try_from(resource: &XdsWorkload) -> Result<Self, Self::Error> {
        let resource: XdsWorkload = resource.to_owned();

        let wp = match &resource.waypoint {
            Some(w) => Some(GatewayAddress::try_from(w)?),
            None => None,
        };

        let network_gw = match &resource.network_gateway {
            Some(w) => Some(GatewayAddress::try_from(w)?),
            None => None,
        };

        let address = byte_to_ip(&resource.address)?;
        let workload_type = resource.workload_type().as_str_name().to_lowercase();
        Ok(Workload {
            workload_ip: address,
            waypoint: wp,
            network_gateway: network_gw,
            gateway_address: None,

            protocol: Protocol::try_from(xds::istio::workload::TunnelProtocol::from_i32(
                resource.tunnel_protocol,
            ))?,

            name: resource.name,
            namespace: resource.namespace,
            trust_domain: {
                let result = resource.trust_domain;
                if result.is_empty() {
                    "cluster.local".into()
                } else {
                    result
                }
            },
            service_account: {
                let result = resource.service_account;
                if result.is_empty() {
                    "default".into()
                } else {
                    result
                }
            },
            node: resource.node,
            network: resource.network,
            workload_name: resource.workload_name,
            workload_type,
            canonical_name: resource.canonical_name,
            canonical_revision: resource.canonical_revision,

            status: HealthStatus::try_from(xds::istio::workload::WorkloadStatus::from_i32(
                resource.status,
            ))?,

            native_tunnel: resource.native_tunnel,
            authorization_policies: resource.authorization_policies,

            cluster_id: {
                let result = resource.cluster_id;
                if result.is_empty() {
                    "Kubernetes".into()
                } else {
                    result
                }
            },
        })
    }
}

pub struct WorkloadManager {
    workloads: WorkloadInformation,
    xds_client: Option<AdsClient>,
}

impl xds::Handler<XdsWorkload> for Arc<Mutex<WorkloadStore>> {
    fn handle(&self, updates: Vec<XdsUpdate<XdsWorkload>>) -> Result<(), Vec<RejectedConfig>> {
        let mut wli = self.lock().unwrap();
        let handle = |res: XdsUpdate<XdsWorkload>| {
            match res {
                XdsUpdate::Update(w) => wli.insert_xds_workload(w.resource)?,
                XdsUpdate::Remove(name) => {
                    info!("handling delete {}", name);
                    wli.remove(name);
                }
            }
            Ok(())
        };
        xds::handle_single_resource(updates, handle)
    }
}

impl xds::Handler<XdsAddress> for Arc<Mutex<WorkloadStore>> {
    fn handle(&self, updates: Vec<XdsUpdate<XdsAddress>>) -> Result<(), Vec<RejectedConfig>> {
        let mut wli = self.lock().unwrap();
        let handle = |res: XdsUpdate<XdsAddress>| {
            match res {
                XdsUpdate::Update(w) => wli.insert_xds_address(w.resource)?,
                XdsUpdate::Remove(name) => {
                    info!("handling delete {}", name);
                    wli.remove(name);
                }
            }
            Ok(())
        };
        xds::handle_single_resource(updates, handle)
    }
}

impl xds::Handler<XdsAuthorization> for Arc<Mutex<WorkloadStore>> {
    fn handle(&self, updates: Vec<XdsUpdate<XdsAuthorization>>) -> Result<(), Vec<RejectedConfig>> {
        let mut wli = self.lock().unwrap();
        let handle = |res: XdsUpdate<XdsAuthorization>| {
            match res {
                XdsUpdate::Update(w) => {
                    info!("handling RBAC update {}", w.name);
                    wli.insert_xds_authorization(w.resource)?;
                }
                XdsUpdate::Remove(name) => {
                    info!("handling RBAC delete {}", name);
                    wli.remove_rbac(name);
                }
            }
            Ok(())
        };
        xds::handle_single_resource(updates, handle)
    }
}

impl WorkloadManager {
    pub async fn new(
        config: config::Config,
        metrics: Arc<Metrics>,
        awaiting_ready: readiness::BlockReady,
        cert_manager: Arc<SecretManager>,
    ) -> anyhow::Result<WorkloadManager> {
        let (tx, mut rx) = mpsc::channel::<Identity>(256);
        // todo ratelimit prefetching to a reasonable limit
        tokio::spawn(async move {
            while let Some(workload_identity) = rx.recv().await {
                match cert_manager.fetch_certificate(&workload_identity).await {
                    Ok(_) => debug!("prefetched cert for {:?}", workload_identity.to_string()),
                    Err(e) => error!(
                        "unable to prefetch cert for {:?}, skipping, {:?}",
                        workload_identity.to_string(),
                        e
                    ),
                }
            }
        });
        let workloads: Arc<Mutex<WorkloadStore>> = Arc::new(Mutex::new(WorkloadStore {
            cert_tx: Some(tx),
            proxy_mode: config.proxy_mode.clone(),
            local_node: config.local_node.clone(),
            ..Default::default()
        }));
        let xds_workloads = workloads.clone();
        let xds_rbac = workloads.clone();
        let xds_client = if config.xds_address.is_some() {
            Some(
                xds::Config::new(config.clone())
                    .with_address_handler(xds_workloads)
                    .with_authorization_handler(xds_rbac)
                    .watch(xds::ADDRESS_TYPE.into())
                    .watch(xds::AUTHORIZATION_TYPE.into())
                    .build(metrics, awaiting_ready),
            )
        } else {
            None
        };
        if let Some(cfg) = config.local_xds_config {
            let local_client = LocalClient {
                cfg,
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
    cfg: ConfigSource,
    workloads: Arc<Mutex<WorkloadStore>>,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalWorkload {
    #[serde(flatten)]
    pub workload: Workload,
    pub vips: HashMap<String, HashMap<u16, u16>>,
}

#[derive(Default, Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub workloads: Vec<LocalWorkload>,
    #[serde(default)]
    pub policies: Vec<Authorization>,
    #[serde(default)]
    pub services: Vec<Service>,
}

impl LocalClient {
    #[instrument(skip_all, name = "local_client")]
    async fn run(self) -> Result<(), anyhow::Error> {
        // Currently, we just load the file once. In the future, we could dynamically reload.
        let data = self.cfg.read_to_string().await?;
        trace!("local config: {data}");
        let r: LocalConfig = serde_yaml::from_str(&data)?;
        let mut wli = self.workloads.lock().unwrap();
        let workloads = r.workloads.len();
        let policies = r.policies.len();
        for wl in r.workloads {
            let wip = wl.workload.workload_ip;
            debug!(
                "inserting local workloads {wip} ({}/{})",
                &wl.workload.namespace, &wl.workload.name
            );
            wli.insert_workload(wl.workload);
        }
        for rbac in r.policies {
            wli.insert_authorization(rbac);
        }
        for svc in r.services {
            wli.insert_svc(svc);
        }
        info!(%workloads, %policies, "local config initialized");
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

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum WaypointError {
    #[error("failed to find waypoint for workload: {0}")]
    FindWaypointError(String),
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),
}

impl WorkloadInformation {
    pub async fn assert_rbac(&self, conn: &rbac::Connection) -> bool {
        let nw_addr = network_addr(&conn.dst_network, conn.dst.ip());
        let Some(wl) = self.fetch_workload(&nw_addr).await else {
            debug!("destination workload not found {}", nw_addr);
            return false;
        };

        let wli = self.info.lock().unwrap();

        // We can get policies from namespace, global, and workload...
        let ns = wli
            .policies_by_namespace
            .get(&wl.namespace)
            .into_iter()
            .flatten();
        let global = wli.policies_by_namespace.get("").into_iter().flatten();
        let workload = wl.authorization_policies.iter();

        // Aggregate all of them based on type
        let (allow, deny): (Vec<_>, Vec<_>) = ns
            .chain(global)
            .chain(workload)
            .filter_map(|k| wli.policies.get(k))
            .partition(|p| p.action == rbac::RbacAction::Allow);

        trace!(
            allow = allow.len(),
            deny = deny.len(),
            "checking connection"
        );

        // Allow and deny logic follows https://istio.io/latest/docs/reference/config/security/authorization-policy/

        // "If there are any DENY policies that match the request, deny the request."
        for pol in deny.iter() {
            if pol.matches(conn) {
                debug!(policy = pol.to_key(), "deny policy match");
                return false;
            } else {
                trace!(policy = pol.to_key(), "deny policy does not match");
            }
        }
        // "If there are no ALLOW policies for the workload, allow the request."
        if allow.is_empty() {
            debug!("no allow policies, allow");
            return true;
        }
        // "If any of the ALLOW policies match the request, allow the request."
        for pol in allow.iter() {
            if pol.matches(conn) {
                debug!(policy = pol.to_key(), "allow policy match");
                return true;
            } else {
                trace!(policy = pol.to_key(), "allow policy does not match");
            }
        }
        // "Deny the request."
        debug!("no allow policies matched");
        false
    }

    // only support workload
    pub async fn fetch_workload(&self, addr: &NetworkAddress) -> Option<Workload> {
        // Wait for it on-demand, *if* needed
        debug!(%addr, "fetch workload");
        // use self.find_workload() so we unlock before fetching on demand
        match self.find_workload(addr) {
            None => {
                self.fetch_on_demand(addr).await;
                self.find_workload(addr)
            }
            wl @ Some(_) => wl,
        }
    }

    pub async fn find_upstream(
        &self,
        network: &str,
        addr: SocketAddr,
        hbone_port: u16,
    ) -> Option<Upstream> {
        self.fetch_address(network_addr(network, addr.ip())).await;
        let wi = self.info.lock().unwrap();
        wi.find_upstream(network, addr, hbone_port)
    }

    pub async fn find_waypoint(&self, wl: Workload) -> Result<Option<Upstream>, WaypointError> {
        let Some(gw_address) = &wl.waypoint else {
            return Ok(None);
        };
        // Even in this case, we are picking a single upstream pod and deciding if it has a remote proxy.
        // Typically this is all or nothing, but if not we should probably send to remote proxy if *any* upstream has one.
        let wp_nw_addr = match &gw_address.destination {
            gatewayaddress::Destination::Address(ip) => ip,
            gatewayaddress::Destination::Hostname(_) => {
                return Err(WaypointError::UnsupportedFeature(
                    "hostname lookup not supported yet".to_string(),
                ));
            }
        };
        let wp_socket_addr = SocketAddr::new(wp_nw_addr.address, gw_address.port);
        match self
            .find_upstream(&wp_nw_addr.network, wp_socket_addr, gw_address.port)
            .await
        {
            Some(upstream) => {
                debug!(%wl.name, "found waypoint upstream");
                Ok(Some(upstream))
            }
            None => {
                debug!(%wl.name, "waypoint upstream not found");
                Err(WaypointError::FindWaypointError(wl.name))
            }
        }
    }

    // Support workload and VIP
    // It is to do on demand workload fetch if necessary, it handles both workload ip and services
    pub async fn fetch_address(&self, network_addr: NetworkAddress) -> Option<Address> {
        // Wait for it on-demand, *if* needed
        debug!(%network_addr.address, "fetch address");
        // use self.find_address() so we unlock before fetching on demand
        if let Some(address) = self.find_address(network_addr.clone()) {
            return Some(address);
        }
        // if both cache not found, start on demand fetch
        self.fetch_on_demand(&network_addr).await;
        self.find_address(network_addr)
    }

    async fn fetch_on_demand(&self, key: &NetworkAddress) {
        if let Some(demand) = &self.demand {
            debug!(%key, "sending demand request");
            demand.demand(key.to_string()).await.recv().await;
            debug!(%key, "on demand ready");
        }
    }

    // keep private so that we can ensure that we always use fetch_address
    fn find_address(&self, network_addr: NetworkAddress) -> Option<Address> {
        // 1. handle workload ip, if workload not found fallback to service.
        let wi = self.info.lock().unwrap(); // don't use self.find_workload() to avoid locking twice
        match wi.find_workload(&network_addr).cloned() {
            None => {
                // 2. handle service
                if let Some(svc) = wi.vips.get(&network_addr).cloned() {
                    return Some(Address::Service(Box::new(svc)));
                }
                None
            }
            Some(wl) => Some(Address::Workload(Box::new(wl))),
        }
    }

    // keep private so that we can ensure that we always use fetch_workload
    fn find_workload(&self, addr: &NetworkAddress) -> Option<Workload> {
        let wi = self.info.lock().unwrap();
        wi.find_workload(addr).cloned()
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub namespace: String,
    pub hostname: String,
    pub addresses: Vec<NetworkAddress>,
    pub ports: HashMap<u16, u16>,
    pub endpoints: HashMap<NetworkAddress, Endpoint>,
}
#[derive(Debug, Eq, PartialEq, Hash, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamespacedHostname {
    pub namespace: String,
    pub hostname: String,
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct NetworkAddress {
    pub network: String,
    pub address: IpAddr,
}

// we need custom serde serialization since NetworkAddress is keying maps
impl Serialize for NetworkAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self)
    }
}

// we need custom serde deserialization because we have custom serialization
impl<'de> Deserialize<'de> for NetworkAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NetworkAddressVisitor;

        impl<'de> Visitor<'de> for NetworkAddressVisitor {
            type Value = NetworkAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string for NetworkAddress with format network/IP")
            }

            fn visit_str<E>(self, value: &str) -> Result<NetworkAddress, E>
            where
                E: serde::de::Error,
            {
                let Some((network, address)) = value.split_once('/') else {
                    return Err(serde::de::Error::invalid_value(serde::de::Unexpected::Str(value), &self));
                };
                use std::str::FromStr;
                let Ok(ip_addr) = IpAddr::from_str(address) else {
                    return Err(serde::de::Error::invalid_value(serde::de::Unexpected::Str(value), &self));
                };
                Ok(NetworkAddress {
                    network: network.to_string(),
                    address: ip_addr,
                })
            }
        }
        deserializer.deserialize_str(NetworkAddressVisitor)
    }
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.address,)
    }
}

pub fn network_addr(network: &str, vip: IpAddr) -> NetworkAddress {
    NetworkAddress {
        network: network.to_owned(),
        address: vip,
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    pub address: NetworkAddress,
    pub port: HashMap<u16, u16>,
}

impl TryFrom<&XdsService> for Service {
    type Error = WorkloadError;

    fn try_from(s: &XdsService) -> Result<Self, Self::Error> {
        let mut nw_addrs = Vec::new();
        for addr in &s.addresses {
            let network_address = network_addr(
                &addr.network,
                byte_to_ip(&Bytes::copy_from_slice(&addr.address))?,
            );
            nw_addrs.push(network_address);
        }
        let svc = Service {
            name: s.name.to_string(),
            namespace: s.namespace.to_string(),
            hostname: s.hostname.to_string(),
            addresses: nw_addrs,
            ports: (&PortList {
                ports: s.ports.clone(),
            })
                .into(),
            endpoints: Default::default(), // intentionally empty; will be populated once inserted into the workload store
        };
        Ok(svc)
    }
}

/// A WorkloadStore encapsulates all information about workloads in the mesh
#[derive(serde::Serialize, Default, Debug)]
pub struct WorkloadStore {
    workloads: HashMap<NetworkAddress, Workload>,
    /// workload_to_vip maintains a mapping of workload IP to VIP. This is used only to handle removals.
    workload_to_vip: HashMap<NetworkAddress, HashSet<IpAddr>>,
    /// vips maintains a mapping of socket address with service port to workload ip and socket address
    /// with target ports in hashset.
    vips: HashMap<NetworkAddress, Service>,
    /// staged_vips maintains a mapping of service IP -> (workload IP -> Endpoint)
    /// this is used to handle ordering issues if workloads with VIPs are received before services.
    staged_vips: HashMap<NetworkAddress, HashMap<NetworkAddress, Endpoint>>,
    /// policies maintains a mapping of ns/name to policy.
    policies: HashMap<String, rbac::Authorization>,
    // policies_by_namespace maintains a mapping of namespace (or "" for global) to policy names
    policies_by_namespace: HashMap<String, HashSet<String>>,

    #[serde(skip_serializing, default)]
    cert_tx: Option<mpsc::Sender<Identity>>,

    // needed to determine whether or not to prefetch certs
    proxy_mode: ProxyMode,
    local_node: Option<String>,
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

    fn insert_xds_address(&mut self, a: XdsAddress) -> anyhow::Result<()> {
        match a.r#type {
            Some(XdsType::Workload(w)) => self.insert_xds_workload(w),
            Some(XdsType::Service(s)) => self.insert_xds_service(s),
            _ => Err(anyhow::anyhow!("unknown address type")),
        }
    }

    fn insert_xds_service(&mut self, s: XdsService) -> anyhow::Result<()> {
        let svc: Service = Service::try_from(&s)?;
        self.insert_svc(svc);
        Ok(())
    }

    fn insert_xds_workload(&mut self, w: XdsWorkload) -> anyhow::Result<()> {
        let workload = Workload::try_from(&w)?;
        let wip = network_addr(&workload.network, workload.workload_ip);
        // First, remove the entry entirely to make sure things are cleaned up properly. Note this is
        // under a lock, so there is no race here.
        self.remove(wip.to_string());
        let widentity = workload.identity();
        let status = workload.status;
        self.insert_workload(workload.clone());
        // Unhealthy workloads are always inserted, as we may get or recieve traffic to them. But we shouldn't
        // include them in load balancing we do to Services.
        if status == HealthStatus::Healthy {
            for (vip, pl) in &w.virtual_ips {
                let vip = vip.parse::<IpAddr>()?;
                let ep = Endpoint {
                    address: wip.clone(),
                    port: pl.into(),
                };
                if let Some(svc) = self.vips.get_mut(&network_addr(&w.network, vip)) {
                    svc.endpoints.insert(ep.address.clone(), ep.clone());
                    self.workload_to_vip
                        .entry(wip.clone())
                        .or_default()
                        .insert(vip);
                } else {
                    // Can happen due to ordering issues
                    trace!("pod has VIP {vip}, but VIP not found");
                    self.staged_vips
                        .entry(network_addr(&workload.network, vip))
                        .or_default()
                        .insert(wip.clone(), ep.clone());
                    self.workload_to_vip
                        .entry(wip.clone())
                        .or_default()
                        .insert(vip);
                }
            }
        }

        if self.proxy_mode == ProxyMode::Shared && Some(&w.node) == self.local_node.as_ref() {
            if let Some(tx) = self.cert_tx.as_mut() {
                if let Err(e) = tx.try_send(widentity) {
                    info!("couldn't prefetch: {:?}", e)
                }
            }
        }
        Ok(())
    }

    fn insert_xds_authorization(&mut self, r: XdsAuthorization) -> anyhow::Result<()> {
        let rbac = rbac::Authorization::try_from(&r)?;
        trace!("insert policy {}", serde_json::to_string(&rbac)?);
        self.insert_authorization(rbac);
        Ok(())
    }

    fn insert_authorization(&mut self, rbac: Authorization) {
        let key = rbac.to_key();
        match rbac.scope {
            RbacScope::Global => {
                self.policies_by_namespace
                    .entry("".to_string())
                    .or_default()
                    .insert(key.clone());
            }
            RbacScope::Namespace => {
                self.policies_by_namespace
                    .entry(rbac.namespace.clone())
                    .or_default()
                    .insert(key.clone());
            }
            RbacScope::WorkloadSelector => {}
        }
        self.policies.insert(key, rbac);
    }

    fn remove_rbac(&mut self, name: String) {
        let Some(rbac) = self.policies.remove(&name) else {
            return;
        };
        if let Some(key) = match rbac.scope {
            RbacScope::Global => Some("".to_string()),
            RbacScope::Namespace => Some(rbac.namespace),
            RbacScope::WorkloadSelector => None,
        } {
            if let Some(pl) = self.policies_by_namespace.get_mut(&key) {
                pl.remove(&name);
                if pl.is_empty() {
                    self.policies_by_namespace.remove(&key);
                }
            }
        }
    }

    fn insert_workload(&mut self, w: Workload) {
        self.workloads
            .insert(network_addr(&w.network, w.workload_ip), w);
    }

    fn insert_svc(&mut self, mut svc: Service) {
        // first mutate the service and add all missing endpoints
        for network_addr in svc.addresses.as_slice() {
            // due to ordering issues, we may have gotten workloads with VIPs before we got the service
            // we should add those workloads to the vips map now
            if let Some(wips_to_endpoints) = self.staged_vips.remove(network_addr) {
                for (wip, ep) in wips_to_endpoints {
                    self.workload_to_vip
                        .entry(wip.clone())
                        .or_default()
                        .insert(network_addr.address);
                    svc.endpoints.insert(wip.clone(), ep);
                }
            }
        }

        // now persist copies of the service to our persisted map, passing ownership to the map
        for network_addr in svc.addresses.as_slice() {
            // if svc already exists, just add new endpoints to existing svc
            if let Some(prev) = self.vips.get_mut(network_addr) {
                for (wip, ep) in &svc.endpoints {
                    prev.endpoints.insert(wip.clone(), ep.clone());
                    self.workload_to_vip
                        .entry(wip.clone())
                        .or_default()
                        .insert(network_addr.address);
                }
            } else {
                // svc is new, add it as is
                self.vips.insert(network_addr.clone(), svc.clone());
            }
        }
    }

    fn remove(&mut self, xds_name: String) {
        let parts = xds_name.split_once('/');
        if parts.is_none() {
            error!("received invalid resource removal {}, ignoring", xds_name);
            return;
        }
        // we received either network/IP for workload/service or namespace/hostname for service
        let (network_or_namespace, ip_or_hostname) = parts.unwrap();

        // TODO: add support for namespace/hostname. For now we assume network/IP
        use std::str::FromStr;
        let ip: IpAddr = match IpAddr::from_str(ip_or_hostname) {
            Err(e) => {
                error!(
                    "received invalid resource removal {}, ignoring: {}",
                    ip_or_hostname, e
                );
                return;
            }
            Ok(i) => i,
        };

        if let Some(prev) = self
            .workloads
            .remove(&network_addr(network_or_namespace, ip))
        {
            if let Some(vips) = self
                .workload_to_vip
                .remove(&network_addr(&prev.network, prev.workload_ip))
            {
                for vip in vips {
                    self.staged_vips
                        .entry(network_addr(&prev.network, vip))
                        .or_default()
                        .remove(&network_addr(&prev.network, prev.workload_ip));
                    if self.staged_vips[&network_addr(&prev.network, vip)].is_empty() {
                        self.staged_vips.remove(&network_addr(&prev.network, vip));
                    }
                    if let Some(wls) = self.vips.get_mut(&network_addr(&prev.network, vip)) {
                        wls.endpoints
                            .remove(&network_addr(&prev.network, prev.workload_ip));
                    }
                }
            }
        }

        if let Some(prev) = self.vips.remove(&network_addr(network_or_namespace, ip)) {
            for (ep_ip, _) in prev.endpoints {
                self.workload_to_vip.remove(&ep_ip);
                for network_addr in &prev.addresses {
                    self.staged_vips
                        .entry(network_addr.clone())
                        .or_default()
                        .remove(&ep_ip);
                    if self.staged_vips[network_addr].is_empty() {
                        self.staged_vips.remove(network_addr);
                    }
                }
            }
        }
    }

    fn find_workload(&self, addr: &NetworkAddress) -> Option<&Workload> {
        self.workloads.get(addr)
    }

    fn find_upstream(&self, network: &str, addr: SocketAddr, hbone_port: u16) -> Option<Upstream> {
        if let Some(svc) = self.vips.get(&network_addr(network, addr.ip())) {
            let Some(target_port) = svc.ports.get(&addr.port()) else {
                debug!("found VIP {}, but port {} was unknown", addr.ip(), addr.port());
                return None
            };
            // Randomly pick an upstream
            // TODO: do this more efficiently, and not just randomly
            let Some((_, ep)) = svc.endpoints.iter().choose(&mut rand::thread_rng()) else {
                debug!("VIP {} has no healthy endpoints", addr);
                return None
            };
            let Some(wl) = self.workloads.get(&network_addr(network, ep.address.address)) else {
                debug!("failed to fetch workload for {}", ep.address);
                return None
            };
            // If endpoint overrides the target port, use that instead
            let target_port = ep.port.get(&addr.port()).unwrap_or(target_port);
            let mut us = Upstream {
                workload: wl.to_owned(),
                port: *target_port,
            };
            Self::set_gateway_address(&mut us, hbone_port);
            debug!("found upstream {} from VIP {}", us, addr.ip());
            return Some(us);
        }
        if let Some(wl) = self.workloads.get(&network_addr(network, addr.ip())) {
            let mut us = Upstream {
                workload: wl.to_owned(),
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
                        .waypoint_svc_ip_address()
                        .unwrap()
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
    #[error("invalid cidr: {0}")]
    PrefixParse(#[from] ipnet::PrefixLenError),
    #[error("unknown enum: {0}")]
    EnumParse(String),
    #[error("nonempty gateway address is missing address")]
    MissingGatewayAddress,
}

#[cfg(test)]
mod tests {
    use std::default::Default;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use crate::test_helpers;
    use crate::test_helpers::helpers::initialize_telemetry;
    use crate::xds::istio::workload::Port as XdsPort;
    use crate::xds::istio::workload::PortList as XdsPortList;
    use crate::xds::istio::workload::WorkloadStatus as XdsStatus;

    use xds::istio::workload::NetworkAddress as XdsNetworkAddress;

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
        initialize_telemetry();
        let mut wi = WorkloadStore::default();
        assert_eq!((wi.workloads.len()), 0);
        assert_eq!((wi.vips.len()), 0);
        assert_eq!((wi.staged_vips.len()), 0);

        let xds_ip1 = Bytes::copy_from_slice(&[127, 0, 0, 1]);
        let ip1 = network_addr("defaultnw", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let xds_ip2 = Bytes::copy_from_slice(&[127, 0, 0, 2]);

        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip1.clone(),
            name: "some name".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((wi.workloads.len()), 1);
        assert_eq!(
            wi.find_workload(&ip1),
            Some(&Workload {
                workload_ip: ip1.address,
                name: "some name".to_string(),
                ..test_helpers::test_default_workload()
            })
        );

        wi.remove("defaultnw/invalid".to_string());
        assert_eq!(
            wi.find_workload(&ip1),
            Some(&Workload {
                workload_ip: ip1.address,
                name: "some name".to_string(),
                ..test_helpers::test_default_workload()
            })
        );

        wi.remove("defaultnw/127.0.0.2".to_string());
        assert_eq!(
            wi.find_workload(&ip1),
            Some(&Workload {
                workload_ip: ip1.address,
                name: "some name".to_string(),
                ..test_helpers::test_default_workload()
            })
        );

        wi.remove("defaultnw/127.0.0.1".to_string());
        assert_eq!(wi.find_workload(&ip1), None);
        assert_eq!(wi.workloads.len(), 0);

        let vip = HashMap::from([(
            "127.0.1.1".to_string(),
            XdsPortList {
                ports: vec![XdsPort {
                    service_port: 80,
                    target_port: 8080,
                }],
            },
        )]);
        assert_vips(&wi, vec![]);

        // Add two workloads into the VIP. Add out of order to further test
        assert_eq!((wi.staged_vips.len()), 0);
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip1.clone(),
            name: "some name".to_string(),
            virtual_ips: vip.clone(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((wi.staged_vips.len()), 1);
        wi.insert_xds_service(XdsService {
            name: "svc1".to_string(),
            namespace: "ns".to_string(),
            hostname: "svc1.ns.svc.cluster.local".to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "defaultnw".to_string(),
                address: [127, 0, 1, 1].to_vec(),
            }],
            ports: vec![XdsPort {
                service_port: 80,
                target_port: 80,
            }],
            subject_alt_names: vec![],
            opaque_endpoint: None,
        })
        .unwrap();
        assert_eq!((wi.staged_vips.len()), 0);

        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip2.clone(),
            name: "some name2".to_string(),
            virtual_ips: vip.clone(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((wi.staged_vips.len()), 0); // vip already in a service, should not be staged

        assert_vips(&wi, vec!["some name", "some name2"]);
        wi.remove("defaultnw/127.0.0.2".to_string());
        assert_vips(&wi, vec!["some name"]);
        wi.remove("defaultnw/127.0.0.1".to_string());
        assert_vips(&wi, vec![]);

        // Add 2 workload with VIP
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip1.clone(),
            name: "some name".to_string(),
            virtual_ips: vip.clone(),
            ..Default::default()
        })
        .unwrap();
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip2.clone(),
            name: "some name2".to_string(),
            virtual_ips: vip.clone(),
            ..Default::default()
        })
        .unwrap();
        assert_vips(&wi, vec!["some name", "some name2"]);
        // now update it without the VIP
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip1,
            name: "some name".to_string(),
            ..Default::default()
        })
        .unwrap();
        // Should be remove
        assert_vips(&wi, vec!["some name2"]);
        // now update it with unhealthy
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip2,
            name: "some name2".to_string(),
            virtual_ips: vip,
            status: XdsStatus::Unhealthy as i32,
            ..Default::default()
        })
        .unwrap();
        // Should be removed
        assert_vips(&wi, vec![]);

        // Remove the VIP entirely
        wi.remove("defaultnw/127.0.1.1".to_string());
        assert_eq!(wi.vips.len(), 0);
    }

    #[test]
    fn staged_vips_cleanup() {
        initialize_telemetry();
        let mut wi = WorkloadStore::default();
        assert_eq!((wi.workloads.len()), 0);
        assert_eq!((wi.vips.len()), 0);
        assert_eq!((wi.staged_vips.len()), 0);

        let xds_ip1 = Bytes::copy_from_slice(&[127, 0, 0, 1]);

        let vip = HashMap::from([(
            "127.0.1.1".to_string(),
            XdsPortList {
                ports: vec![XdsPort {
                    service_port: 80,
                    target_port: 8080,
                }],
            },
        )]);
        assert_vips(&wi, vec![]);

        // Add 2 workload with VIP
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip1.clone(),
            name: "some name".to_string(),
            virtual_ips: vip.clone(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((wi.staged_vips.len()), 1);

        // now update it without the VIP
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip1.clone(),
            name: "some name".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!((wi.staged_vips.len()), 0); // should remove the VIP if no longer needed

        // Add 2 workload with VIP again
        wi.insert_xds_workload(XdsWorkload {
            network: "defaultnw".to_string(),
            address: xds_ip1,
            name: "some name".to_string(),
            virtual_ips: vip,
            ..Default::default()
        })
        .unwrap();
        assert_eq!((wi.staged_vips.len()), 1); // VIP should be staged again

        wi.remove("defaultnw/127.0.0.1".to_string());
        assert_eq!((wi.staged_vips.len()), 0); // should remove the VIP if no longer needed
    }

    #[track_caller]
    fn assert_vips(wi: &WorkloadStore, want: Vec<&str>) {
        let mut wants: HashSet<String> = HashSet::from_iter(want.iter().map(|x| x.to_string()));
        let mut found: HashSet<String> = HashSet::new();
        // VIP has randomness. We will try to fetch the VIP 1k times and assert the we got the expected results
        // at least once, and no unexpected results
        for _ in 0..1000 {
            if let Some(us) = wi.find_upstream("defaultnw", "127.0.1.1:80".parse().unwrap(), 15008)
            {
                let n = &us.workload.name; // borrow name instead of cloning
                found.insert(n.to_owned()); // insert an owned copy of the borrowed n
                wants.remove(n); // remove using the borrow
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
        let cfg = ConfigSource::File(
            std::path::PathBuf::from(std::env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("localhost.yaml"),
        );
        let workloads: Arc<Mutex<WorkloadStore>> = Arc::new(Mutex::new(WorkloadStore::default()));

        let local_client = LocalClient {
            cfg,
            workloads: workloads.clone(),
        };
        local_client.run().await.expect("client should run");
        let store = workloads.lock().unwrap();
        let wl = store.find_workload(&network_addr("defaultnw", "127.0.0.1".parse().unwrap()));
        // Make sure we get a valid workload
        assert!(wl.is_some());
        assert_eq!(wl.unwrap().service_account, "default");
        let us = store.find_upstream("defaultnw", "127.10.0.1:80".parse().unwrap(), 15008);
        // Make sure we get a valid VIP
        assert!(us.is_some());
        assert_eq!(us.unwrap().port, 8080);
    }
}
