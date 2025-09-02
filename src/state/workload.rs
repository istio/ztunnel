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

use crate::identity::Identity;

use crate::state::WorkloadInfo;
use crate::strng::Strng;
use crate::xds::istio::workload::{Port, PortList};
use crate::{strng, xds};
use bytes::Bytes;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use serde::de::Visitor;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::convert::Into;
use std::default::Default;
use std::fmt::Write;
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, net};
use thiserror::Error;
use tokio::sync::watch::{Receiver, Sender};
use tracing::{error, trace};
use xds::istio::workload::ApplicationTunnel as XdsApplicationTunnel;
use xds::istio::workload::GatewayAddress as XdsGatewayAddress;
use xds::istio::workload::Workload as XdsWorkload;

// The protocol that the final workload expects
#[derive(
    Default,
    Debug,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Clone,
    Copy,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum InboundProtocol {
    #[default]
    TCP,
    HBONE,
}

impl From<xds::istio::workload::TunnelProtocol> for InboundProtocol {
    fn from(value: xds::istio::workload::TunnelProtocol) -> Self {
        match value {
            xds::istio::workload::TunnelProtocol::Hbone => InboundProtocol::HBONE,
            xds::istio::workload::TunnelProtocol::None => InboundProtocol::TCP,
        }
    }
}

// The protocol that the sender should use to send data. Can be different from ServerProtocol when there is a
// proxy in the middle (e.g. e/w gateway with double hbone).
#[derive(
    Default,
    Debug,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Clone,
    Copy,
    serde::Serialize,
    serde::Deserialize,
)]
pub enum OutboundProtocol {
    #[default]
    TCP,
    HBONE,
    DOUBLEHBONE,
}

impl From<InboundProtocol> for OutboundProtocol {
    fn from(value: InboundProtocol) -> Self {
        match value {
            InboundProtocol::HBONE => OutboundProtocol::HBONE,
            InboundProtocol::TCP => OutboundProtocol::TCP,
        }
    }
}

#[derive(
    Default, Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
pub enum NetworkMode {
    #[default]
    Standard,
    HostNetwork,
}

impl From<xds::istio::workload::NetworkMode> for NetworkMode {
    fn from(value: xds::istio::workload::NetworkMode) -> Self {
        match value {
            xds::istio::workload::NetworkMode::Standard => NetworkMode::Standard,
            xds::istio::workload::NetworkMode::HostNetwork => NetworkMode::HostNetwork,
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

#[derive(Default, Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub struct Locality {
    pub region: Strng,
    pub zone: Strng,
    pub subzone: Strng,
}

impl From<xds::istio::workload::Locality> for Locality {
    fn from(value: xds::istio::workload::Locality) -> Self {
        Locality {
            region: value.region.into(),
            zone: value.zone.into(),
            subzone: value.subzone.into(),
        }
    }
}

impl From<xds::istio::workload::WorkloadStatus> for HealthStatus {
    fn from(value: xds::istio::workload::WorkloadStatus) -> Self {
        match value {
            xds::istio::workload::WorkloadStatus::Healthy => HealthStatus::Healthy,
            xds::istio::workload::WorkloadStatus::Unhealthy => HealthStatus::Unhealthy,
        }
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayAddress {
    pub destination: gatewayaddress::Destination,
    pub hbone_mtls_port: u16,
}

pub mod gatewayaddress {
    use super::{NamespacedHostname, NetworkAddress};
    #[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Destination {
        Address(NetworkAddress),
        Hostname(NamespacedHostname),
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationTunnel {
    pub protocol: application_tunnel::Protocol,
    pub port: Option<u16>,
}

pub mod application_tunnel {
    use crate::xds::istio::workload::application_tunnel::Protocol as XdsProtocol;

    #[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
    pub enum Protocol {
        NONE,
        PROXY,
    }

    impl Protocol {
        pub fn supports_localhost_send(&self) -> bool {
            match self {
                Protocol::NONE => false,
                Protocol::PROXY => true,
            }
        }
    }

    impl From<XdsProtocol> for Protocol {
        fn from(value: XdsProtocol) -> Self {
            match value {
                XdsProtocol::None => Protocol::NONE,
                XdsProtocol::Proxy => Protocol::PROXY,
            }
        }
    }
}

pub mod address {
    use crate::state::service::Service;
    use crate::state::workload::Workload;
    use std::sync::Arc;

    #[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Address {
        Workload(Arc<Workload>),
        Service(Arc<Service>),
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Workload {
    pub workload_ips: Vec<IpAddr>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub waypoint: Option<GatewayAddress>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub network_gateway: Option<GatewayAddress>,

    #[serde(default)]
    pub protocol: InboundProtocol,
    #[serde(default)]
    pub network_mode: NetworkMode,

    #[serde(default, skip_serializing_if = "is_default")]
    pub uid: Strng,
    #[serde(default)]
    pub name: Strng,
    pub namespace: Strng,
    #[serde(default, skip_serializing_if = "is_default")]
    pub trust_domain: Strng,
    #[serde(default, skip_serializing_if = "is_default")]
    pub service_account: Strng,
    #[serde(default, skip_serializing_if = "is_default")]
    pub network: Strng,

    #[serde(default, skip_serializing_if = "is_default")]
    pub workload_name: Strng,
    #[serde(default, skip_serializing_if = "is_default")]
    pub workload_type: Strng,
    #[serde(default, skip_serializing_if = "is_default")]
    pub canonical_name: Strng,
    #[serde(default, skip_serializing_if = "is_default")]
    pub canonical_revision: Strng,

    #[serde(default, skip_serializing_if = "is_default")]
    pub hostname: Strng,

    #[serde(default, skip_serializing_if = "is_default")]
    pub node: Strng,

    #[serde(default, skip_serializing_if = "is_default")]
    pub native_tunnel: bool,
    #[serde(default, skip_serializing_if = "is_default")]
    pub application_tunnel: Option<ApplicationTunnel>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub authorization_policies: Vec<Strng>,

    #[serde(default)]
    pub status: HealthStatus,

    #[serde(default)]
    pub cluster_id: Strng,

    #[serde(default, skip_serializing_if = "is_default")]
    pub locality: Locality,

    #[serde(default, skip_serializing_if = "is_default")]
    pub services: Vec<NamespacedHostname>,

    #[serde(default = "default_capacity")]
    pub capacity: u32,
}

fn default_capacity() -> u32 {
    1
}

pub fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
}

impl Workload {
    pub fn identity(&self) -> Identity {
        Identity::Spiffe {
            trust_domain: self.trust_domain.clone(),
            namespace: self.namespace.clone(),
            service_account: self.service_account.clone(),
        }
    }
}

impl fmt::Display for Workload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Workload{{{} with uid {} ({:?})}}",
            self.name, self.uid, self.protocol
        )
    }
}

pub fn byte_to_ip(b: &Bytes) -> Result<IpAddr, WorkloadError> {
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

impl From<HashMap<u16, u16>> for PortList {
    fn from(value: HashMap<u16, u16>) -> Self {
        PortList {
            ports: value
                .iter()
                .map(|(k, v)| Port {
                    service_port: *k as u32,
                    target_port: *v as u32,
                })
                .collect(),
        }
    }
}

impl TryFrom<&XdsApplicationTunnel> for ApplicationTunnel {
    type Error = WorkloadError;

    fn try_from(value: &XdsApplicationTunnel) -> Result<Self, Self::Error> {
        Ok(ApplicationTunnel {
            protocol: application_tunnel::Protocol::from(
                xds::istio::workload::application_tunnel::Protocol::try_from(value.protocol)?,
            ),
            port: if value.port == 0 {
                None
            } else {
                Some(value.port as u16)
            },
        })
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
                            strng::new(&addr.network),
                            byte_to_ip(&Bytes::copy_from_slice(&addr.address))?,
                        )),
                        hbone_mtls_port: value.hbone_mtls_port as u16,
                    }
                }
                xds::istio::workload::gateway_address::Destination::Hostname(hn) => {
                    GatewayAddress {
                        destination: gatewayaddress::Destination::Hostname(NamespacedHostname {
                            namespace: Strng::from(&hn.namespace),
                            hostname: Strng::from(&hn.hostname),
                        }),
                        hbone_mtls_port: value.hbone_mtls_port as u16,
                    }
                }
            },
            None => return Err(WorkloadError::MissingGatewayAddress),
        };
        Ok(gw_addr)
    }
}

impl TryFrom<XdsWorkload> for Workload {
    type Error = WorkloadError;
    fn try_from(resource: XdsWorkload) -> Result<Self, Self::Error> {
        let (w, _): (Workload, HashMap<String, PortList>) = resource.try_into()?;
        Ok(w)
    }
}

impl TryFrom<XdsWorkload> for (Workload, HashMap<String, PortList>) {
    type Error = WorkloadError;
    fn try_from(resource: XdsWorkload) -> Result<Self, Self::Error> {
        let wp = match &resource.waypoint {
            Some(w) => Some(GatewayAddress::try_from(w)?),
            None => None,
        };

        let network_gw = match &resource.network_gateway {
            Some(w) => Some(GatewayAddress::try_from(w)?),
            None => None,
        };

        let application_tunnel = match &resource.application_tunnel {
            Some(ap) => Some(ApplicationTunnel::try_from(ap)?),
            None => None,
        };

        let addresses = resource
            .addresses
            .iter()
            .map(byte_to_ip)
            .collect::<Result<Vec<_>, _>>()?;

        let workload_type = resource.workload_type().as_str_name().to_lowercase();
        let services: Vec<NamespacedHostname> = resource
            .services
            .keys()
            .map(|namespaced_host| match namespaced_host.split_once('/') {
                Some((namespace, hostname)) => Ok(NamespacedHostname {
                    namespace: namespace.into(),
                    hostname: hostname.into(),
                }),
                None => Err(WorkloadError::NamespacedHostnameParse(
                    namespaced_host.clone(),
                )),
            })
            .collect::<Result<_, _>>()?;
        let wl = Workload {
            workload_ips: addresses,
            waypoint: wp,
            network_gateway: network_gw,

            protocol: InboundProtocol::from(xds::istio::workload::TunnelProtocol::try_from(
                resource.tunnel_protocol,
            )?),
            network_mode: NetworkMode::from(xds::istio::workload::NetworkMode::try_from(
                resource.network_mode,
            )?),

            uid: resource.uid.into(),
            name: resource.name.into(),
            namespace: resource.namespace.into(),
            trust_domain: {
                let result = resource.trust_domain;
                if result.is_empty() {
                    "cluster.local".into()
                } else {
                    result.into()
                }
            },
            service_account: {
                let result = resource.service_account;
                if result.is_empty() {
                    "default".into()
                } else {
                    result.into()
                }
            },
            node: resource.node.into(),
            hostname: resource.hostname.into(),
            network: resource.network.into(),
            workload_name: resource.workload_name.into(),
            workload_type: workload_type.into(),
            canonical_name: resource.canonical_name.into(),
            canonical_revision: resource.canonical_revision.into(),

            status: HealthStatus::from(xds::istio::workload::WorkloadStatus::try_from(
                resource.status,
            )?),

            native_tunnel: resource.native_tunnel,
            application_tunnel,

            authorization_policies: resource
                .authorization_policies
                .iter()
                .map(strng::new)
                .collect(),

            locality: resource.locality.map(Locality::from).unwrap_or_default(),

            cluster_id: {
                let result = resource.cluster_id;
                if result.is_empty() {
                    "Kubernetes".into()
                } else {
                    result.into()
                }
            },

            capacity: resource.capacity.unwrap_or(1),
            services,
        };
        // Return back part we did not use (service) so it can be consumed without cloning
        Ok((wl, resource.services))
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum WaypointError {
    #[error("failed to find waypoint for: {0}")]
    FindWaypointError(String),
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct NamespacedHostname {
    pub namespace: Strng,
    pub hostname: Strng,
}

impl FromStr for NamespacedHostname {
    type Err = WorkloadError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((namespace, hostname)) = value.split_once('/') else {
            return Err(WorkloadError::NamespacedHostnameParse(value.to_string()));
        };
        Ok(Self {
            namespace: namespace.into(),
            hostname: hostname.into(),
        })
    }
}

// we need custom serde serialization since NamespacedHostname is keying maps
impl Serialize for NamespacedHostname {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(&self)
    }
}

// we need custom serde deserialization because we have custom serialization
impl<'de> Deserialize<'de> for NamespacedHostname {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NamespacedHostnameVisitor;

        impl Visitor<'_> for NamespacedHostnameVisitor {
            type Value = NamespacedHostname;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string for NamespacedHostname with format namespace/hostname")
            }

            fn visit_str<E>(self, value: &str) -> Result<NamespacedHostname, E>
            where
                E: serde::de::Error,
            {
                NamespacedHostname::from_str(value).map_err(|_| {
                    serde::de::Error::invalid_value(serde::de::Unexpected::Str(value), &self)
                })
            }
        }
        deserializer.deserialize_str(NamespacedHostnameVisitor)
    }
}

impl fmt::Display for NamespacedHostname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.namespace, self.hostname)
    }
}

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct NetworkAddress {
    pub network: Strng,
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

        impl Visitor<'_> for NetworkAddressVisitor {
            type Value = NetworkAddress;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("string for NetworkAddress with format network/IP")
            }

            fn visit_str<E>(self, value: &str) -> Result<NetworkAddress, E>
            where
                E: serde::de::Error,
            {
                let Some((network, address)) = value.split_once('/') else {
                    return Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    ));
                };
                let Ok(ip_addr) = IpAddr::from_str(address) else {
                    return Err(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(value),
                        &self,
                    ));
                };
                Ok(NetworkAddress {
                    network: network.into(),
                    address: ip_addr,
                })
            }
        }
        deserializer.deserialize_str(NetworkAddressVisitor)
    }
}

impl fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.network)?;
        f.write_char('/')?;
        f.write_str(&self.address.to_string())
    }
}

pub fn network_addr(network: Strng, vip: IpAddr) -> NetworkAddress {
    NetworkAddress {
        network,
        address: vip,
    }
}

/// WorkloadIdentity provides information about a workloads identity. This is used in place of Identity
/// in places where we do not have the full identity (no trust domain) and know we are working with workloads specifically.
#[derive(Debug, Hash, Eq, PartialEq)]
struct WorkloadIdentity {
    namespace: Strng,
    service_account: Strng,
}

impl From<&Identity> for WorkloadIdentity {
    fn from(value: &Identity) -> Self {
        let Identity::Spiffe {
            namespace,
            service_account,
            ..
        } = value;
        WorkloadIdentity {
            namespace: namespace.clone(),
            service_account: service_account.clone(),
        }
    }
}

/// A WorkloadStore encapsulates all information about workloads in the mesh
#[derive(Debug)]
pub struct WorkloadStore {
    local_node: Option<Strng>,
    // TODO this could be expanded to Sender<Workload> + a full subscriber/streaming
    // model, but for now just notifying watchers to wake when _any_ insert happens
    // is simpler (and only requires a channelsize of 1)
    insert_notifier: Sender<()>,

    /// by_addr maps workload network addresses to workloads
    by_addr: HashMap<NetworkAddress, WorkloadByAddr>,
    /// by_uid maps workload UIDs to workloads
    pub(super) by_uid: HashMap<Strng, Arc<Workload>>,
    // Identity->Set of UIDs. Only stores local nodes
    node_local_by_identity: HashMap<WorkloadIdentity, HashSet<Strng>>,
}

#[derive(Debug)]
/// WorkloadByAddr is a small wrapper around a single or multiple Workloads
/// We split these as in the vast majority of cases there is only a single one, so we save vec allocation.
enum WorkloadByAddr {
    Single(Arc<Workload>),
    Many(Vec<Arc<Workload>>),
}

impl WorkloadByAddr {
    // insert adds the workload
    pub fn insert(&mut self, w: Arc<Workload>) {
        match self {
            WorkloadByAddr::Single(workload) => {
                *self = WorkloadByAddr::Many(vec![workload.clone(), w]);
            }
            WorkloadByAddr::Many(v) => {
                v.push(w);
            }
        }
    }
    // remove_uid mutates the address to remove the workload referenced by the UID.
    // If 'true' is returned, there is no workload remaining at all
    pub fn remove_uid(&mut self, uid: Strng) -> bool {
        match self {
            WorkloadByAddr::Single(wl) => {
                // Remove it if the UID matches, else do nothing
                wl.uid == uid
            }
            WorkloadByAddr::Many(ws) => {
                ws.retain(|w| w.uid != uid);
                match ws.as_slice() {
                    [] => true,
                    [wl] => {
                        // We now have one workload, transition to Single
                        *self = WorkloadByAddr::Single(wl.clone());
                        false
                    }
                    // We still have many. We removed already so no need to do anything
                    _ => false,
                }
            }
        }
    }
    pub fn get(&self) -> Arc<Workload> {
        match self {
            WorkloadByAddr::Single(workload) => workload.clone(),
            WorkloadByAddr::Many(workloads) => workloads
                .iter()
                .max_by_key(|w| {
                    // Setup a ranking criteria in the event of a conflict.
                    // We prefer pod objects, as they are not (generally) spoof-able and is the most
                    // likely to truthfully correspond to what is behind the service.
                    let is_pod = w.uid.contains("//Pod/");
                    // We fallback to looking for HBONE -- a resource marked as in the mesh is likely
                    // to have more useful context than one not in the mesh.
                    let is_hbone = w.protocol == InboundProtocol::HBONE;
                    match (is_pod, is_hbone) {
                        (true, true) => 3,
                        (true, false) => 2,
                        (false, true) => 1,
                        (false, false) => 0,
                    }
                })
                .expect("must have at least one workload")
                .clone(),
        }
    }
}

impl WorkloadStore {
    pub fn new(local_node: Option<Strng>) -> Self {
        WorkloadStore {
            local_node,
            insert_notifier: Sender::new(()),
            by_addr: Default::default(),
            node_local_by_identity: Default::default(),
            by_uid: Default::default(),
        }
    }

    // Returns a new subscriber. Note that subscribers are only guaranteed to be notified on
    // new values sent _after_ their creation, so callers should create, check current state,
    // then sub.
    pub fn new_subscriber(&self) -> Receiver<()> {
        self.insert_notifier.subscribe()
    }

    pub fn insert(&mut self, w: Arc<Workload>) {
        // First, remove the entry entirely to make sure things are cleaned up properly.
        self.remove(&w.uid);

        if w.network_mode != NetworkMode::HostNetwork {
            for ip in &w.workload_ips {
                let k = network_addr(w.network.clone(), *ip);
                self.by_addr
                    .entry(k)
                    .and_modify(|ws| ws.insert(w.clone()))
                    .or_insert_with(|| WorkloadByAddr::Single(w.clone()));
            }
        }
        self.by_uid.insert(w.uid.clone(), w.clone());
        // Only track local nodes to avoid overhead
        if self.local_node.is_none() || self.local_node.as_ref() == Some(&w.node) {
            self.node_local_by_identity
                .entry((&w.identity()).into())
                .or_default()
                .insert(w.uid.clone());
        }

        // We have stored a newly inserted workload, notify watchers
        // (if any) to wake.
        self.insert_notifier.send_replace(());
    }

    pub fn remove(&mut self, uid: &Strng) -> Option<Workload> {
        match self.by_uid.remove(uid) {
            None => {
                trace!("tried to remove workload but it was not found");
                None
            }
            Some(prev) => {
                if prev.network_mode != NetworkMode::HostNetwork {
                    for wip in prev.workload_ips.iter() {
                        if let Entry::Occupied(mut o) =
                            self.by_addr.entry(network_addr(prev.network.clone(), *wip))
                        {
                            if o.get_mut().remove_uid(prev.uid.clone()) {
                                o.remove();
                            }
                        }
                    }
                }
                let id = (&prev.identity()).into();
                if let Some(set) = self.node_local_by_identity.get_mut(&id) {
                    set.remove(&prev.uid);
                    if set.is_empty() {
                        self.node_local_by_identity.remove(&id);
                    }
                }

                Some(prev.deref().clone())
            }
        }
    }

    /// Finds the workload by address, as an arc.
    pub fn find_address(&self, addr: &NetworkAddress) -> Option<Arc<Workload>> {
        self.by_addr.get(addr).map(WorkloadByAddr::get)
    }

    /// Finds the workload by workload information, as an arc.
    pub fn find_by_info(&self, wl: &WorkloadInfo) -> Option<Arc<Workload>> {
        // We do not have an index directly on the full workload info, but we can narrow it down
        // to only workloads on the same node with the same identity -- a tiny set to iterate over
        self.node_local_by_identity
            .get(&WorkloadIdentity {
                namespace: strng::new(&wl.namespace),
                service_account: strng::new(&wl.service_account),
            })?
            .iter()
            .find_map(|uid| self.by_uid.get(uid).filter(|w| wl.matches(w)).cloned())
    }

    /// Finds the workload by uid.
    pub fn find_uid(&self, uid: &Strng) -> Option<Arc<Workload>> {
        self.by_uid.get(uid).cloned()
    }

    // was_last_identity_on_node is a specialized function to help determine if we should clear a certificate.
    // It is called when a workload is removed, with the node and identity of the workload
    pub fn was_last_identity_on_node(&self, node_name: &Strng, identity: &Identity) -> bool {
        if self.local_node.is_none() || self.local_node.as_ref() == Some(node_name) {
            // This was a workload on the node... now check if there are any remaining workloads with
            // this identity on the node.
            !self.node_local_by_identity.contains_key(&identity.into())
        } else {
            false
        }
    }
}

#[allow(clippy::enum_variant_names)]
#[derive(Error, Debug, PartialEq, Eq)]
pub enum WorkloadError {
    #[error("failed to parse namespaced hostname: {0}")]
    NamespacedHostnameParse(String),
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
    #[error("decode error: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("decode error: {0}")]
    EnumError(#[from] prost::UnknownEnumValue),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigSource;
    use crate::state::{DemandProxyState, ProxyState, ServiceResolutionMode, UpstreamDestination};
    use crate::test_helpers::helpers::initialize_telemetry;
    use crate::xds::istio::workload::PortList as XdsPortList;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::WorkloadStatus as XdsStatus;
    use crate::xds::istio::workload::WorkloadStatus;
    use crate::xds::istio::workload::load_balancing::HealthPolicy;
    use crate::xds::istio::workload::{LoadBalancing, Port as XdsPort};
    use crate::xds::{LocalClient, ProxyStateUpdateMutator};
    use crate::{cert_fetcher, test_helpers};
    use bytes::Bytes;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use prometheus_client::registry::Registry;
    use std::collections::HashSet;
    use std::default::Default;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::RwLock;
    use xds::istio::workload::NetworkAddress as XdsNetworkAddress;

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
        let (state, demand, updater) = setup_test();

        let ip1 = Ipv4Addr::new(127, 0, 0, 1);
        let ip2 = Ipv4Addr::new(127, 0, 0, 2);

        let vip2 = Ipv4Addr::new(127, 0, 1, 2);
        let vip1 = Ipv4Addr::new(127, 0, 1, 1);

        let nw_addr1 = network_addr(strng::EMPTY, IpAddr::V4(ip1));

        let xds_ip1 = Bytes::copy_from_slice(&ip1.octets());
        let xds_ip2 = Bytes::copy_from_slice(&ip2.octets());

        let service1 = HashMap::from([(
            "ns/svc1.ns.svc.cluster.local".to_string(),
            XdsPortList {
                ports: vec![XdsPort {
                    service_port: 80,
                    target_port: 8080,
                }],
            },
        )]);

        let uid1 = format!("cluster1//v1/Pod/default/my-pod/{ip1:?}");
        let uid2 = format!("cluster1//v1/Pod/default/my-pod/{ip2:?}");

        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some name".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.read().unwrap().workloads.by_addr.len(), 1);
        assert_eq!(state.read().unwrap().workloads.by_uid.len(), 1);
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            Some(Arc::new(Workload {
                uid: uid1.as_str().into(),
                workload_ips: vec![nw_addr1.address],
                name: "some name".into(),
                ..test_helpers::test_default_workload()
            }))
        );
        assert_eq!(state.read().unwrap().services.num_vips(), 0);
        assert_eq!(state.read().unwrap().services.num_services(), 0);
        assert_eq!(state.read().unwrap().services.num_staged_services(), 0);

        updater.remove(&mut state.write().unwrap(), &"/invalid".into());
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            Some(Arc::new(Workload {
                uid: uid1.as_str().into(),
                workload_ips: vec![nw_addr1.address],
                name: "some name".into(),
                ..test_helpers::test_default_workload()
            }))
        );

        updater.remove(&mut state.write().unwrap(), &uid2.as_str().into());
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            Some(Arc::new(Workload {
                uid: uid1.as_str().into(),
                workload_ips: vec![nw_addr1.address],
                name: "some name".into(),
                ..test_helpers::test_default_workload()
            }))
        );

        updater.remove(&mut state.write().unwrap(), &uid1.as_str().into());
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            None
        );
        assert_eq!(state.read().unwrap().workloads.by_addr.len(), 0);
        assert_eq!(state.read().unwrap().workloads.by_uid.len(), 0);

        // Add two workloads into the VIP. Add out of order to further test
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some name".into(),
                    services: service1.clone(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.read().unwrap().services.num_vips(), 0);
        assert_eq!(state.read().unwrap().services.num_services(), 0);
        assert_eq!(state.read().unwrap().services.num_staged_services(), 1);

        updater
            .insert_service(
                &mut state.write().unwrap(),
                XdsService {
                    name: "svc1".to_string(),
                    namespace: "ns".to_string(),
                    hostname: "svc1.ns.svc.cluster.local".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vip1.octets().to_vec(),
                    }],
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 80,
                    }],
                    subject_alt_names: vec![],
                    waypoint: None,
                    load_balancing: None,
                    ip_families: 0,
                    extensions: Default::default(),
                },
            )
            .unwrap();
        assert_eq!((state.read().unwrap().services.num_vips()), 1);
        assert_eq!((state.read().unwrap().services.num_services()), 1);
        assert_eq!((state.read().unwrap().services.num_staged_services()), 0);

        // upsert the service to ensure the old endpoints (no longer staged) are carried over
        updater
            .insert_service(
                &mut state.write().unwrap(),
                XdsService {
                    name: "svc1".to_string(),
                    namespace: "ns".to_string(),
                    hostname: "svc1.ns.svc.cluster.local".to_string(),
                    addresses: vec![
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: vip1.octets().to_vec(), // old endpoints associated with this address should be carried over
                        },
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: vip2.octets().to_vec(), // new address just to test upsert
                        },
                    ],
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 80,
                    }],
                    subject_alt_names: vec![],
                    waypoint: None,
                    load_balancing: None,
                    ip_families: 0,
                    extensions: Default::default(),
                },
            )
            .unwrap();

        assert_eq!((state.read().unwrap().services.num_vips()), 2); // there are now two addresses on the same service
        assert_eq!((state.read().unwrap().services.num_services()), 1); // there is still only one service
        assert_eq!((state.read().unwrap().services.num_staged_services()), 0);

        // we need to ensure both copies of the service stored are the same.
        // this is important because we mutate the endpoints on a service in place
        // when we upsert a service (we grab any old endpoints and combine with staged ones)
        assert_eq!(
            (state
                .read()
                .unwrap()
                .services
                .get_by_namespaced_host(&NamespacedHostname {
                    namespace: "ns".into(),
                    hostname: "svc1.ns.svc.cluster.local".into(),
                })
                .unwrap()),
            (state
                .read()
                .unwrap()
                .services
                .get_by_vip(&NetworkAddress {
                    network: strng::EMPTY,
                    address: IpAddr::V4(vip1),
                })
                .unwrap()),
        );

        // ensure we updated the old service, no duplication
        assert_eq!((state.read().unwrap().services.num_vips()), 2); // there are now two addresses on the same service
        assert_eq!((state.read().unwrap().services.num_services()), 1); // there is still only one service

        // upsert the service to remove an address and ensure services_by_ip map is properly cleaned up
        updater
            .insert_service(
                &mut state.write().unwrap(),
                XdsService {
                    name: "svc1".to_string(),
                    namespace: "ns".to_string(),
                    hostname: "svc1.ns.svc.cluster.local".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vip1.octets().to_vec(),
                    }],
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 80,
                    }],
                    subject_alt_names: vec![],
                    waypoint: None,
                    load_balancing: None,
                    ip_families: 0,
                    extensions: Default::default(),
                },
            )
            .unwrap();

        assert_eq!(state.read().unwrap().services.num_vips(), 1); // we removed an address in upsert
        assert_eq!(state.read().unwrap().services.num_services(), 1);
        assert_eq!(state.read().unwrap().services.num_staged_services(), 0);

        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid2.to_owned(),
                    addresses: vec![xds_ip2.clone()],
                    name: "some name2".to_string(),
                    services: service1.clone(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.read().unwrap().services.num_vips(), 1);
        assert_eq!(state.read().unwrap().services.num_services(), 1);
        assert_eq!(state.read().unwrap().services.num_staged_services(), 0); // vip already in a service, should not be staged

        // we need to ensure both copies of the service stored are the same.
        // this is important because we mutate the service endpoints in place
        // when workloads arrive later than the service
        assert_eq!(
            (state
                .read()
                .unwrap()
                .services
                .get_by_namespaced_host(&NamespacedHostname {
                    namespace: "ns".into(),
                    hostname: "svc1.ns.svc.cluster.local".into()
                })
                .unwrap()),
            (state
                .read()
                .unwrap()
                .services
                .get_by_vip(&NetworkAddress {
                    network: strng::EMPTY,
                    address: IpAddr::V4(vip1),
                })
                .unwrap()),
        );

        assert_vips(&demand, vec!["some name", "some name2"]);
        updater.remove(&mut state.write().unwrap(), &uid2.as_str().into());

        // we need to ensure both copies of the service stored are the same.
        // this is important because we mutate the service endpoints in place
        // when workloads it selects are removed
        assert_eq!(
            (state
                .read()
                .unwrap()
                .services
                .get_by_namespaced_host(&NamespacedHostname {
                    namespace: "ns".into(),
                    hostname: "svc1.ns.svc.cluster.local".into()
                })
                .unwrap()),
            (state
                .read()
                .unwrap()
                .services
                .get_by_vip(&NetworkAddress {
                    network: strng::EMPTY,
                    address: IpAddr::V4(vip1),
                })
                .unwrap()),
        );

        assert_vips(&demand, vec!["some name"]);
        updater.remove(&mut state.write().unwrap(), &uid1.as_str().into());
        assert_vips(&demand, vec![]);

        // Add 2 workload with VIP
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some name".to_string(),
                    services: service1.clone(),
                    ..Default::default()
                },
            )
            .unwrap();
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid2.to_owned(),
                    addresses: vec![xds_ip2.clone()],
                    name: "some name2".to_string(),
                    services: service1.clone(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_vips(&demand, vec!["some name", "some name2"]);
        // now update it without the VIP
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1,
                    addresses: vec![xds_ip1],
                    name: "some name".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        // Should be remove
        assert_vips(&demand, vec!["some name2"]);
        // now update it with unhealthy
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid2,
                    addresses: vec![xds_ip2],
                    name: "some name2".to_string(),
                    services: service1,
                    status: XdsStatus::Unhealthy as i32,
                    ..Default::default()
                },
            )
            .unwrap();
        // Should be removed
        assert_vips(&demand, vec![]);

        // Remove the VIP entirely
        updater.remove(
            &mut state.write().unwrap(),
            &"ns/svc1.ns.svc.cluster.local".into(),
        );
        assert_eq!(state.read().unwrap().services.num_vips(), 0);
        assert_eq!((state.read().unwrap().services.num_services()), 0);
    }

    #[test]
    fn overlapping_workload_ip() {
        let (state, _, updater) = setup_test();

        let ip1 = Ipv4Addr::new(127, 0, 0, 1);

        let nw_addr1 = network_addr(strng::EMPTY, IpAddr::V4(ip1));

        let xds_ip1 = Bytes::copy_from_slice(&ip1.octets());

        let uid1 = "cluster1//Pod/default/my-pod/a".to_string();
        let uid2 = "cluster1/networking.istio.io/WorkloadEntry/default/myns".to_string();

        // Insert two workloads with the same IP
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some pod".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid2.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some we".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        // Insert the same object again (i.e. and update)
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some pod".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.read().unwrap().workloads.by_addr.len(), 1);
        assert_eq!(state.read().unwrap().workloads.by_uid.len(), 2);
        {
            let read = state.read().unwrap();
            let WorkloadByAddr::Many(wls) = read.workloads.by_addr.get(&nw_addr1).unwrap() else {
                panic!("unexpected workload");
            };
            assert_eq!(wls.len(), 2);
        }
        // We should get the pod
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            Some(Arc::new(Workload {
                uid: uid1.as_str().into(),
                workload_ips: vec![nw_addr1.address],
                name: "some pod".into(),
                ..test_helpers::test_default_workload()
            }))
        );

        // Remove one...
        updater.remove(&mut state.write().unwrap(), &uid1.as_str().into());
        assert_eq!(state.read().unwrap().workloads.by_addr.len(), 1);
        assert_eq!(state.read().unwrap().workloads.by_uid.len(), 1);
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            Some(Arc::new(Workload {
                uid: uid2.as_str().into(),
                workload_ips: vec![nw_addr1.address],
                name: "some we".into(),
                ..test_helpers::test_default_workload()
            }))
        );

        // Remove the last one
        updater.remove(&mut state.write().unwrap(), &uid2.as_str().into());
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            None,
        );

        assert_eq!(state.read().unwrap().workloads.by_addr.len(), 0);
        assert_eq!(state.read().unwrap().workloads.by_uid.len(), 0);
    }

    #[test]
    fn unhealthy_workloads_staged() {
        let (state, _, updater) = setup_test();
        let services = HashMap::from([
            (
                "ns/svc-normal".to_string(),
                XdsPortList {
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            ),
            (
                "ns/svc-allow-unhealthy".to_string(),
                XdsPortList {
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            ),
        ]);
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: "uid1".to_owned(),
                    name: "unhealthy".to_string(),
                    addresses: vec![],
                    services: services.clone(),
                    status: WorkloadStatus::Unhealthy as i32,
                    ..Default::default()
                },
            )
            .unwrap();
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: "uid2".to_owned(),
                    name: "healthy".to_string(),
                    addresses: vec![],
                    services: services.clone(),
                    status: WorkloadStatus::Healthy as i32,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(state.read().unwrap().services.num_staged_services(), 2);

        let vip2 = Ipv4Addr::new(127, 0, 1, 2);
        let vip1 = Ipv4Addr::new(127, 0, 1, 1);
        updater
            .insert_service(
                &mut state.write().unwrap(),
                XdsService {
                    name: "svc1".to_string(),
                    namespace: "ns".to_string(),
                    hostname: "svc-normal".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vip1.octets().to_vec(),
                    }],
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 80,
                    }],
                    subject_alt_names: vec![],
                    waypoint: None,
                    load_balancing: None,
                    ip_families: 0,
                    extensions: Default::default(),
                },
            )
            .unwrap();
        updater
            .insert_service(
                &mut state.write().unwrap(),
                XdsService {
                    name: "svc1".to_string(),
                    namespace: "ns".to_string(),
                    hostname: "svc-allow-unhealthy".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vip2.octets().to_vec(),
                    }],
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 80,
                    }],
                    subject_alt_names: vec![],
                    waypoint: None,
                    load_balancing: Some(LoadBalancing {
                        routing_preference: vec![],
                        mode: 0,
                        health_policy: HealthPolicy::AllowAll as i32,
                    }),
                    ip_families: 0,
                    extensions: Default::default(),
                },
            )
            .unwrap();

        let svc = state
            .read()
            .unwrap()
            .services
            .get_by_namespaced_host(&NamespacedHostname {
                namespace: "ns".into(),
                hostname: "svc-allow-unhealthy".into(),
            });
        assert_eq!(svc.unwrap().endpoints.inner.len(), 2);
        let svc = state
            .read()
            .unwrap()
            .services
            .get_by_namespaced_host(&NamespacedHostname {
                namespace: "ns".into(),
                hostname: "svc-normal".into(),
            });
        assert_eq!(svc.unwrap().endpoints.inner.len(), 1);
    }

    #[test]
    fn unhealthy_workloads() {
        let (state, _, updater) = setup_test();

        let vip2 = Ipv4Addr::new(127, 0, 1, 2);
        let vip1 = Ipv4Addr::new(127, 0, 1, 1);
        let svc = XdsService {
            name: "svc1".to_string(),
            namespace: "ns".to_string(),
            hostname: "svc-allow-unhealthy".to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "".to_string(),
                address: vip2.octets().to_vec(),
            }],
            ports: vec![XdsPort {
                service_port: 80,
                target_port: 80,
            }],
            subject_alt_names: vec![],
            waypoint: None,
            load_balancing: Some(LoadBalancing {
                routing_preference: vec![],
                mode: 0,
                health_policy: HealthPolicy::AllowAll as i32,
            }),
            ip_families: 0,
            extensions: Default::default(),
        };
        updater
            .insert_service(
                &mut state.write().unwrap(),
                XdsService {
                    name: "svc1".to_string(),
                    namespace: "ns".to_string(),
                    hostname: "svc-normal".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vip1.octets().to_vec(),
                    }],
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 80,
                    }],
                    subject_alt_names: vec![],
                    waypoint: None,
                    load_balancing: None,
                    ip_families: 0,
                    extensions: Default::default(),
                },
            )
            .unwrap();
        updater
            .insert_service(&mut state.write().unwrap(), svc.clone())
            .unwrap();

        let services = HashMap::from([
            (
                "ns/svc-normal".to_string(),
                XdsPortList {
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            ),
            (
                "ns/svc-allow-unhealthy".to_string(),
                XdsPortList {
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            ),
        ]);
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: "uid1".to_owned(),
                    name: "unhealthy".to_string(),
                    addresses: vec![],
                    services: services.clone(),
                    status: WorkloadStatus::Unhealthy as i32,
                    ..Default::default()
                },
            )
            .unwrap();
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: "uid2".to_owned(),
                    name: "healthy".to_string(),
                    addresses: vec![],
                    services: services.clone(),
                    status: WorkloadStatus::Healthy as i32,
                    ..Default::default()
                },
            )
            .unwrap();

        let assert = |host: &str, want: usize| {
            let s = state
                .read()
                .unwrap()
                .services
                .get_by_namespaced_host(&NamespacedHostname {
                    namespace: "ns".into(),
                    hostname: host.into(),
                });
            assert_eq!(
                s.unwrap().endpoints.inner.len(),
                want,
                "host {host} wanted {want}"
            );
        };
        assert("svc-allow-unhealthy", 2);
        assert("svc-normal", 1);

        // Switch the service to not allow unhealthy
        let mut swapped = svc.clone();
        swapped.load_balancing = None;
        updater
            .insert_service(&mut state.write().unwrap(), swapped)
            .unwrap();
        assert("svc-allow-unhealthy", 1);
        assert("svc-normal", 1);

        // Switch the service to allow unhealthy again
        let mut swapped = svc.clone();
        swapped.load_balancing = Some(LoadBalancing {
            routing_preference: vec![],
            mode: 0,
            health_policy: HealthPolicy::AllowAll as i32,
        });
        updater
            .insert_service(&mut state.write().unwrap(), swapped)
            .unwrap();
        // TODO: this is not currently supported. The endpoints set on services is not reconcile, but rather
        // incrementally updated on adds/updates/removes. Since we don't store unhealthy endpoints,
        // we cannot add them back.
        // A fix for this would be to always store endpoints and make sure we filter them out where needed.
        assert("svc-allow-unhealthy", 1);
        assert("svc-normal", 1);
    }
    #[test]
    fn staged_services_cleanup() {
        let (state, demand, updater) = setup_test();
        assert_eq!((state.read().unwrap().workloads.by_addr.len()), 0);
        assert_eq!((state.read().unwrap().workloads.by_uid.len()), 0);
        assert_eq!((state.read().unwrap().services.num_vips()), 0);
        assert_eq!((state.read().unwrap().services.num_services()), 0);
        assert_eq!((state.read().unwrap().services.num_staged_services()), 0);

        let xds_ip1 = Bytes::copy_from_slice(&[127, 0, 0, 1]);
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let uid1 = format!("cluster1//v1/Pod/default/my-pod/{ip1:?}");

        let services = HashMap::from([(
            "ns/svc1.ns.svc.cluster.local".to_string(),
            XdsPortList {
                ports: vec![XdsPort {
                    service_port: 80,
                    target_port: 8080,
                }],
            },
        )]);
        assert_vips(&demand, vec![]);

        // Add 2 workload with service
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some name".to_string(),
                    services: services.clone(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!((state.read().unwrap().services.num_staged_services()), 1);

        // now update it without the service
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1.clone()],
                    name: "some name".to_string(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!((state.read().unwrap().services.num_staged_services()), 0); // should remove the VIP if no longer needed

        // Add 2 workload with service again
        updater
            .insert_workload(
                &mut state.write().unwrap(),
                XdsWorkload {
                    uid: uid1.to_owned(),
                    addresses: vec![xds_ip1],
                    name: "some name".to_string(),
                    services,
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!((state.read().unwrap().services.num_staged_services()), 1); // VIP should be staged again

        updater.remove(&mut state.write().unwrap(), &uid1.into());
        assert_eq!((state.read().unwrap().services.num_staged_services()), 0); // should remove the VIP if no longer needed
    }

    fn setup_test() -> (
        Arc<RwLock<ProxyState>>,
        DemandProxyState,
        ProxyStateUpdateMutator,
    ) {
        initialize_telemetry();
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let demand = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );
        let updater = ProxyStateUpdateMutator::new_no_fetch();
        (state, demand, updater)
    }

    #[track_caller]
    fn assert_vips(state: &DemandProxyState, want: Vec<&str>) {
        let mut wants: HashSet<String> = HashSet::from_iter(want.iter().map(|x| x.to_string()));
        let mut found: HashSet<String> = HashSet::new();
        // VIP has randomness. We will try to fetch the VIP 1k times and assert the we got the expected results
        // at least once, and no unexpected results
        let wl: Workload = (XdsWorkload {
            name: "some name".into(),
            ..Default::default()
        })
        .try_into()
        .unwrap();
        for _ in 0..1000 {
            if let Some(UpstreamDestination::UpstreamParts(workload, _, _)) = state.state.read().unwrap().find_upstream(
                strng::EMPTY,
                &wl,
                "127.0.1.1:80".parse().unwrap(),
                ServiceResolutionMode::Standard,
            ) {
                let n = &workload.name; // borrow name instead of cloning
                found.insert(n.to_string()); // insert an owned copy of the borrowed n
                wants.remove(&n.to_string()); // remove using the borrow
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
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("localhost.yaml"),
        );
        let (state, demand, _) = setup_test();
        let local_client = LocalClient {
            cfg,
            state: state.clone(),
            cert_fetcher: Arc::new(cert_fetcher::NoCertFetcher()),
            local_node: None,
        };
        local_client.run().await.expect("client should run");
        let wl = demand
            .state
            .read()
            .unwrap()
            .workloads
            .find_address(&network_addr(strng::EMPTY, "127.0.0.1".parse().unwrap()));
        // Make sure we get a valid workload
        assert!(wl.is_some());
        assert_eq!(wl.as_ref().unwrap().service_account, "default");

        let (port, svc) = match demand
            .state
            .read()
            .unwrap()
            .find_upstream(
                strng::EMPTY,
                wl.as_ref().unwrap(),
                "127.10.0.1:80".parse().unwrap(),
                ServiceResolutionMode::Standard,
            )
        {
            Some(UpstreamDestination::UpstreamParts(_, port, svc)) => (port, svc),
            _ => panic!("should get"),
        };
        // Make sure we get a valid VIP
        assert_eq!(port, 8080);
        assert_eq!(
            svc.unwrap().subject_alt_names,
            vec!["spiffe://cluster.local/ns/default/sa/local".to_string()]
        );

        // test that we can have a service in another network than workloads it selects
        let port = match demand
            .state
            .read()
            .unwrap()
            .find_upstream(
                "remote".into(),
                wl.as_ref().unwrap(),
                "127.10.0.2:80".parse().unwrap(),
                ServiceResolutionMode::Standard,
            )
            {
                Some(UpstreamDestination::UpstreamParts(_, port, _)) => port,
                _ => panic!("should get"),
            };
        // Make sure we get a valid VIP
        assert_eq!(port, 8080);
    }
}
