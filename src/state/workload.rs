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

use crate::xds;
use crate::xds::istio::workload::{Port, PortList};
use bytes::Bytes;
use serde::de::Visitor;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use std::collections::HashMap;
use std::convert::Into;
use std::default::Default;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::{fmt, net};
use thiserror::Error;
use tracing::{error, trace};
use xds::istio::workload::GatewayAddress as XdsGatewayAddress;
use xds::istio::workload::Workload as XdsWorkload;

#[derive(
    Default, Debug, Hash, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize,
)]
pub enum Protocol {
    #[default]
    TCP,
    HBONE,
}

impl From<xds::istio::workload::TunnelProtocol> for Protocol {
    fn from(value: xds::istio::workload::TunnelProtocol) -> Self {
        match value {
            xds::istio::workload::TunnelProtocol::Hbone => Protocol::HBONE,
            xds::istio::workload::TunnelProtocol::None => Protocol::TCP,
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
    pub hbone_single_tls_port: Option<u16>,
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

pub mod address {
    use crate::state::service::Service;
    use crate::state::workload::Workload;

    #[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
    #[serde(untagged)]
    pub enum Address {
        Workload(Box<Workload>),
        Service(Box<Service>),
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
    #[serde(default, skip_serializing_if = "is_default")]
    pub gateway_address: Option<SocketAddr>,

    #[serde(default)]
    pub protocol: Protocol,

    #[serde(default, skip_serializing_if = "is_default")]
    pub uid: String,
    #[serde(default)]
    pub name: String,
    pub namespace: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub trust_domain: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub service_account: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub network: String,

    #[serde(default, skip_serializing_if = "is_default")]
    pub workload_name: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub workload_type: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub canonical_name: String,
    #[serde(default, skip_serializing_if = "is_default")]
    pub canonical_revision: String,

    #[serde(default, skip_serializing_if = "is_default")]
    pub hostname: String,

    #[serde(default, skip_serializing_if = "is_default")]
    pub node: String,

    #[serde(default, skip_serializing_if = "is_default")]
    pub native_tunnel: bool,

    #[serde(default, skip_serializing_if = "is_default")]
    pub authorization_policies: Vec<String>,

    #[serde(default)]
    pub status: HealthStatus,

    #[serde(default)]
    pub cluster_id: String,
}

fn is_default<T: Default + PartialEq>(t: &T) -> bool {
    *t == Default::default()
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
            return match &gw_address.destination {
                gatewayaddress::Destination::Hostname(_) => Err(WaypointError::UnsupportedFeature(
                    "hostname lookup not supported yet".to_string(),
                )),
                gatewayaddress::Destination::Address(ip) => Ok(Some(ip.address)),
            };
        }
        Ok(None)
    }
}

impl fmt::Display for Workload {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Workload{{{} with uid {} via {} ({:?})}}",
            self.name,
            self.uid,
            self.gateway_address
                .map(|x| format!("{x}"))
                .unwrap_or_else(|| "None".into()),
            self.protocol
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
                        hbone_mtls_port: value.hbone_mtls_port as u16,
                        hbone_single_tls_port: if value.hbone_single_tls_port == 0 {
                            None
                        } else {
                            Some(value.hbone_single_tls_port as u16)
                        },
                    }
                }
                xds::istio::workload::gateway_address::Destination::Hostname(hn) => {
                    GatewayAddress {
                        destination: gatewayaddress::Destination::Hostname(NamespacedHostname {
                            namespace: hn.namespace.clone(),
                            hostname: hn.hostname.clone(),
                        }),
                        hbone_mtls_port: value.hbone_mtls_port as u16,
                        hbone_single_tls_port: if value.hbone_single_tls_port == 0 {
                            None
                        } else {
                            Some(value.hbone_single_tls_port as u16)
                        },
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

        let addresses = resource
            .addresses
            .iter()
            .map(byte_to_ip)
            .collect::<Result<Vec<_>, _>>()?;

        let workload_type = resource.workload_type().as_str_name().to_lowercase();
        Ok(Workload {
            workload_ips: addresses,
            waypoint: wp,
            network_gateway: network_gw,
            gateway_address: None,

            protocol: Protocol::from(xds::istio::workload::TunnelProtocol::try_from(
                resource.tunnel_protocol,
            )?),

            uid: resource.uid,
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
            hostname: resource.hostname,
            network: resource.network,
            workload_name: resource.workload_name,
            workload_type,
            canonical_name: resource.canonical_name,
            canonical_revision: resource.canonical_revision,

            status: HealthStatus::from(xds::istio::workload::WorkloadStatus::try_from(
                resource.status,
            )?),

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
    pub namespace: String,
    pub hostname: String,
}

impl FromStr for NamespacedHostname {
    type Err = WorkloadError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some((namespace, hostname)) = value.split_once('/') else {
            return Err(WorkloadError::NamespacedHostnameParse(value.to_string()));
        };
        Ok(Self {
            namespace: namespace.to_string(),
            hostname: hostname.to_string(),
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

        impl<'de> Visitor<'de> for NamespacedHostnameVisitor {
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
        write!(f, "{}/{}", self.network, self.address)
    }
}

pub fn network_addr(network: &str, vip: IpAddr) -> NetworkAddress {
    NetworkAddress {
        network: network.to_owned(),
        address: vip,
    }
}

/// A WorkloadStore encapsulates all information about workloads in the mesh
#[derive(serde::Serialize, Default, Debug)]
pub struct WorkloadStore {
    /// byAddress maps workload network addresses to workloads
    by_addr: HashMap<NetworkAddress, Arc<Workload>>,
    /// byUid maps workload UIDs to workloads
    by_uid: HashMap<String, Arc<Workload>>,
    /// byHostname maps workload hostname to workloads.
    by_hostname: HashMap<String, Arc<Workload>>,
}

impl WorkloadStore {
    pub fn insert(&mut self, w: Workload) -> anyhow::Result<()> {
        // First, remove the entry entirely to make sure things are cleaned up properly.
        self.remove(w.uid.as_str());

        let w = Arc::new(w);
        for ip in &w.workload_ips {
            self.by_addr
                .insert(network_addr(&w.network, *ip), w.clone());
        }
        if !w.hostname.is_empty() {
            self.by_hostname.insert(w.hostname.clone(), w.clone());
        }
        self.by_uid.insert(w.uid.clone(), w.clone());
        Ok(())
    }

    pub fn remove(&mut self, uid: &str) -> Option<Workload> {
        match self.by_uid.remove(uid) {
            None => {
                trace!("tried to remove workload keyed by {} but it was not found; presumably it was a service", uid);
                None
            }
            Some(prev) => {
                for wip in prev.workload_ips.iter() {
                    self.by_addr.remove(&network_addr(&prev.network, *wip));
                }
                self.by_hostname.remove(prev.hostname.as_str());
                Some(prev.deref().clone())
            }
        }
    }

    /// Finds the workload by address.
    pub fn find_address(&self, addr: &NetworkAddress) -> Option<Workload> {
        self.by_addr.get(addr).map(|wl| wl.deref().clone())
    }

    /// Finds the workload by hostname.
    pub fn find_hostname<T: AsRef<str>>(&self, hostname: T) -> Option<Workload> {
        self.by_hostname
            .get(hostname.as_ref())
            .map(|wl| wl.deref().clone())
    }

    /// Finds the workload by uid.
    pub fn find_uid(&self, uid: &str) -> Option<Workload> {
        self.by_uid.get(uid).map(|wl| wl.deref().clone())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigSource;
    use crate::state::{DemandProxyState, ProxyState};
    use crate::test_helpers::helpers::initialize_telemetry;
    use crate::xds::istio::workload::Port as XdsPort;
    use crate::xds::istio::workload::PortList as XdsPortList;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::WorkloadStatus as XdsStatus;
    use crate::xds::{LocalClient, ProxyStateUpdateMutator};
    use crate::{cert_fetcher, test_helpers};
    use bytes::Bytes;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
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
        initialize_telemetry();
        let state = Arc::new(RwLock::new(ProxyState::default()));
        let demand = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        let updater = ProxyStateUpdateMutator::new_no_fetch();

        let ip1 = Ipv4Addr::new(127, 0, 0, 1);
        let ip2 = Ipv4Addr::new(127, 0, 0, 2);

        let vip2 = Ipv4Addr::new(127, 0, 1, 2);
        let vip1 = Ipv4Addr::new(127, 0, 1, 1);

        let nw_addr1 = network_addr("", IpAddr::V4(ip1));

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

        let uid1 = format!("cluster1//v1/Pod/default/my-pod/{:?}", ip1);
        let uid2 = format!("cluster1//v1/Pod/default/my-pod/{:?}", ip2);

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
            Some(Workload {
                uid: uid1.to_owned(),
                workload_ips: vec![nw_addr1.address],
                name: "some name".to_string(),
                ..test_helpers::test_default_workload()
            })
        );
        assert_eq!(state.read().unwrap().services.num_vips(), 0);
        assert_eq!(state.read().unwrap().services.num_services(), 0);
        assert_eq!(state.read().unwrap().services.num_staged_services(), 0);

        updater.remove(&mut state.write().unwrap(), &"/invalid".to_string());
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            Some(Workload {
                uid: uid1.to_owned(),
                workload_ips: vec![nw_addr1.address],
                name: "some name".to_string(),
                ..test_helpers::test_default_workload()
            })
        );

        updater.remove(&mut state.write().unwrap(), &uid2);
        assert_eq!(
            state.read().unwrap().workloads.find_address(&nw_addr1),
            Some(Workload {
                uid: uid1.to_owned(),
                workload_ips: vec![nw_addr1.address],
                name: "some name".to_string(),
                ..test_helpers::test_default_workload()
            })
        );

        updater.remove(&mut state.write().unwrap(), &uid1);
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
                    name: "some name".to_string(),
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
                    namespace: "ns".to_string(),
                    hostname: "svc1.ns.svc.cluster.local".to_string(),
                })
                .unwrap()),
            (state
                .read()
                .unwrap()
                .services
                .get_by_vip(&NetworkAddress {
                    network: "".to_string(),
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
                    namespace: "ns".to_string(),
                    hostname: "svc1.ns.svc.cluster.local".to_string()
                })
                .unwrap()),
            (state
                .read()
                .unwrap()
                .services
                .get_by_vip(&NetworkAddress {
                    network: "".to_string(),
                    address: IpAddr::V4(vip1),
                })
                .unwrap()),
        );

        assert_vips(&demand, vec!["some name", "some name2"]);
        updater.remove(&mut state.write().unwrap(), &uid2);

        // we need to ensure both copies of the service stored are the same.
        // this is important because we mutate the service endpoints in place
        // when workloads it selects are removed
        assert_eq!(
            (state
                .read()
                .unwrap()
                .services
                .get_by_namespaced_host(&NamespacedHostname {
                    namespace: "ns".to_string(),
                    hostname: "svc1.ns.svc.cluster.local".to_string()
                })
                .unwrap()),
            (state
                .read()
                .unwrap()
                .services
                .get_by_vip(&NetworkAddress {
                    network: "".to_string(),
                    address: IpAddr::V4(vip1),
                })
                .unwrap()),
        );

        assert_vips(&demand, vec!["some name"]);
        updater.remove(&mut state.write().unwrap(), &uid1);
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
            &"ns/svc1.ns.svc.cluster.local".to_string(),
        );
        assert_eq!(state.read().unwrap().services.num_vips(), 0);
        assert_eq!((state.read().unwrap().services.num_services()), 0);
    }

    #[test]
    fn staged_services_cleanup() {
        initialize_telemetry();
        let state = Arc::new(RwLock::new(ProxyState::default()));
        let demand = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        let updater = ProxyStateUpdateMutator::new_no_fetch();
        assert_eq!((state.read().unwrap().workloads.by_addr.len()), 0);
        assert_eq!((state.read().unwrap().workloads.by_uid.len()), 0);
        assert_eq!((state.read().unwrap().services.num_vips()), 0);
        assert_eq!((state.read().unwrap().services.num_services()), 0);
        assert_eq!((state.read().unwrap().services.num_staged_services()), 0);

        let xds_ip1 = Bytes::copy_from_slice(&[127, 0, 0, 1]);
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let uid1 = format!("cluster1//v1/Pod/default/my-pod/{:?}", ip1);

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

        updater.remove(&mut state.write().unwrap(), &uid1);
        assert_eq!((state.read().unwrap().services.num_staged_services()), 0); // should remove the VIP if no longer needed
    }

    #[track_caller]
    fn assert_vips(state: &DemandProxyState, want: Vec<&str>) {
        let mut wants: HashSet<String> = HashSet::from_iter(want.iter().map(|x| x.to_string()));
        let mut found: HashSet<String> = HashSet::new();
        // VIP has randomness. We will try to fetch the VIP 1k times and assert the we got the expected results
        // at least once, and no unexpected results
        for _ in 0..1000 {
            if let Some(us) = state
                .state
                .read()
                .unwrap()
                .find_upstream("", "127.0.1.1:80".parse().unwrap())
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
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("examples")
                .join("localhost.yaml"),
        );
        let state = Arc::new(RwLock::new(ProxyState::default()));
        let demand = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        let local_client = LocalClient {
            cfg,
            state: state.clone(),
            cert_fetcher: Arc::new(cert_fetcher::NoCertFetcher()),
        };
        local_client.run().await.expect("client should run");
        let wl = demand
            .state
            .read()
            .unwrap()
            .workloads
            .find_address(&network_addr("", "127.0.0.1".parse().unwrap()));
        // Make sure we get a valid workload
        assert!(wl.is_some());
        assert_eq!(wl.unwrap().service_account, "default");
        let us = demand
            .state
            .read()
            .unwrap()
            .find_upstream("", "127.10.0.1:80".parse().unwrap());
        // Make sure we get a valid VIP
        assert!(us.is_some());
        assert_eq!(us.clone().unwrap().port, 8080);
        assert_eq!(
            us.unwrap().sans,
            vec!["spiffe://cluster.local/ns/default/sa/local".to_string()]
        );

        // test that we can have a service in another network than workloads it selects
        let us = demand
            .state
            .read()
            .unwrap()
            .find_upstream("remote", "127.10.0.2:80".parse().unwrap());
        // Make sure we get a valid VIP
        assert!(us.is_some());
        assert_eq!(us.unwrap().port, 8080);
    }
}
