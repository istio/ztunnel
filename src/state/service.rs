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
use ipnet::IpNet;
use itertools::Itertools;
use serde::{Deserializer, Serializer};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::trace;

use xds::istio::workload::Service as XdsService;

use crate::state::workload::{
    GatewayAddress, NamespacedHostname, NetworkAddress, NetworkCidr, Workload, WorkloadError,
    byte_to_ip, network_addr, network_cidr,
};
use crate::state::workload::{HealthStatus, is_default};
use crate::strng::Strng;
use crate::xds::istio::workload::load_balancing::Scope as XdsScope;
use crate::xds::istio::workload::{IpFamilies, PortList};
use crate::{strng, xds};

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Service {
    pub name: Strng,
    pub namespace: Strng,
    pub hostname: Strng,
    pub vips: Vec<NetworkAddress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cidr_vips: Vec<NetworkCidr>,
    pub ports: HashMap<u16, u16>,

    /// Maps endpoint UIDs to service [Endpoint]s.
    #[serde(default)]
    pub endpoints: EndpointSet,
    #[serde(default)]
    pub subject_alt_names: Vec<Strng>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub waypoint: Option<GatewayAddress>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub load_balancer: Option<LoadBalancer>,

    #[serde(default, skip_serializing_if = "is_default")]
    pub ip_families: Option<IpFamily>,

    #[serde(default)]
    pub canonical: bool,
}

/// EndpointSet is an abstraction over a set of endpoints.
/// While this is currently not very useful, merely wrapping a HashMap, the intent is to make this future
/// proofed to future enhancements, such as keeping track of load balancing information the ability
/// to incrementally update.
#[derive(Debug, Eq, PartialEq, Clone, Default)]
pub struct EndpointSet {
    pub inner: HashMap<Strng, Arc<Endpoint>>,
}

impl serde::Serialize for EndpointSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.inner.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EndpointSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        <HashMap<Strng, Arc<Endpoint>>>::deserialize(deserializer)
            .map(|inner| EndpointSet { inner })
    }
}

impl EndpointSet {
    pub fn from_list<const N: usize>(eps: [Endpoint; N]) -> EndpointSet {
        let mut endpoints = HashMap::with_capacity(eps.len());
        for ep in eps.into_iter() {
            endpoints.insert(ep.workload_uid.clone(), Arc::new(ep));
        }
        EndpointSet { inner: endpoints }
    }

    pub fn insert(&mut self, k: Strng, v: Endpoint) {
        self.inner.insert(k, Arc::new(v));
    }

    pub fn contains(&self, key: &Strng) -> bool {
        self.inner.contains_key(key)
    }

    pub fn get(&self, key: &Strng) -> Option<&Endpoint> {
        self.inner.get(key).map(Arc::as_ref)
    }

    pub fn remove(&mut self, key: &Strng) {
        self.inner.remove(key);
    }

    pub fn iter(&self) -> impl Iterator<Item = &Endpoint> {
        self.inner.values().map(Arc::as_ref)
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum LoadBalancerMode {
    // Do not consider LoadBalancerScopes when picking endpoints
    Standard,
    // Only select endpoints matching all LoadBalancerScopes when picking endpoints; otherwise, fail.
    Strict,
    // Prefer select endpoints matching all LoadBalancerScopes when picking endpoints but allow mismatches
    Failover,
    // In PASSTHROUGH mode, endpoint selection will not be done and traffic passes directly through to the original
    // desitnation address.
    Passthrough,
}

impl From<xds::istio::workload::load_balancing::Mode> for LoadBalancerMode {
    fn from(value: xds::istio::workload::load_balancing::Mode) -> Self {
        match value {
            xds::istio::workload::load_balancing::Mode::Strict => LoadBalancerMode::Strict,
            xds::istio::workload::load_balancing::Mode::Failover => LoadBalancerMode::Failover,
            xds::istio::workload::load_balancing::Mode::UnspecifiedMode => {
                LoadBalancerMode::Standard
            }
            xds::istio::workload::load_balancing::Mode::Passthrough => {
                LoadBalancerMode::Passthrough
            }
        }
    }
}

#[derive(Default, Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum LoadBalancerHealthPolicy {
    #[default]
    OnlyHealthy,
    AllowAll,
}

impl From<xds::istio::workload::load_balancing::HealthPolicy> for LoadBalancerHealthPolicy {
    fn from(value: xds::istio::workload::load_balancing::HealthPolicy) -> Self {
        match value {
            xds::istio::workload::load_balancing::HealthPolicy::OnlyHealthy => {
                LoadBalancerHealthPolicy::OnlyHealthy
            }
            xds::istio::workload::load_balancing::HealthPolicy::AllowAll => {
                LoadBalancerHealthPolicy::AllowAll
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
pub enum LoadBalancerScopes {
    Region,
    Zone,
    Subzone,
    Node,
    Cluster,
    Network,
}

impl TryFrom<XdsScope> for LoadBalancerScopes {
    type Error = WorkloadError;
    fn try_from(value: XdsScope) -> Result<Self, Self::Error> {
        match value {
            XdsScope::Region => Ok(LoadBalancerScopes::Region),
            XdsScope::Zone => Ok(LoadBalancerScopes::Zone),
            XdsScope::Subzone => Ok(LoadBalancerScopes::Subzone),
            XdsScope::Node => Ok(LoadBalancerScopes::Node),
            XdsScope::Cluster => Ok(LoadBalancerScopes::Cluster),
            XdsScope::Network => Ok(LoadBalancerScopes::Network),
            _ => Err(WorkloadError::EnumParse("invalid target".to_string())),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LoadBalancer {
    pub routing_preferences: Vec<LoadBalancerScopes>,
    pub mode: LoadBalancerMode,
    pub health_policy: LoadBalancerHealthPolicy,
}

impl From<xds::istio::workload::IpFamilies> for Option<IpFamily> {
    fn from(value: xds::istio::workload::IpFamilies) -> Self {
        match value {
            IpFamilies::Automatic => None,
            IpFamilies::Ipv4Only => Some(IpFamily::IPv4),
            IpFamilies::Ipv6Only => Some(IpFamily::IPv6),
            IpFamilies::Dual => Some(IpFamily::Dual),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum IpFamily {
    Dual,
    IPv4,
    IPv6,
}

impl IpFamily {
    /// accepts_ip returns true if the provided IP is supposed by the IP family
    pub fn accepts_ip(&self, ip: IpAddr) -> bool {
        match self {
            IpFamily::Dual => true,
            IpFamily::IPv4 => ip.is_ipv4(),
            IpFamily::IPv6 => ip.is_ipv6(),
        }
    }
}

impl Service {
    pub fn namespaced_hostname(&self) -> NamespacedHostname {
        NamespacedHostname {
            namespace: self.namespace.clone(),
            hostname: self.hostname.clone(),
        }
    }

    pub fn contains_endpoint(&self, wl: &Workload) -> bool {
        self.endpoints.contains(&wl.uid)
    }

    pub fn should_include_endpoint(&self, ep_health: HealthStatus) -> bool {
        ep_health == HealthStatus::Healthy
            || self
                .load_balancer
                .as_ref()
                .map(|lb| lb.health_policy == LoadBalancerHealthPolicy::AllowAll)
                .unwrap_or(false)
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize)]
pub struct ServiceDescription {
    pub hostname: Strng,
    pub name: Strng,
    pub namespace: Strng,
}

impl From<&Service> for ServiceDescription {
    fn from(value: &Service) -> Self {
        ServiceDescription {
            hostname: value.hostname.clone(),
            name: value.name.clone(),
            namespace: value.namespace.clone(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    /// The workload UID for this endpoint.
    pub workload_uid: Strng,

    /// The port mapping.
    pub port: HashMap<u16, u16>,

    /// Health status for the endpoint
    pub status: HealthStatus,
}

impl TryFrom<&XdsService> for Service {
    type Error = WorkloadError;

    fn try_from(s: &XdsService) -> Result<Self, Self::Error> {
        let mut nw_addrs = Vec::new();
        let mut cidr_vips = Vec::new();
        for addr in &s.addresses {
            let ip = byte_to_ip(&Bytes::copy_from_slice(&addr.address))?;
            let network = strng::new(&addr.network);
            let max_prefix: u32 = if ip.is_ipv4() { 32 } else { 128 };
            match addr.length {
                Some(pl) if pl != max_prefix => {
                    let cidr = IpNet::new(ip, pl as u8)?;
                    cidr_vips.push(network_cidr(network, cidr));
                }
                _ => {
                    nw_addrs.push(network_addr(network, ip));
                }
            }
        }
        let waypoint = match &s.waypoint {
            Some(w) => Some(GatewayAddress::try_from(w)?),
            None => None,
        };
        let lb = if let Some(lb) = &s.load_balancing {
            Some(LoadBalancer {
                routing_preferences: lb
                    .routing_preference
                    .iter()
                    .map(|r| {
                        xds::istio::workload::load_balancing::Scope::try_from(*r)
                            .map_err(WorkloadError::EnumError)
                            .and_then(|r| r.try_into())
                    })
                    .collect::<Result<Vec<LoadBalancerScopes>, WorkloadError>>()?,
                mode: xds::istio::workload::load_balancing::Mode::try_from(lb.mode)?.into(),
                health_policy: xds::istio::workload::load_balancing::HealthPolicy::try_from(
                    lb.health_policy,
                )?
                .into(),
            })
        } else {
            None
        };
        let ip_families = xds::istio::workload::IpFamilies::try_from(s.ip_families)?.into();
        let svc = Service {
            name: Strng::from(&s.name),
            namespace: Strng::from(&s.namespace),
            hostname: Strng::from(&s.hostname),
            vips: nw_addrs,
            cidr_vips,
            ports: (&PortList {
                ports: s.ports.clone(),
            })
                .into(),
            endpoints: Default::default(), // Will be populated once inserted into the store.
            subject_alt_names: s.subject_alt_names.iter().map(strng::new).collect(),
            waypoint,
            load_balancer: lb,
            ip_families,
            canonical: s.canonical,
        };
        Ok(svc)
    }
}

/// Data store for service information.
#[derive(Default, Debug)]
pub struct ServiceStore {
    /// Maintains a mapping of service key -> (endpoint UID -> workload endpoint)
    /// this is used to handle ordering issues if workloads are received before services.
    pub(super) staged_services: HashMap<NamespacedHostname, HashMap<Strng, Endpoint>>,

    /// Allows for lookup of services by network address, the service's xds secondary key.
    /// Multiple services in different namespaces may share the same VIP.
    pub(super) by_vip: HashMap<NetworkAddress, Vec<Arc<Service>>>,

    /// Allows for lookup of services by CIDR VIP. Checked as a fallback when exact VIP
    /// lookup misses, using longest-prefix-match semantics.
    pub(super) by_cidr_vip: Vec<(NetworkCidr, Arc<Service>)>,

    /// Allows for lookup of services by hostname, and then by namespace. XDS uses a combination
    /// of hostname and namespace as the primary key. In most cases, there will be a single
    /// service for a given hostname. However, `ServiceEntry` allows hostnames to be overridden
    /// on a per-namespace basis.
    pub(super) by_host: HashMap<Strng, Vec<Arc<Service>>>,
}

impl ServiceStore {
    /// Returns the list of [Service]s matching the given VIP. Multiple services in
    /// different namespaces may share the same VIP.
    pub fn get_by_vip(&self, vip: &NetworkAddress) -> Option<Vec<Arc<Service>>> {
        self.by_vip.get(vip).map(|v| v.to_vec())
    }

    /// Returns the "best" [Service] matching the given VIP.
    /// If a namespace is provided, a Service from that namespace is preferred.
    /// Next, a Service marked `canonical` is preferred.
    /// Falls back to CIDR matching with longest-prefix-match if no exact VIP match.
    pub fn get_best_by_vip(
        &self,
        vip: &NetworkAddress,
        ns: Option<&Strng>,
    ) -> Option<Arc<Service>> {
        let services = self.get_by_vip(vip).or_else(|| self.get_by_cidr_vip(vip))?;
        Some(ServiceMatch::find_best_match(services.iter(), ns, None)?.clone())
    }

    /// Returns all services whose CIDR VIPs contain the given address,
    /// filtered to the longest matching prefix length.
    fn get_by_cidr_vip(&self, vip: &NetworkAddress) -> Option<Vec<Arc<Service>>> {
        let mut best_prefix: Option<u8> = None;
        let mut matches: Vec<Arc<Service>> = Vec::new();
        for (nc, svc) in &self.by_cidr_vip {
            if nc.network == vip.network && nc.cidr.contains(&vip.address) {
                let pl = nc.cidr.prefix_len();
                match best_prefix {
                    Some(bp) if pl > bp => {
                        best_prefix = Some(pl);
                        matches.clear();
                        matches.push(svc.clone());
                    }
                    Some(bp) if pl == bp => {
                        matches.push(svc.clone());
                    }
                    None => {
                        best_prefix = Some(pl);
                        matches.push(svc.clone());
                    }
                    _ => {}
                }
            }
        }
        if matches.is_empty() {
            None
        } else {
            Some(matches)
        }
    }

    /// Returns the list of [Service]s matching the given hostname. Istio `ServiceEntry`
    /// affords the ability to define the same hostname (e.g. `www.google.com`) in different
    /// namespaces. In most cases, only a single [Service] will be returned.
    ///
    /// # Arguments
    ///
    /// * `hostname` - the hostname of the service.
    pub fn get_by_host(&self, hostname: &Strng) -> Option<Vec<Arc<Service>>> {
        self.by_host.get(hostname).map(|v| v.to_vec())
    }

    // Returns the "best" [Srevice] matching the given hostname.
    // If a namespace is provided, a Service from that namespace is preferred.
    // Next, a Service marked `canonical` is prerferred.
    pub fn get_best_by_host(&self, hostname: &Strng, ns: Option<&Strng>) -> Option<Arc<Service>> {
        let services = self.get_by_host(hostname)?;
        Some(ServiceMatch::find_best_match(services.iter(), ns, None)?.clone())
    }

    pub fn get_by_workload(&self, workload: &Workload) -> Vec<Arc<Service>> {
        workload
            .services
            .iter()
            .filter_map(|s| self.get_by_namespaced_host(s))
            .collect()
    }

    /// Returns the [Service] matching the given namespace and hostname. Istio `ServiceEntry`
    /// affords the ability to define the same hostname (e.g. `www.google.com`) in different
    /// namespaces. This method will return the [Service] for the requested namespace.
    ///
    /// # Arguments
    ///
    /// * `host` - the namespaced hostname.
    pub fn get_by_namespaced_host(&self, host: &NamespacedHostname) -> Option<Arc<Service>> {
        // Get the list of services that match the hostname. Typically there will only be one, but
        // ServiceEntry allows configuring arbitrary hostnames on a per-namespace basis.
        match self.by_host.get(&host.hostname) {
            None => None,
            Some(services) => {
                // Return the service that matches the requested namespace.
                for service in services {
                    if service.namespace == host.namespace {
                        return Some(service.clone());
                    }
                }
                None
            }
        }
    }

    /// Adds an endpoint for the service VIP.
    pub fn insert_endpoint(&mut self, service_name: NamespacedHostname, ep: Endpoint) {
        let ep_uid = ep.workload_uid.clone();
        if let Some(svc) = self.get_by_namespaced_host(&service_name) {
            // We may or may not accept the endpoint based on it's health
            if !svc.should_include_endpoint(ep.status) {
                trace!(
                    "service doesn't accept pod with status {:?}, skip",
                    ep.status
                );
                return;
            }
            let mut svc = Arc::unwrap_or_clone(svc);

            // Clone the service and add the endpoint.
            svc.endpoints.insert(ep_uid, ep);

            // Update the service.
            self.insert_endpoint_update(svc);
        } else {
            // We received workload endpoints, but don't have the Service yet.
            // This can happen due to ordering issues.
            trace!("pod has service {}, but service not found", service_name);

            // Add a staged entry. This will be added to the service once we receive it.
            self.staged_services
                .entry(service_name.clone())
                .or_default()
                .insert(ep_uid, ep.clone());
        }
    }

    /// Removes entries for the given endpoint address.
    pub fn remove_endpoint(&mut self, prev_workload: &Workload) {
        let mut services_to_update = HashSet::new();
        let workload_uid = &prev_workload.uid;
        for svc in prev_workload.services.iter() {
            // Remove the endpoint from the staged services.
            self.staged_services
                .entry(svc.clone())
                .or_default()
                .remove(workload_uid);
            if self.staged_services[svc].is_empty() {
                self.staged_services.remove(svc);
            }

            services_to_update.insert(svc.clone());
        }

        // Now remove the endpoint from all Services.
        for svc in &services_to_update {
            if let Some(svc) = self.get_by_namespaced_host(svc) {
                let mut svc = Arc::unwrap_or_clone(svc);
                svc.endpoints.remove(workload_uid);

                // Update the service.
                self.insert_endpoint_update(svc);
            }
        }
    }

    /// Adds the given service.
    pub fn insert(&mut self, service: Service) {
        self.insert_internal(service, false)
    }

    /// insert_endpoint_update is like insert, but optimized for the case where we know only endpoints change.
    pub fn insert_endpoint_update(&mut self, service: Service) {
        self.insert_internal(service, true)
    }

    fn insert_internal(&mut self, mut service: Service, endpoint_update_only: bool) {
        let namespaced_hostname = service.namespaced_hostname();
        // If we're replacing an existing service, remove the old one from all data structures.
        if !endpoint_update_only {
            // First add any staged service endpoints. Due to ordering issues, we may have received
            // the workloads before their associated services.
            if let Some(endpoints) = self.staged_services.remove(&namespaced_hostname) {
                trace!(
                    "staged service found, inserting {} endpoints",
                    endpoints.len()
                );
                for (wip, ep) in endpoints {
                    if service.should_include_endpoint(ep.status) {
                        service.endpoints.insert(wip.clone(), ep);
                    }
                }
            }

            let _ = self.remove(&namespaced_hostname);
        }

        // Create the Arc.
        let service = Arc::new(service);
        let hostname = &service.hostname;

        // Map the vips to the service.
        for vip in &service.vips {
            match self.by_vip.get_mut(vip) {
                None => {
                    self.by_vip.insert(vip.clone(), vec![service.clone()]);
                }
                Some(services) => {
                    if let Some((cur, _)) = services
                        .iter()
                        .find_position(|s| s.namespace == service.namespace)
                    {
                        services[cur] = service.clone();
                    } else {
                        services.push(service.clone());
                    }
                }
            }
        }
        for cidr in &service.cidr_vips {
            self.by_cidr_vip.push((cidr.clone(), service.clone()));
        }

        // Map the hostname to the service.
        match self.by_host.get_mut(hostname) {
            None => {
                let _ = self.by_host.insert(hostname.clone(), vec![service.clone()]);
            }
            Some(services) => {
                if let Some((cur, _)) = services
                    .iter()
                    .find_position(|s| s.namespace == service.namespace)
                {
                    // Service already exists; replace the slot
                    services[cur] = service.clone()
                } else {
                    // No service exists yet, append it
                    services.push(service.clone());
                }
            }
        }
    }

    /// Removes the service for the given host and namespace, and returns whether something was removed
    pub fn remove(&mut self, namespaced_host: &NamespacedHostname) -> bool {
        match self.by_host.get_mut(&namespaced_host.hostname) {
            None => false,
            Some(services) => {
                // Remove the previous service from the by_host map.
                let Some(prev) = ({
                    let mut prev = None;
                    for i in 0..services.len() {
                        if services[i].namespace == namespaced_host.namespace {
                            // Remove this service from the list.
                            prev = Some(services.remove(i));

                            // If the the services list is empty, remove the entire entry.
                            if services.is_empty() {
                                self.by_host.remove(&namespaced_host.hostname);
                            }
                            break;
                        }
                    }
                    prev
                }) else {
                    // Not found.
                    return false;
                };

                // Remove the entries for the previous service VIPs.
                prev.vips.iter().for_each(|addr| {
                    if let Some(vip_services) = self.by_vip.get_mut(addr) {
                        vip_services.retain(|s| s.namespace != prev.namespace);
                        if vip_services.is_empty() {
                            self.by_vip.remove(addr);
                        }
                    }
                });
                let prev_host = prev.namespaced_hostname();
                self.by_cidr_vip
                    .retain(|(_, svc)| svc.namespaced_hostname() != prev_host);

                // Remove the staged service.
                // TODO(nmittler): no endpoints for this service should be staged at this point.
                self.staged_services.remove(namespaced_host);

                // Remove successful.
                true
            }
        }
    }

    #[cfg(test)]
    pub fn num_vips(&self) -> usize {
        self.by_vip.len()
    }

    #[cfg(test)]
    pub fn num_services(&self) -> usize {
        let mut count = 0;
        for (_, value) in self.by_host.iter() {
            count += value.len();
        }
        count
    }

    #[cfg(test)]
    pub fn num_staged_services(&self) -> usize {
        self.staged_services.len()
    }
}

/// Represents the reason a service was matched during lookup.
/// Used with fold_while to implement priority-based service selection
/// with short-circuit on best match (namespace + primary hostname).
///
/// Priority order (lower is better): Namespace > Canonical > First
pub enum ServiceMatch<'a> {
    Canonical(&'a Arc<Service>),
    Namespace(&'a Arc<Service>),
    PreferredNamespace(&'a Arc<Service>),
    First(&'a Arc<Service>),
    None,
}

impl<'a> From<ServiceMatch<'a>> for Option<&'a Arc<Service>> {
    fn from(value: ServiceMatch<'a>) -> Option<&'a Arc<Service>> {
        match value {
            ServiceMatch::Canonical(s)
            | ServiceMatch::First(s)
            | ServiceMatch::Namespace(s)
            | ServiceMatch::PreferredNamespace(s) => Some(s),
            ServiceMatch::None => None,
        }
    }
}

impl<'a> ServiceMatch<'a> {
    /// Finds the best matching service from an iterator using fold_while.
    /// Short-circuits on Namespace match - the best possible result.
    pub fn find_best_match(
        mut services: impl Iterator<Item = &'a Arc<Service>>,
        client_ns: Option<&Strng>,
        preferred_namespace: Option<&Strng>,
    ) -> Option<&'a Arc<Service>> {
        services
            .fold_while(ServiceMatch::None, |r, s| {
                if Some(&s.namespace) == client_ns {
                    itertools::FoldWhile::Done(ServiceMatch::Namespace(s))
                } else if s.canonical {
                    itertools::FoldWhile::Continue(ServiceMatch::Canonical(s))
                } else {
                    // TODO: deprecate preferred_service_namespace
                    // https://github.com/istio/ztunnel/issues/1709
                    if let Some(preferred_namespace) = preferred_namespace
                        && preferred_namespace == &s.namespace
                        && !matches!(r, ServiceMatch::Canonical(_))
                    {
                        return itertools::FoldWhile::Continue(ServiceMatch::PreferredNamespace(s));
                    }
                    match r {
                        ServiceMatch::None => {
                            itertools::FoldWhile::Continue(ServiceMatch::First(s))
                        }
                        _ => itertools::FoldWhile::Continue(r),
                    }
                }
            })
            .into_inner()
            .into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::workload::{NetworkCidr, network_cidr};
    use ipnet::IpNet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn nw(ip: IpAddr) -> NetworkAddress {
        NetworkAddress {
            address: ip,
            network: crate::strng::EMPTY,
        }
    }

    fn make_service(name: &str, ns: &str, vips: Vec<IpAddr>, cidrs: Vec<IpNet>) -> Service {
        Service {
            name: name.into(),
            namespace: ns.into(),
            hostname: format!("{name}.{ns}.svc.cluster.local").into(),
            vips: vips.into_iter().map(nw).collect(),
            cidr_vips: cidrs
                .into_iter()
                .map(|c| network_cidr(crate::strng::EMPTY, c))
                .collect(),
            ports: HashMap::new(),
            endpoints: EndpointSet::from_list([]),
            subject_alt_names: vec![],
            waypoint: None,
            load_balancer: None,
            ip_families: None,
            canonical: false,
        }
    }

    fn cidr(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn ip6(segments: [u16; 8]) -> IpAddr {
        IpAddr::V6(Ipv6Addr::from(segments))
    }

    #[test]
    fn shared_vip_different_namespaces() {
        let mut store = ServiceStore::default();
        let shared = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let only_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let only_b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        let ns_a: Strng = "ns-a".into();
        let ns_b: Strng = "ns-b".into();

        let svc_a = make_service("svc", "ns-a", vec![shared, only_a], vec![]);
        let svc_b = make_service("svc", "ns-b", vec![shared, only_b], vec![]);

        store.insert(svc_a);
        store.insert(svc_b);

        assert_eq!(store.num_vips(), 3);
        assert_eq!(store.num_services(), 2);

        let all = store.get_by_vip(&nw(shared)).unwrap();
        assert_eq!(all.len(), 2);

        assert_eq!(store.get_by_vip(&nw(only_a)).unwrap().len(), 1);
        assert_eq!(store.get_by_vip(&nw(only_b)).unwrap().len(), 1);

        assert_eq!(
            store
                .get_best_by_vip(&nw(shared), Some(&ns_a))
                .unwrap()
                .namespace,
            ns_a,
        );
        assert_eq!(
            store
                .get_best_by_vip(&nw(shared), Some(&ns_b))
                .unwrap()
                .namespace,
            ns_b,
        );

        assert_eq!(
            store
                .get_best_by_vip(&nw(only_a), Some(&ns_b))
                .unwrap()
                .namespace,
            ns_a,
        );
        assert_eq!(
            store
                .get_best_by_vip(&nw(only_b), Some(&ns_a))
                .unwrap()
                .namespace,
            ns_b,
        );

        assert!(store.get_best_by_vip(&nw(shared), None).is_some());

        store.remove(&NamespacedHostname {
            namespace: "ns-a".into(),
            hostname: "svc.ns-a.svc.cluster.local".into(),
        });
        assert_eq!(store.num_vips(), 2);
        assert_eq!(store.num_services(), 1);

        let all = store.get_by_vip(&nw(shared)).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].namespace, ns_b);

        assert!(store.get_by_vip(&nw(only_a)).is_none());
        assert!(store.get_by_vip(&nw(only_b)).is_some());

        store.remove(&NamespacedHostname {
            namespace: "ns-b".into(),
            hostname: "svc.ns-b.svc.cluster.local".into(),
        });
        assert_eq!(store.num_vips(), 0);
        assert_eq!(store.num_services(), 0);
        assert!(store.get_by_vip(&nw(shared)).is_none());
        assert!(store.get_by_vip(&nw(only_b)).is_none());
    }

    #[test]
    fn cidr_match_v4() {
        let mut store = ServiceStore::default();
        store.insert(make_service("svc", "ns", vec![], vec![cidr("10.0.0.0/24")]));

        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).is_some());
        assert!(
            store
                .get_best_by_vip(&nw(ip(10, 0, 0, 255)), None)
                .is_some()
        );
        assert!(store.get_best_by_vip(&nw(ip(10, 0, 1, 5)), None).is_none());
    }

    #[test]
    fn cidr_match_v6() {
        let mut store = ServiceStore::default();
        store.insert(make_service("svc", "ns", vec![], vec![cidr("fd00::/112")]));

        // Inside the /112
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 5])), None)
                .is_some()
        );
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 0xffff])), None)
                .is_some()
        );
        // Outside the /112
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 1, 0])), None)
                .is_none()
        );
        // Different prefix entirely
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd01, 0, 0, 0, 0, 0, 0, 5])), None)
                .is_none()
        );
    }

    #[test]
    fn longest_prefix_match_v4() {
        let mut store = ServiceStore::default();
        store.insert(make_service(
            "wide",
            "ns",
            vec![],
            vec![cidr("10.0.0.0/16")],
        ));
        store.insert(make_service(
            "narrow",
            "ns",
            vec![],
            vec![cidr("10.0.0.0/24")],
        ));

        let svc = store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).unwrap();
        assert_eq!(svc.name, "narrow");

        let svc = store.get_best_by_vip(&nw(ip(10, 0, 1, 5)), None).unwrap();
        assert_eq!(svc.name, "wide");
    }

    #[test]
    fn longest_prefix_match_v6() {
        let mut store = ServiceStore::default();
        store.insert(make_service("wide", "ns", vec![], vec![cidr("fd00::/48")]));
        store.insert(make_service(
            "narrow",
            "ns",
            vec![],
            vec![cidr("fd00::/112")],
        ));

        // Inside both, /112 wins
        let svc = store
            .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 5])), None)
            .unwrap();
        assert_eq!(svc.name, "narrow");

        // Outside /112 but inside /48
        let svc = store
            .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 1, 0])), None)
            .unwrap();
        assert_eq!(svc.name, "wide");
    }

    #[test]
    fn dual_stack_cidr() {
        let mut store = ServiceStore::default();
        // A single service with both v4 and v6 CIDRs
        store.insert(make_service(
            "dual",
            "ns",
            vec![],
            vec![cidr("10.0.0.0/24"), cidr("fd00::/112")],
        ));

        // v4 matches
        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).is_some());
        // v6 matches
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 5])), None)
                .is_some()
        );
        // v4 outside range
        assert!(store.get_best_by_vip(&nw(ip(10, 0, 1, 5)), None).is_none());
        // v6 outside range
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 1, 0])), None)
                .is_none()
        );
    }

    #[test]
    fn cidr_family_mismatch() {
        let mut store = ServiceStore::default();
        store.insert(make_service("v4", "ns", vec![], vec![cidr("10.0.0.0/24")]));
        store.insert(make_service("v6", "ns", vec![], vec![cidr("fd00::/112")]));

        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 5])), None)
                .is_some()
        );
        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).is_some());

        // IPv4 addresses should never match IPv6 CIDRs.
        assert!(
            store
                .get_best_by_vip(&nw(ip(0xfd, 0, 0, 0)), None)
                .is_none()
        );
        // IPv6 addresses should never match IPv4 CIDRs.
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0x0a00, 0, 0, 0, 0, 0, 0, 5])), None)
                .is_none()
        );
    }

    #[test]
    fn exact_v4_with_cidr_v6() {
        let mut store = ServiceStore::default();
        // Service with exact v4 VIP and v6 CIDR
        store.insert(make_service(
            "mixed",
            "ns",
            vec![ip(10, 0, 0, 1)],
            vec![cidr("fd00::/112")],
        ));

        // Exact v4 match
        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 1)), None).is_some());
        // v6 CIDR match
        assert!(
            store
                .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 5])), None)
                .is_some()
        );
        // v4 not in exact set
        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 2)), None).is_none());
    }

    #[test]
    fn exact_match_priority_over_cidr_v4() {
        let mut store = ServiceStore::default();
        store.insert(make_service(
            "cidr-svc",
            "ns",
            vec![],
            vec![cidr("10.0.0.0/24")],
        ));
        store.insert(make_service(
            "exact-svc",
            "ns",
            vec![ip(10, 0, 0, 5)],
            vec![],
        ));

        let svc = store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).unwrap();
        assert_eq!(svc.name, "exact-svc");

        let svc = store.get_best_by_vip(&nw(ip(10, 0, 0, 6)), None).unwrap();
        assert_eq!(svc.name, "cidr-svc");
    }

    #[test]
    fn exact_match_priority_over_cidr_v6() {
        let mut store = ServiceStore::default();
        store.insert(make_service(
            "cidr-svc",
            "ns",
            vec![],
            vec![cidr("fd00::/112")],
        ));
        store.insert(make_service(
            "exact-svc",
            "ns",
            vec![ip6([0xfd00, 0, 0, 0, 0, 0, 0, 5])],
            vec![],
        ));

        let svc = store
            .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 5])), None)
            .unwrap();
        assert_eq!(svc.name, "exact-svc");

        let svc = store
            .get_best_by_vip(&nw(ip6([0xfd00, 0, 0, 0, 0, 0, 0, 6])), None)
            .unwrap();
        assert_eq!(svc.name, "cidr-svc");
    }

    #[test]
    fn cidr_network_scoping() {
        let mut store = ServiceStore::default();
        let svc = Service {
            name: "svc".into(),
            namespace: "ns".into(),
            hostname: "svc.ns.svc.cluster.local".into(),
            vips: vec![],
            cidr_vips: vec![NetworkCidr {
                network: "net-a".into(),
                cidr: cidr("10.0.0.0/24"),
            }],
            ports: HashMap::new(),
            endpoints: EndpointSet::from_list([]),
            subject_alt_names: vec![],
            waypoint: None,
            load_balancer: None,
            ip_families: None,
            canonical: false,
        };
        store.insert(svc);

        let addr_a = NetworkAddress {
            network: "net-a".into(),
            address: ip(10, 0, 0, 5),
        };
        assert!(store.get_best_by_vip(&addr_a, None).is_some());

        let addr_b = NetworkAddress {
            network: "net-b".into(),
            address: ip(10, 0, 0, 5),
        };
        assert!(store.get_best_by_vip(&addr_b, None).is_none());
    }

    #[test]
    fn cidr_remove_cleanup() {
        let mut store = ServiceStore::default();
        store.insert(make_service("svc", "ns", vec![], vec![cidr("10.0.0.0/24")]));

        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).is_some());

        store.remove(&NamespacedHostname {
            namespace: "ns".into(),
            hostname: "svc.ns.svc.cluster.local".into(),
        });

        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).is_none());
        assert!(store.by_cidr_vip.is_empty());
    }

    #[test]
    fn overlapping_cidr_different_namespaces() {
        let mut store = ServiceStore::default();
        store.insert(make_service(
            "svc",
            "ns-a",
            vec![],
            vec![cidr("10.0.0.0/24")],
        ));
        store.insert(make_service(
            "svc",
            "ns-b",
            vec![],
            vec![cidr("10.0.0.0/24")],
        ));

        assert_eq!(store.by_cidr_vip.len(), 2);

        let ns_a: Strng = "ns-a".into();
        let ns_b: Strng = "ns-b".into();

        assert_eq!(
            store
                .get_best_by_vip(&nw(ip(10, 0, 0, 5)), Some(&ns_a))
                .unwrap()
                .namespace,
            ns_a,
        );
        assert_eq!(
            store
                .get_best_by_vip(&nw(ip(10, 0, 0, 5)), Some(&ns_b))
                .unwrap()
                .namespace,
            ns_b,
        );

        store.remove(&NamespacedHostname {
            namespace: "ns-a".into(),
            hostname: "svc.ns-a.svc.cluster.local".into(),
        });
        assert_eq!(store.by_cidr_vip.len(), 1);
        let svc = store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).unwrap();
        assert_eq!(svc.namespace, "ns-b");

        store.remove(&NamespacedHostname {
            namespace: "ns-b".into(),
            hostname: "svc.ns-b.svc.cluster.local".into(),
        });
        assert!(store.by_cidr_vip.is_empty());
        assert!(store.get_best_by_vip(&nw(ip(10, 0, 0, 5)), None).is_none());
    }
}
