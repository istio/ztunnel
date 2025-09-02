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
use itertools::Itertools;
use serde::{Deserializer, Serializer};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::trace;

use xds::istio::workload::Service as XdsService;

use crate::state::workload::{
    GatewayAddress, NamespacedHostname, NetworkAddress, Workload, WorkloadError, byte_to_ip,
    network_addr,
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
            },
            xds::istio::workload::load_balancing::Mode::Passthrough => LoadBalancerMode::Passthrough,
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
        for addr in &s.addresses {
            let network_address = network_addr(
                strng::new(&addr.network),
                byte_to_ip(&Bytes::copy_from_slice(&addr.address))?,
            );
            nw_addrs.push(network_address);
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
            ports: (&PortList {
                ports: s.ports.clone(),
            })
                .into(),
            endpoints: Default::default(), // Will be populated once inserted into the store.
            subject_alt_names: s.subject_alt_names.iter().map(strng::new).collect(),
            waypoint,
            load_balancer: lb,
            ip_families,
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
    pub(super) by_vip: HashMap<NetworkAddress, Arc<Service>>,

    /// Allows for lookup of services by hostname, and then by namespace. XDS uses a combination
    /// of hostname and namespace as the primary key. In most cases, there will be a single
    /// service for a given hostname. However, `ServiceEntry` allows hostnames to be overridden
    /// on a per-namespace basis.
    pub(super) by_host: HashMap<Strng, Vec<Arc<Service>>>,
}

impl ServiceStore {
    /// Returns the [Service] matching the given VIP.
    pub fn get_by_vip(&self, vip: &NetworkAddress) -> Option<Arc<Service>> {
        self.by_vip.get(vip).cloned()
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
            self.by_vip.insert(vip.clone(), service.clone());
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
                    self.by_vip.remove(addr);
                });

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
