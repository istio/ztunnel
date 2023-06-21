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

use crate::state::workload::{
    byte_to_ip, network_addr, NamespacedHostname, NetworkAddress, WorkloadError,
};
use crate::xds;
use crate::xds::istio::workload::PortList;
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::ops::Deref;
use std::sync::Arc;
use tracing::trace;
use xds::istio::workload::Service as XdsService;

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub namespace: String,
    pub hostname: String,
    pub vips: Vec<NetworkAddress>,
    pub ports: HashMap<u16, u16>,

    /// Maps workload endpoint addresses to [Endpoint]s.
    #[serde(default)]
    pub endpoints: HashMap<NetworkAddress, Endpoint>,
    #[serde(default)]
    pub subject_alt_names: Vec<String>,
}

impl Service {
    pub fn namespaced_hostname(&self) -> NamespacedHostname {
        NamespacedHostname {
            namespace: self.namespace.clone(),
            hostname: self.hostname.clone(),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Endpoint {
    /// The service VIP for this endpoint.
    pub vip: NetworkAddress,

    /// The workload address.
    pub address: NetworkAddress,

    /// The port mapping.
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
            vips: nw_addrs,
            ports: (&PortList {
                ports: s.ports.clone(),
            })
                .into(),
            endpoints: Default::default(), // Will be populated once inserted into the store.
            subject_alt_names: s.subject_alt_names.clone(),
        };
        Ok(svc)
    }
}

/// Data store for service information.
#[derive(serde::Serialize, Default, Debug)]
pub struct ServiceStore {
    /// Maintains a mapping of service IP -> (workload IP -> workload endpoint)
    /// this is used to handle ordering issues if workloads with VIPs are received before services.
    staged_vips: HashMap<NetworkAddress, HashMap<NetworkAddress, Endpoint>>,

    /// Maintains a mapping of workload IP to VIP. This is used only to handle removal of service
    /// endpoints when a workload is removed.
    workload_to_vips: HashMap<NetworkAddress, HashSet<NetworkAddress>>,

    /// Allows for lookup of services by network address, the service's xds secondary key.
    by_vip: HashMap<NetworkAddress, Arc<Service>>,

    /// Allows for lookup of services by hostname, and then by namespace. XDS uses a combination
    /// of hostname and namespace as the primary key. In most cases, there will be a single
    /// service for a given hostname. However, `ServiceEntry` allows hostnames to be overridden
    /// on a per-namespace basis.
    by_host: HashMap<String, Vec<Arc<Service>>>,
}

impl ServiceStore {
    /// Returns the [Service] matching the given VIP.
    pub fn get_by_vip(&self, vip: &NetworkAddress) -> Option<Service> {
        self.by_vip.get(vip).map(|s| s.deref().clone())
    }

    /// Returns the list of [Service]s matching the given hostname. Istio `ServiceEntry`
    /// affords the ability to define the same hostname (e.g. `www.google.com`) in different
    /// namespaces. In most cases, only a single [Service] will be returned.
    ///
    /// # Arguments
    ///
    /// * `hostname` - the hostname of the service.
    pub fn get_by_host(&self, hostname: &String) -> Option<Vec<Service>> {
        self.by_host.get(hostname).map(|services| {
            services
                .iter()
                .map(|service| service.deref().clone())
                .collect()
        })
    }

    /// Returns the [Service] matching the given namespace and hostname. Istio `ServiceEntry`
    /// affords the ability to define the same hostname (e.g. `www.google.com`) in different
    /// namespaces. This method will return the [Service] for the requested namespace.
    ///
    /// # Arguments
    ///
    /// * `host` - the namespaced hostname.
    pub fn get_by_namespaced_host(&self, host: &NamespacedHostname) -> Option<Service> {
        // Get the list of services that match the hostname. Typically there will only be one, but
        // ServiceEntry allows configuring arbitrary hostnames on a per-namespace basis.
        match self.by_host.get(&host.hostname) {
            None => None,
            Some(services) => {
                // Return the service that matches the requested namespace.
                for service in services {
                    if service.namespace == host.namespace {
                        return Some(service.deref().clone());
                    }
                }
                None
            }
        }
    }

    /// Adds an endpoint for the service VIP.
    pub fn insert_endpoint(&mut self, ep: Endpoint) {
        if let Some(svc) = self.by_vip.get(&ep.vip) {
            // Clone the service and add the endpoint.
            let mut svc = svc.deref().clone();
            svc.endpoints.insert(ep.address.clone(), ep);

            // Update the service.
            self.insert(svc);
        } else {
            // We received workload endpoints, but don't have the Service yet.
            // This can happen due to ordering issues.
            trace!("pod has VIP {}, but VIP not found", ep.vip);

            // Add a staged entry. This will be added to the service once we receive it.
            self.staged_vips
                .entry(ep.vip.clone())
                .or_default()
                .insert(ep.address.clone(), ep.clone());

            // Insert a mapping from the workload address to the VIP.
            self.workload_to_vips
                .entry(ep.address.clone())
                .or_default()
                .insert(ep.vip.clone());
        }
    }

    /// Removes entries for the given endpoint address.
    pub fn remove_endpoint(&mut self, addr: &NetworkAddress) {
        // Remove the endpoint from the VIP map.
        let Some(prev_vips) = self.workload_to_vips.remove(addr) else {
            return;
        };

        for vip in prev_vips.iter() {
            // Remove the endpoint from the staged VIPs map.
            self.staged_vips
                .entry(vip.to_owned())
                .or_default()
                .remove(addr);
            if self.staged_vips[vip].is_empty() {
                self.staged_vips.remove(vip);
            }

            // Remove the endpoint from the service.
            if let Some(service) = self.by_vip.get(vip) {
                // Clone the service and remove the endpoint.
                let mut service = service.deref().clone();
                service.endpoints.remove(addr);

                // Update the service.
                self.insert(service);
            }
        }
    }

    /// Adds the given service.
    pub fn insert(&mut self, mut service: Service) {
        // First mutate the service and add all missing endpoints
        for vip in &service.vips {
            // Due to ordering issues, we may have gotten workloads with VIPs before we got the service
            // we should add those workloads to the vips map now
            if let Some(endpoints) = self.staged_vips.remove(vip) {
                for (wip, ep) in endpoints {
                    service.endpoints.insert(wip.clone(), ep);
                }
            }
        }

        // If we're replacing an existing service, remove the old one from all data structures.
        let _ = self.remove(&service.namespaced_hostname());

        // Save values used for the indexes.
        let vips = service.vips.clone();
        let hostname = service.hostname.clone();

        // Create the Arc.
        let service = Arc::new(service);

        // Map the vips to the service.
        for vip in &vips {
            self.by_vip.insert(vip.clone(), service.clone());
        }

        // Map the hostname to the service.
        match self.by_host.get_mut(&hostname) {
            None => {
                let _ = self.by_host.insert(hostname.clone(), vec![service.clone()]);
            }
            Some(services) => {
                services.push(service.clone());
            }
        }

        // Map the workload address to the endpoint.
        for (_, ep) in service.endpoints.iter() {
            self.workload_to_vips
                .entry(ep.address.clone())
                .or_default()
                .insert(ep.vip.clone());
        }
    }

    /// Removes the service for the given host and namespace.
    pub fn remove(&mut self, namespaced_host: &NamespacedHostname) -> Option<Service> {
        // Remove the previous service from the by_host map.
        let mut remove_hostname = false;
        let prev = {
            match self.by_host.get_mut(&namespaced_host.hostname) {
                None => None,
                Some(services) => {
                    // Iterate over the services in the list. Typically there will be only one.
                    let mut found = None;

                    let mut i = 0;
                    while i < services.len() {
                        if services[i].namespace.as_str() == namespaced_host.namespace {
                            found = Some(services.remove(i));

                            // If the array is empty, also remove the Vec.
                            remove_hostname = services.is_empty();
                            break;
                        }
                        i += 1
                    }

                    found
                }
            }
        };

        match prev {
            None => None,
            Some(prev) => {
                // If the Vec for the hostname is empty now, remove it.
                if remove_hostname {
                    self.by_host.remove(&prev.hostname);
                }

                // Remove the entries for the previous service IPs.
                prev.vips.iter().for_each(|addr| {
                    self.by_vip.remove(addr);
                });

                // Remove mapping from workload to the VIPs for this service.
                for (ep_ip, _) in prev.endpoints.iter() {
                    self.workload_to_vips.remove(ep_ip);
                    for network_addr in prev.vips.iter() {
                        self.staged_vips
                            .entry(network_addr.clone())
                            .or_default()
                            .remove(ep_ip);
                        if self.staged_vips[network_addr].is_empty() {
                            self.staged_vips.remove(network_addr);
                        }
                    }
                }

                // Remove successful.
                Some(prev.deref().clone())
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
    pub fn num_staged_vips(&self) -> usize {
        self.staged_vips.len()
    }
}
