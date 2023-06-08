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

use crate::workload::{
    byte_to_ip, network_addr, NamespacedHostname, NetworkAddress, WorkloadError,
};
use crate::xds::istio::workload::PortList;
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use tracing::trace;

use xds::istio::workload::Service as XdsService;

use crate::xds;

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub namespace: String,
    pub hostname: String,
    pub addresses: Vec<NetworkAddress>,
    pub ports: HashMap<u16, u16>,
    #[serde(default)]
    pub endpoints: HashMap<NetworkAddress, Endpoint>,
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
    /// this map stores the same services as `services_by_hostname` so we can mutate the services in both maps
    /// at once when a service is updated or workload updates affect a service's endpoints.
    by_vip: HashMap<NetworkAddress, Arc<RwLock<Service>>>,

    /// Allows for lookup of services by namespaced and hostname, the service's xds primary key.
    /// this map stores the same services as `services_by_ip` so we can mutate the services in both maps
    /// at once when a service is updated or workload updates affect a service's endpoints.
    by_host: HashMap<String, Vec<Arc<RwLock<Service>>>>,
}

impl ServiceStore {
    /// Returns the [Service] matching the given VIP.
    pub fn get_by_vip(&self, vip: &NetworkAddress) -> Option<Arc<RwLock<Service>>> {
        self.by_vip.get(vip).cloned()
    }

    /// Returns the list of [Service]s matching the given hostname. Istio `ServiceEntry`
    /// affords the ability to define the same hostname (e.g. `www.google.com`) in different
    /// namespaces. In most cases, only a single [Service] will be returned.
    ///
    /// # Arguments
    ///
    /// * `hostname` - the hostname of the service.
    pub fn get_by_host(&self, hostname: &String) -> Option<Vec<Arc<RwLock<Service>>>> {
        self.by_host.get(hostname).cloned()
    }

    /// Returns the [Service] matching the given namespace and hostname. Istio `ServiceEntry`
    /// affords the ability to define the same hostname (e.g. `www.google.com`) in different
    /// namespaces. This method will return the [Service] for the requested namespace.
    ///
    /// # Arguments
    ///
    /// * `host` - the namespaced hostname.
    pub fn get_by_namespaced_host(
        &self,
        host: &NamespacedHostname,
    ) -> Option<Arc<RwLock<Service>>> {
        // Get the list of services that match the hostname. Typically there will only be one, but
        // ServiceEntry allows configuring arbitrary hostnames on a per-namespace basis.
        match self.by_host.get(&host.hostname) {
            None => None,
            Some(services) => {
                // Return the service that matches the requested namespace.
                for service in services {
                    if service.read().unwrap().namespace == host.namespace {
                        return Some(service.clone());
                    }
                }
                None
            }
        }
    }

    /// Adds an endpoint for the service VIP.
    pub(super) fn insert_endpoint(&mut self, vip: &NetworkAddress, ep: Endpoint) {
        // Insert a mapping from the address to the service VIP.
        self.workload_to_vips
            .entry(ep.address.clone())
            .or_default()
            .insert(vip.clone());

        if let Some(svc) = self.by_vip.get_mut(vip) {
            // Add the endpoint to the service.
            svc.write()
                .unwrap()
                .endpoints
                .insert(ep.address.clone(), ep);
        } else {
            // Can happen due to ordering issues
            trace!("pod has VIP {vip}, but VIP not found");
            self.staged_vips
                .entry(vip.clone())
                .or_default()
                .insert(ep.address.clone(), ep);
        }
    }

    /// Removes entries for the given endpoint.
    pub(super) fn remove_endpoint(&mut self, addr: &NetworkAddress) {
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
            if let Some(wls) = self.by_vip.get_mut(vip) {
                wls.write().unwrap().endpoints.remove(addr);
            }
        }
    }

    /// Adds the given service.
    pub(super) fn insert(&mut self, mut service: Service) {
        // First mutate the service and add all missing endpoints
        for addr in service.addresses.as_slice() {
            // Due to ordering issues, we may have gotten workloads with VIPs before we got the service
            // we should add those workloads to the vips map now
            if let Some(wips_to_endpoints) = self.staged_vips.remove(addr) {
                for (wip, ep) in wips_to_endpoints {
                    service.endpoints.insert(wip.clone(), ep);
                }
            }

            // If svc already exists, add old endpoints to new svc
            if let Some(prev) = self.by_vip.get_mut(addr) {
                let prev = prev.read().unwrap();
                for (wip, ep) in prev.endpoints.iter() {
                    service.endpoints.insert(wip.clone(), ep.clone());
                }
            }
        }

        // If we're replacing an existing service, remove the old one from all data structures.
        self.remove(&service.namespaced_hostname());

        // Save values used for the indexes.
        let addresses = service.addresses.clone();
        let hostname = service.hostname.clone();

        // Create the Arc.
        let service = Arc::new(RwLock::new(service));

        // Add the service to the data structures.
        for addr in &addresses {
            self.by_vip.insert(addr.clone(), service.clone());
        }
        match self.by_host.get_mut(&hostname) {
            None => {
                let _ = self.by_host.insert(hostname.clone(), vec![service]);
            }
            Some(services) => {
                services.push(service);
            }
        }
    }

    /// Removes the service for the given host and namespace.
    pub(super) fn remove(&mut self, namespaced_host: &NamespacedHostname) -> bool {
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
                        if services[i].read().unwrap().namespace.as_str()
                            == namespaced_host.namespace
                        {
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

        // Lock the service for read.
        let prev = match &prev {
            None => {
                // Remove unsuccessful - not found.
                return false;
            }
            Some(prev) => prev.read().unwrap(),
        };

        // If the Vec for the hostname is empty now, remove it.
        if remove_hostname {
            self.by_host.remove(&prev.hostname);
        }

        // Remove the entries for the previous service IPs.
        prev.addresses.iter().for_each(|addr| {
            self.by_vip.remove(addr);
        });

        // Remove mapping from workload to the VIPs for this service.
        for (ep_ip, _) in prev.endpoints.iter() {
            self.workload_to_vips.remove(ep_ip);
            for network_addr in prev.addresses.iter() {
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
        true
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
