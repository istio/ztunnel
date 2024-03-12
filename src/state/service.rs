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
use std::ops::Deref;
use std::sync::Arc;

use bytes::Bytes;
use tracing::trace;

use xds::istio::workload::Service as XdsService;

use crate::state::workload::{
    byte_to_ip, network_addr, GatewayAddress, NamespacedHostname, NetworkAddress, Workload,
    WorkloadError,
};
use crate::xds;
use crate::xds::istio::workload::PortList;

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Service {
    pub name: String,
    pub namespace: String,
    pub hostname: String,
    pub vips: Vec<NetworkAddress>,
    pub ports: HashMap<u16, u16>,

    /// Maps endpoint UIDs to service [Endpoint]s.
    #[serde(default)]
    pub endpoints: HashMap<String, Endpoint>,
    #[serde(default)]
    pub subject_alt_names: Vec<String>,
    pub waypoint: Option<GatewayAddress>,
}

impl Service {
    pub fn namespaced_hostname(&self) -> NamespacedHostname {
        NamespacedHostname {
            namespace: self.namespace.clone(),
            hostname: self.hostname.clone(),
        }
    }

    pub fn contains_endpoint(&self, wl: &Workload, addr: Option<&NetworkAddress>) -> bool {
        self.endpoints.contains_key(&endpoint_uid(&wl.uid, addr))
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize)]
pub struct ServiceDescription {
    pub hostname: String,
    pub name: String,
    pub namespace: String,
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
    pub workload_uid: String,

    /// The service for this endpoint.
    pub service: NamespacedHostname,

    /// The workload address, if any.
    /// A workload with a hostname may have no addresses.
    pub address: Option<NetworkAddress>,

    /// The port mapping.
    pub port: HashMap<u16, u16>,
}

pub fn endpoint_uid(workload_uid: &str, address: Option<&NetworkAddress>) -> String {
    format!(
        "{}:{}",
        workload_uid,
        address.map(|a| a.to_string()).unwrap_or_default()
    )
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
        let waypoint = match &s.waypoint {
            Some(w) => Some(GatewayAddress::try_from(w)?),
            None => None,
        };
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
            waypoint,
        };
        Ok(svc)
    }
}

/// Data store for service information.
#[derive(serde::Serialize, Default, Debug)]
pub struct ServiceStore {
    /// Maintains a mapping of service key -> (endpoint UID -> workload endpoint)
    /// this is used to handle ordering issues if workloads are received before services.
    staged_services: HashMap<NamespacedHostname, HashMap<String, Endpoint>>,

    /// Maintains a mapping of workload UID to service. This is used only to handle removal of
    /// service endpoints when a workload is removed.
    workload_to_services: HashMap<String, HashSet<NamespacedHostname>>,

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

    pub fn get_by_workload(&self, workload: &Workload) -> Vec<Service> {
        let Some(svc) = self.workload_to_services.get(&workload.uid) else {
            return Vec::new();
        };
        svc.iter()
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
        let ep_uid = endpoint_uid(&ep.workload_uid, ep.address.as_ref());
        if let Some(mut svc) = self.get_by_namespaced_host(&ep.service) {
            // Clone the service and add the endpoint.
            svc.endpoints.insert(ep_uid, ep);

            // Update the service.
            self.insert(svc);
        } else {
            // We received workload endpoints, but don't have the Service yet.
            // This can happen due to ordering issues.
            trace!("pod has service {}, but service not found", ep.service,);

            // Add a staged entry. This will be added to the service once we receive it.
            self.staged_services
                .entry(ep.service.clone())
                .or_default()
                .insert(ep_uid, ep.clone());

            // Insert a reverse-mapping from the workload address to the service.
            self.workload_to_services
                .entry(ep.workload_uid.clone())
                .or_default()
                .insert(ep.service.clone());
        }
    }

    /// Removes entries for the given endpoint address.
    pub fn remove_endpoint(&mut self, workload_uid: &str, endpoint_uid: &str) {
        let mut services_to_update = HashSet::new();
        if let Some(prev_services) = self.workload_to_services.remove(workload_uid) {
            for svc in prev_services.iter() {
                // Remove the endpoint from the staged services.
                self.staged_services
                    .entry(svc.clone())
                    .or_default()
                    .remove(endpoint_uid);
                if self.staged_services[svc].is_empty() {
                    self.staged_services.remove(svc);
                }

                services_to_update.insert(svc.clone());
            }
        }

        // Now remove the endpoint from all Services.
        for svc in &services_to_update {
            if let Some(mut svc) = self.get_by_namespaced_host(svc) {
                svc.endpoints.remove(endpoint_uid);

                // Update the service.
                self.insert(svc);
            }
        }
    }

    /// Adds the given service.
    pub fn insert(&mut self, mut service: Service) {
        // First add any staged service endpoints. Due to ordering issues, we may have received
        // the workloads before their associated services.
        let namespaced_hostname = service.namespaced_hostname();
        if let Some(endpoints) = self.staged_services.remove(&namespaced_hostname) {
            for (wip, ep) in endpoints {
                service.endpoints.insert(wip.clone(), ep);
            }
        }

        // If we're replacing an existing service, remove the old one from all data structures.
        let _ = self.remove(&namespaced_hostname);

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

        // Map the workload address to the service.
        for (_, ep) in service.endpoints.iter() {
            self.workload_to_services
                .entry(ep.workload_uid.to_string())
                .or_default()
                .insert(namespaced_hostname.clone());
        }
    }

    /// Removes the service for the given host and namespace.
    pub fn remove(&mut self, namespaced_host: &NamespacedHostname) -> Option<Service> {
        match self.by_host.get_mut(&namespaced_host.hostname) {
            None => None,
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
                    return None;
                };

                // Remove the entries for the previous service VIPs.
                prev.vips.iter().for_each(|addr| {
                    self.by_vip.remove(addr);
                });

                // Remove the staged service.
                // TODO(nmittler): no endpoints for this service should be staged at this point.
                self.staged_services.remove(namespaced_host);

                // Remove mapping from workload to the VIPs for this service.
                for (ep_ip, _) in prev.endpoints.iter() {
                    // Remove the workload IP mapping for this service.
                    self.workload_to_services
                        .entry(ep_ip.clone())
                        .or_default()
                        .remove(namespaced_host);
                    if self.workload_to_services[ep_ip].is_empty() {
                        self.workload_to_services.remove(ep_ip);
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
    pub fn num_staged_services(&self) -> usize {
        self.staged_services.len()
    }
}
