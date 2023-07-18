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

use crate::identity::SecretManager;
use crate::proxy::Error;
use crate::state::policy::PolicyStore;
use crate::state::service::ServiceStore;
use crate::state::workload::{
    address::Address, gatewayaddress::Destination, network_addr, NamespacedHostname,
    NetworkAddress, Protocol, WaypointError, Workload, WorkloadStore,
};
use crate::xds::metrics::Metrics;
use crate::xds::{AdsClient, Demander, LocalClient, ProxyStateUpdater};
use crate::{cert_fetcher, config, rbac, readiness, xds};
use rand::prelude::IteratorRandom;
use rand::seq::SliceRandom;
use std::convert::Into;
use std::default::Default;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{debug, trace};

pub mod policy;
pub mod service;
pub mod workload;

#[derive(Debug, Hash, Eq, PartialEq, Clone, serde::Serialize)]
pub struct Upstream {
    pub workload: Workload,
    pub port: u16,
    pub sans: Vec<String>,
}

impl fmt::Display for Upstream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Upstream{{{} with uid {}:{} via {} ({:?}) sans:{:?}}}",
            self.workload.name,
            self.workload.uid,
            self.port,
            self.workload
                .gateway_address
                .map(|x| format!("{x}"))
                .unwrap_or_else(|| "None".into()),
            self.workload.protocol,
            self.sans,
        )
    }
}

/// The current state information for this proxy.
#[derive(serde::Serialize, Default, Debug)]
pub struct ProxyState {
    #[serde(flatten)]
    pub workloads: WorkloadStore,

    #[serde(flatten)]
    pub services: ServiceStore,

    #[serde(flatten)]
    pub policies: PolicyStore,

    pub resolved_dns: ResolvedDnsStore,
}

use std::collections::HashMap;
use std::collections::HashSet;
use tracing::{info};


/// A WorkloadStore encapsulates all information about workloads in the mesh
#[derive(serde::Serialize, Default, Debug)]
pub struct ResolvedDnsStore {
    // workload UID to resolved IP addresses
    by_hostname: HashMap<String, HashSet<IpAddr>>,
}

impl ResolvedDnsStore {
    pub fn get_dns(&self, hostname: String) -> Option<IpAddr> {
        info!("get dns, by_hostname len: {}", self.by_hostname.len());

        // TODO(kdorohs) add support for different dns logical vs strict LB

        let Some(ipset) = self.by_hostname.get(&hostname) else {
            // todo
            return None;
        };

        let ips_vec = ipset.into_iter().collect::<Vec<_>>();

        let Some(ip) = ips_vec.choose(&mut rand::thread_rng()) else {
            // todo
            return None;
        };

        return Some(**ip);
    }

    pub fn set_dns(&mut self, uid: String, ips : Vec<Ipv4Addr>) {
        let set = HashSet::from_iter(ips.iter().map(|x| IpAddr::V4(*x)));
        self.by_hostname.insert(uid.clone(), set);
        info!("set dns, by_hostname len: {}", self.by_hostname.len());
    }
}

impl ProxyState {
    /// Find either a workload or service by the destination.
    pub fn find_destination(&self, dest: &Destination) -> Option<Address> {
        match dest {
            Destination::Address(addr) => self.find_address(addr),
            Destination::Hostname(hostname) => self.find_hostname(hostname),
        }
    }

    /// Find either a workload or a service by address.
    pub fn find_address(&self, network_addr: &NetworkAddress) -> Option<Address> {
        // 1. handle workload ip, if workload not found fallback to service.
        match self.workloads.find_address(network_addr) {
            None => {
                // 2. handle service
                if let Some(svc) = self.services.get_by_vip(network_addr) {
                    return Some(Address::Service(Box::new(svc)));
                }
                None
            }
            Some(wl) => Some(Address::Workload(Box::new(wl))),
        }
    }

    /// Find either a workload or a service by hostname.
    pub fn find_hostname(&self, name: &NamespacedHostname) -> Option<Address> {
        // Hostnames for services are more common, so lookup service first and fallback
        // to workload.
        match self.services.get_by_namespaced_host(name) {
            None => {
                // Workload hostnames (generally per-pod statefulset hostnames) are globally unique, so ignore the namespace.
                self.workloads
                    .find_hostname(&name.hostname)
                    .map(|wl| Address::Workload(Box::new(wl)))
            }
            Some(svc) => Some(Address::Service(Box::new(svc))),
        }
    }

    pub fn find_upstream(
        &self,
        network: &str,
        addr: SocketAddr,
        hbone_port: u16,
    ) -> Option<Upstream> {
        if let Some(svc) = self.services.get_by_vip(&network_addr(network, addr.ip())) {
            let Some(target_port) = svc.ports.get(&addr.port()) else {
                info!("found VIP {}, but port {} was unknown", addr.ip(), addr.port());
                return None
            };
            // Randomly pick an upstream
            // TODO: do this more efficiently, and not just randomly
            let Some((_, ep)) = svc.endpoints.iter().choose(&mut rand::thread_rng()) else {
                info!("VIP {} has no healthy endpoints", addr);
                return None
            };
            let Some(wl) = self.workloads.find_uid(&ep.workload_uid) else {
                info!("failed to fetch workload for {}", ep.workload_uid);
                return None
            };
            // If endpoint overrides the target port, use that instead
            let target_port = ep.port.get(&addr.port()).unwrap_or(target_port);
            let mut us = Upstream {
                workload: wl,
                port: *target_port,
                sans: svc.subject_alt_names.clone(),
            };
            return match self.set_gateway_address(&mut us, hbone_port) {
                Ok(_) => {
                    debug!("found upstream {} from VIP {}", us, addr.ip());
                    Some(us)
                }
                Err(e) => {
                    debug!("failed to set gateway address for upstream: {}", e);
                    None
                }
            };
        }
        if let Some(wl) = self
            .workloads
            .find_address(&network_addr(network, addr.ip()))
        {
            let mut us = Upstream {
                workload: wl,
                port: addr.port(),
                sans: Vec::new(),
            };
            return match self.set_gateway_address(&mut us, hbone_port) {
                Ok(_) => {
                    debug!("found upstream {}", us);
                    Some(us)
                }
                Err(e) => {
                    debug!("failed to set gateway address for upstream: {}", e);
                    None
                }
            };
        }
        info!("no upstream found for {}", addr);
        None
    }

    fn set_gateway_address(&self, us: &mut Upstream, hbone_port: u16) -> anyhow::Result<()> {

        let ipsmap =  self.resolved_dns.get_dns(us.workload.clone().uid);
        let workload_ip = match ipsmap {
            Some(ips) => ips,
            None => us.workload.choose_ip()?,
        };

        if us.workload.gateway_address.is_none() {
            us.workload.gateway_address = Some(match us.workload.protocol {
                Protocol::HBONE => {
                    let ip = us
                        .workload
                        .waypoint_svc_ip_address()?
                        .unwrap_or(workload_ip);
                    SocketAddr::from((ip, hbone_port))
                }
                Protocol::TCP => SocketAddr::from((workload_ip, us.port)),
            });
        }
        Ok(())
    }


}

/// Wrapper around [ProxyState] that provides additional methods for requesting information
/// on-demand.
#[derive(serde::Serialize, Debug, Clone)]
pub struct DemandProxyState {
    #[serde(flatten)]
    pub state: Arc<RwLock<ProxyState>>,

    /// If present, used to request on-demand updates for workloads.
    #[serde(skip_serializing)]
    demand: Option<Demander>,
}

impl DemandProxyState {
    pub fn new(state: Arc<RwLock<ProxyState>>, demand: Option<Demander>) -> Self {
        Self { state, demand }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, ProxyState> {
        self.state.read().unwrap()
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, ProxyState> {
        self.state.write().unwrap()
    }

    pub async fn assert_rbac(&self, conn: &rbac::Connection) -> bool {
        let nw_addr = network_addr(&conn.dst_network, conn.dst.ip());
        let Some(wl) = self.fetch_workload(&nw_addr).await else {
            debug!("destination workload not found {}", nw_addr);
            return false;
        };

        let state = self.state.read().unwrap();

        // We can get policies from namespace, global, and workload...
        let ns = state.policies.get_by_namespace(&wl.namespace);
        let global = state.policies.get_by_namespace("");
        let workload = wl.authorization_policies.iter();

        // Aggregate all of them based on type
        let (allow, deny): (Vec<_>, Vec<_>) = ns
            .iter()
            .chain(global.iter())
            .chain(workload)
            .filter_map(|k| state.policies.get(k))
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
        if let Some(wl) = self.state.read().unwrap().workloads.find_address(addr) {
            return Some(wl);
        }
        self.fetch_on_demand(addr.to_string()).await;
        self.state.read().unwrap().workloads.find_address(addr)
    }

    // only support workload
    pub async fn fetch_workload_by_uid(&self, uid: &str) -> Option<Workload> {
        // Wait for it on-demand, *if* needed
        debug!(%uid, "fetch workload");
        if let Some(wl) = self.state.read().unwrap().workloads.find_uid(uid) {
            return Some(wl);
        }
        self.fetch_on_demand(uid.to_string()).await;
        self.state.read().unwrap().workloads.find_uid(uid)
    }

    pub async fn fetch_upstream(
        &self,
        network: &str,
        addr: SocketAddr,
        hbone_port: u16,
    ) -> Option<Upstream> {
        self.fetch_address(&network_addr(network, addr.ip())).await;
        self.state
            .read()
            .unwrap()
            .find_upstream(network, addr, hbone_port)
    }

    pub async fn fetch_waypoint(&self, wl: Workload) -> Result<Option<Upstream>, WaypointError> {
        let Some(gw_address) = &wl.waypoint else {
            return Ok(None);
        };
        // Even in this case, we are picking a single upstream pod and deciding if it has a remote proxy.
        // Typically this is all or nothing, but if not we should probably send to remote proxy if *any* upstream has one.
        let wp_nw_addr = match &gw_address.destination {
            Destination::Address(ip) => ip,
            Destination::Hostname(_) => {
                return Err(WaypointError::UnsupportedFeature(
                    "hostname lookup not supported yet".to_string(),
                ));
            }
        };
        let wp_socket_addr = SocketAddr::new(wp_nw_addr.address, gw_address.port);
        match self
            .fetch_upstream(&wp_nw_addr.network, wp_socket_addr, gw_address.port)
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

    /// Looks for either a workload or service by the destination. If not found locally,
    /// attempts to fetch on-demand.
    pub async fn fetch_destination(&self, dest: &Destination) -> Option<Address> {
        match dest {
            Destination::Address(addr) => self.fetch_address(addr).await,
            Destination::Hostname(hostname) => self.fetch_hostname(hostname).await,
        }
    }

    /// Looks for the given address to find either a workload or service by IP. If not found
    /// locally, attempts to fetch on-demand.
    pub async fn fetch_address(&self, network_addr: &NetworkAddress) -> Option<Address> {
        // Wait for it on-demand, *if* needed
        debug!(%network_addr.address, "fetch address");
        if let Some(address) = self.state.read().unwrap().find_address(network_addr) {
            return Some(address);
        }
        // if both cache not found, start on demand fetch
        self.fetch_on_demand(network_addr.to_string()).await;
        self.state.read().unwrap().find_address(network_addr)
    }

    /// Looks for the given hostname to find either a workload or service by IP. If not found
    /// locally, attempts to fetch on-demand.
    pub async fn fetch_hostname(&self, hostname: &NamespacedHostname) -> Option<Address> {
        // Wait for it on-demand, *if* needed
        debug!(%hostname, "fetch hostname");
        if let Some(address) = self.state.read().unwrap().find_hostname(hostname) {
            return Some(address);
        }
        // if both cache not found, start on demand fetch
        self.fetch_on_demand(hostname.to_string()).await;
        self.state.read().unwrap().find_hostname(hostname)
    }

    async fn fetch_on_demand(&self, key: String) {
        if let Some(demand) = &self.demand {
            debug!(%key, "sending demand request");
            demand.demand(key.clone()).await.recv().await;
            debug!(%key, "on demand ready");
        }
    }
}

// TODO: add more sophisticated routing logic, perhaps based on ipv4/ipv6 support underneath us.
// if/when we support that, this function may need to move to get access to the necessary metadata.
fn choose_workload_ip(workload: &Workload) -> Result<IpAddr, Error> {
    // Randomly pick an IP
    // TODO: do this more efficiently, and not just randomly
    let Some(ip) = workload.workload_ips.choose(&mut rand::thread_rng()) else {
        debug!("workload {} has no suitable workload IPs for routing", workload.name);
        return Err(Error::NoValidDestination(Box::new(workload.to_owned())))
    };
    Ok(*ip)
}

#[derive(serde::Serialize)]
pub struct ProxyStateManager {
    #[serde(flatten)]
    state: DemandProxyState,

    #[serde(skip_serializing)]
    xds_client: Option<AdsClient>,
}

impl ProxyStateManager {
    pub async fn new(
        config: config::Config,
        metrics: Metrics,
        awaiting_ready: readiness::BlockReady,
        cert_manager: Arc<SecretManager>,
    ) -> anyhow::Result<ProxyStateManager> {
        let cert_fetcher = cert_fetcher::new(&config, cert_manager);
        let state: Arc<RwLock<ProxyState>> = Arc::new(RwLock::new(ProxyState::default()));
        let xds_client = if config.xds_address.is_some() {
            let updater = ProxyStateUpdater::new(state.clone(), cert_fetcher.clone());
            Some(
                xds::Config::new(config.clone())
                    .with_address_handler(updater.clone())
                    .with_authorization_handler(updater)
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
                state: state.clone(),
                cert_fetcher,
            };
            local_client.run().await?;
        }
        let demand = xds_client.as_ref().and_then(AdsClient::demander);
        Ok(ProxyStateManager {
            xds_client,
            state: DemandProxyState { state, demand },
        })
    }

    pub fn state(&self) -> DemandProxyState {
        self.state.clone()
    }

    pub async fn run(self) -> anyhow::Result<()> {
        match self.xds_client {
            Some(xds) => xds.run().await.map_err(|e| anyhow::anyhow!(e)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, time::Duration};

    use super::*;
    use crate::test_helpers;

    #[tokio::test]
    async fn lookup_address() {
        let mut state = ProxyState::default();
        state
            .workloads
            .insert(test_helpers::test_default_workload())
            .unwrap();
        state.services.insert(test_helpers::mock_default_service());

        let mock_proxy_state = DemandProxyState::new(Arc::new(RwLock::new(state)), None);

        // Some from Address
        let dst = Destination::Address(NetworkAddress {
            network: "".to_string(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });
        test_helpers::assert_eventually(
            Duration::from_secs(5),
            || mock_proxy_state.fetch_destination(&dst),
            Some(Address::Workload(Box::new(
                test_helpers::test_default_workload(),
            ))),
        )
        .await;

        // Some from Hostname
        let dst = Destination::Hostname(NamespacedHostname {
            namespace: "default".to_string(),
            hostname: "defaulthost".to_string(),
        });
        test_helpers::assert_eventually(
            Duration::from_secs(5),
            || mock_proxy_state.fetch_destination(&dst),
            Some(Address::Service(Box::new(
                test_helpers::mock_default_service(),
            ))),
        )
        .await;

        // None from Address
        let dst = Destination::Address(NetworkAddress {
            network: "".to_string(),
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        });
        test_helpers::assert_eventually(
            Duration::from_secs(5),
            || mock_proxy_state.fetch_destination(&dst),
            None,
        )
        .await;

        // None from Hostname
        let dst = Destination::Hostname(NamespacedHostname {
            namespace: "default".to_string(),
            hostname: "nothost".to_string(),
        });
        test_helpers::assert_eventually(
            Duration::from_secs(5),
            || mock_proxy_state.fetch_destination(&dst),
            None,
        )
        .await;
    }
}
