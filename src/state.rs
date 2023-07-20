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
use std::collections::{HashMap, HashSet};
use std::convert::Into;
use std::default::Default;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{debug, trace};

pub mod policy;
pub mod service;
pub mod workload;

// TODO(kdorosh) DRY the copied code following here and generally clean up any latest placeholder test values
use crate::dns;
use itertools::Itertools;
use tracing::warn;
use trust_dns_proto::op::{Message, MessageType, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::BinDecodable;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::server::Request;

/// Constructs a new [Message] of type [MessageType::Query];
pub fn new_message(name: Name, rr_type: RecordType) -> Message {
    let mut msg = Message::new();
    msg.set_id(123);
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, rr_type));
    msg
}

/// Converts the given [Message] into a server-side [Request] with dummy values for
/// the client IP and protocol.
pub fn server_request(
    msg: &Message,
    client_addr: SocketAddr,
    protocol: trust_dns_server::server::Protocol,
) -> Request {
    // Serialize the message.
    let wire_bytes = msg.to_vec().unwrap();

    // Deserialize into a server-side request.
    let msg_request = MessageRequest::from_bytes(&wire_bytes).unwrap();

    Request::new(msg_request, client_addr, protocol)
}

/// Creates a A-record [Request] for the given name.
pub fn a_request(
    name: Name,
    client_addr: SocketAddr,
    protocol: trust_dns_server::server::Protocol,
) -> Request {
    server_request(&new_message(name, RecordType::A), client_addr, protocol)
}

/// A short-hand helper for constructing a [Name].
pub fn n<S: AsRef<str>>(name: S) -> Name {
    Name::from_utf8(name).unwrap()
}

/// Helper for parsing a [SocketAddr] string.
pub fn socket_addr<S: AsRef<str>>(socket_addr: S) -> SocketAddr {
    socket_addr.as_ref().parse().unwrap()
}

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

/// A ResolvedDnsStore encapsulates all per-workload resolved DNS information for workloads in the mesh
#[derive(serde::Serialize, Default, Debug)]
pub struct ResolvedDnsStore {
    // workload UID to resolved IP addresses
    by_workload_uid: HashMap<String, ResolvedDns>,
}

// TODO(kdorosh) placeholder for now, to refactor
#[derive(serde::Serialize, Default, Debug, Clone, Hash, Eq, PartialEq)]
pub struct WorkloadUidHostname {
    pub workload_uid: String,
    pub hostname: String,
}

#[derive(serde::Serialize, Default, Debug, Clone)]
pub struct ResolvedDns {
    hostname: String,
    ips: HashSet<IpAddr>,
    #[serde(skip_serializing)]
    last_queried: Option<std::time::Instant>,
    dns_ttl: std::time::Duration,
}

impl ResolvedDns {
    pub fn new(hostname: String, ips: HashSet<IpAddr>, dns_ttl: std::time::Duration) -> Self {
        Self {
            hostname,
            ips,
            last_queried: None,
            dns_ttl,
        }
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
                // Workload hostnames are globally unique, so ignore the namespace.
                self.workloads
                    .find_hostname(&name.hostname)
                    .map(|wl| Address::Workload(Box::new(wl)))
            }
            Some(svc) => Some(Address::Service(Box::new(svc))),
        }
    }

    pub fn find_upstream(&self, network: &str, addr: SocketAddr) -> Option<Upstream> {
        if let Some(svc) = self.services.get_by_vip(&network_addr(network, addr.ip())) {
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
            let Some(wl) = self.workloads.find_uid(&ep.workload_uid) else {
                debug!("failed to fetch workload for {}", ep.workload_uid);
                return None
            };
            // If endpoint overrides the target port, use that instead
            let target_port = ep.port.get(&addr.port()).unwrap_or(target_port);
            let us = Upstream {
                workload: wl,
                port: *target_port,
                sans: svc.subject_alt_names.clone(),
            };
            return Some(us);
        }
        if let Some(wl) = self
            .workloads
            .find_address(&network_addr(network, addr.ip()))
        {
            let us = Upstream {
                workload: wl,
                port: addr.port(),
                sans: Vec::new(),
            };
            return Some(us);
        }
        None
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

    // this should only be called once per workload (the workload itself and it's waypoint) per outgoing request
    pub async fn load_balance(&self, workload: &Workload) -> Result<IpAddr, Error> {
        // TODO: add more sophisticated routing logic, perhaps based on ipv4/ipv6 support underneath us.
        // if/when we support that, this function may need to move to get access to the necessary metadata.
        // Randomly pick an IP
        // TODO: do this more efficiently, and not just randomly
        if let Some(ip) = workload.workload_ips.choose(&mut rand::thread_rng()) {
            return Ok(*ip);
        }
        if workload.hostname.is_empty() {
            debug!(
                "workload {} has no suitable workload IPs for routing",
                workload.name
            );
            return Err(Error::NoValidDestination(Box::new(workload.clone())));
        }
        let ip = self
            .load_balance_for_workload(workload.clone().uid, workload.clone().hostname)
            .await?;
        Ok(ip)
    }

    async fn load_balance_for_workload(
        &self,
        workload_uid: String,
        hostname: String,
    ) -> Result<IpAddr, Error> {
        let mut s_to_move: DemandProxyState = self.clone();
        let mut s_not_moved: DemandProxyState = self.clone();
        let Some(rdns) = s_to_move.get_ips_for_workload(workload_uid.to_owned()) else {

            // no current task ongoing for DNS to resolve this workload. kick one off
            let workload_uid_clone = workload_uid.clone();

            // TODO(kdorosh) DRY this code
            let jh = tokio::spawn(async move {
                let hostname = hostname.clone();
                trace!("dns workload async task started for {:?}", &hostname);

                // TODO(kdorosh): don't make a new forwarder for every request?

                // nip_io = "116.203.255.68"
                let sa = SocketAddr::from(([116, 203, 255, 68], 53));

                let fw = dns::forwarder_for_mode(config::ProxyMode::Shared, vec![sa]).unwrap(); // TODO(kdorosh) handle unwrap, don't hardcode
                let r = fw.resolver();

                // Lookup a host.
                let req = a_request(
                    n(&hostname),
                    socket_addr("1.1.1.1:80"), // TODO(kdorosh): don't hardcode this
                    trust_dns_server::server::Protocol::Udp,
                );
                let resp = r.lookup(&req).await;
                if resp.is_err() {
                    warn!(
                        "dns async response for workload {} is: {:?}",
                        &workload_uid_clone, resp
                    );
                    return;
                } else {
                    trace!(
                        "dns async response for workload {} is: {:?}",
                        &workload_uid_clone,
                        resp
                    );
                }
                let resp = resp.unwrap();
                let ips = resp
                    .record_iter()
                    .filter_map(|record| {
                        if record.rr_type().is_ip_addr() {
                            // TODO: handle ipv6
                            return record.data().unwrap().as_a().copied();
                        }
                        None
                    })
                    .collect_vec();
                let set = HashSet::from_iter(ips.iter().map(|x| IpAddr::V4(*x)));
                let now = std::time::Instant::now();
                let rdns = ResolvedDns {
                    hostname: hostname.clone(),
                    ips: set,
                    last_queried: Some(now),
                    dns_ttl: std::time::Duration::from_secs(60), // TODO(kdorosh) get from DNS record
                };
                s_to_move.set_ips_for_workload(workload_uid_clone, rdns);
            });

            match jh.await {
                Ok(_) => {
                    trace!("dns async task finished for {:?}", &workload_uid);
                }
                Err(e) => {
                    warn!("dns async task failed for {:?}: {:?}", &workload_uid, e);
                    return Err(Error::NoResolvedAddresses(workload_uid));
                }
            };

            // try to get it again
            let new_ipset = s_not_moved.get_ips_for_workload(workload_uid.to_owned());
            match new_ipset {
                Some(rdns) => {
                    let ipset = rdns.ips;
                    let ips_vec = ipset.iter().collect::<Vec<_>>();
                    let Some(ip) = ips_vec.choose(&mut rand::thread_rng()) else {
                        return Err(Error::EmptyResolvedAddresses(workload_uid));
                    };
                    return Ok(**ip);
                }
                None => {
                    return Err(Error::NoResolvedAddresses(workload_uid));
                }
            }
        };

        s_not_moved.update_latest_request(&workload_uid);

        let ipset = rdns.ips;
        let ips_vec = ipset.iter().collect::<Vec<_>>();
        let Some(ip) = ips_vec.choose(&mut rand::thread_rng()) else {
            return Err(Error::EmptyResolvedAddresses(workload_uid));
        };
        Ok(**ip)
    }

    // TODO: ipv6 support
    pub fn set_ips_for_workload(&mut self, workload_uid: String, rdns: ResolvedDns) {
        self.state
            .write()
            .unwrap()
            .resolved_dns
            .by_workload_uid
            .insert(workload_uid, rdns);
    }

    pub fn get_ips_for_workload(&mut self, workload_uid: String) -> Option<ResolvedDns> {
        let s = self.state.read().unwrap();
        s.resolved_dns.by_workload_uid.get(&workload_uid).cloned()
    }

    // we had a resolved DNS cache hit; update the last_queried time
    pub fn update_latest_request(&mut self, workload_uid: &String) {
        let mut s = self.state.write().unwrap();
        s.resolved_dns
            .by_workload_uid
            .get_mut(workload_uid)
            .unwrap()
            .last_queried = Some(std::time::Instant::now());
    }

    // get workloads that have received requests recently to their hostname
    pub fn get_recent_workloads_queried(&mut self) -> HashSet<WorkloadUidHostname> {
        let s = self.state.read().unwrap();
        let mut set = HashSet::new();
        for (uid, rdns) in s.resolved_dns.by_workload_uid.iter() {
            if rdns.last_queried.is_some() && rdns.last_queried.unwrap().elapsed() < rdns.dns_ttl {
                set.insert(WorkloadUidHostname {
                    workload_uid: uid.to_owned(),
                    hostname: rdns.hostname.to_owned(),
                });
            }
        }
        set
    }

    pub async fn set_gateway_address(
        &self,
        us: &mut Upstream,
        workload_ip: IpAddr,
        hbone_port: u16,
    ) -> anyhow::Result<()> {
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

    pub async fn fetch_upstream(&self, network: &str, addr: SocketAddr) -> Option<Upstream> {
        self.fetch_address(&network_addr(network, addr.ip())).await;
        self.state.read().unwrap().find_upstream(network, addr)
    }

    pub async fn fetch_waypoint(
        &self,
        wl: Workload,
        workload_ip: IpAddr,
    ) -> Result<Option<Upstream>, WaypointError> {
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
            .fetch_upstream(&wp_nw_addr.network, wp_socket_addr)
            .await
        {
            Some(mut upstream) => {
                debug!(%wl.name, "found waypoint upstream");
                match self
                    .set_gateway_address(&mut upstream, workload_ip, gw_address.port)
                    .await
                {
                    Ok(_) => Ok(Some(upstream)),
                    Err(e) => {
                        debug!(%wl.name, "failed to set gateway address for upstream: {}", e);
                        Err(WaypointError::FindWaypointError(wl.name))
                    }
                }
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
