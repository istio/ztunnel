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
use crate::proxy;
use crate::proxy::{Error, OnDemandDnsLabels};
use crate::rbac::Authorization;
use crate::state::policy::PolicyStore;
use crate::state::service::{Endpoint, LoadBalancerMode, LoadBalancerScopes, ServiceStore};
use crate::state::service::{Service, ServiceDescription};
use crate::state::workload::{
    address::Address, gatewayaddress::Destination, network_addr, NamespacedHostname,
    NetworkAddress, Protocol, WaypointError, Workload, WorkloadStore,
};
use crate::tls;
use crate::xds::istio::security::Authorization as XdsAuthorization;
use crate::xds::istio::workload::Address as XdsAddress;
use crate::xds::metrics::Metrics;
use crate::xds::{AdsClient, Demander, LocalClient, ProxyStateUpdater};
use crate::{cert_fetcher, config, rbac, xds};
use futures_util::FutureExt;
use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioAsyncResolver;
use rand::prelude::IteratorRandom;
use rand::seq::SliceRandom;
use serde::Serializer;
use std::collections::{HashMap, HashSet};
use std::convert::Into;
use std::default::Default;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use tracing::{debug, error, trace, warn};
use crate::strng::Strng;

pub mod policy;
pub mod service;
pub mod workload;

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize)]
pub struct Upstream {
    pub workload: Workload,
    pub port: u16,
    pub sans: Vec<Strng>,
    pub destination_service: Option<ServiceDescription>,
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

// Workload information that a specific proxy instance represents. This is used to cross check
// with the workload fetched using destination address when making RBAC decisions.
#[derive(
    Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadInfo {
    pub name: String,
    pub namespace: String,
    pub trust_domain: String,
    pub service_account: String,
}

impl fmt::Display for WorkloadInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{} ({})",
            self.service_account, self.namespace, self.trust_domain, self.name
        )
    }
}

impl WorkloadInfo {
    pub fn new(
        name: String,
        namespace: String,
        trust_domain: String,
        service_account: String,
    ) -> Self {
        Self {
            name,
            namespace,
            trust_domain,
            service_account,
        }
    }

    pub fn matches(&self, w: &Workload) -> bool {
        self.name == w.name
            && self.namespace == w.namespace
            && self.trust_domain == w.trust_domain
            && self.service_account == w.service_account
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct ProxyRbacContext {
    pub conn: rbac::Connection,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dest_workload_info: Option<Arc<WorkloadInfo>>,
}

impl fmt::Display for ProxyRbacContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.conn)?;
        if let Some(ref info) = self.dest_workload_info {
            write!(f, "({})", info)?;
        }
        Ok(())
    }
}
/// The current state information for this proxy.
#[derive(Default, Debug)]
pub struct ProxyState {
    pub workloads: WorkloadStore,

    pub services: ServiceStore,

    pub policies: PolicyStore,

    pub resolved_dns: ResolvedDnsStore,
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ProxyStateSerialization<'a> {
    workloads: &'a HashMap<NetworkAddress, Arc<Workload>>,
    services: &'a HashMap<NetworkAddress, Arc<Service>>,
    staged_services: &'a HashMap<NamespacedHostname, HashMap<Strng, Endpoint>>,
    policies: &'a HashMap<Strng, Authorization>,
}

impl serde::Serialize for ProxyState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let serializable = ProxyStateSerialization {
            workloads: &self.workloads.by_addr,
            services: &self.services.by_vip,
            staged_services: &self.services.staged_services,
            policies: &self.policies.by_key,
        };
        serializable.serialize(serializer)
    }
}

/// A ResolvedDnsStore encapsulates all resolved DNS information for workloads in the mesh
#[derive(Default, Debug)]
pub struct ResolvedDnsStore {
    // by_hostname is a map from hostname to resolved IP addresses for now.
    //
    // in a future with support for per-pod DNS resolv.conf settings we may need
    // to change this to a map from source workload uid to resolved IP addresses.
    by_hostname: HashMap<Strng, ResolvedDns>,
}

#[derive(serde::Serialize, Default, Debug, Clone)]
pub struct ResolvedDns {
    hostname: Strng,
    ips: HashSet<IpAddr>,
    #[serde(skip_serializing)]
    initial_query: Option<std::time::Instant>,
    // the shortest DNS ttl of all records in the response; used for cache refresh.
    // we use the shortest ttl rather than just relying on the older records so we don't
    // load-balance to just the older records as the records with early ttl expire.
    dns_refresh_rate: std::time::Duration,
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
        match self.workloads.find_address_arc(network_addr) {
            None => {
                // 2. handle service
                if let Some(svc) = self.services.get_by_vip(network_addr) {
                    return Some(Address::Service(svc));
                }
                None
            }
            Some(wl) => Some(Address::Workload(wl)),
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
                    .map(Address::Workload)
            }
            Some(svc) => Some(Address::Service(svc)),
        }
    }

    pub fn find_upstream(
        &self,
        network: &str,
        source_workload: &Workload,
        addr: SocketAddr,
    ) -> Option<Upstream> {
        if let Some(svc) = self.services.get_by_vip(&network_addr(network, addr.ip())) {
            let Some(target_port) = svc.ports.get(&addr.port()) else {
                debug!(
                    "found VIP {}, but port {} was unknown",
                    addr.ip(),
                    addr.port()
                );
                return None;
            };
            // Randomly pick an upstream
            // TODO: do this more efficiently, and not just randomly
            let Some(ep) = self.load_balance(source_workload, &svc) else {
                debug!("VIP {} has no healthy endpoints", addr);
                return None;
            };
            let Some(wl) = self.workloads.find_uid(&ep.workload_uid) else {
                debug!("failed to fetch workload for {}", ep.workload_uid);
                return None;
            };
            // If endpoint overrides the target port, use that instead
            let target_port = ep.port.get(&addr.port()).unwrap_or(target_port);
            let us = Upstream {
                workload: wl,
                port: *target_port,
                sans: svc.subject_alt_names.clone(),
                destination_service: Some(ServiceDescription::from(svc.as_ref())),
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
                destination_service: None,
            };
            return Some(us);
        }
        None
    }

    fn load_balance<'a>(&self, src: &Workload, svc: &'a Service) -> Option<&'a Endpoint> {
        match svc.load_balancer {
            None => svc.endpoints.values().choose(&mut rand::thread_rng()),
            Some(ref lb) => {
                let ranks = svc
                    .endpoints
                    .iter()
                    .filter_map(|(_, ep)| {
                        let Some(wl) = self.workloads.find_uid(&ep.workload_uid) else {
                            debug!("failed to fetch workload for {}", ep.workload_uid);
                            return None;
                        };
                        // Load balancer will define N targets we want to match
                        // Consider [network, region, zone]
                        // Rank = 3 means we match all of them
                        // Rank = 2 means network and region match
                        // Rank = 0 means none match
                        let mut rank = 0;
                        for target in &lb.routing_preferences {
                            let matches = match target {
                                LoadBalancerScopes::Region => {
                                    src.locality.region == wl.locality.region
                                }
                                LoadBalancerScopes::Zone => src.locality.zone == wl.locality.zone,
                                LoadBalancerScopes::Subzone => {
                                    src.locality.subzone == wl.locality.subzone
                                }
                                LoadBalancerScopes::Node => src.node == wl.node,
                                LoadBalancerScopes::Cluster => src.cluster_id == wl.cluster_id,
                                LoadBalancerScopes::Network => src.network == wl.network,
                            };
                            if matches {
                                rank += 1;
                            } else {
                                break;
                            }
                        }
                        // Doesn't match all, and required to. Do not select this endpoint
                        if lb.mode == LoadBalancerMode::Strict
                            && rank != lb.routing_preferences.len()
                        {
                            return None;
                        }
                        Some((rank, ep))
                    })
                    .collect::<Vec<_>>();
                let max = *ranks.iter().map(|(rank, _ep)| rank).max()?;
                ranks
                    .into_iter()
                    .filter(|(rank, _ep)| *rank == max)
                    .map(|(_, ep)| ep)
                    .choose(&mut rand::thread_rng())
            }
        }
    }
}

/// Wrapper around [ProxyState] that provides additional methods for requesting information
/// on-demand.
#[derive(serde::Serialize, Debug, Clone)]
pub struct DemandProxyState {
    #[serde(flatten)]
    state: Arc<RwLock<ProxyState>>,

    /// If present, used to request on-demand updates for workloads.
    #[serde(skip_serializing)]
    demand: Option<Demander>,

    #[serde(skip_serializing)]
    dns_resolver_cfg: ResolverConfig,

    #[serde(skip_serializing)]
    dns_resolver_opts: ResolverOpts,
}

impl DemandProxyState {
    pub fn new(
        state: Arc<RwLock<ProxyState>>,
        demand: Option<Demander>,
        dns_resolver_cfg: ResolverConfig,
        dns_resolver_opts: ResolverOpts,
    ) -> Self {
        Self {
            state,
            demand,
            dns_resolver_cfg,
            dns_resolver_opts,
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, ProxyState> {
        self.state.read().unwrap()
    }

    pub async fn assert_rbac(&self, ctx: &ProxyRbacContext) -> bool {
        let nw_addr = network_addr(&ctx.conn.dst_network, ctx.conn.dst.ip());
        let Some(wl) = self.fetch_workload(&nw_addr).await else {
            debug!("destination workload not found {}", nw_addr);
            return false;
        };
        if let Some(ref wl_info) = ctx.dest_workload_info {
            // make sure that the workload we fetched matches the workload info we got over ZDS.
            if !wl_info.matches(&wl) {
                error!("workload does not match proxy workload uid. this is probably a bug. please report an issue");
                return false;
            }
        }
        let conn = &ctx.conn;
        let state = self.state.read().unwrap();

        // We can get policies from namespace, global, and workload...
        let ns = state.policies.get_by_namespace(&wl.namespace);
        let global = state.policies.get_by_namespace(&crate::strng::new(""));
        let workload = wl.authorization_policies.iter();

        // Aggregate all of them based on type
        let (allow, deny): (Vec<_>, Vec<_>) = ns
            .iter()
            .chain(global.iter())
            .chain(workload)
            .filter_map(|k| {
                let pol = state.policies.get(k);
                // Policy not found. This is probably transition state where the policy hasn't been sent
                // by the control plane, or it was just removed.
                if pol.is_none() {
                    warn!("skipping unknown policy {k}");
                }
                pol
            })
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

    // this should only be called once per request (for the workload itself and potentially its waypoint)
    pub async fn pick_workload_destination(
        &self,
        dst_workload: &Workload,
        src_workload: &Workload,
        metrics: Arc<proxy::Metrics>,
    ) -> Result<IpAddr, Error> {
        // TODO: add more sophisticated routing logic, perhaps based on ipv4/ipv6 support underneath us.
        // if/when we support that, this function may need to move to get access to the necessary metadata.
        // Randomly pick an IP
        // TODO: do this more efficiently, and not just randomly
        if let Some(ip) = dst_workload.workload_ips.choose(&mut rand::thread_rng()) {
            return Ok(*ip);
        }
        if dst_workload.hostname.is_empty() {
            debug!(
                "workload {} has no suitable workload IPs for routing",
                dst_workload.name
            );
            return Err(Error::NoValidDestination(Box::new(dst_workload.clone())));
        }
        let ip =
            Box::pin(self.load_balance_for_hostname(dst_workload, src_workload, metrics)).await?;
        Ok(ip)
    }

    async fn load_balance_for_hostname(
        &self,
        workload: &Workload,
        src_workload: &Workload,
        metrics: Arc<proxy::Metrics>,
    ) -> Result<IpAddr, Error> {
        let labels = OnDemandDnsLabels::new()
            .with_destination(workload)
            .with_source(src_workload);
        let workload_uid = workload.uid.to_owned();
        let hostname = workload.hostname.to_owned();
        metrics.as_ref().on_demand_dns.get_or_create(&labels).inc();
        let rdns = match self.get_ips_for_hostname(&workload.hostname) {
            Some(r) => r,
            None => {
                metrics
                    .as_ref()
                    .on_demand_dns_cache_misses
                    .get_or_create(&labels)
                    .inc();
                // TODO: optimize so that if multiple requests to the same hostname come in at the same time,
                // we don't start more than one background on-demand DNS task

                Self::resolve_on_demand_dns(self, workload).await;
                // try to get it again
                let updated_rdns = self.get_ips_for_hostname(&hostname);
                match updated_rdns {
                    Some(rdns) => rdns,
                    None => {
                        return Err(Error::NoResolvedAddresses(workload_uid.to_string()));
                    }
                }
            }
        };

        // TODO: add more sophisticated routing logic, perhaps based on ipv4/ipv6 support underneath us.
        // if/when we support that, this function may need to move to get access to the necessary metadata.
        // Randomly pick an IP
        // TODO: do this more efficiently, and not just randomly
        let Some(ip) = rdns.ips.iter().choose(&mut rand::thread_rng()) else {
            return Err(Error::EmptyResolvedAddresses(workload_uid.to_string()));
        };
        Ok(*ip)
    }

    async fn resolve_on_demand_dns(state: &DemandProxyState, workload: &Workload) {
        let workload_uid = workload.uid.clone();
        let hostname = workload.hostname.clone();
        trace!("dns workload async task started for {:?}", &hostname);

        let resolver_result = TokioAsyncResolver::new(
            state.dns_resolver_cfg.to_owned(),
            state.dns_resolver_opts.clone(),
            TokioConnectionProvider::default(),
        );

        let resp = resolver_result.lookup_ip(hostname.as_ref()).await;
        if resp.is_err() {
            warn!(
                "system dns async resolution: error response for workload {} is: {:?}",
                &workload_uid, resp
            );
            return;
        } else {
            trace!(
                "system dns async resolution: response for workload {} is: {:?}",
                &workload_uid,
                resp
            );
        }
        let resp = resp.unwrap();
        let mut dns_refresh_rate = std::time::Duration::from_secs(u64::MAX);
        let ips = HashSet::from_iter(resp.as_lookup().record_iter().filter_map(|record| {
            if record.record_type().is_ip_addr() {
                let record_ttl = u64::from(record.ttl());
                if let Some(ipv4) = record.data().unwrap().as_a() {
                    if record_ttl < dns_refresh_rate.as_secs() {
                        dns_refresh_rate = std::time::Duration::from_secs(record_ttl);
                    }
                    return Some(IpAddr::V4(ipv4.0));
                }
                if let Some(ipv6) = record.data().unwrap().as_aaaa() {
                    if record_ttl < dns_refresh_rate.as_secs() {
                        dns_refresh_rate = std::time::Duration::from_secs(record_ttl);
                    }
                    return Some(IpAddr::V6(ipv6.0));
                }
                return None;
            }
            None
        }));
        if ips.is_empty() {
            // if we have no DNS records with a TTL to lean on; lets try to refresh again in 60s
            dns_refresh_rate = std::time::Duration::from_secs(60);
        }
        let now = std::time::Instant::now();
        let rdns = ResolvedDns {
            hostname: hostname.to_owned(),
            ips,
            initial_query: Some(now),
            dns_refresh_rate,
        };
        state.set_ips_for_hostname(hostname, rdns);
    }

    pub fn set_ips_for_hostname(&self, hostname: Strng, rdns: ResolvedDns) {
        self.state
            .write()
            .unwrap()
            .resolved_dns
            .by_hostname
            .insert(hostname, rdns);
    }

    pub fn get_ips_for_hostname(&self, hostname: &Strng) -> Option<ResolvedDns> {
        self.state
            .read()
            .unwrap()
            .resolved_dns
            .by_hostname
            .get(hostname)
            .filter(|rdns| {
                rdns.initial_query.is_some()
                    && rdns.initial_query.unwrap().elapsed() < rdns.dns_refresh_rate
            })
            .cloned()
    }

    pub async fn fetch_workload_services(
        &self,
        addr: &NetworkAddress,
    ) -> Option<(Workload, Vec<Arc<Service>>)> {
        // Wait for it on-demand, *if* needed
        debug!(%addr, "fetch workload and service");
        let fetch = |addr: &NetworkAddress| {
            let state = self.state.read().unwrap();
            state.workloads.find_address(addr).map(|wl| {
                let svc = state.services.get_by_workload(&wl);
                (wl, svc)
            })
        };
        if let Some(wl) = fetch(addr) {
            return Some(wl);
        }
        if !self.supports_on_demand() {
            return None;
        }
        self.fetch_on_demand(addr.to_string()).await;
        fetch(addr)
    }

    // only support workload
    pub async fn fetch_workload(&self, addr: &NetworkAddress) -> Option<Workload> {
        // Wait for it on-demand, *if* needed
        debug!(%addr, "fetch workload");
        if let Some(wl) = self.state.read().unwrap().workloads.find_address(addr) {
            return Some(wl);
        }
        if !self.supports_on_demand() {
            return None;
        }
        self.fetch_on_demand(addr.to_string()).await;
        self.state.read().unwrap().workloads.find_address(addr)
    }

    // only support workload
    pub async fn fetch_workload_by_uid(&self, uid: &Strng) -> Option<Workload> {
        // Wait for it on-demand, *if* needed
        debug!(%uid, "fetch workload");
        if let Some(wl) = self.state.read().unwrap().workloads.find_uid(uid) {
            return Some(wl);
        }
        if !self.supports_on_demand() {
            return None;
        }
        self.fetch_on_demand(uid.to_string()).await;
        self.state.read().unwrap().workloads.find_uid(uid)
    }

    pub async fn fetch_upstream(
        &self,
        network: &str,
        source_workload: &Workload,
        addr: SocketAddr,
    ) -> Option<Upstream> {
        self.fetch_address(&network_addr(network, addr.ip())).await;
        self.state
            .read()
            .unwrap()
            .find_upstream(network, source_workload, addr)
    }

    pub async fn fetch_waypoint(
        &self,
        wl: &Workload,
        source_workload: &Workload,
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
        let wp_socket_addr = SocketAddr::new(wp_nw_addr.address, gw_address.hbone_mtls_port);
        match self
            .fetch_upstream(&wp_nw_addr.network, source_workload, wp_socket_addr)
            .await
        {
            Some(mut upstream) => {
                debug!(%wl.name, "found waypoint upstream");
                match set_gateway_address(&mut upstream, workload_ip, gw_address.hbone_mtls_port) {
                    Ok(_) => Ok(Some(upstream)),
                    Err(e) => {
                        debug!(%wl.name, "failed to set gateway address for upstream: {}", e);
                        Err(WaypointError::FindWaypointError(wl.name.to_string()))
                    }
                }
            }
            None => {
                debug!(%wl.name, "waypoint upstream not found");
                Err(WaypointError::FindWaypointError(wl.name.to_string()))
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
        if !self.supports_on_demand() {
            return None;
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
        if !self.supports_on_demand() {
            return None;
        }
        // if both cache not found, start on demand fetch
        self.fetch_on_demand(hostname.to_string()).await;
        self.state.read().unwrap().find_hostname(hostname)
    }

    pub fn supports_on_demand(&self) -> bool {
        self.demand.is_some()
    }

    /// fetch_on_demand looks up the provided key on-demand and waits for it to return
    pub async fn fetch_on_demand(&self, key: String) {
        if let Some(demand) = &self.demand {
            debug!(%key, "sending demand request");
            Box::pin(
                demand
                    .demand(xds::ADDRESS_TYPE.to_string(), key.clone())
                    .then(|o| o.recv()),
            )
            .await;
            debug!(%key, "on demand ready");
        }
    }
}

pub fn set_gateway_address(
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

#[derive(serde::Serialize)]
pub struct ProxyStateManager {
    #[serde(flatten)]
    state: DemandProxyState,

    #[serde(skip_serializing)]
    xds_client: Option<AdsClient>,
}

impl ProxyStateManager {
    pub async fn new(
        config: Arc<config::Config>,
        metrics: Metrics,
        awaiting_ready: tokio::sync::watch::Sender<()>,
        cert_manager: Arc<SecretManager>,
    ) -> anyhow::Result<ProxyStateManager> {
        let cert_fetcher = cert_fetcher::new(&config, cert_manager);
        let state: Arc<RwLock<ProxyState>> = Arc::new(RwLock::new(ProxyState::default()));
        let xds_client = if config.xds_address.is_some() {
            let updater = ProxyStateUpdater::new(state.clone(), cert_fetcher.clone());
            let tls_client_fetcher = Box::new(tls::ControlPlaneAuthentication::RootCert(
                config.xds_root_cert.clone(),
            ));
            Some(
                xds::Config::new(config.clone(), tls_client_fetcher)
                    .with_watched_handler::<XdsAddress>(xds::ADDRESS_TYPE, updater.clone())
                    .with_watched_handler::<XdsAuthorization>(xds::AUTHORIZATION_TYPE, updater)
                    .build(metrics, awaiting_ready),
            )
        } else {
            None
        };
        if let Some(cfg) = &config.local_xds_config {
            let local_client = LocalClient {
                cfg: cfg.clone(),
                state: state.clone(),
                cert_fetcher,
            };
            local_client.run().await?;
        }
        let demand = xds_client.as_ref().and_then(AdsClient::demander);
        Ok(ProxyStateManager {
            xds_client,
            state: DemandProxyState {
                state,
                demand,
                dns_resolver_cfg: config.dns_resolver_cfg.clone(),
                dns_resolver_opts: config.dns_resolver_opts.clone(),
            },
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
    use crate::state::service::LoadBalancer;
    use crate::state::workload::Locality;
    use std::{net::Ipv4Addr, net::SocketAddrV4, time::Duration};

    use super::*;
    use crate::test_helpers;
    use crate::test_helpers::TEST_SERVICE_NAMESPACE;

    #[tokio::test]
    async fn lookup_address() {
        let mut state = ProxyState::default();
        state
            .workloads
            .insert(test_helpers::test_default_workload());
        state.services.insert(test_helpers::mock_default_service());

        let mock_proxy_state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        // Some from Address
        let dst = Destination::Address(NetworkAddress {
            network: "".to_string(),
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });
        test_helpers::assert_eventually(
            Duration::from_secs(5),
            || mock_proxy_state.fetch_destination(&dst),
            Some(Address::Workload(Arc::new(
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
            Some(Address::Service(Arc::new(
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

    #[tokio::test]
    async fn assert_rbac_with_dest_workload_info() {
        let mut state = ProxyState::default();
        let wl = Workload {
            name: "test".to_string(),
            namespace: "default".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "defaultacct".to_string(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))],
            ..test_helpers::test_default_workload()
        };
        state.workloads.insert(wl);

        let mock_proxy_state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let wi = WorkloadInfo {
            name: "test".to_string(),
            namespace: "default".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "defaultacct".to_string(),
        };

        let mut ctx = crate::state::ProxyRbacContext {
            conn: rbac::Connection {
                src_identity: None,
                src: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 1),
                    1234,
                )),
                dst_network: "".to_string(),
                dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 2),
                    8080,
                )),
            },
            dest_workload_info: Some(Arc::new(wi.clone())),
        };
        assert!(mock_proxy_state.assert_rbac(&ctx).await);

        // now make sure it fails when we change just one property of the workload info
        {
            let mut wi = wi.clone();
            wi.name = "not-test".to_string();
            ctx.dest_workload_info = Some(Arc::new(wi.clone()));
            assert!(!mock_proxy_state.assert_rbac(&ctx).await);
        }
        {
            let mut wi = wi.clone();
            wi.namespace = "not-test".to_string();
            ctx.dest_workload_info = Some(Arc::new(wi.clone()));
            assert!(!mock_proxy_state.assert_rbac(&ctx).await);
        }
        {
            let mut wi = wi.clone();
            wi.service_account = "not-test".to_string();
            ctx.dest_workload_info = Some(Arc::new(wi.clone()));
            assert!(!mock_proxy_state.assert_rbac(&ctx).await);
        }
        {
            let mut wi = wi.clone();
            wi.trust_domain = "not-test".to_string();
            ctx.dest_workload_info = Some(Arc::new(wi.clone()));
            assert!(!mock_proxy_state.assert_rbac(&ctx).await);
        }
    }

    #[tokio::test]
    async fn test_load_balance() {
        let mut state = ProxyState::default();
        let wl_no_locality = Workload {
            uid: "cluster1//v1/Pod/default/wl_no_locality".to_string(),
            name: "wl_no_locality".to_string(),
            namespace: "default".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))],
            ..test_helpers::test_default_workload()
        };
        let wl_match = Workload {
            uid: "cluster1//v1/Pod/default/wl_match".to_string(),
            name: "wl_match".to_string(),
            namespace: "default".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))],
            network: "network".to_string(),
            locality: Locality {
                region: "reg".to_string(),
                zone: "zone".to_string(),
                subzone: "".to_string(),
            },
            ..test_helpers::test_default_workload()
        };
        let wl_almost = Workload {
            uid: "cluster1//v1/Pod/default/wl_almost".to_string(),
            name: "wl_almost".to_string(),
            namespace: "default".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3))],
            network: "network".to_string(),
            locality: Locality {
                region: "reg".to_string(),
                zone: "not-zone".to_string(),
                subzone: "".to_string(),
            },
            ..test_helpers::test_default_workload()
        };
        let _ep_almost = Workload {
            uid: "cluster1//v1/Pod/default/ep_almost".to_string(),
            name: "wl_almost".to_string(),
            namespace: "default".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 4))],
            network: "network".to_string(),
            locality: Locality {
                region: "reg".to_string(),
                zone: "other-not-zone".to_string(),
                subzone: "".to_string(),
            },
            ..test_helpers::test_default_workload()
        };
        let _ep_no_match = Workload {
            uid: "cluster1//v1/Pod/default/ep_no_match".to_string(),
            name: "wl_almost".to_string(),
            namespace: "default".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5))],
            network: "not-network".to_string(),
            locality: Locality {
                region: "not-reg".to_string(),
                zone: "unmatched-zone".to_string(),
                subzone: "".to_string(),
            },
            ..test_helpers::test_default_workload()
        };
        let endpoints = HashMap::from([
            (
                "cluster1//v1/Pod/default/ep_almost".to_string(),
                Endpoint {
                    workload_uid: "cluster1//v1/Pod/default/ep_almost".to_string(),
                    service: NamespacedHostname {
                        namespace: TEST_SERVICE_NAMESPACE.to_string(),
                        hostname: "example.com".to_string(),
                    },
                    address: Some(NetworkAddress {
                        address: "192.168.0.4".parse().unwrap(),
                        network: "".to_string(),
                    }),
                    port: HashMap::from([(80u16, 80u16)]),
                },
            ),
            (
                "cluster1//v1/Pod/default/ep_no_match".to_string(),
                Endpoint {
                    workload_uid: "cluster1//v1/Pod/default/ep_almost".to_string(),
                    service: NamespacedHostname {
                        namespace: TEST_SERVICE_NAMESPACE.to_string(),
                        hostname: "example.com".to_string(),
                    },
                    address: Some(NetworkAddress {
                        address: "192.168.0.5".parse().unwrap(),
                        network: "".to_string(),
                    }),
                    port: HashMap::from([(80u16, 80u16)]),
                },
            ),
            (
                "cluster1//v1/Pod/default/wl_match".to_string(),
                Endpoint {
                    workload_uid: "cluster1//v1/Pod/default/wl_match".to_string(),
                    service: NamespacedHostname {
                        namespace: TEST_SERVICE_NAMESPACE.to_string(),
                        hostname: "example.com".to_string(),
                    },
                    address: Some(NetworkAddress {
                        address: "192.168.0.2".parse().unwrap(),
                        network: "".to_string(),
                    }),
                    port: HashMap::from([(80u16, 80u16)]),
                },
            ),
        ]);
        let strict_svc = Service {
            endpoints: endpoints.clone(),
            load_balancer: Some(LoadBalancer {
                mode: LoadBalancerMode::Strict,
                routing_preferences: vec![
                    LoadBalancerScopes::Network,
                    LoadBalancerScopes::Region,
                    LoadBalancerScopes::Zone,
                ],
            }),
            ..test_helpers::mock_default_service()
        };
        let failover_svc = Service {
            endpoints,
            load_balancer: Some(LoadBalancer {
                mode: LoadBalancerMode::Failover,
                routing_preferences: vec![
                    LoadBalancerScopes::Network,
                    LoadBalancerScopes::Region,
                    LoadBalancerScopes::Zone,
                ],
            }),
            ..test_helpers::mock_default_service()
        };
        state.workloads.insert(wl_no_locality.clone());
        state.workloads.insert(wl_match.clone());
        state.workloads.insert(wl_almost.clone());
        state.services.insert(strict_svc.clone());
        state.services.insert(failover_svc.clone());

        let assert_endpoint = |src: &Workload, svc: &Service, ips: Vec<&str>, desc: &str| {
            let got = state
                .load_balance(src, svc)
                .and_then(|ep| ep.address.clone())
                .map(|addr| addr.address.to_string());
            if ips.is_empty() {
                assert!(got.is_none(), "{}", desc);
            } else {
                let want: Vec<String> = ips.iter().map(ToString::to_string).collect();
                assert!(want.contains(&got.unwrap()), "{}", desc);
            }
        };

        assert_endpoint(
            &wl_no_locality,
            &strict_svc,
            vec![],
            "strict no match should not select",
        );
        assert_endpoint(
            &wl_almost,
            &strict_svc,
            vec![],
            "strict no match should not select",
        );
        assert_endpoint(&wl_match, &strict_svc, vec!["192.168.0.2"], "strict match");

        assert_endpoint(
            &wl_no_locality,
            &failover_svc,
            vec!["192.168.0.2", "192.168.0.4", "192.168.0.5"],
            "failover no match can select any endpoint",
        );
        assert_endpoint(
            &wl_almost,
            &failover_svc,
            vec!["192.168.0.2", "192.168.0.4"],
            "failover almost match can select any close matches",
        );
        assert_endpoint(
            &wl_match,
            &failover_svc,
            vec!["192.168.0.2"],
            "failover full match selects closest match",
        );
    }
}
