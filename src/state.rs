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

use crate::identity::{Identity, SecretManager};
use crate::proxy;
use crate::proxy::{Error, OnDemandDnsLabels};
use crate::rbac::Authorization;
use crate::state::policy::PolicyStore;
use crate::state::service::{
    Endpoint, IpFamily, LoadBalancerMode, LoadBalancerScopes, ServiceStore,
};
use crate::state::service::{Service, ServiceDescription};
use crate::state::workload::{
    address::Address, gatewayaddress::Destination, network_addr, GatewayAddress,
    NamespacedHostname, NetworkAddress, Workload, WorkloadStore,
};
use crate::strng::Strng;
use crate::tls;
use crate::xds::istio::security::Authorization as XdsAuthorization;
use crate::xds::istio::workload::Address as XdsAddress;
use crate::xds::{AdsClient, Demander, LocalClient, ProxyStateUpdater};
use crate::{cert_fetcher, config, rbac, xds};
use futures_util::FutureExt;
use hickory_resolver::config::*;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioAsyncResolver;
use itertools::Itertools;
use rand::prelude::IteratorRandom;
use serde::Serializer;
use std::collections::HashMap;
use std::convert::Into;
use std::default::Default;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::Duration;
use tracing::{debug, error, trace, warn};

use self::workload::ApplicationTunnel;

pub mod policy;
pub mod service;
pub mod workload;

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Upstream {
    /// Workload is the workload we are connecting to
    pub workload: Arc<Workload>,
    /// selected_workload_ip defines the IP address we should actually use to connect to this workload
    /// This handles multiple IPs (dual stack) or Hostname destinations (DNS resolution)
    pub selected_workload_ip: IpAddr,
    /// Port is the port we should connect to
    pub port: u16,
    /// Service SANs defines SANs defined at the service level *only*. A complete view of things requires
    /// looking at workload.identity() as well.
    pub service_sans: Vec<Strng>,
    /// If this was from a service, the service info.
    pub destination_service: Option<ServiceDescription>,
}

impl Upstream {
    pub fn workload_socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.selected_workload_ip, self.port)
    }
    pub fn workload_and_services_san(&self) -> Vec<Identity> {
        self.service_sans
            .iter()
            .flat_map(|san| match Identity::from_str(san) {
                Ok(id) => Some(id),
                Err(err) => {
                    warn!("ignoring invalid SAN {}: {}", san, err);
                    None
                }
            })
            .chain(std::iter::once(self.workload.identity()))
            .collect()
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
    pub service_account: String,
}

impl fmt::Display for WorkloadInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{} ({})",
            self.service_account, self.namespace, self.name
        )
    }
}

impl WorkloadInfo {
    pub fn new(name: String, namespace: String, service_account: String) -> Self {
        Self {
            name,
            namespace,
            service_account,
        }
    }

    pub fn matches(&self, w: &Workload) -> bool {
        self.name == w.name
            && self.namespace == w.namespace
            && self.service_account == w.service_account
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
pub struct ProxyRbacContext {
    pub conn: rbac::Connection,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub dest_workload_info: Option<Arc<WorkloadInfo>>,
}
impl ProxyRbacContext {
    pub fn into_conn(self) -> rbac::Connection {
        self.conn
    }
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
}

#[derive(serde::Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ProxyStateSerialization<'a> {
    workloads: Vec<Arc<Workload>>,
    services: Vec<Arc<Service>>,
    policies: Vec<Authorization>,
    staged_services: &'a HashMap<NamespacedHostname, HashMap<Strng, Endpoint>>,
}

impl serde::Serialize for ProxyState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Services all have hostname, so use that as the key
        let services: Vec<_> = self
            .services
            .by_host
            .iter()
            .sorted_by_key(|k| k.0)
            .flat_map(|k| k.1)
            .cloned()
            .collect();
        // Workloads all have a UID, so use that as the key
        let workloads: Vec<_> = self
            .workloads
            .by_uid
            .iter()
            .sorted_by_key(|k| k.0)
            .map(|k| k.1)
            .cloned()
            .collect();
        let policies: Vec<_> = self
            .policies
            .by_key
            .iter()
            .sorted_by_key(|k| k.0)
            .map(|k| k.1)
            .cloned()
            .collect();
        let serializable = ProxyStateSerialization {
            workloads,
            services,
            policies,
            staged_services: &self.services.staged_services,
        };
        serializable.serialize(serializer)
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
        // We do not looking up workloads by hostname. We could, but we only allow referencing "frontends",
        // not backends
        self.services
            .get_by_namespaced_host(name)
            .map(Address::Service)
    }

    fn find_upstream(
        &self,
        network: Strng,
        source_workload: &Workload,
        addr: SocketAddr,
        resolution_mode: ServiceResolutionMode,
    ) -> Option<(Arc<Workload>, u16, Option<Arc<Service>>)> {
        if let Some(svc) = self
            .services
            .get_by_vip(&network_addr(network.clone(), addr.ip()))
        {
            return self.find_upstream_from_service(
                source_workload,
                addr.port(),
                resolution_mode,
                svc,
            );
        }
        if let Some(wl) = self
            .workloads
            .find_address(&network_addr(network, addr.ip()))
        {
            return Some((wl, addr.port(), None));
        }
        None
    }

    fn find_upstream_from_service(
        &self,
        source_workload: &Workload,
        svc_port: u16,
        resolution_mode: ServiceResolutionMode,
        svc: Arc<Service>,
    ) -> Option<(Arc<Workload>, u16, Option<Arc<Service>>)> {
        // Randomly pick an upstream
        // TODO: do this more efficiently, and not just randomly
        let Some((ep, wl)) = self.load_balance(source_workload, &svc, svc_port, resolution_mode)
        else {
            debug!("Service {} has no healthy endpoints", svc.hostname);
            return None;
        };

        let svc_target_port = svc.ports.get(&svc_port).copied().unwrap_or_default();
        let target_port = if let Some(&ep_target_port) = ep.port.get(&svc_port) {
            // prefer endpoint port mapping
            ep_target_port
        } else if svc_target_port > 0 {
            // otherwise, see if the service has this port
            svc_target_port
        } else if let Some(ApplicationTunnel { port: Some(_), .. }) = &wl.application_tunnel {
            // when using app tunnel, we don't require the port to be found on the service
            svc_port
        } else {
            // no app tunnel or port mapping, error
            debug!(
                "found service {}, but port {} was unknown",
                svc.hostname, svc_port
            );
            return None;
        };

        Some((wl, target_port, Some(svc)))
    }

    fn load_balance<'a>(
        &self,
        src: &Workload,
        svc: &'a Service,
        svc_port: u16,
        resolution_mode: ServiceResolutionMode,
    ) -> Option<(&'a Endpoint, Arc<Workload>)> {
        let target_port = svc.ports.get(&svc_port).copied();

        if resolution_mode == ServiceResolutionMode::Standard && target_port.is_none() {
            // Port doesn't exist on the service at all, this is invalid
            debug!("service {} does not have port {}", svc.hostname, svc_port);
            return None;
        };

        let endpoints = svc.endpoints.values().filter_map(|ep| {
            let Some(wl) = self.workloads.find_uid(&ep.workload_uid) else {
                debug!("failed to fetch workload for {}", ep.workload_uid);
                return None;
            };
            match resolution_mode {
                ServiceResolutionMode::Standard => {
                    if target_port.unwrap_or_default() == 0 && !ep.port.contains_key(&svc_port) {
                        // Filter workload out, it doesn't have a matching port
                        trace!(
                            "filter endpoint {}, it does not have service port {}",
                            ep.workload_uid,
                            svc_port
                        );
                        return None;
                    }
                }
                ServiceResolutionMode::Waypoint => {
                    if target_port.is_none() && wl.application_tunnel.is_none() {
                        // We ignore this for app_tunnel; in this case, the port does not need to be on the service.
                        // This is only valid for waypoints, which are not explicitly addressed by users.
                        // We do happen to do a lookup by `waypoint-svc:15008`, this is not a literal call on that service;
                        // the port is not required at all if they have application tunnel, as it will be handled by ztunnel on the other end.
                        trace!(
                            "filter waypoint endpoint {}, target port is not defined",
                            ep.workload_uid
                        );
                        return None;
                    }
                }
            }
            Some((ep, wl))
        });

        match svc.load_balancer {
            Some(ref lb) if lb.mode != LoadBalancerMode::Standard => {
                let ranks = endpoints
                    .filter_map(|(ep, wl)| {
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
                        Some((rank, ep, wl))
                    })
                    .collect::<Vec<_>>();
                let max = *ranks.iter().map(|(rank, _ep, _wl)| rank).max()?;
                ranks
                    .into_iter()
                    .filter(|(rank, _ep, _wl)| *rank == max)
                    .map(|(_, ep, wl)| (ep, wl))
                    .choose(&mut rand::thread_rng())
            }
            _ => endpoints.choose(&mut rand::thread_rng()),
        }
    }
}

/// Wrapper around [ProxyState] that provides additional methods for requesting information
/// on-demand.
#[derive(serde::Serialize, Clone)]
pub struct DemandProxyState {
    #[serde(flatten)]
    state: Arc<RwLock<ProxyState>>,

    /// If present, used to request on-demand updates for workloads.
    #[serde(skip_serializing)]
    demand: Option<Demander>,

    #[serde(skip_serializing)]
    metrics: Arc<proxy::Metrics>,

    #[serde(skip_serializing)]
    dns_resolver: TokioAsyncResolver,
}

impl DemandProxyState {
    pub fn new(
        state: Arc<RwLock<ProxyState>>,
        demand: Option<Demander>,
        dns_resolver_cfg: ResolverConfig,
        dns_resolver_opts: ResolverOpts,
        metrics: Arc<proxy::Metrics>,
    ) -> Self {
        let dns_resolver = TokioAsyncResolver::new(
            dns_resolver_cfg.to_owned(),
            dns_resolver_opts.clone(),
            TokioConnectionProvider::default(),
        );
        Self {
            state,
            demand,
            dns_resolver,
            metrics,
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, ProxyState> {
        self.state.read().unwrap()
    }

    pub async fn assert_rbac(&self, ctx: &ProxyRbacContext) -> bool {
        let nw_addr = network_addr(ctx.conn.dst_network.clone(), ctx.conn.dst.ip());
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
        let global = state.policies.get_by_namespace(&crate::strng::EMPTY);
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
                debug!(policy = pol.to_key().as_str(), "deny policy match");
                return false;
            } else {
                trace!(policy = pol.to_key().as_str(), "deny policy does not match");
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
                debug!(policy = pol.to_key().as_str(), "allow policy match");
                return true;
            } else {
                trace!(
                    policy = pol.to_key().as_str(),
                    "allow policy does not match"
                );
            }
        }
        // "Deny the request."
        debug!("no allow policies matched");
        false
    }

    // Select a workload IP, with DNS resolution if needed
    async fn pick_workload_destination_or_resolve(
        &self,
        dst_workload: &Workload,
        src_workload: &Workload,
        original_target_address: SocketAddr,
        ip_family_restriction: Option<IpFamily>,
    ) -> Result<IpAddr, Error> {
        // If the user requested the pod by a specific IP, use that directly.
        if dst_workload
            .workload_ips
            .contains(&original_target_address.ip())
        {
            return Ok(original_target_address.ip());
        }
        // They may have 1 or 2 IPs (single/dual stack)
        // Ensure we are meeting the Service family restriction (if any is defined).
        // Otherwise, prefer the same IP family as the original request.
        if let Some(ip) = dst_workload
            .workload_ips
            .iter()
            .filter(|ip| {
                ip_family_restriction
                    .map(|f| f.accepts_ip(**ip))
                    .unwrap_or(true)
            })
            .find_or_first(|ip| ip.is_ipv6() == original_target_address.is_ipv6())
        {
            return Ok(*ip);
        }
        if dst_workload.hostname.is_empty() {
            debug!(
                "workload {} has no suitable workload IPs for routing",
                dst_workload.name
            );
            return Err(Error::NoValidDestination(Box::new(dst_workload.clone())));
        }
        let ip = Box::pin(self.resolve_workload_address(
            dst_workload,
            src_workload,
            original_target_address,
        ))
        .await?;
        Ok(ip)
    }

    async fn resolve_workload_address(
        &self,
        workload: &Workload,
        src_workload: &Workload,
        original_target_address: SocketAddr,
    ) -> Result<IpAddr, Error> {
        let labels = OnDemandDnsLabels::new()
            .with_destination(workload)
            .with_source(src_workload);
        self.metrics
            .as_ref()
            .on_demand_dns
            .get_or_create(&labels)
            .inc();
        self.resolve_on_demand_dns(workload, original_target_address)
            .await
    }

    async fn resolve_on_demand_dns(
        &self,
        workload: &Workload,
        original_target_address: SocketAddr,
    ) -> Result<IpAddr, Error> {
        let workload_uid = workload.uid.clone();
        let hostname = workload.hostname.clone();
        trace!(%hostname, "starting DNS lookup");

        let resp = match self.dns_resolver.lookup_ip(hostname.as_str()).await {
            Err(err) => {
                warn!(?err,%hostname,"dns lookup failed");
                return Err(Error::NoResolvedAddresses(workload_uid.to_string()));
            }
            Ok(resp) => resp,
        };
        trace!(%hostname, "dns lookup complete {resp:?}");

        let (matching, unmatching): (Vec<_>, Vec<_>) = resp
            .as_lookup()
            .record_iter()
            .filter_map(|record| record.data().and_then(|d| d.ip_addr()))
            .partition(|record| record.is_ipv6() == original_target_address.is_ipv6());
        // Randomly pick an IP, prefer to match the IP family of the downstream request.
        // Without this, we run into trouble in pure v4 or pure v6 environments.
        matching
            .into_iter()
            .choose(&mut rand::thread_rng())
            .or_else(|| unmatching.into_iter().choose(&mut rand::thread_rng()))
            .ok_or_else(|| Error::EmptyResolvedAddresses(workload_uid.to_string()))
    }

    pub async fn fetch_workload_services(
        &self,
        addr: &NetworkAddress,
    ) -> Option<(Arc<Workload>, Vec<Arc<Service>>)> {
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
        self.fetch_on_demand(addr.to_string().into()).await;
        fetch(addr)
    }

    // same as fetch_workload, but if the caller knows the workload is enroute already,
    // will retry on cache miss for a configured amount of time - returning the workload
    // when we get it, or nothing if the timeout is exceeded, whichever happens first
    pub async fn wait_for_workload(
        &self,
        addr: &NetworkAddress,
        deadline: Duration,
    ) -> Option<Arc<Workload>> {
        debug!(%addr, "wait for workload");

        // Take a watch listener *before* checking state (so we don't miss anything)
        let mut wl_sub = self.state.read().unwrap().workloads.new_subscriber();

        debug!(%addr, "got sub, waiting for workload");

        if let Some(wl) = self.fetch_workload(addr).await {
            return Some(wl);
        }

        // We didn't find the workload we expected, so
        // loop until the subscriber wakes us on new workload,
        // or we hit the deadline timeout and give up
        let timeout = tokio::time::sleep(deadline);
        tokio::pin!(timeout);
        loop {
            tokio::select! {
                _ = &mut timeout => {
                    warn!("timed out waiting for workload from xds");
                    break None;
                },
                _ = wl_sub.changed() => {
                    if let Some(wl) = self.fetch_workload(addr).await {
                        break Some(wl);
                    }
                }
            }
        }
    }

    // only support workload
    pub async fn fetch_workload(&self, addr: &NetworkAddress) -> Option<Arc<Workload>> {
        // Wait for it on-demand, *if* needed
        debug!(%addr, "fetch workload");
        if let Some(wl) = self.state.read().unwrap().workloads.find_address(addr) {
            return Some(wl);
        }
        if !self.supports_on_demand() {
            return None;
        }
        self.fetch_on_demand(addr.to_string().into()).await;
        self.state.read().unwrap().workloads.find_address(addr)
    }

    // only support workload
    pub async fn fetch_workload_by_uid(&self, uid: &Strng) -> Option<Arc<Workload>> {
        // Wait for it on-demand, *if* needed
        debug!(%uid, "fetch workload");
        if let Some(wl) = self.state.read().unwrap().workloads.find_uid(uid) {
            return Some(wl);
        }
        if !self.supports_on_demand() {
            return None;
        }
        self.fetch_on_demand(uid.clone()).await;
        self.read().workloads.find_uid(uid)
    }

    pub async fn fetch_upstream(
        &self,
        network: Strng,
        source_workload: &Workload,
        addr: SocketAddr,
        resolution_mode: ServiceResolutionMode,
    ) -> Result<Option<Upstream>, Error> {
        self.fetch_address(&network_addr(network.clone(), addr.ip()))
            .await;
        let upstream = {
            self.read()
                .find_upstream(network, source_workload, addr, resolution_mode)
            // Drop the lock
        };
        tracing::trace!(%addr, ?upstream, "fetch_upstream");
        self.finalize_upstream(source_workload, addr, upstream)
            .await
    }

    async fn finalize_upstream(
        &self,
        source_workload: &Workload,
        original_target_address: SocketAddr,
        upstream: Option<(Arc<Workload>, u16, Option<Arc<Service>>)>,
    ) -> Result<Option<Upstream>, Error> {
        let Some((wl, port, svc)) = upstream else {
            return Ok(None);
        };
        let svc_desc = svc.clone().map(|s| ServiceDescription::from(s.as_ref()));
        let ip_family_restriction = svc.as_ref().and_then(|s| s.ip_families);
        let selected_workload_ip = self
            .pick_workload_destination_or_resolve(
                &wl,
                source_workload,
                original_target_address,
                ip_family_restriction,
            )
            .await?; // if we can't load balance just return the error
        let res = Upstream {
            workload: wl,
            selected_workload_ip,
            port,
            service_sans: svc.map(|s| s.subject_alt_names.clone()).unwrap_or_default(),
            destination_service: svc_desc,
        };
        tracing::trace!(?res, "finalize_upstream");
        Ok(Some(res))
    }

    async fn fetch_waypoint(
        &self,
        gw_address: &GatewayAddress,
        source_workload: &Workload,
        original_destination_address: SocketAddr,
    ) -> Result<Upstream, Error> {
        // Waypoint can be referred to by an IP or Hostname.
        // Hostname is preferred as it is a more stable identifier.
        let (res, target_address) = match &gw_address.destination {
            Destination::Address(ip) => {
                let addr = SocketAddr::new(ip.address, gw_address.hbone_mtls_port);
                let us = self.state.read().unwrap().find_upstream(
                    ip.network.clone(),
                    source_workload,
                    addr,
                    ServiceResolutionMode::Waypoint,
                );
                // If they referenced a waypoint by IP, use that IP as the destination.
                // Note this means that an IPv6 call may be translated to IPv4 if the waypoint is specified
                // as an IPv4 address.
                // For this reason, the Hostname method is preferred which can adapt to the callers IP family.
                (us, addr)
            }
            Destination::Hostname(host) => {
                let state = self.read();
                match state.find_hostname(host) {
                    Some(Address::Service(s)) => {
                        let us = state.find_upstream_from_service(
                            source_workload,
                            gw_address.hbone_mtls_port,
                            ServiceResolutionMode::Waypoint,
                            s,
                        );
                        // For hostname, use the original_destination_address as the target so we can
                        // adapt to the callers IP family.
                        (us, original_destination_address)
                    }
                    Some(_) => {
                        return Err(Error::UnsupportedFeature(
                            "waypoint must be a service, not a workload".to_string(),
                        ))
                    }
                    None => {
                        return Err(Error::UnknownWaypoint(format!(
                            "waypoint {} not found",
                            host.hostname
                        )))
                    }
                }
            }
        };
        self.finalize_upstream(source_workload, target_address, res)
            .await?
            .ok_or_else(|| Error::UnknownWaypoint(format!("waypoint {:?} not found", gw_address)))
    }

    pub async fn fetch_service_waypoint(
        &self,
        service: &Service,
        source_workload: &Workload,
        original_destination_address: SocketAddr,
    ) -> Result<Option<Upstream>, Error> {
        let Some(gw_address) = &service.waypoint else {
            // no waypoint
            return Ok(None);
        };
        self.fetch_waypoint(gw_address, source_workload, original_destination_address)
            .await
            .map(Some)
    }

    pub async fn fetch_workload_waypoint(
        &self,
        wl: &Workload,
        source_workload: &Workload,
        original_destination_address: SocketAddr,
    ) -> Result<Option<Upstream>, Error> {
        let Some(gw_address) = &wl.waypoint else {
            // no waypoint
            return Ok(None);
        };
        self.fetch_waypoint(gw_address, source_workload, original_destination_address)
            .await
            .map(Some)
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
        self.fetch_on_demand(network_addr.to_string().into()).await;
        self.state.read().unwrap().find_address(network_addr)
    }

    /// Looks for the given hostname to find either a workload or service by IP. If not found
    /// locally, attempts to fetch on-demand.
    async fn fetch_hostname(&self, hostname: &NamespacedHostname) -> Option<Address> {
        // Wait for it on-demand, *if* needed
        debug!(%hostname, "fetch hostname");
        if let Some(address) = self.state.read().unwrap().find_hostname(hostname) {
            return Some(address);
        }
        if !self.supports_on_demand() {
            return None;
        }
        // if both cache not found, start on demand fetch
        self.fetch_on_demand(hostname.to_string().into()).await;
        self.state.read().unwrap().find_hostname(hostname)
    }

    pub fn supports_on_demand(&self) -> bool {
        self.demand.is_some()
    }

    /// fetch_on_demand looks up the provided key on-demand and waits for it to return
    pub async fn fetch_on_demand(&self, key: Strng) {
        if let Some(demand) = &self.demand {
            debug!(%key, "sending demand request");
            Box::pin(
                demand
                    .demand(xds::ADDRESS_TYPE, key.clone())
                    .then(|o| o.recv()),
            )
            .await;
            debug!(%key, "on demand ready");
        }
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum ServiceResolutionMode {
    // We are resolving a normal service
    Standard,
    // We are resolving a waypoint proxy
    Waypoint,
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
        xds_metrics: xds::Metrics,
        proxy_metrics: Arc<proxy::Metrics>,
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
                    .build(xds_metrics, awaiting_ready),
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
            state: DemandProxyState::new(
                state,
                demand,
                config.dns_resolver_cfg.clone(),
                config.dns_resolver_opts.clone(),
                proxy_metrics,
            ),
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
    use crate::state::service::{LoadBalancer, LoadBalancerHealthPolicy};
    use crate::state::workload::{HealthStatus, Locality};
    use prometheus_client::registry::Registry;
    use std::{net::Ipv4Addr, net::SocketAddrV4, time::Duration};

    use self::workload::{application_tunnel::Protocol as AppProtocol, ApplicationTunnel};

    use super::*;
    use crate::test_helpers::helpers::initialize_telemetry;
    use crate::test_helpers::TEST_SERVICE_NAMESPACE;
    use crate::{strng, test_helpers};
    use test_case::test_case;

    #[tokio::test]
    async fn test_wait_for_workload() {
        let mut state = ProxyState::default();
        let delayed_wl = Arc::new(test_helpers::test_default_workload());
        state.workloads.insert(delayed_wl.clone(), true);

        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let mock_proxy_state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );

        // Some from Address
        let dst = NetworkAddress {
            network: strng::EMPTY,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };

        test_helpers::assert_eventually(
            Duration::from_secs(1),
            || mock_proxy_state.wait_for_workload(&dst, Duration::from_millis(50)),
            Some(delayed_wl),
        )
        .await;
    }

    #[tokio::test]
    async fn test_wait_for_workload_delay_fails() {
        let state = ProxyState::default();

        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let mock_proxy_state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );

        // Some from Address
        let dst = NetworkAddress {
            network: strng::EMPTY,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };

        test_helpers::assert_eventually(
            Duration::from_millis(10),
            || mock_proxy_state.wait_for_workload(&dst, Duration::from_millis(5)),
            None,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_wait_for_workload_eventually() {
        initialize_telemetry();
        let state = ProxyState::default();
        let wrap_state = Arc::new(RwLock::new(state));
        let not_delayed_wl = Arc::new(Workload {
            workload_ips: vec!["1.2.3.4".parse().unwrap()],
            uid: "uid".into(),
            name: "n".into(),
            namespace: "ns".into(),
            ..test_helpers::test_default_workload()
        });
        let delayed_wl = Arc::new(test_helpers::test_default_workload());

        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let mock_proxy_state = DemandProxyState::new(
            wrap_state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );

        // Some from Address
        let dst = NetworkAddress {
            network: strng::EMPTY,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };

        let expected_wl = delayed_wl.clone();
        let t = tokio::spawn(async move {
            test_helpers::assert_eventually(
                Duration::from_millis(500),
                || mock_proxy_state.wait_for_workload(&dst, Duration::from_millis(250)),
                Some(expected_wl),
            )
            .await;
        });
        // Send the wrong workload through
        wrap_state
            .write()
            .unwrap()
            .workloads
            .insert(not_delayed_wl, true);
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Send the correct workload through
        wrap_state
            .write()
            .unwrap()
            .workloads
            .insert(delayed_wl, true);
        t.await.expect("should not fail");
    }

    #[tokio::test]
    async fn lookup_address() {
        let mut state = ProxyState::default();
        state
            .workloads
            .insert(Arc::new(test_helpers::test_default_workload()), true);
        state.services.insert(test_helpers::mock_default_service());

        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let mock_proxy_state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );

        // Some from Address
        let dst = Destination::Address(NetworkAddress {
            network: strng::EMPTY,
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
            namespace: "default".into(),
            hostname: "defaulthost".into(),
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
            network: "".into(),
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
            namespace: "default".into(),
            hostname: "nothost".into(),
        });
        test_helpers::assert_eventually(
            Duration::from_secs(5),
            || mock_proxy_state.fetch_destination(&dst),
            None,
        )
        .await;
    }

    enum PortMappingTestCase {
        EndpointMapping,
        ServiceMapping,
        AppTunnel,
    }

    impl PortMappingTestCase {
        fn service_mapping(&self) -> HashMap<u16, u16> {
            if let PortMappingTestCase::ServiceMapping = self {
                return HashMap::from([(80, 8080)]);
            }
            HashMap::from([(80, 0)])
        }

        fn endpoint_mapping(&self) -> HashMap<u16, u16> {
            if let PortMappingTestCase::EndpointMapping = self {
                return HashMap::from([(80, 9090)]);
            }
            HashMap::from([])
        }

        fn app_tunnel(&self) -> Option<ApplicationTunnel> {
            if let PortMappingTestCase::AppTunnel = self {
                return Some(ApplicationTunnel {
                    protocol: AppProtocol::PROXY,
                    port: Some(15088),
                });
            }
            None
        }

        fn expected_port(&self) -> u16 {
            match self {
                PortMappingTestCase::ServiceMapping => 8080,
                PortMappingTestCase::EndpointMapping => 9090,
                _ => 80,
            }
        }
    }

    #[test_case(PortMappingTestCase::EndpointMapping; "ep mapping")]
    #[test_case(PortMappingTestCase::ServiceMapping; "svc mapping")]
    #[test_case(PortMappingTestCase::AppTunnel; "app tunnel")]
    #[tokio::test]
    async fn find_upstream_port_mappings(tc: PortMappingTestCase) {
        initialize_telemetry();
        let wl = Workload {
            uid: "cluster1//v1/Pod/default/ep_no_port_mapping".into(),
            name: "ep_no_port_mapping".into(),
            namespace: "default".into(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))],
            application_tunnel: tc.app_tunnel(),
            ..test_helpers::test_default_workload()
        };
        let svc = Service {
            name: "test-svc".into(),
            hostname: "example.com".into(),
            namespace: "default".into(),
            vips: vec![NetworkAddress {
                address: "10.0.0.1".parse().unwrap(),
                network: "".into(),
            }],
            endpoints: HashMap::from([(
                "cluster1//v1/Pod/default/ep_no_port_mapping".into(),
                Endpoint {
                    workload_uid: "cluster1//v1/Pod/default/ep_no_port_mapping".into(),
                    service: NamespacedHostname {
                        namespace: "default".into(),
                        hostname: "example.com".into(),
                    },
                    address: Some(NetworkAddress {
                        address: "192.168.0.1".parse().unwrap(),
                        network: "".into(),
                    }),
                    port: tc.endpoint_mapping(),
                    status: HealthStatus::Healthy,
                },
            )]),
            ports: tc.service_mapping(),
            ..test_helpers::mock_default_service()
        };

        let mut state = ProxyState::default();
        state.workloads.insert(wl.clone().into(), true);
        state.services.insert(svc);

        let mode = match tc {
            PortMappingTestCase::AppTunnel => ServiceResolutionMode::Waypoint,
            _ => ServiceResolutionMode::Standard,
        };

        let (_, port, _) = state
            .find_upstream("".into(), &wl, "10.0.0.1:80".parse().unwrap(), mode)
            .expect("upstream to be found");
        assert_eq!(port, tc.expected_port());
    }

    #[tokio::test]
    async fn assert_rbac_with_dest_workload_info() {
        let mut state = ProxyState::default();
        let wl = Workload {
            name: "test".into(),
            namespace: "default".into(),
            trust_domain: "cluster.local".into(),
            service_account: "defaultacct".into(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))],
            ..test_helpers::test_default_workload()
        };
        state.workloads.insert(Arc::new(wl), true);

        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let mock_proxy_state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );

        let wi = WorkloadInfo {
            name: "test".into(),
            namespace: "default".into(),
            service_account: "defaultacct".into(),
        };

        let mut ctx = crate::state::ProxyRbacContext {
            conn: rbac::Connection {
                src_identity: None,
                src: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 1),
                    1234,
                )),
                dst_network: "".into(),
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
            wi.name = "not-test".into();
            ctx.dest_workload_info = Some(Arc::new(wi.clone()));
            assert!(!mock_proxy_state.assert_rbac(&ctx).await);
        }
        {
            let mut wi = wi.clone();
            wi.namespace = "not-test".into();
            ctx.dest_workload_info = Some(Arc::new(wi.clone()));
            assert!(!mock_proxy_state.assert_rbac(&ctx).await);
        }
        {
            let mut wi = wi.clone();
            wi.service_account = "not-test".into();
            ctx.dest_workload_info = Some(Arc::new(wi.clone()));
            assert!(!mock_proxy_state.assert_rbac(&ctx).await);
        }
    }

    #[tokio::test]
    async fn test_load_balance() {
        initialize_telemetry();
        let mut state = ProxyState::default();
        let wl_no_locality = Workload {
            uid: "cluster1//v1/Pod/default/wl_no_locality".into(),
            name: "wl_no_locality".into(),
            namespace: "default".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))],
            ..test_helpers::test_default_workload()
        };
        let wl_match = Workload {
            uid: "cluster1//v1/Pod/default/wl_match".into(),
            name: "wl_match".into(),
            namespace: "default".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2))],
            network: "network".into(),
            locality: Locality {
                region: "reg".into(),
                zone: "zone".into(),
                subzone: "".into(),
            },
            ..test_helpers::test_default_workload()
        };
        let wl_almost = Workload {
            uid: "cluster1//v1/Pod/default/wl_almost".into(),
            name: "wl_almost".into(),
            namespace: "default".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3))],
            network: "network".into(),
            locality: Locality {
                region: "reg".into(),
                zone: "not-zone".into(),
                subzone: "".into(),
            },
            ..test_helpers::test_default_workload()
        };
        let _ep_almost = Workload {
            uid: "cluster1//v1/Pod/default/ep_almost".into(),
            name: "wl_almost".into(),
            namespace: "default".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 4))],
            network: "network".into(),
            locality: Locality {
                region: "reg".into(),
                zone: "other-not-zone".into(),
                subzone: "".into(),
            },
            ..test_helpers::test_default_workload()
        };
        let _ep_no_match = Workload {
            uid: "cluster1//v1/Pod/default/ep_no_match".into(),
            name: "wl_almost".into(),
            namespace: "default".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            workload_ips: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 0, 5))],
            network: "not-network".into(),
            locality: Locality {
                region: "not-reg".into(),
                zone: "unmatched-zone".into(),
                subzone: "".into(),
            },
            ..test_helpers::test_default_workload()
        };
        let endpoints = HashMap::from([
            (
                "cluster1//v1/Pod/default/ep_almost".into(),
                Endpoint {
                    workload_uid: "cluster1//v1/Pod/default/ep_almost".into(),
                    service: NamespacedHostname {
                        namespace: TEST_SERVICE_NAMESPACE.into(),
                        hostname: "example.com".into(),
                    },
                    address: Some(NetworkAddress {
                        address: "192.168.0.4".parse().unwrap(),
                        network: "".into(),
                    }),
                    port: HashMap::from([(80u16, 80u16)]),
                    status: HealthStatus::Healthy,
                },
            ),
            (
                "cluster1//v1/Pod/default/ep_no_match".into(),
                Endpoint {
                    workload_uid: "cluster1//v1/Pod/default/ep_almost".into(),
                    service: NamespacedHostname {
                        namespace: TEST_SERVICE_NAMESPACE.into(),
                        hostname: "example.com".into(),
                    },
                    address: Some(NetworkAddress {
                        address: "192.168.0.5".parse().unwrap(),
                        network: "".into(),
                    }),
                    port: HashMap::from([(80u16, 80u16)]),
                    status: HealthStatus::Healthy,
                },
            ),
            (
                "cluster1//v1/Pod/default/wl_match".into(),
                Endpoint {
                    workload_uid: "cluster1//v1/Pod/default/wl_match".into(),
                    service: NamespacedHostname {
                        namespace: TEST_SERVICE_NAMESPACE.into(),
                        hostname: "example.com".into(),
                    },
                    address: Some(NetworkAddress {
                        address: "192.168.0.2".parse().unwrap(),
                        network: "".into(),
                    }),
                    port: HashMap::from([(80u16, 80u16)]),
                    status: HealthStatus::Healthy,
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
                health_policy: LoadBalancerHealthPolicy::OnlyHealthy,
            }),
            ports: HashMap::from([(80u16, 80u16)]),
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
                health_policy: LoadBalancerHealthPolicy::OnlyHealthy,
            }),
            ports: HashMap::from([(80u16, 80u16)]),
            ..test_helpers::mock_default_service()
        };
        state
            .workloads
            .insert(Arc::new(wl_no_locality.clone()), true);
        state.workloads.insert(Arc::new(wl_match.clone()), true);
        state.workloads.insert(Arc::new(wl_almost.clone()), true);
        state.services.insert(strict_svc.clone());
        state.services.insert(failover_svc.clone());

        let assert_endpoint = |src: &Workload, svc: &Service, ips: Vec<&str>, desc: &str| {
            let got = state
                .load_balance(src, svc, 80, ServiceResolutionMode::Standard)
                .and_then(|(ep, _)| ep.address.clone())
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
