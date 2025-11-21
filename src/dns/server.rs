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

use hickory_proto::ProtoErrorKind;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::system_conf::read_system_conf;
use hickory_server::ServerFuture;
use hickory_server::authority::LookupError;
use hickory_server::server::Request;
use itertools::Itertools;
use once_cell::sync::Lazy;
use rand::rng;
use rand::seq::SliceRandom;
use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tracing::event;
use tracing::{debug, info, instrument, trace, warn};

use crate::proxy::{LocalWorkloadFetcher, SocketFactory};

use crate::config::ProxyMode;
use crate::dns::metrics::{
    DnsRequest, ForwardedDuration, ForwardedFailure, ForwardedRequest, Metrics,
};
use crate::dns::name_util::{has_domain, trim_domain};
use crate::dns::resolver::{Answer, Resolver};
use crate::drain::{DrainMode, DrainWatcher};
use crate::metrics::{DeferRecorder, IncrementRecorder, Recorder};
use crate::proxy::Error;
use crate::state::DemandProxyState;
use crate::state::service::{IpFamily, Service};
use crate::state::workload::Workload;
use crate::state::workload::address::Address;
use crate::{config, dns};

const DEFAULT_TCP_REQUEST_TIMEOUT: u64 = 5;
const DEFAULT_TTL_SECONDS: u32 = 30;

static SVC: Lazy<Name> = Lazy::new(|| as_name("svc"));

/// A DNS server that serves known hostnames from ztunnel data structures.
/// Unknown hosts are forwarded to an upstream resolver.
pub struct Server {
    store: Arc<Store>,
    tcp_addr: SocketAddr,
    udp_addr: SocketAddr,
    server: ServerFuture<dns::handler::Handler>,
    drain: DrainWatcher,
}

impl Server {
    /// Creates a new handler.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address on which to run the DNS server.
    /// * `state` - The state of ztunnel.
    /// * `forwarder` - The forwarder to use for requests not handled by this server.
    #[allow(clippy::too_many_arguments)] // no good way of grouping arguments here..
    pub async fn new(
        domain: String,
        address: config::Address,
        state: DemandProxyState,
        forwarder: Arc<dyn Forwarder>,
        metrics: Arc<Metrics>,
        drain: DrainWatcher,
        socket_factory: &(dyn SocketFactory + Send + Sync),
        local_workload_information: Arc<LocalWorkloadFetcher>,
        prefered_service_namespace: Option<String>,
        ipv6_enabled: bool,
    ) -> Result<Self, Error> {
        // if the address we got from config is supposed to be v6-enabled,
        // actually check if the local pod context our socketfactory operates in supports V6.
        // This is to ensure globally-enabled V6 support doesn't try to create V6 addresses in pods
        // that do not support it, and also ensure globally-disabled V6 support doesn't create V6 address
        // even if that's turned off.
        let local_address = address.maybe_downgrade_ipv6(socket_factory.ipv6_enabled_localhost().unwrap_or_else(|e| {
            warn!(err=?e, "failed to determine if IPv6 was disabled; continuing anyways, but this may fail");
            true
        }));
        // Create the DNS server, backed by ztunnel data structures.
        let store = Store::new(
            domain,
            state,
            forwarder,
            metrics,
            local_workload_information,
            prefered_service_namespace,
            ipv6_enabled,
        );
        let store = Arc::new(store);
        let handler = dns::handler::Handler::new(store.clone());
        let mut server = ServerFuture::new(handler);
        info!(
            address=%local_address,
            component="dns",
            "starting local DNS server",
        );
        // We may have multiple TCP/UDP addresses; we will just take one. This is only for tests, so one is sufficient.
        let mut tcp_addr = None;
        let mut udp_addr = None;
        for addr in local_address.into_iter() {
            // Bind and register the TCP socket.
            let tcp_listener = socket_factory
                .tcp_bind(addr)
                .map_err(|e| Error::Bind(addr, e))?;
            // Save the bound address.
            tcp_addr = Some(tcp_listener.local_addr());
            server.register_listener(
                tcp_listener.inner(),
                Duration::from_secs(DEFAULT_TCP_REQUEST_TIMEOUT),
            );

            // Bind and register the UDP socket.
            let udp_socket = socket_factory
                .udp_bind(addr)
                .map_err(|e| Error::Bind(addr, e))?;
            udp_addr = Some(
                udp_socket
                    .local_addr()
                    .expect("bound udp socket must have a local address"),
            );
            server.register_socket(udp_socket);
        }

        Ok(Self {
            store,
            tcp_addr: tcp_addr.expect("must have at least one address"),
            udp_addr: udp_addr.expect("must have at least one address"),
            server,
            drain,
        })
    }

    /// Returns the address to which this DNS server is bound for TCP.
    pub fn tcp_address(&self) -> SocketAddr {
        self.tcp_addr
    }

    /// Returns the address to which this DNS server is bound for UDP.
    pub fn udp_address(&self) -> SocketAddr {
        self.udp_addr
    }

    pub fn resolver(&self) -> Arc<dyn Resolver + Send + Sync> {
        self.store.clone()
    }

    /// Runs this DNS server to completion.
    pub async fn run(mut self) {
        tokio::select! {
            res = self.server.block_until_done() =>{
                if let Err(e) = res {
                    match e.kind() {
                        ProtoErrorKind::NoError => (),
                        _ => warn!("DNS server shutdown error: {e}"),
                    }
                }
            }
            res = self.drain.wait_for_drain() => {
                info!("shutting down the DNS server");
                if res.mode() == DrainMode::Graceful {
                    let _ = self.server.shutdown_gracefully().await;
                }
            }
        }
        info!("dns server drained");
    }
}

/// A DNS [Resolver] backed by the ztunnel [DemandProxyState].
struct Store {
    state: DemandProxyState,
    forwarder: Arc<dyn Forwarder>,
    domain: Name,
    svc_domain: Name,
    metrics: Arc<Metrics>,
    local_workload: Arc<LocalWorkloadFetcher>,
    prefered_service_namespace: Option<String>,
    ipv6_enabled: bool,
}

impl Store {
    fn new(
        domain: String,
        state: DemandProxyState,
        forwarder: Arc<dyn Forwarder>,
        metrics: Arc<Metrics>,
        local_workload_information: Arc<LocalWorkloadFetcher>,
        prefered_service_namespace: Option<String>,
        ipv6_enabled: bool,
    ) -> Self {
        let domain = as_name(domain);
        let svc_domain = append_name(as_name("svc"), &domain);

        Self {
            state,
            forwarder,
            domain,
            svc_domain,
            metrics,
            local_workload: local_workload_information,
            prefered_service_namespace,
            ipv6_enabled,
        }
    }

    /// Enumerates the possible aliases for the requested hostname
    fn get_aliases(&self, client: &Workload, name: &Name) -> Vec<Alias> {
        let mut out = Vec::new();
        let mut added = HashSet::new();

        let mut add_alias = |alias: Alias| {
            if !added.contains(&alias.name) {
                added.insert(alias.name.clone());
                out.push(alias);
            }
        };

        // Insert the requested name.
        add_alias(Alias {
            name: name.clone(),
            stripped: None,
        });

        let namespaced_domain = append_name(as_name(&client.namespace), &self.svc_domain);

        // If the name can be expanded to a k8s FQDN, add that as well.
        for kube_fqdn in self.to_kube_fqdns(name, &namespaced_domain) {
            add_alias(Alias {
                name: kube_fqdn,
                stripped: None,
            });
        }

        // Strip the search domains from the requested host and add aliases.
        for search_domain in self.forwarder.search_domains(client) {
            if let Some(stripped_name) = trim_domain(name, &search_domain) {
                // Insert an alias for a stripped search domain.
                add_alias(Alias {
                    name: stripped_name.clone(),
                    stripped: Some(stripped_name.clone()),
                });

                // If the name can be expanded to a k8s FQDN, add that as well.
                for kube_fqdn in self.to_kube_fqdns(&stripped_name, &namespaced_domain) {
                    add_alias(Alias {
                        name: kube_fqdn,
                        stripped: Some(stripped_name.clone()),
                    });
                }
            }
        }

        out
    }

    /// Attempts to expand the requested hostname into one or more possible
    /// Kubernetes FQDNs.
    ///
    /// The k8s FQDN forms supported by Ambient:
    ///
    /// - Standard service:
    ///   <service-name>.<namespace>.svc.<cluster-domain>
    /// - Pod host when sub-domain is set (e.g. when part of a statefulset):
    ///   <pod-hostname>.<pod-sub-domain>.<namespace>.svc.<cluster-domain>
    ///
    /// Everything else will not be handled directly by Ambient and will instead
    /// just be forwarded to k8s.
    fn to_kube_fqdns(&self, name: &Name, namespaced_domain: &Name) -> Vec<Name> {
        let mut out = Vec::new();

        // Rather than just blindly adding every possible extension, only add the extensions
        // possible given the requested hostname.
        let iter = name.iter();
        match iter.len() {
            1 => {
                // Only one label in the name. Assume the client is calling a service by name
                // within the same namespace. Append "<ns>.svc.cluster.local".
                out.push(append_name(name.clone(), namespaced_domain));
            }
            2 => {
                // Expand <service-name>.<namespace> to
                // <service-name>.<namespace>.svc.<cluster-domain>.
                out.push(append_name(name.clone(), &self.svc_domain));
                // Expand <pod-hostname>.<pod-sub-domain> to
                // <pod-hostname>.<pod-sub-domain>.<namespace>.svc.<cluster-domain>.
                out.push(append_name(name.clone(), namespaced_domain));
            }
            3 => {
                if has_domain(name, SVC.deref()) {
                    // Expand <service-name>.<namespace>.svc to
                    // <service-name>.<namespace>.svc.<cluster-domain>.
                    out.push(append_name(name.clone(), &self.domain));
                }

                // Expand <pod-hostname>.<pod-sub-domain>.<namespace> to
                // <pod-hostname>.<pod-sub-domain>.<namespace>.svc.<cluster-domain>.
                out.push(append_name(name.clone(), &self.svc_domain));
            }
            4 => {
                if has_domain(name, SVC.deref()) {
                    // Expand <pod-hostname>.<pod-sub-domain>.<namespace>.svc to
                    // <pod-hostname>.<pod-sub-domain>.<namespace>.svc.<cluster-domain>.
                    out.push(append_name(name.clone(), &self.domain));
                }
            }
            _ => {
                // Everything else is either already an FQDN or not a supported
                // kubernetes hostname.
            }
        }

        out
    }

    fn find_server(&self, client: &Workload, requested_name: &Name) -> Option<ServerMatch> {
        // Lock the workload store for the duration of this function, since we're calling it
        // in a loop.
        let state = self.state.read();

        // Iterate over all possible aliases for the requested hostname from the perspective of
        // the client (e.g. <svc>, <svc>.<ns>, <svc>.<ns>.svc, <svc>.<ns>.svc.cluster.local).
        trace!(
            "checking aliases {:#?}",
            self.get_aliases(client, requested_name)
        );
        for alias in self.get_aliases(client, requested_name) {
            // For each alias, try matching against all possible wildcards.
            //
            // For example, if the alias is 'www.example.com`, we'll try to match in the
            // following order:
            //
            //   'www.example.com' (the alias, itself)
            //   '*.example.com'
            //   '*.com'
            trace!(
                "checking against wildcards {:#?}",
                get_wildcards(&alias.name)
            );
            for mut search_name in get_wildcards(&alias.name) {
                // Convert the name to a string for lookup, removing the trailing '.'.
                search_name.set_fqdn(false);
                let search_name_str = search_name.to_string().into();
                search_name.set_fqdn(true);

                let services: Vec<Arc<Service>> = state
                    .services
                    .get_by_host(&search_name_str)
                    .iter()
                    .flatten()
                    // Remove things without a VIP, unless they are Kubernetes headless services.
                    // This will trigger us to forward upstream.
                    // TODO: we should have a reliable way to distinguish these. In sidecars, we use
                    // `svc.Attributes.ServiceRegistry`, but we don't pass anything similar over WDS.
                    // For now, checking the domain is good enough.
                    // This does mean a `.svc.cluster.local` ServiceEntry will use these semantics, but
                    // its better than *ALL* ServiceEntry doing this
                    .filter(|service| {
                        // Domain will be like `.svc.cluster.local.` (trailing .), so ignore the last character.
                        let domain = ".".to_string() + &self.svc_domain.to_utf8();

                        let domain = domain
                            .strip_suffix('.')
                            .expect("the svc domain must have a trailing '.'");
                        !service.vips.is_empty() || service.hostname.ends_with(domain)
                    })
                    // Get the service matching the client namespace. If no match exists, just
                    // return the first service.
                    // .find_or_first(|service| service.namespace == client.namespace)
                    .cloned()
                    .collect();

                // TODO: ideally we'd sort these by creation time so that the oldest would be used if there are no namespace matches
                // presently service doesn't have creation time in WDS, but we could add it
                // TODO: if the local namespace doesn't define a service, kube service should be prioritized over se
                let service = match services
                    .iter()
                    .find(|service| service.namespace == client.namespace)
                {
                    Some(service) => Some(service),
                    None => match self.prefered_service_namespace.as_ref() {
                        Some(prefered_namespace) => services.iter().find_or_first(|service| {
                            service.namespace == prefered_namespace.as_str()
                        }),
                        None => services.first(),
                    },
                };

                // First, lookup the host as a service.
                if let Some(service) = service {
                    return Some(ServerMatch {
                        server: Address::Service(service.clone()),
                        name: search_name,
                        alias,
                    });
                }
                // TODO(): add support for workload lookups for headless pods
            }
        }

        None
    }

    fn record_type_enabled(&self, addr: &IpAddr) -> bool {
        match addr {
            IpAddr::V4(_) => true,              // IPv4 always
            IpAddr::V6(_) => self.ipv6_enabled, // IPv6 must be not be disabled in config
        }
    }

    /// Gets the list of addresses of the requested record type from the server.
    fn get_addresses(
        &self,
        client: &Workload,
        server: &Address,
        record_type: RecordType,
    ) -> Vec<IpAddr> {
        let mut addrs: Vec<IpAddr> = match server {
            Address::Workload(wl) => wl
                .workload_ips
                .iter()
                .filter_map(|addr| {
                    if is_record_type(addr, record_type) && self.record_type_enabled(addr) {
                        Some(*addr)
                    } else {
                        None
                    }
                })
                .collect(),
            Address::Service(service) => {
                if service.vips.is_empty() {
                    // Headless service. Use the endpoint IPs.
                    let workloads = &self.state.read().workloads;
                    service
                        .endpoints
                        .iter()
                        .filter_map(|ep| {
                            let Some(wl) = workloads.find_uid(&ep.workload_uid) else {
                                debug!("failed to fetch workload for {}", ep.workload_uid);
                                return None;
                            };
                            wl.workload_ips.iter().copied().find(|addr| {
                                is_record_type(addr, record_type) && self.record_type_enabled(addr)
                            })
                        })
                        .collect()
                } else {
                    // "Normal" service with VIPs.
                    // Add service VIPs that are callable from the client.
                    service
                        .vips
                        .iter()
                        .filter_map(|vip| {
                            if is_record_type(&vip.address, record_type)
                                && client.network == vip.network
                                && self.record_type_enabled(&vip.address)
                            {
                                Some(vip.address)
                            } else {
                                None
                            }
                        })
                        .collect()
                }
            }
        };

        // Randomize the order of the returned addresses.
        addrs.shuffle(&mut rng());

        addrs
    }

    async fn forward(
        &self,
        client: Option<&Workload>,
        request: &Request,
    ) -> Result<Answer, LookupError> {
        // Increment counter for all requests.
        self.metrics.increment(&DnsRequest {
            request,
            source: client,
        });

        // Increment counter for forwarded requests.
        self.metrics.increment(&ForwardedRequest {
            request,
            source: client,
        });

        // Record the forwarded request duration when the function exits.
        let start = std::time::Instant::now();
        let _forwarded_duration = self.metrics.defer_record(|metrics| {
            metrics.record(
                &ForwardedDuration {
                    request,
                    source: client,
                },
                start.elapsed(),
            );
        });

        match self.forwarder.forward(client, request).await {
            Ok(answer) => Ok(answer),
            Err(e) => {
                // Increment counter for forwarding failures.
                self.metrics.increment(&ForwardedFailure {
                    request,
                    source: client,
                });

                Err(e)
            }
        }
    }
}

fn access_log(request: &Request, source: Option<&Workload>, result: &str, ep_count: usize) {
    let src = source.as_ref();
    let query = request.request_info().ok().map(|info| info.query);
    event!(
        target: "dns",
        parent: None,
        tracing::Level::DEBUG,

        src.workload = src.map(|w| w.name.as_str()).unwrap_or("unknown"),
        src.namespace = src.map(|w| w.namespace.as_str()).unwrap_or("unknown"),

        query = query.map(|q| q.query_type().to_string()),
        domain = query.map(|q| q.name().to_string()),

        result = result,
        endpoints = ep_count,
    );
}

#[async_trait::async_trait]
impl Resolver for Store {
    #[instrument(
        level = "debug",
        skip_all,
        fields(
            src=%request.src(),
            query=%request.request_info()?.query.query_type(),
            name=%request.request_info()?.query.name(),
        ),
    )]
    async fn lookup(&self, request: &Request) -> Result<Answer, LookupError> {
        let client = self.local_workload.get_workload().await.map_err(|_| {
            debug!("unknown source");
            self.metrics.increment(&DnsRequest {
                request,
                source: None,
            });
            LookupError::ResponseCode(ResponseCode::ServFail)
        })?;

        let query = request.request_info()?.query;
        // Make sure the request is for IP records. Anything else, we forward.
        let record_type = query.query_type();
        if !is_record_type_supported(record_type) {
            debug!("unknown record type");
            let result = self.forward(Some(&client), request).await;
            match result {
                Ok(ref answer) => {
                    access_log(
                        request,
                        Some(&client),
                        "forwarded",
                        answer.record_iter().count(),
                    );
                }
                Err(e) => {
                    // Forwarding failed. Just return the error.
                    access_log(
                        request,
                        Some(&client),
                        &format!("forwarding failed ({e})"),
                        0,
                    );
                    return Err(e);
                }
            }
            return result;
        }

        // Find the service for the requested host.
        let requested_name = Name::from(query.name().clone());
        trace!("incoming request {requested_name:?}");
        let Some(service_match) = self.find_server(&client, &requested_name) else {
            trace!("unknown host, forwarding");
            // Unknown host. Forward to the upstream resolver.
            let result = self.forward(Some(&client), request).await;
            match result {
                Ok(ref answer) => {
                    access_log(
                        request,
                        Some(&client),
                        "forwarded",
                        answer.record_iter().count(),
                    );
                }
                Err(e) => {
                    // Forwarding failed. Just return the error.
                    access_log(
                        request,
                        Some(&client),
                        &format!("forwarding failed ({e})"),
                        0,
                    );
                    return Err(e);
                }
            }
            return result;
        };

        // Increment counter for all requests.
        self.metrics.increment(&DnsRequest {
            request,
            source: Some(&client),
        });

        // From this point on, we are the authority for the response.
        let is_authoritative = true;

        if !service_family_allowed(&service_match.server, record_type, self.ipv6_enabled) {
            access_log(
                request,
                Some(&client),
                "service does not support this record type",
                0,
            );
            // This is not NXDOMAIN, since we found the host. Just return an empty set of records.
            return Ok(Answer::new(Vec::default(), is_authoritative));
        }

        // Get the addresses for the service.
        let addresses = self.get_addresses(&client, &service_match.server, record_type);

        if addresses.is_empty() {
            access_log(request, Some(&client), "no records", 0);
            // Lookup succeeded, but no records were returned. This is not NXDOMAIN, since we
            // found the host. Just return an empty set of records.
            return Ok(Answer::new(Vec::default(), is_authoritative));
        }

        // Create a vec to hold the output records.
        let mut records = Vec::new();

        // Assume that we'll just use the requested name as the record name.
        let mut ip_record_name = requested_name.clone();

        // If the service was found by stripping off one of the search domains, create a
        // CNAME record to map to the appropriate canonical name.
        if let Some(stripped) = service_match.alias.stripped
            && !service_match.name.is_wildcard()
        {
            // Create a CNAME record to map from the requested name -> stripped name.
            records.push(cname_record(requested_name.clone(), stripped.clone()));

            // Also use the stripped name as the IP record name.
            ip_record_name = stripped;
        }

        access_log(request, Some(&client), "success", records.len());
        // Add the IP records.
        ip_records(ip_record_name, addresses, &mut records);

        Ok(Answer::new(records, is_authoritative))
    }
}

/// service_family_allowed indicates whether the service supports the given record type.
/// This is primarily to support headless services; an IPv4 only service should only have IPv4 addresses
/// anyway, so would naturally work.
/// Headless services, however, do not have VIPs, and the Pods behind them can have dual stack IPs even with
/// the Service being single-stack. In this case, we are NOT supposed to return both IPs.
/// If IPv6 is globally disabled, AAAA records are not allowed.
fn service_family_allowed(server: &Address, record_type: RecordType, ipv6_enabled: bool) -> bool {
    // If IPv6 is globally disabled, don't allow AAAA records
    if !ipv6_enabled && record_type == RecordType::AAAA {
        return false;
    }

    match server {
        Address::Service(service) => match service.ip_families {
            Some(IpFamily::IPv4) if record_type == RecordType::AAAA => false,
            Some(IpFamily::IPv6) if record_type == RecordType::A => false,
            _ => true,
        },
        _ => true,
    }
}

/// An alias for the requested hostname.
#[derive(Debug)]
struct Alias {
    /// The name to be used in the search.
    name: Name,

    /// If `Some`, indicates that this alias was generated from the requested host that
    /// was stripped of
    stripped: Option<Name>,
}

impl Display for Alias {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.name.to_utf8())
    }
}

/// Returned when a server was successfully found for the requested hostname.
#[derive(Debug)]
struct ServerMatch {
    /// The hostname that was used to find the service. This is identical to the
    /// service hostname, except that it is an FQDN [Name].
    name: Name,

    /// The alias that produced the `match_name`.
    alias: Alias,

    /// The server (workload or service) that was found.
    server: Address,
}

fn as_name<T: AsRef<str>>(name: T) -> Name {
    Name::from_str(name.as_ref()).unwrap()
}

fn append_name(name1: Name, name2: &Name) -> Name {
    name1.append_domain(name2).unwrap()
}

/// Creates the list of wildcard searches to try for the given hostname. The list
/// will begin with the requested hostname, followed by wildcards of decreasing
/// specificity. For example, a request of 'svc1.ns1.svc.cluster.local` will return
/// ['svc1.ns1.svc.cluster.local`, '*.ns1.svc.cluster.local`, '*.svc.cluster.local`,
/// '*.cluster.local`, '*.local`].
fn get_wildcards(name: &Name) -> Vec<Name> {
    let mut out = vec![name.clone()];

    let mut name = name.clone();
    while name.num_labels() > 1 {
        // Replace the first label with a wildcard (e.g. www.example.com -> *.example.com).
        out.push(name.clone().into_wildcard());

        // Remove the first label.
        name = name.base_name();
    }

    out
}

fn is_record_type_supported(record_type: RecordType) -> bool {
    matches!(record_type, RecordType::A | RecordType::AAAA)
}

fn is_record_type(addr: &IpAddr, record_type: RecordType) -> bool {
    match addr {
        IpAddr::V4(_) => record_type == RecordType::A,
        IpAddr::V6(_) => record_type == RecordType::AAAA,
    }
}

fn to_record(name: Name, rdata: RData) -> Record {
    Record::from_rdata(name, DEFAULT_TTL_SECONDS, rdata)
}

fn cname_record(name: Name, canonical_name: Name) -> Record {
    to_record(name, RData::CNAME(CNAME(canonical_name)))
}

fn ip_records(name: Name, addrs: Vec<IpAddr>, out: &mut Vec<Record>) {
    for addr in addrs {
        match addr {
            IpAddr::V4(addr) => out.push(to_record(name.clone(), RData::A(A(addr)))),
            IpAddr::V6(addr) => out.push(to_record(name.clone(), RData::AAAA(AAAA(addr)))),
        }
    }
}

/// Forwards a request to an upstream resolver.
#[async_trait::async_trait]
pub trait Forwarder: Send + Sync {
    /// Returns the list of resolver search domains for the client.
    fn search_domains(&self, client: &Workload) -> Vec<Name>;

    /// Forwards the request from the client.
    async fn forward(
        &self,
        client: Option<&Workload>,
        request: &Request,
    ) -> Result<Answer, LookupError>;
}

/// Creates the appropriate DNS forwarder for the proxy mode.
pub fn forwarder_for_mode(
    proxy_mode: ProxyMode,
    cluster_domain: String,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
) -> Result<Arc<dyn Forwarder>, Error> {
    Ok(match proxy_mode {
        ProxyMode::Shared => {
            // TODO(https://github.com/istio/ztunnel/issues/555): Use pod settings if available.
            // Today, we only support the basic namespace awareness
            Arc::new(SystemForwarder::new(true, cluster_domain, socket_factory)?)
        }
        ProxyMode::Dedicated => {
            Arc::new(SystemForwarder::new(false, cluster_domain, socket_factory)?)
        }
    })
}

/// DNS forwarder that uses the system resolver config in `/etc/resolv.conf`.
/// When running in dedicated (sidecar) proxy mode, this will be the same resolver configuration
/// that would have been used by the client. For shared proxy mode, this will be the resolver
/// configuration for the ztunnel DaemonSet (i.e. node-level resolver settings).
struct SystemForwarder {
    search_domains: SearchDomains,
    resolver: Arc<dyn Resolver>,
}

enum SearchDomains {
    Static(Vec<Name>),
    Dynamic(String),
}

impl SystemForwarder {
    fn new(
        per_pod: bool,
        cluster_domain: String,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    ) -> Result<Self, Error> {
        // Get the resolver config from `ztunnel's` /etc/resolv.conf.
        let (cfg, opts) = read_system_conf().map_err(|e| Error::Generic(Box::new(e)))?;

        // Extract the parts.
        let domain = cfg.domain().cloned();
        let search_domains = cfg.search().to_vec();
        let name_servers = cfg.name_servers().to_vec();

        Self::from_parts(
            per_pod,
            cluster_domain,
            socket_factory,
            opts,
            domain,
            search_domains,
            name_servers,
        )
    }

    fn from_parts(
        per_pod: bool,
        cluster_domain: String,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        opts: ResolverOpts,
        domain: Option<Name>,
        search_domains: Vec<Name>,
        name_servers: Vec<NameServerConfig>,
    ) -> Result<Self, Error> {
        // Remove the search list before passing to the resolver. The local resolver that
        // sends the original request will already have search domains applied. We want
        // this resolver to simply use the request host rather than re-adding search domains.
        let cfg = ResolverConfig::from_parts(domain, vec![], name_servers);

        // Create the resolver.
        let resolver = Arc::new(
            dns::forwarder::Forwarder::new(cfg, socket_factory, opts)
                .map_err(|e| Error::Generic(Box::new(e)))?,
        );
        let search_domains = if per_pod {
            // Standard Kubernetes search is 'istio-system.svc.cluster.local svc.cluster.local cluster.local'
            // But we need a *per-pod* one, or we will search for the wrong thing
            SearchDomains::Dynamic(cluster_domain)
        } else {
            SearchDomains::Static(search_domains)
        };

        Ok(Self {
            search_domains,
            resolver,
        })
    }
}

#[async_trait::async_trait]
impl Forwarder for SystemForwarder {
    fn search_domains(&self, wl: &Workload) -> Vec<Name> {
        // TODO: https://github.com/istio/ztunnel/issues/555 really get this from pods
        // Today we hardcode the default search assumptions
        match &self.search_domains {
            SearchDomains::Static(s) => s.clone(),
            SearchDomains::Dynamic(cluster_domain) => vec![
                Name::from_utf8(format!("{}.svc.{cluster_domain}", wl.namespace))
                    .expect("inputs must be valid DNS labels"),
                Name::from_utf8(format!("svc.{cluster_domain}"))
                    .expect("inputs must be valid DNS labels"),
                Name::from_utf8(cluster_domain).expect("inputs must be valid DNS labels"),
            ],
        }
    }

    async fn forward(
        &self,
        _: Option<&Workload>,
        request: &Request,
    ) -> Result<Answer, LookupError> {
        self.resolver.lookup(request).await
    }
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::net::{SocketAddrV4, SocketAddrV6};

    use bytes::Bytes;
    use hickory_proto::xfer::Protocol;
    use prometheus_client::registry::Registry;

    use super::*;
    use crate::state::WorkloadInfo;
    use crate::test_helpers::dns::{
        a, aaaa, cname, ip, ipv4, ipv6, n, new_message, new_tcp_client, new_udp_client, run_dns,
        send_request, server_request,
    };
    use crate::test_helpers::helpers::initialize_telemetry;
    use crate::test_helpers::{new_proxy_state, test_default_workload};
    use crate::xds::istio::workload::Port as XdsPort;
    use crate::xds::istio::workload::PortList as XdsPortList;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::{IpFamilies, NetworkAddress as XdsNetworkAddress};

    use crate::proxy::DefaultSocketFactory;
    use crate::state::workload::{NetworkAddress, Workload};
    use crate::strng::Strng;
    use crate::{drain, strng};
    use crate::{metrics, test_helpers};

    const NS1: &str = "ns1";
    const NS2: &str = "ns2";
    const PREFERRED: &str = "preferred-ns";
    const NW1: Strng = strng::literal!("nw1");
    const NW2: Strng = strng::literal!("nw2");

    #[test]
    fn test_to_kube_fqdns() {
        struct Case {
            host: &'static str,
            client_namespace: &'static str,
            expected: Vec<Name>,
        }

        let cases: &[Case] = &[
            Case {
                // Expand single label values to namespace of the client.
                host: "name",
                client_namespace: "ns1",
                expected: vec![
                    // Generated based on form: <service-name>
                    n("name.ns1.svc.cluster.local."),
                ],
            },
            Case {
                host: "name.",
                client_namespace: "ns1",
                expected: vec![
                    // Generated based on form: <service-name>
                    n("name.ns1.svc.cluster.local."),
                ],
            },
            Case {
                host: "name.ns2",
                client_namespace: "ns1",
                expected: vec![
                    // Generated based on form: <service-name>.<namespace>
                    n("name.ns2.svc.cluster.local."),
                    // Generated based on form: <pod-hostname>.<pod-sub-domain>
                    n("name.ns2.ns1.svc.cluster.local."),
                ],
            },
            Case {
                host: "name.ns2.svc.",
                client_namespace: "ns1",
                expected: vec![
                    // Generated based on form: <service-name>.<namespace>.svc
                    n("name.ns2.svc.cluster.local."),
                    // Generated based on form: <pod-hostname>.<pod-sub-domain>.<namespace>
                    n("name.ns2.svc.svc.cluster.local."),
                ],
            },
            Case {
                host: "name.ns2.not-svc.",
                client_namespace: "ns1",
                expected: vec![
                    // Generated based on form: <pod-hostname>.<pod-sub-domain>.<namespace>
                    n("name.ns2.not-svc.svc.cluster.local."),
                ],
            },
            Case {
                host: "pod.sub-domain.ns.svc",
                client_namespace: "ns1",
                expected: vec![
                    // Generated based on form: <pod-hostname>.<pod-sub-domain>.<namespace>.svc
                    n("pod.sub-domain.ns.svc.cluster.local."),
                ],
            },
            Case {
                host: "pod.sub-domain.ns.not-svc",
                client_namespace: "ns1",
                expected: vec![],
            },
            Case {
                // Invalid short-form for a k8s host.
                host: "name.ns2.svc.cluster.",
                client_namespace: "ns1",
                expected: vec![],
            },
            Case {
                // The request is already a k8s FQDN.
                host: "name.ns2.svc.cluster.local",
                client_namespace: "ns1",
                expected: vec![],
            },
            Case {
                // Non-k8s
                host: "www.google.com.",
                client_namespace: "ns1",
                expected: vec![
                    // Generated based on form: <pod-hostname>.<pod-sub-domain>.<namespace>.
                    n("www.google.com.svc.cluster.local."),
                ],
            },
        ];

        for c in cases {
            let mut wl = test_default_workload();
            wl.namespace = c.client_namespace.into();

            // Create the DNS store.
            let (state, local_workload) = state();
            let forwarder = forwarder();
            let store = Store {
                domain: as_name("cluster.local"),
                svc_domain: as_name("svc.cluster.local."),
                state,
                forwarder,
                metrics: test_metrics(),
                local_workload,
                prefered_service_namespace: None,
                ipv6_enabled: true,
            };

            let namespaced_domain = n(format!("{}.svc.cluster.local", c.client_namespace));

            let actual = store.to_kube_fqdns(&n(c.host), &namespaced_domain);
            assert_eq!(c.expected, actual, "requested host: {}", c.host);
        }
    }

    #[test]
    fn test_get_wildcards() {
        let actual = get_wildcards(&n("svc1."));
        let expected: Vec<Name> = vec![n("svc1.")];
        assert_eq!(expected, actual);

        let actual = get_wildcards(&n("svc1.ns1.svc.cluster.local."));
        let expected: Vec<Name> = vec![
            n("svc1.ns1.svc.cluster.local."),
            n("*.ns1.svc.cluster.local."),
            n("*.svc.cluster.local."),
            n("*.cluster.local."),
            n("*.local."),
        ];
        assert_eq!(expected, actual);
    }

    #[tokio::test]
    async fn lookup() {
        initialize_telemetry();

        #[derive(Clone)]
        struct Case {
            name: &'static str,
            host: &'static str,
            query_type: RecordType,
            expect_code: ResponseCode,
            expect_authoritative: bool,
            expect_records: Vec<Record>,
        }

        impl Default for Case {
            fn default() -> Self {
                Self {
                    name: "",
                    host: "",
                    query_type: RecordType::A,
                    expect_code: ResponseCode::NoError,
                    expect_authoritative: true,
                    expect_records: vec![],
                }
            }
        }

        let cases = [
            Case {
                name: "failure: unsupported record type will forward",
                host: "productpage.ns1.",
                query_type: RecordType::NS,
                expect_authoritative: false, // Forwarded.
                expect_code: ResponseCode::NXDomain,
                ..Default::default()
            },
            Case {
                name: "success: non k8s host in local cache",
                host: "www.google.com",
                expect_records: vec![a(n("www.google.com."), ipv4("1.1.1.1"))],
                ..Default::default()
            },
            Case {
                name: "success: non k8s host with search namespace yields cname+A record",
                host: "www.google.com.ns1.svc.cluster.local.",
                expect_records: vec![
                    cname(
                        n("www.google.com.ns1.svc.cluster.local."),
                        n("www.google.com."),
                    ),
                    a(n("www.google.com."), ipv4("1.1.1.1")),
                ],
                ..Default::default()
            },
            Case {
                name: "success: non k8s host not in local cache",
                host: "www.bing.com",
                expect_authoritative: false,
                expect_records: vec![a(n("www.bing.com."), ipv4("1.1.1.1"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - fqdn",
                host: "productpage.ns1.svc.cluster.local.",
                expect_records: vec![a(n("productpage.ns1.svc.cluster.local."), ipv4("9.9.9.9"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - name.namespace",
                host: "productpage.ns1.",
                expect_records: vec![a(n("productpage.ns1."), ipv4("9.9.9.9"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - shortname",
                host: "productpage.",
                expect_records: vec![a(n("productpage."), ipv4("9.9.9.9"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host (name.namespace) with search namespace yields cname+A record",
                host: "productpage.ns1.ns1.svc.cluster.local.",
                expect_records: vec![
                    cname(
                        n("productpage.ns1.ns1.svc.cluster.local."),
                        n("productpage.ns1."),
                    ),
                    a(n("productpage.ns1."), ipv4("9.9.9.9")),
                ],
                ..Default::default()
            },
            Case {
                name: "success: AAAA query for IPv4 k8s host (name.namespace) with search namespace",
                host: "productpage.ns1.ns1.svc.cluster.local.",
                query_type: RecordType::AAAA,
                expect_records: vec![],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - non local namespace - name.namespace",
                host: "example.ns2.",
                expect_records: vec![a(n("example.ns2."), ipv4("10.10.10.10"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - non local namespace - fqdn",
                host: "example.ns2.svc.cluster.local.",
                expect_records: vec![a(n("example.ns2.svc.cluster.local."), ipv4("10.10.10.10"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - non local namespace - name.namespace.svc",
                host: "example.ns2.svc.",
                expect_records: vec![a(n("example.ns2.svc."), ipv4("10.10.10.10"))],
                ..Default::default()
            },
            Case {
                name: "failure: k8s host - non local namespace - shortname",
                host: "example.",
                expect_authoritative: false, // Forwarded.
                expect_code: ResponseCode::NXDomain,
                ..Default::default()
            },
            Case {
                name: "success: remote cluster k8s svc - same ns and different domain - fqdn",
                host: "details.ns2.svc.cluster.remote.",
                expect_records: vec![
                    a(n("details.ns2.svc.cluster.remote."), ipv4("11.11.11.11")),
                    a(n("details.ns2.svc.cluster.remote."), ipv4("12.12.12.12")),
                    a(n("details.ns2.svc.cluster.remote."), ipv4("13.13.13.13")),
                    a(n("details.ns2.svc.cluster.remote."), ipv4("14.14.14.14")),
                ],
                ..Default::default()
            },
            Case {
                name: "failure: remote cluster k8s svc - same ns and different domain - name.namespace",
                host: "details.ns2.",
                expect_authoritative: false, // Forwarded.
                expect_code: ResponseCode::NXDomain,
                ..Default::default()
            },
            Case {
                name: "success: TypeA query returns A records only",
                host: "dual.localhost.",
                expect_records: vec![a(n("dual.localhost."), ipv4("2.2.2.2"))],
                ..Default::default()
            },
            Case {
                name: "success: TypeAAAA query returns AAAA records only",
                host: "dual.localhost.",
                query_type: RecordType::AAAA,
                expect_records: vec![aaaa(
                    n("dual.localhost."),
                    ipv6("2001:db8:0:0:0:ff00:42:8329"),
                )],
                ..Default::default()
            },
            Case {
                // This is not a NXDOMAIN, but empty response
                name: "success: Error response if only AAAA records exist for typeA",
                host: "ipv6.localhost.",
                ..Default::default()
            },
            Case {
                // This is not a NXDOMAIN, but empty response
                name: "success: Error response if only A records exist for typeAAAA",
                host: "ipv4.localhost.",
                query_type: RecordType::AAAA,
                ..Default::default()
            },
            Case {
                name: "success: wild card returns A record correctly",
                host: "foo.wildcard.",
                expect_records: vec![a(n("foo.wildcard."), ipv4("10.10.10.10"))],
                ..Default::default()
            },
            Case {
                name: "success: specific wild card returns A record correctly",
                host: "a.b.wildcard.",
                expect_records: vec![a(n("a.b.wildcard."), ipv4("11.11.11.11"))],
                ..Default::default()
            },
            Case {
                name: "success: wild card with domain returns A record correctly",
                host: "foo.svc.mesh.company.net.",
                expect_records: vec![a(n("foo.svc.mesh.company.net."), ipv4("10.1.2.3"))],
                ..Default::default()
            },
            Case {
                name: "success: wild card with namespace with domain returns A record correctly",
                host: "foo.foons.svc.mesh.company.net.",
                expect_records: vec![a(n("foo.foons.svc.mesh.company.net."), ipv4("10.1.2.3"))],
                ..Default::default()
            },
            Case {
                name: "success: wild card with search domain returns A record correctly",
                host: "foo.svc.mesh.company.net.ns1.svc.cluster.local.",
                expect_records: vec![a(
                    n("foo.svc.mesh.company.net.ns1.svc.cluster.local."),
                    ipv4("10.1.2.3"),
                )],
                ..Default::default()
            },
            Case {
                name: "success: no vip on client network returns no records",
                host: "nw2-only.ns1.svc.cluster.local.",
                expect_records: vec![],
                ..Default::default()
            },
            Case {
                name: "success: return vip for client network only",
                host: "both-networks.ns1.svc.cluster.local.",
                expect_records: vec![a(
                    n("both-networks.ns1.svc.cluster.local."),
                    ipv4("21.21.21.21"),
                )],
                ..Default::default()
            },
            Case {
                name: "success: headless service returns workload ips for A",
                host: "headless.ns1.svc.cluster.local.",
                expect_records: vec![
                    a(n("headless.ns1.svc.cluster.local."), ipv4("30.30.30.30")),
                    a(n("headless.ns1.svc.cluster.local."), ipv4("31.31.31.31")),
                ],
                ..Default::default()
            },
            Case {
                name: "success: headless service returns workload ips for AAAA",
                host: "headless.ns1.svc.cluster.local.",
                query_type: RecordType::AAAA,
                expect_records: vec![
                    aaaa(n("headless.ns1.svc.cluster.local."), ipv6("2001:db8::30")),
                    aaaa(n("headless.ns1.svc.cluster.local."), ipv6("2001:db8::31")),
                ],
                ..Default::default()
            },
            Case {
                name: "success: headless-ipv6 service returns records for AAAA",
                host: "headless-ipv6.ns1.svc.cluster.local.",
                query_type: RecordType::AAAA,
                expect_records: vec![aaaa(
                    n("headless-ipv6.ns1.svc.cluster.local."),
                    ipv6("2001:db8::33"),
                )],
                ..Default::default()
            },
            Case {
                name: "success: headless-ipv6 service returns empty for A",
                host: "headless-ipv6.ns1.svc.cluster.local.",
                expect_records: vec![],
                ..Default::default()
            },
            // TODO(https://github.com/istio/ztunnel/issues/1119)
            Case {
                name: "todo: k8s pod - fqdn",
                host: "headless.pod0.ns1.svc.cluster.local.",
                expect_authoritative: false, // forwarded.
                expect_code: ResponseCode::NXDomain,
                ..Default::default()
            },
            // TODO(https://github.com/istio/ztunnel/issues/1119)
            Case {
                name: "todo: k8s pod - name.domain.ns",
                host: "headless.pod0.ns1.",
                expect_authoritative: false, // forwarded.
                expect_code: ResponseCode::NXDomain,
                ..Default::default()
            },
            Case {
                name: "failure: headless external without IPs",
                host: "headless-no-endpoints.example.com",
                expect_authoritative: false, // forwarded.
                expect_code: ResponseCode::NXDomain,
                ..Default::default()
            },
            Case {
                name: "failure: headless external",
                host: "headless.example.com",
                expect_authoritative: false, // forwarded.
                expect_code: ResponseCode::NXDomain,
                ..Default::default()
            },
            Case {
                name: "success: preferred namespace is chosen if local namespace is not defined",
                host: "preferred.io.",
                expect_records: vec![a(n("preferred.io."), ipv4("10.10.10.211"))],
                ..Default::default()
            },
            Case {
                name: "success: external service resolves to local namespace's address",
                host: "everywhere.io.",
                expect_records: vec![a(n("everywhere.io."), ipv4("10.10.10.112"))],
                ..Default::default()
            },
        ];

        // Create and start the proxy.
        let domain = "cluster.local".to_string();
        let (state, local_workload) = state();
        let forwarder = forwarder();
        let (_signal, drain) = drain::new();
        let factory = crate::proxy::DefaultSocketFactory::default();
        let proxy = Server::new(
            domain,
            config::Address::Localhost(false, 0),
            state,
            forwarder,
            test_metrics(),
            drain,
            &factory,
            local_workload,
            Some(PREFERRED.to_string()),
            true, // ipv6_enabled for tests
        )
        .await
        .unwrap();
        let tcp_addr = proxy.tcp_address();
        let udp_addr = proxy.udp_address();
        tokio::spawn(proxy.run());

        let tcp_client = new_tcp_client(tcp_addr).await;
        let udp_client = new_udp_client(udp_addr).await;

        // Lookup the server from the client.
        let mut tasks = vec![];
        for c in cases {
            for (protocol, mut client) in [("tcp", tcp_client.clone()), ("udp", udp_client.clone())]
            {
                let c = c.clone();
                tasks.push(async move {
                    let name = format!("[{protocol}] {}", c.name);
                    let resp = send_request(&mut client, n(c.host), c.query_type).await;
                    assert_eq!(c.expect_authoritative, resp.authoritative(), "{name}");
                    assert_eq!(c.expect_code, resp.response_code(), "{name}");

                    if c.expect_code == ResponseCode::NoError {
                        let mut actual = resp.answers().to_vec();

                        // The IP records in an authoritative response will be randomly sorted to
                        // accommodate DNS-based load balancing. If the response is authoritative,
                        // sort the IP records so that we can directly compare them to the expected.
                        if c.expect_authoritative {
                            sort_records(&mut actual);
                        }
                        assert_eq!(c.expect_records, actual, "{name}");
                    }
                });
            }
        }
        let stream = futures::stream::iter(tasks).buffer_unordered(10);
        let _ = stream.collect::<Vec<_>>().await;
    }

    #[tokio::test]
    async fn forward_to_server() {
        initialize_telemetry();
        // Other test use fake forwarder; here we forward to a real server (which we run locally)

        struct Case {
            name: &'static str,
            host: &'static str,
            expect_code: ResponseCode,
        }

        let cases = [
            Case {
                name: "success: www.google.com",
                host: "test.example.com.",
                expect_code: ResponseCode::NoError,
            },
            Case {
                name: "failure: fake-blahblahblah.com",
                host: "fake-blahblahblah.com",
                expect_code: ResponseCode::NXDomain,
            },
        ];

        // Create and start the server.
        let domain = "cluster.local".to_string();
        let (state, local_workload) = state();
        let forwarder = Arc::new(
            run_dns(HashMap::from([(
                n("test.example.com."),
                vec![ip("1.1.1.1")],
            )]))
            .await
            .unwrap(),
        );
        let (_signal, drain) = drain::new();
        let factory = crate::proxy::DefaultSocketFactory::default();
        let server = Server::new(
            domain,
            config::Address::Localhost(false, 0),
            state,
            forwarder,
            test_metrics(),
            drain,
            &factory,
            local_workload,
            None,
            true, // ipv6_enabled for tests
        )
        .await
        .unwrap();
        let tcp_addr = server.tcp_address();
        let udp_addr = server.udp_address();
        tokio::spawn(server.run());

        let mut tcp_client = new_tcp_client(tcp_addr).await;
        let mut udp_client = new_udp_client(udp_addr).await;

        for c in cases {
            for (protocol, client) in [("tcp", &mut tcp_client), ("udp", &mut udp_client)] {
                let name = format!("[{protocol}] {}", c.name);
                let resp = send_request(client, n(c.host), RecordType::A).await;
                assert_eq!(c.expect_code, resp.response_code(), "{name}");
                if c.expect_code == ResponseCode::NoError {
                    assert!(!resp.answers().is_empty());
                }
            }
        }
    }

    // TODO we might actually want to return both A and AAAA in this case, ultimately,
    // and let the client deal with the mix.
    // See https://datatracker.ietf.org/doc/html/rfc4038#section-3.2
    // and https://github.com/istio/ztunnel/issues/582
    #[tokio::test]
    async fn ipv4_in_6_should_unwrap() {
        initialize_telemetry();
        let fake_ips = vec![ip("2.2.2.2")];
        let fake_wls = vec![xds_workload("client-fake", NS1, "", &NW1, &[], &fake_ips)];

        // Create the DNS store.
        let state = new_proxy_state(&fake_wls, &[], &[]);
        let forwarder = forwarder();
        let store = Store {
            state: state.clone(),
            forwarder,
            domain: n("cluster.local"),
            svc_domain: n("svc.cluster.local."),
            metrics: test_metrics(),
            local_workload: LocalWorkloadFetcher::new(
                Arc::new(WorkloadInfo {
                    name: "client-fake".to_string(),
                    namespace: NS1.to_string(),
                    service_account: "default".to_string(),
                }),
                state.clone(),
            ),
            prefered_service_namespace: None,
            ipv6_enabled: true,
        };

        let ip4n6_client_ip = ip("::ffff:202:202");
        let req = req(n("www.bing.com"), ip4n6_client_ip, RecordType::A);
        match store.lookup(&req).await {
            Ok(_) => {}
            Err(e) => {
                panic!("IPv6 encoded IPv4 should work! Error was {e:?}");
            }
        }
    }
    #[tokio::test]
    async fn large_response() {
        initialize_telemetry();
        // Create and start the proxy with an an empty state. The forwarder is configured to
        // return a large response.
        let (state, local_workload) = state();
        let forwarder = Arc::new(FakeForwarder {
            search_domains: vec![],
            ips: HashMap::from([(n("large.com."), new_large_response())]),
        });
        let domain = "cluster.local".to_string();
        let (_signal, drain) = drain::new();
        let factory = crate::proxy::DefaultSocketFactory::default();
        let server = Server::new(
            domain,
            config::Address::Localhost(false, 0),
            state,
            forwarder,
            test_metrics(),
            drain,
            &factory,
            local_workload,
            None,
            true, // ipv6_enabled for tests
        )
        .await
        .unwrap();
        let tcp_addr = server.tcp_address();
        let udp_addr = server.udp_address();
        tokio::spawn(server.run());

        let mut tcp_client = new_tcp_client(tcp_addr).await;
        let mut udp_client = new_udp_client(udp_addr).await;

        let resp = send_request(&mut tcp_client, n("large.com."), RecordType::A).await;
        assert!(!resp.truncated(), "TCP should not truncate");
        assert_eq!(256, resp.answers().len());

        let resp = send_request(&mut udp_client, n("large.com."), RecordType::A).await;
        // UDP is truncated
        assert!(resp.truncated());
        assert_eq!(74, resp.answers().len(), "expected UDP to be truncated");
    }

    #[test]
    fn search_domains() {
        let opts = ResolverOpts::default();
        let search = vec![
            as_name("istio-system.svc.cluster.local"),
            as_name("svc.cluster.local"),
            as_name("cluster.local"),
        ];
        let f = SystemForwarder::from_parts(
            true,
            "cluster.local".to_string(),
            Arc::new(DefaultSocketFactory::default()),
            opts,
            None,
            search,
            vec![],
        )
        .unwrap();
        let make_workload = |ns: &str| Workload {
            name: "something".into(),
            namespace: ns.into(),
            ..test_helpers::test_default_workload()
        };

        assert_eq!(
            f.search_domains(&make_workload("default-ns")),
            vec![
                as_name("default-ns.svc.cluster.local"),
                as_name("svc.cluster.local"),
                as_name("cluster.local"),
            ]
        );
    }

    /// Sort the IP records so that we can directly compare them to the expected. The resulting
    /// list will contain CNAME first, followed by A, and then by AAAA. Within each record type,
    /// records will be sorted in ascending order by their string representation.
    fn sort_records(records: &mut [Record]) {
        let rtype_priority = |rtype: RecordType| -> u8 {
            match rtype {
                RecordType::A => 2,
                RecordType::AAAA => 3,
                _ => 1,
            }
        };

        records.sort_by(|a, b| {
            // First, sort by record type.
            match rtype_priority(a.record_type()).cmp(&rtype_priority(b.record_type())) {
                Ordering::Less => Ordering::Less,
                Ordering::Greater => Ordering::Greater,
                Ordering::Equal => {
                    // Within the same record type, sort them by their string
                    // representations.
                    a.to_string().cmp(&b.to_string())
                }
            }
        });
    }

    fn new_large_response() -> Vec<IpAddr> {
        let mut out = Vec::new();
        for i in 0..256 {
            out.push(ip(format!("240.0.0.{i}")));
        }
        out
    }

    fn req(host: Name, client_ip: IpAddr, query_type: RecordType) -> Request {
        let socket_addr = match client_ip {
            IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, 80)),
            IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, 80, 0, 0)),
        };

        server_request(&new_message(host, query_type), socket_addr, Protocol::Udp)
    }

    fn forwarder() -> Arc<dyn Forwarder> {
        Arc::new(FakeForwarder {
            // Use the standard search domains for Kubernetes.
            search_domains: vec![
                n("ns1.svc.cluster.local"),
                n("svc.cluster.local"),
                n("cluster.local"),
            ],
            ips: HashMap::from([(n("www.bing.com."), vec![ip("1.1.1.1")])]),
        })
    }

    fn state() -> (DemandProxyState, Arc<LocalWorkloadFetcher>) {
        let mut headless_ipv6 = xds_service("headless-ipv6", NS1, &[]);
        headless_ipv6.set_ip_families(IpFamilies::Ipv6Only);
        let services = vec![
            xds_external_service("www.google.com", &[na(NW1, "1.1.1.1")]),
            xds_service("productpage", NS1, &[na(NW1, "9.9.9.9")]),
            xds_service("example", NS2, &[na(NW1, "10.10.10.10")]),
            // Service with the same name in another namespace
            // This should not be used if the preferred service namespace is set
            xds_namespaced_external_service("everywhere.io", NS2, &[na(NW1, "10.10.10.110")]),
            xds_namespaced_external_service("preferred.io", NS2, &[na(NW1, "10.10.10.210")]),
            // Preferred service namespace
            xds_namespaced_external_service("everywhere.io", PREFERRED, &[na(NW1, "10.10.10.111")]),
            xds_namespaced_external_service("preferred.io", PREFERRED, &[na(NW1, "10.10.10.211")]),
            // Service with the same name in the same namespace
            // Client in NS1 should use this service
            xds_namespaced_external_service("everywhere.io", NS1, &[na(NW1, "10.10.10.112")]),
            with_fqdn(
                "details.ns2.svc.cluster.remote",
                xds_service(
                    "details",
                    NS2,
                    &[
                        na(NW1, "11.11.11.11"),
                        na(NW1, "12.12.12.12"),
                        na(NW1, "13.13.13.13"),
                        na(NW1, "14.14.14.14"),
                    ],
                ),
            ),
            // IPv4-only, IPv6-only, dual stack.
            xds_external_service("ipv4.localhost", &[na(NW1, "2.2.2.2")]),
            xds_external_service("ipv6.localhost", &[na(NW1, "2001:db8:0:0:0:ff00:42:8329")]),
            xds_external_service(
                "dual.localhost",
                &[na(NW1, "2.2.2.2"), na(NW1, "2001:db8:0:0:0:ff00:42:8329")],
            ),
            // Wildcards.
            xds_external_service("*.wildcard", &[na(NW1, "10.10.10.10")]),
            xds_external_service("*.b.wildcard", &[na(NW1, "11.11.11.11")]),
            xds_external_service("*.svc.mesh.company.net", &[na(NW1, "10.1.2.3")]),
            // VIP on different/multiple networks.
            xds_service("nw2-only", NS1, &[na(NW2, "20.20.20.20")]),
            xds_service(
                "both-networks",
                NS1,
                &[na(NW1, "21.21.21.21"), na(NW2, "22.22.22.22")],
            ),
            // Headless services.
            // TODO: test and support subdomain format (https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-hostname-and-subdomain-fields)
            xds_service("headless", NS1, &[]),
            xds_external_service("headless.example.com", &[]),
            xds_external_service("headless-no-endpoints.example.com", &[]),
            headless_ipv6,
        ];

        let workloads = vec![
            // Just add a workload for the local machine that resides in NS1 on NW1.
            local_workload(),
            // Workloads backing headless service.
            xds_workload(
                "headless0",
                NS1,
                "headless.pod0.ns1.svc.cluster.local",
                &NW1,
                &[format!("{}/{}", NS1, kube_fqdn("headless", NS1)).as_str()],
                &[ip("30.30.30.30"), ip("2001:db8::30")],
            ),
            xds_workload(
                "headless1",
                NS1,
                "headless.pod1.ns1.svc.cluster.local",
                &NW1,
                &[format!("{}/{}", NS1, kube_fqdn("headless", NS1)).as_str()],
                &[ip("31.31.31.31"), ip("2001:db8::31")],
            ),
            xds_workload(
                "headless-external",
                NS1,
                "",
                &NW1,
                &[format!("{}/{}", NS1, "headless.example.com").as_str()],
                &[ip("32.32.32.32"), ip("2001:db8::32")],
            ),
            xds_workload(
                "headless2",
                NS1,
                "headless2.pod2.ns1.svc.cluster.local",
                &NW1,
                &[format!("{}/{}", NS1, kube_fqdn("headless-ipv6", NS1)).as_str()],
                &[ip("33.33.33.33"), ip("2001:db8::33")],
            ),
        ];

        let state = new_proxy_state(&workloads, &services, &[]);
        let fetch = LocalWorkloadFetcher::new(
            Arc::new(WorkloadInfo {
                name: "client".to_string(),
                namespace: NS1.to_string(),
                service_account: "default".to_string(),
            }),
            state.clone(),
        );
        (state, fetch)
    }

    fn na<S1: AsRef<str>, S2: AsRef<str>>(network: S1, addr: S2) -> NetworkAddress {
        NetworkAddress {
            network: strng::new(network.as_ref()),
            address: ip(addr),
        }
    }

    /// Creates a workload for the local machine that resides in NS1 on NW1.
    fn local_workload() -> XdsWorkload {
        xds_workload("client", NS1, "", &NW1, &[], &local_ips())
    }

    fn local_ips() -> Vec<IpAddr> {
        local_ip_address::list_afinet_netifas()
            .unwrap()
            .iter()
            .map(|(_, addr)| *addr)
            .collect_vec()
    }

    fn kube_fqdn<S1: AsRef<str>, S2: AsRef<str>>(name: S1, ns: S2) -> String {
        format!("{}.{}.svc.cluster.local", name.as_ref(), ns.as_ref())
    }

    fn addr_bytes(addr: IpAddr) -> Vec<u8> {
        match addr {
            IpAddr::V4(addr) => addr.octets().to_vec(),
            IpAddr::V6(addr) => addr.octets().to_vec(),
        }
    }

    fn with_fqdn<S: AsRef<str>>(fqdn: S, mut svc: XdsService) -> XdsService {
        svc.hostname = fqdn.as_ref().to_string();
        svc
    }

    fn xds_service<S1: AsRef<str>, S2: AsRef<str>>(
        name: S1,
        ns: S2,
        vips: &[NetworkAddress],
    ) -> XdsService {
        XdsService {
            name: name.as_ref().to_string(),
            namespace: ns.as_ref().to_string(),
            hostname: kube_fqdn(name, ns),
            addresses: vips
                .iter()
                .map(|vip| XdsNetworkAddress {
                    network: vip.network.to_string(),
                    address: addr_bytes(vip.address),
                })
                .collect(),
            ports: vec![XdsPort {
                service_port: 80,
                target_port: 80,
            }],
            ..Default::default()
        }
    }

    fn xds_external_service<S: AsRef<str>>(hostname: S, addrs: &[NetworkAddress]) -> XdsService {
        xds_namespaced_external_service(hostname, NS1, addrs)
    }

    fn xds_namespaced_external_service<S1: AsRef<str>, S2: AsRef<str>>(
        hostname: S1,
        ns: S2,
        vips: &[NetworkAddress],
    ) -> XdsService {
        with_fqdn(
            hostname.as_ref(),
            xds_service(hostname.as_ref(), ns.as_ref(), vips),
        )
    }

    fn xds_workload(
        name: &str,
        ns: &str,
        host: &str,
        nw: &str,
        services: &[&str],
        ips: &[IpAddr],
    ) -> XdsWorkload {
        XdsWorkload {
            addresses: ips
                .iter()
                .map(|ip| Bytes::copy_from_slice(&addr_bytes(*ip)))
                .collect(),
            uid: name.to_string(),
            name: name.to_string(),
            namespace: ns.to_string(),
            hostname: host.to_string(),
            trust_domain: "cluster.local".to_string(),
            network: nw.to_string(),
            workload_name: name.to_string(),
            canonical_name: name.to_string(),
            node: name.to_string(),
            cluster_id: "Kubernetes".to_string(),
            services: {
                let mut out = HashMap::new();
                for service in services {
                    out.insert(
                        service.to_string(),
                        XdsPortList {
                            ports: vec![XdsPort {
                                service_port: 80,
                                target_port: 80,
                            }],
                        },
                    );
                }
                out
            },
            ..Default::default()
        }
    }

    struct FakeForwarder {
        search_domains: Vec<Name>,
        ips: HashMap<Name, Vec<IpAddr>>,
    }

    #[async_trait::async_trait]
    impl Forwarder for FakeForwarder {
        fn search_domains(&self, _: &Workload) -> Vec<Name> {
            self.search_domains.clone()
        }

        async fn forward(
            &self,
            _: Option<&Workload>,
            request: &Request,
        ) -> Result<Answer, LookupError> {
            let query = request.request_info()?.query;
            let name = query.name().into();
            let Some(ips) = self.ips.get(&name) else {
                // Not found.
                return Err(LookupError::ResponseCode(ResponseCode::NXDomain));
            };

            let mut out = Vec::new();
            let rtype = query.query_type();
            for ip in ips {
                match ip {
                    IpAddr::V4(ip) => {
                        if rtype == RecordType::A {
                            out.push(a(query.name().into(), *ip));
                        }
                    }
                    IpAddr::V6(ip) => {
                        if rtype == RecordType::AAAA {
                            out.push(aaaa(query.name().into(), *ip));
                        }
                    }
                }
            }

            return Ok(Answer::new(out, false));
        }
    }

    fn test_metrics() -> Arc<Metrics> {
        let mut registry = Registry::default();
        let istio_registry = metrics::sub_registry(&mut registry);
        Arc::new(Metrics::new(istio_registry))
    }
}
