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

pub mod forwarder;
pub mod name_util;
pub mod proxy;
pub mod resolver;

use crate::config::ProxyMode;
use crate::proxy::dns::name_util::trim_domain;
use crate::proxy::dns::resolver::{Answer, Resolver};
use crate::proxy::Error;
use crate::state::service::Service;
use crate::state::workload::{NetworkAddress, Workload};
use crate::state::ProxyState;
use itertools::Itertools;
use log::warn;
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::thread_rng;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_proto::error::ProtoErrorKind;
use trust_dns_proto::op::ResponseCode;
use trust_dns_proto::rr::{Name, RData, Record, RecordType};
use trust_dns_resolver::system_conf::read_system_conf;
use trust_dns_server::authority::LookupError;
use trust_dns_server::server::Request;
use trust_dns_server::ServerFuture;

const DEFAULT_TCP_REQUEST_TIMEOUT: u64 = 5;
const DEFAULT_TTL_SECONDS: u32 = 30;

static SVC_CLUSTER_LOCAL: Lazy<Name> = Lazy::new(|| Name::from_str("svc.cluster.local").unwrap());
static CLUSTER_LOCAL: Lazy<Name> = Lazy::new(|| Name::from_str("cluster.local").unwrap());

/// A proxy that serves known hostnames from ztunnel data structures. Unknown hosts are
/// forwarded to an upstream resolver.
pub(super) struct DnsProxy {
    addr: SocketAddr,
    server: ServerFuture<proxy::Proxy>,
}

impl DnsProxy {
    /// Creates a new proxy.
    ///
    /// # Arguments
    ///
    /// * `addr` - The socket address on which to run the DNS proxy.
    /// * `network` - The network of the current node.
    /// * `state` - The state of this proxy.
    /// * `forwarder` - The forwarder to use for requests not handled by this proxy.
    pub(super) async fn new<S: AsRef<str>>(
        addr: SocketAddr,
        network: S,
        state: Arc<RwLock<ProxyState>>,
        forwarder: Arc<dyn Forwarder>,
    ) -> Result<Self, Error> {
        // Create the DNS server, backed by ztunnel data structures.
        let handler = proxy::Proxy::new(Arc::new(DnsStore {
            state,
            network: network.as_ref().to_string(),
            forwarder,
        }));
        let mut server = ServerFuture::new(handler);

        // Bind and register the UDP socket.
        let udp_socket = UdpSocket::bind(addr)
            .await
            .map_err(|e| Error::Bind(addr, e))?;
        server.register_socket(udp_socket);

        // Bind and register the TCP socket.
        let tcp_listener = TcpListener::bind(addr)
            .await
            .map_err(|e| Error::Bind(addr, e))?;
        server.register_listener(
            tcp_listener,
            Duration::from_secs(DEFAULT_TCP_REQUEST_TIMEOUT),
        );

        Ok(Self { addr, server })
    }

    /// Returns the address to which this DNS proxy is bound.
    pub(super) fn address(&self) -> SocketAddr {
        self.addr
    }

    /// Runs this DNS proxy to completion.
    pub async fn run(self) {
        // TODO(nmittler): Do we need to use drain?
        if let Err(e) = self.server.block_until_done().await {
            match e.kind() {
                ProtoErrorKind::NoError => (),
                _ => warn!("DNS server shutdown error: {e}"),
            }
        }
    }
}

/// A DNS [Resolver] backed by the ztunnel [ProxyState].
struct DnsStore {
    network: String,
    state: Arc<RwLock<ProxyState>>,
    forwarder: Arc<dyn Forwarder>,
}

impl DnsStore {
    /// Find the workload for the client address.
    fn find_client(&self, client_addr: SocketAddr) -> Option<Workload> {
        let state = self.state.read().unwrap();
        state.workloads.find_address(&NetworkAddress {
            network: self.network.clone(),
            address: client_addr.ip(),
        })
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

        // If the name can be expanded to a k8s FQDN, add that as well.
        if let Some(kube_fqdn) = to_kube_fqdn(client, name) {
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
                    stripped: Some(Stripped {
                        name: stripped_name.clone(),
                        search_domain: search_domain.clone(),
                    }),
                });

                // If the name can be expanded to a k8s FQDN, add that as well.
                if let Some(kube_fqdn) = to_kube_fqdn(client, &stripped_name) {
                    add_alias(Alias {
                        name: kube_fqdn,
                        stripped: Some(Stripped {
                            name: stripped_name.clone(),
                            search_domain: search_domain.clone(),
                        }),
                    });
                }
            }
        }

        out
    }

    fn find_service(&self, client: &Workload, requested_name: &Name) -> Option<ServiceMatch> {
        // Lock the workload store for the duration of this function, since we're calling it
        // in a loop.
        let state = self.state.read().unwrap();

        // Iterate over all possible aliases for the requested hostname from the perspective of
        // the client (e.g. <svc>, <svc>.<ns>, <svc>.<ns>.svc, <svc>.<ns>.svc.cluster.local).
        for alias in self.get_aliases(client, requested_name) {
            // For each alias, try matching against all possible wildcards.
            //
            // For example, if the alias is 'www.example.com`, we'll try to match in the
            // following order:
            //
            //   'www.example.com' (the alias, itself)
            //   '*.example.com'
            //   '*.com'
            for mut search_name in get_wildcards(&alias.name) {
                // Convert the name to a string for lookup, removing the trailing '.'.
                search_name.set_fqdn(false);
                let search_name_str = search_name.to_string();
                search_name.set_fqdn(true);

                if let Some(services) = state.services.get_by_host(&search_name_str) {
                    // We found a match. We always return `Some` result, even if there
                    // are zero records returned.

                    // Get the service matching the client namespace. If no match exists, just
                    // return the first service.
                    let service = services
                        .iter()
                        .find_or_first(|service| service.namespace == client.namespace)
                        .cloned()
                        // Should never be empty, since we delete the Vec when it's empty.
                        .unwrap();

                    return Some(ServiceMatch {
                        service,
                        name: search_name,
                        alias,
                    });
                }
            }
        }

        None
    }

    /// Gets the list of addresses of the requested record type from the service.
    fn get_addresses(
        &self,
        client: &Workload,
        service: &Service,
        record_type: RecordType,
    ) -> Vec<IpAddr> {
        let mut addrs = Vec::new();

        // TODO(https://github.com/istio/ztunnel/issues/554): Add support for headless services.
        if !service.vips.is_empty() {
            // Add service VIPs that are callable from the client.
            for network_addr in &service.vips {
                if is_record_type(&network_addr.address, record_type)
                    && client.network == network_addr.network
                {
                    addrs.push(network_addr.address)
                }
            }
        }

        // Randomize the order of the returned addresses.
        addrs.shuffle(&mut thread_rng());

        addrs
    }
}

#[async_trait::async_trait]
impl Resolver for DnsStore {
    async fn lookup(&self, request: &Request) -> Result<Answer, LookupError> {
        // Find the client workload.
        let client = match self.find_client(request.src()) {
            None => return Err(LookupError::ResponseCode(ResponseCode::ServFail)),
            Some(client) => client,
        };

        // Make sure the request is for IP records. Anything else, we forward.
        let record_type = request.query().query_type();
        if !is_record_type_supported(record_type) {
            return self.forwarder.forward(&client, request).await;
        }

        // Find the service for the requested host.
        let requested_name = Name::from(request.query().name().clone());
        let Some(service_match) = self.find_service(&client, &requested_name) else {
            // Unknown host. Forward to the upstream resolver.
            return self.forwarder.forward(&client, request).await;
        };

        // Get the addresses for the service.
        let addresses = self.get_addresses(&client, &service_match.service, record_type);

        // From this point on, we are the authority for the response.
        let is_authoritative = true;

        if addresses.is_empty() {
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
        if let Some(stripped) = service_match.alias.stripped {
            if service_match.name.is_wildcard() {
                // The match is a wildcard...

                // Create a CNAME record that maps from the wildcard with the search domain to
                // the wildcard without it.
                let cname_record_name = service_match
                    .name
                    .clone()
                    .append_domain(&stripped.search_domain)
                    .unwrap();
                let canonical_name = service_match.name;
                records.push(cname_record(cname_record_name, canonical_name));

                // For wildcards, continue using the original requested hostname for IP records.
            } else {
                // The match is NOT a wildcard...

                // Create a CNAME record to map from the requested name -> stripped name.
                let canonical_name = stripped.name;
                records.push(cname_record(requested_name.clone(), canonical_name.clone()));

                // Also use the stripped name as the IP record name.
                ip_record_name = canonical_name;
            }
        }

        // Add the IP records.
        ip_records(ip_record_name, addresses, &mut records);

        Ok(Answer::new(records, is_authoritative))
    }
}

/// An alias for the requested hostname.
struct Alias {
    /// The name to be used in the search.
    name: Name,

    /// If `Some`, indicates that this alias was generated from the requested host that
    /// was stripped of
    stripped: Option<Stripped>,
}

/// Created for an alias generated by stripping a search domain from the requested host.
struct Stripped {
    /// The requested hostname with the `search_domain` removed.
    name: Name,

    /// The search domain that was removed from the requested host to generate `name`.
    search_domain: Name,
}

/// Returned when a service was successfully found for the requested hostname.
struct ServiceMatch {
    /// The hostname that was used to find the service. This is identical to the
    /// service hostname, except that it is an FQDN [Name].
    name: Name,

    /// The alias that produced the `match_name`.
    alias: Alias,

    /// The service that was found.
    service: Service,
}

/// Converts the requested hostname into a Kubernetes FQDN of the form
/// `name.ns.svc.cluster.local`. Returns `None` if no conversion was possible.
fn to_kube_fqdn(client: &Workload, name: &Name) -> Option<Name> {
    // TODO(nmittler): Do we need to support user-defined cluster domains?
    let iter = name.iter();
    match iter.len() {
        1 => {
            // Only one label in the name. Assume the client is calling a service by name
            // within the same namespace. Append "<ns>.svc.cluster.local".
            Some(
                name.clone()
                    .append_label(client.namespace.as_bytes())
                    .unwrap()
                    .append_domain(SVC_CLUSTER_LOCAL.deref())
                    .unwrap(),
            )
        }
        2 => {
            // Assume the client is calling the service by "name.ns".
            // Append "svc.cluster.local".
            Some(
                name.clone()
                    .append_domain(SVC_CLUSTER_LOCAL.deref())
                    .unwrap(),
            )
        }
        3 => {
            // Assume the client is calling "name.ns.svc". Check to make sure the last
            // label is "svc".
            let svc = iter.rev().next().unwrap();
            if svc == b"svc" {
                // Append "cluster.local".
                Some(name.clone().append_domain(CLUSTER_LOCAL.deref()).unwrap())
            } else {
                None
            }
        }
        _ => {
            // Everything else is either already an FQDN or not a valid kubernetes hostname.
            None
        }
    }
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
    to_record(name, RData::CNAME(canonical_name))
}

fn ip_records(name: Name, addrs: Vec<IpAddr>, out: &mut Vec<Record>) {
    for addr in addrs {
        match addr {
            IpAddr::V4(addr) => out.push(to_record(name.clone(), RData::A(addr))),
            IpAddr::V6(addr) => out.push(to_record(name.clone(), RData::AAAA(addr))),
        }
    }
}

/// Forwards a request to an upstream resolver.
#[async_trait::async_trait]
pub(super) trait Forwarder: Send + Sync {
    /// Returns the list of resolver search domains for the client.
    fn search_domains(&self, client: &Workload) -> Vec<Name>;

    /// Forwards the request from the client.
    async fn forward(&self, client: &Workload, request: &Request) -> Result<Answer, LookupError>;
}

/// Creates the appropriate DNS forwarder for the proxy mode.
pub(super) fn forwarder_for_mode(proxy_mode: ProxyMode) -> Result<Arc<dyn Forwarder>, Error> {
    Ok(match proxy_mode {
        ProxyMode::Shared => {
            // TODO(https://github.com/istio/ztunnel/issues/555): Use pod settings if available.
            Arc::new(SystemForwarder::new()?)
        }
        ProxyMode::Dedicated => Arc::new(SystemForwarder::new()?),
    })
}

/// DNS forwarder that uses the system resolver config in `/etc/resolv.conf`.
/// When running in dedicated (sidecar) proxy mode, this will be the same resolver configuration
/// that would have been used by the client. For shared proxy mode, this will be the resolver
/// configuration for the ztunnel DaemonSet (i.e. node-level resolver settings).
struct SystemForwarder {
    search_domains: Vec<Name>,
    resolver: Arc<dyn Resolver>,
}

impl SystemForwarder {
    fn new() -> Result<Self, Error> {
        // Get the resolver config from /etc/resolv.conf.
        let (cfg, opts) = read_system_conf()?;

        // Extract the search domains from the config.
        let search_domains = cfg.search().to_vec();

        // Create the resolver.
        let resolver = Arc::new(
            forwarder::Forwarder::new(cfg, opts).map_err(|e| Error::Generic(Box::new(e)))?,
        );

        Ok(Self {
            search_domains,
            resolver,
        })
    }
}

#[async_trait::async_trait]
impl Forwarder for SystemForwarder {
    fn search_domains(&self, _: &Workload) -> Vec<Name> {
        self.search_domains.clone()
    }

    async fn forward(&self, _: &Workload, request: &Request) -> Result<Answer, LookupError> {
        self.resolver.lookup(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::dns::{
        a, aaaa, cname, ip, ipv4, ipv6, n, new_message, new_tcp_client, new_udp_client,
        send_request, server_request, socket_addr,
    };
    use crate::test_helpers::helpers::subscribe;
    use crate::test_helpers::{new_proxy_state, test_default_workload};
    use crate::xds::istio::workload::NetworkAddress as XdsNetworkAddress;
    use crate::xds::istio::workload::Port as XdsPort;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use bytes::Bytes;
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::net::{SocketAddrV4, SocketAddrV6};
    use trust_dns_server::server::Protocol;

    const NS1: &str = "ns1";
    const NS2: &str = "ns2";
    const NW1: &str = "nw1";
    const NW2: &str = "nw2";

    #[test]
    fn test_to_kube_fqdn() {
        struct Case {
            host: &'static str,
            client_namespace: &'static str,
            expected: Option<Name>,
        }

        let cases: &[Case] = &[
            Case {
                // Expand single label values to namespace of the client.
                host: "name",
                client_namespace: "ns1",
                expected: Some(n("name.ns1.svc.cluster.local.")),
            },
            Case {
                host: "name.",
                client_namespace: "ns1",
                expected: Some(n("name.ns1.svc.cluster.local.")),
            },
            Case {
                host: "name.ns2",
                client_namespace: "ns1",
                expected: Some(n("name.ns2.svc.cluster.local.")),
            },
            Case {
                host: "name.ns2.svc.",
                client_namespace: "ns1",
                expected: Some(n("name.ns2.svc.cluster.local.")),
            },
            Case {
                // Invalid short-form for a k8s host.
                host: "name.ns2.svc.cluster.",
                client_namespace: "ns1",
                expected: None,
            },
            Case {
                // The request is already a k8s FQDN.
                host: "name.ns2.svc.cluster.local",
                client_namespace: "ns1",
                expected: None,
            },
            Case {
                // Non-k8s
                host: "www.google.com.",
                client_namespace: "ns1",
                expected: None,
            },
        ];

        for c in cases {
            let mut wl = test_default_workload();
            wl.namespace = c.client_namespace.into();

            let actual = to_kube_fqdn(&wl, &n(c.host));
            assert_eq!(c.expected, actual);
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

    // TODO(nmittler): Test headless services (https://github.com/istio/ztunnel/issues/554).
    // TODO(nmittler): Test truncation once fixed (https://github.com/bluejekyll/trust-dns/issues/1973).
    #[tokio::test]
    async fn lookup() {
        let _guard = subscribe();

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
                    cname(n("www.google.com.ns1.svc.cluster.local."), n("www.google.com.")),
                    a(n("www.google.com."), ipv4("1.1.1.1"))],
                ..Default::default()
            },
            Case {
                name: "success: non k8s host not in local cache",
                host: "www.bing.com",
                expect_authoritative: false,
                expect_records: vec![
                    a(n("www.bing.com."), ipv4("1.1.1.1"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - fqdn",
                host: "productpage.ns1.svc.cluster.local.",
                expect_records: vec![
                    a(n("productpage.ns1.svc.cluster.local."), ipv4("9.9.9.9"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - name.namespace",
                host: "productpage.ns1.",
                expect_records: vec![
                    a(n("productpage.ns1."), ipv4("9.9.9.9"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - shortname",
                host: "productpage.",
                expect_records: vec![
                    a(n("productpage."), ipv4("9.9.9.9"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host (name.namespace) with search namespace yields cname+A record",
                host: "productpage.ns1.ns1.svc.cluster.local.",
                expect_records: vec![
                    cname(n("productpage.ns1.ns1.svc.cluster.local."), n("productpage.ns1.")),
                    a(n("productpage.ns1."), ipv4("9.9.9.9"))],
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
                expect_records: vec![
                    a(n("example.ns2."), ipv4("10.10.10.10"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - non local namespace - fqdn",
                host: "example.ns2.svc.cluster.local.",
                expect_records: vec![
                    a(n("example.ns2.svc.cluster.local."), ipv4("10.10.10.10"))],
                ..Default::default()
            },
            Case {
                name: "success: k8s host - non local namespace - name.namespace.svc",
                host: "example.ns2.svc.",
                expect_records: vec![
                    a(n("example.ns2.svc."), ipv4("10.10.10.10"))],
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
                    a(n("details.ns2.svc.cluster.remote."), ipv4("14.14.14.14"))],
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
                expect_records: vec![
                    a(n("dual.localhost."), ipv4("2.2.2.2"))],
                ..Default::default()
            },
            Case {
                name: "success: TypeA query returns A records only",
                host: "dual.localhost.",
                expect_records: vec![
                    a(n("dual.localhost."), ipv4("2.2.2.2"))],
                ..Default::default()
            },
            Case {
                name: "success: TypeAAAA query returns AAAA records only",
                host: "dual.localhost.",
                query_type: RecordType::AAAA,
                expect_records: vec![
                    aaaa(n("dual.localhost."), ipv6("2001:db8:0:0:0:ff00:42:8329"))],
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
                expect_records: vec![
                    a(n("foo.wildcard."), ipv4("10.10.10.10"))],
                ..Default::default()
            },
            Case {
                name: "success: specific wild card returns A record correctly",
                host: "a.b.wildcard.",
                expect_records: vec![
                    a(n("a.b.wildcard."), ipv4("11.11.11.11"))],
                ..Default::default()
            },
            Case {
                name: "success: wild card with domain returns A record correctly",
                host: "foo.svc.mesh.company.net.",
                expect_records: vec![
                    a(n("foo.svc.mesh.company.net."), ipv4("10.1.2.3"))],
                ..Default::default()
            },
            Case {
                name: "success: wild card with namespace with domain returns A record correctly",
                host: "foo.foons.svc.mesh.company.net.",
                expect_records: vec![
                    a(n("foo.foons.svc.mesh.company.net."), ipv4("10.1.2.3"))],
                ..Default::default()
            },
            Case {
                name: "success: wild card with search domain returns A record correctly",
                host: "foo.svc.mesh.company.net.ns1.svc.cluster.local.",
                expect_records: vec![
                    cname(n("*.svc.mesh.company.net.ns1.svc.cluster.local."), n("*.svc.mesh.company.net.")),
                    a(n("foo.svc.mesh.company.net.ns1.svc.cluster.local."), ipv4("10.1.2.3"))],
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
                expect_records: vec![
                    a(n("both-networks.ns1.svc.cluster.local."), ipv4("21.21.21.21"))],
                ..Default::default()
            },
        ];

        // Create and start the proxy.
        let addr = new_socket_addr().await;
        let state = state();
        let forwarder = forwarder();
        let proxy = DnsProxy::new(addr, NW1, state, forwarder).await.unwrap();
        tokio::spawn(proxy.run());

        let mut tcp_client = new_tcp_client(addr).await;
        let mut udp_client = new_udp_client(addr).await;

        // Lookup the server from the client.
        for c in cases {
            for (protocol, client) in [("tcp", &mut tcp_client), ("udp", &mut udp_client)] {
                let name = format!("[{protocol}] {}", c.name);
                let resp = send_request(client, n(c.host), c.query_type).await;
                assert_eq!(c.expect_authoritative, resp.authoritative(), "{}", name);
                assert_eq!(c.expect_code, resp.response_code(), "{}", name);

                if c.expect_code == ResponseCode::NoError {
                    let mut actual = resp.answers().to_vec();

                    // The IP records in an authoritative response will be randomly sorted to
                    // accommodate DNS-based load balancing. If the response is authoritative,
                    // sort the IP records so that we can directly compare them to the expected.
                    if c.expect_authoritative {
                        sort_records(&mut actual);
                    }
                    assert_eq!(c.expect_records, actual, "{}", name);
                }
            }
        }
    }

    #[tokio::test]
    async fn unknown_client_should_fail() {
        let _guard = subscribe();

        // Create the DNS store.
        let state = state();
        let forwarder = forwarder();
        let store = DnsStore {
            network: NW1.to_string(),
            state,
            forwarder,
        };

        let bad_client_ip = ip("5.5.5.5");
        let req = req(n("www.google.com"), bad_client_ip, RecordType::A);
        match store.lookup(&req).await {
            Ok(_) => panic!("expected error"),
            Err(e) => {
                if let Some(resp_code) = e.as_response_code() {
                    assert_eq!(ResponseCode::ServFail, *resp_code);
                } else {
                    panic!("unexpected error: {:?}", e)
                }
            }
        }
    }

    // #[tokio::test]
    // async fn large_response() {
    //     // Create and start the proxy with an an empty state. The forwarder is configured to
    //     // return a large response.
    //     let addr = new_socket_addr().await;
    //     let state = new_proxy_state(&[local_workload()], &[], &[]).state;
    //     let forwarder = Arc::new(FakeForwarder {
    //         search_domains: vec![],
    //         ips: HashMap::from([(n("large.com."), new_large_response())]),
    //     });
    //     let proxy = DnsProxy::new(addr, NW1, state, forwarder).await.unwrap();
    //     tokio::spawn(proxy.run());
    //
    //     let mut tcp_client = new_tcp_client(addr).await;
    //
    //     let resp = send_with_max_size(&mut tcp_client, n("large.com."), RecordType::A, 20).await;
    //     //resp.answers()[0].
    //     //let resp = send_request(&mut tcp_client, n("large.com."), RecordType::A).await;
    //     //assert!(resp.truncated());
    //     println!("{:?}", resp);
    // }

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

    // fn new_large_response() -> Vec<Record> {
    //     let mut out = Vec::new();
    //     for i in 0..64 {
    //         out.push(a(n("aaaaaaaaaaaa.aaaaaa."), ipv4(format!("240.0.0.{i}"))));
    //     }
    //     out
    // }

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

    async fn new_socket_addr() -> SocketAddr {
        let s = UdpSocket::bind(socket_addr("127.0.0.1:0")).await.unwrap();
        s.local_addr().unwrap()
    }

    fn state() -> Arc<RwLock<ProxyState>> {
        let services = vec![
            xds_external_service("www.google.com", &[na(NW1, "1.1.1.1")]),
            xds_service("productpage", NS1, &[na(NW1, "9.9.9.9")]),
            xds_service("example", NS2, &[na(NW1, "10.10.10.10")]),
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
        ];

        let workloads = vec![
            // Just add a workload for the local machine that resides in NS1 on NW1.
            local_workload(),
        ];

        new_proxy_state(&workloads, &services, &[]).state
    }

    fn na<S1: AsRef<str>, S2: AsRef<str>>(network: S1, addr: S2) -> NetworkAddress {
        NetworkAddress {
            network: network.as_ref().to_string(),
            address: ip(addr),
        }
    }

    /// Creates a workload for the local machine that resides in NS1 on NW1.
    fn local_workload() -> XdsWorkload {
        xds_workload("client", NS1, NW1, &local_ips())
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
                    network: vip.network.clone(),
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
        with_fqdn(
            hostname.as_ref(),
            xds_service(hostname.as_ref(), NS1, addrs),
        )
    }

    fn xds_workload(name: &str, ns: &str, nw: &str, ips: &[IpAddr]) -> XdsWorkload {
        XdsWorkload {
            addresses: ips
                .iter()
                .map(|ip| Bytes::copy_from_slice(&addr_bytes(*ip)))
                .collect(),
            uid: name.to_string(),
            name: name.to_string(),
            namespace: ns.to_string(),
            trust_domain: "cluster.local".to_string(),
            network: nw.to_string(),
            workload_name: name.to_string(),
            canonical_name: name.to_string(),
            node: name.to_string(),
            cluster_id: "Kubernetes".to_string(),
            // virtual_ips: HashMap::from([(
            //     vip(svc, ns, nw).to_string(),
            //     XdsPortList {
            //         ports: vec![XdsPort {
            //             service_port: 80,
            //             target_port: 8080,
            //         }],
            //     },
            // )]),
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

        async fn forward(&self, _: &Workload, request: &Request) -> Result<Answer, LookupError> {
            let name = request.query().name().into();
            let Some(ips) = self.ips.get(&name) else {
                // Not found.
                return Err(LookupError::ResponseCode(ResponseCode::NXDomain))
            };

            let mut out = Vec::new();
            let rtype = request.query().query_type();
            for ip in ips {
                match ip {
                    IpAddr::V4(ip) => {
                        if rtype == RecordType::A {
                            out.push(a(request.query().name().into(), *ip));
                        }
                    }
                    IpAddr::V6(ip) => {
                        if rtype == RecordType::AAAA {
                            out.push(aaaa(request.query().name().into(), *ip));
                        }
                    }
                }
            }

            return Ok(Answer::new(out, false));
        }
    }
}
