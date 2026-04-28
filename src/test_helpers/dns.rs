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

use crate::config::Address;
use crate::dns::Metrics;
use crate::dns::resolver::{Resolver, Response};
use crate::drain::DrainTrigger;
use crate::proxy::Error;
use crate::state::WorkloadInfo;
use crate::state::workload::Workload;
use crate::test_helpers::new_proxy_state;
use crate::xds::istio::workload::Workload as XdsWorkload;
use crate::{dns, drain, metrics};
use futures_util::StreamExt;
use hickory_net::DnsHandle;
use hickory_net::client::{Client, ClientHandle};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_net::tcp::TcpClientStream;
use hickory_net::udp::UdpClientStream;
use hickory_net::xfer::Protocol;
use hickory_proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Edns, Message, MessageType, OpCode, Query,
    ResponseCode,
};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_server::server::Request;
use hickory_server::zone_handler::LookupError;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;

const TTL: u32 = 5;

/// A short-hand helper for constructing a [Name].
pub fn n<S: AsRef<str>>(name: S) -> Name {
    Name::from_utf8(name).unwrap()
}

/// Creates an A record for the name and IP.
pub fn a(name: Name, addr: Ipv4Addr) -> Record {
    Record::from_rdata(name, TTL, RData::A(A(addr)))
}

/// Creates an AAAA record for the name and IP.
pub fn aaaa(name: Name, addr: Ipv6Addr) -> Record {
    Record::from_rdata(name, TTL, RData::AAAA(AAAA(addr)))
}

/// Creates a CNAME record for the given canonical name.
pub fn cname(name: Name, canonical_name: Name) -> Record {
    Record::from_rdata(name, TTL, RData::CNAME(CNAME(canonical_name)))
}

/// Creates a new DNS client that establishes a TCP connection to the nameserver at the given
/// address.
pub async fn new_tcp_client(addr: SocketAddr) -> Client<TokioRuntimeProvider> {
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(
        addr,
        None,
        None,
        TokioRuntimeProvider::new(),
    );
    let (client, bg) = Client::new(stream.await.unwrap(), sender);

    // Run the client exchange in the background.
    tokio::spawn(bg);

    client
}

/// Creates a new DNS client that establishes a UDP connection to the nameserver at the given address.
pub async fn new_udp_client(addr: SocketAddr) -> Client<TokioRuntimeProvider> {
    let stream =
        UdpClientStream::<TokioRuntimeProvider>::builder(addr, TokioRuntimeProvider::new()).build();
    let (client, bg) = Client::from_sender(stream);

    // Run the client exchange in the background.
    tokio::spawn(bg);

    client
}

/// Sends a request via the client.
pub async fn send_request<C: ClientHandle>(
    client: &mut C,
    name: Name,
    rr_type: RecordType,
) -> DnsResponse {
    client.query(name, DNSClass::IN, rr_type).await.unwrap()
}

/// Sends a request with the given maximum response payload size.
pub async fn send_with_max_size(
    client: &mut Client<TokioRuntimeProvider>,
    name: Name,
    rr_type: RecordType,
    max_payload: u16,
) -> DnsResponse {
    // Build the request message.
    let mut message: Message =
        Message::new(rand::random::<u16>(), MessageType::Query, OpCode::Query);
    let mut query = Query::query(name, rr_type);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);
    message.metadata.recursion_desired = true;
    let mut edns = Edns::new();
    edns.set_max_payload(max_payload).set_version(0);
    message.set_edns(edns);

    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    client
        .send(DnsRequest::new(message, options))
        .next()
        .await
        .expect("dns response stream ended unexpectedly")
        .unwrap()
}

/// Constructs a new [Message] of type [MessageType::Query];
pub fn new_message(name: Name, rr_type: RecordType) -> Message {
    let mut msg = Message::new(123, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(Query::query(name, rr_type));
    msg
}

/// Converts the given [Message] into a server-side [Request] with dummy values for
/// the client IP and protocol.
pub fn server_request(msg: &Message, client_addr: SocketAddr, protocol: Protocol) -> Request {
    // Serialize the message.
    let wire_bytes = msg.to_vec().unwrap();

    // Deserialize into a server-side request.
    Request::from_bytes(wire_bytes, client_addr, protocol).unwrap()
}

/// Creates a A-record [Request] for the given name.
pub fn a_request(name: Name, client_addr: SocketAddr, protocol: Protocol) -> Request {
    server_request(&new_message(name, RecordType::A), client_addr, protocol)
}

/// Creates a AAAA-record [Request] for the given name.
pub fn aaaa_request(name: Name, client_addr: SocketAddr, protocol: Protocol) -> Request {
    server_request(&new_message(name, RecordType::AAAA), client_addr, protocol)
}

/// Helper for parsing a [SocketAddr] string.
pub fn socket_addr<S: AsRef<str>>(socket_addr: S) -> SocketAddr {
    socket_addr.as_ref().parse().unwrap()
}

/// Helper for parsing a [IpAddr] string.
pub fn ip<S: AsRef<str>>(addr: S) -> IpAddr {
    addr.as_ref().parse().unwrap()
}

/// Helper for parsing a [Ipv4Addr] string.
pub fn ipv4<S: AsRef<str>>(addr: S) -> Ipv4Addr {
    addr.as_ref().parse().unwrap()
}

/// Helper for parsing a [Ipv6Addr] string.
pub fn ipv6<S: AsRef<str>>(addr: S) -> Ipv6Addr {
    addr.as_ref().parse().unwrap()
}

pub struct TestDnsServer {
    tcp: SocketAddr,
    udp: SocketAddr,
    resolver: Arc<dyn Resolver>,
    _drain: DrainTrigger,
}

impl TestDnsServer {
    /// resolver_config gets a config that can be passed to Ztunnel to make this the resolver
    pub fn resolver_config(&self) -> ResolverConfig {
        internal_resolver_config(self.tcp, self.udp)
    }
}

fn internal_resolver_config(tcp: SocketAddr, udp: SocketAddr) -> ResolverConfig {
    let mut udp_conn = ConnectionConfig::udp();
    udp_conn.port = udp.port();
    let mut tcp_conn = ConnectionConfig::tcp();
    tcp_conn.port = tcp.port();
    ResolverConfig::from_parts(
        None,
        vec![],
        vec![
            NameServerConfig::new(udp.ip(), true, vec![udp_conn]),
            NameServerConfig::new(tcp.ip(), true, vec![tcp_conn]),
        ],
    )
}

// run_dns sets up a test DNS server. We happen to have a DNS server implementation, so we abuse that here.
pub async fn run_dns(responses: HashMap<Name, Vec<IpAddr>>) -> anyhow::Result<TestDnsServer> {
    let test_metrics = {
        let mut registry = Registry::default();
        let istio_registry = metrics::sub_registry(&mut registry);
        Arc::new(Metrics::new(istio_registry))
    };
    let (signal, drain) = drain::new();
    let factory = crate::proxy::DefaultSocketFactory::default();

    let state = new_proxy_state(
        &[XdsWorkload {
            uid: "local".to_string(),
            name: "local".to_string(),
            namespace: "ns".to_string(),
            ..Default::default()
        }],
        &[],
        &[],
    );
    let forwarder = Arc::new(FakeForwarder {
        // Use the standard search domains for Kubernetes.
        search_domains: vec![
            n("ns1.svc.cluster.local"),
            n("svc.cluster.local"),
            n("cluster.local"),
        ],
        ips: responses,
    });
    let srv = crate::dns::Server::new(
        "example.com".to_string(),
        Address::Localhost(false, 0),
        state.clone(),
        forwarder,
        test_metrics,
        drain,
        &factory,
        crate::proxy::LocalWorkloadFetcher::new(
            Arc::new(WorkloadInfo {
                name: "local".to_string(),
                namespace: "ns".to_string(),
                service_account: "default".to_string(),
            }),
            state.clone(),
        ),
        Some("prefered-namespace".to_string()),
        true, // ipv6_enabled for tests
    )
    .await?;

    let tcp = srv.tcp_address();
    let udp = srv.udp_address();
    tokio::spawn(srv.run());
    let cfg = internal_resolver_config(tcp, udp);
    let opts = ResolverOpts::default();
    let resolver = Arc::new(
        dns::forwarder::Forwarder::new(cfg, Arc::new(factory), opts)
            .map_err(|e| Error::Generic(Box::new(e)))?,
    );
    Ok(TestDnsServer {
        tcp,
        udp,
        resolver,
        _drain: signal,
    })
}

// Implement a Forwarder that sends a request to our server. This is used for testing the DNS server itself.
// This is somewhat recursive. `Server --this Forwarder--> Server --FakeForwarder--> Mock`
#[async_trait::async_trait]
impl crate::dns::Forwarder for TestDnsServer {
    fn search_domains(&self, _: &Workload) -> Vec<Name> {
        vec![
            n("ns1.svc.cluster.local"),
            n("svc.cluster.local"),
            n("cluster.local"),
        ]
    }

    async fn forward(
        &self,
        _: Option<&Workload>,
        request: &Request,
    ) -> Result<Response, LookupError> {
        self.resolver.lookup(request).await
    }
}
#[async_trait::async_trait]
impl Resolver for TestDnsServer {
    async fn lookup(&self, request: &Request) -> Result<Response, LookupError> {
        self.resolver.lookup(request).await
    }
}

struct FakeForwarder {
    search_domains: Vec<Name>,
    ips: HashMap<Name, Vec<IpAddr>>,
}

#[async_trait::async_trait]
impl crate::dns::Forwarder for FakeForwarder {
    fn search_domains(&self, _: &Workload) -> Vec<Name> {
        self.search_domains.clone()
    }

    async fn forward(
        &self,
        _: Option<&Workload>,
        request: &Request,
    ) -> Result<Response, LookupError> {
        let query = request.request_info()?.query;
        let name: Name = query.name().into();
        let utf = name.to_string();
        if let Some(ip) = utf.strip_suffix(".reflect.internal.") {
            // Magic to allow `ip.reflect.internal` to always return ip (like nip.io)
            return Ok(Response::new(
                vec![a(query.name().into(), ip.parse().unwrap())],
                Vec::default(),
                false,
            ));
        }
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

        return Ok(Response::new(out, Vec::default(), false));
    }
}
