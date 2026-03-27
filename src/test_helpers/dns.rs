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
use crate::dns::resolver::{Answer, Resolver};
use crate::drain::DrainTrigger;
use crate::proxy::Error;
use crate::state::WorkloadInfo;
use crate::state::workload::Workload;
use crate::test_helpers::new_proxy_state;
use crate::xds::istio::workload::Workload as XdsWorkload;
use crate::{dns, drain, metrics};
use futures_util::ready;
use futures_util::stream::{Stream, StreamExt};
use hickory_client::ClientError;
use hickory_client::client::{Client, ClientHandle};
use hickory_proto::DnsHandle;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_proto::serialize::binary::BinDecodable;
use hickory_proto::tcp::TcpClientStream;
use hickory_proto::udp::UdpClientStream;
use hickory_proto::xfer::Protocol;
use hickory_proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
use hickory_proto::{ProtoError, ProtoErrorKind};
use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_server::authority::{LookupError, MessageRequest};
use hickory_server::server::Request;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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
pub async fn new_tcp_client(addr: SocketAddr) -> Client {
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(
        addr,
        None,
        None,
        TokioRuntimeProvider::new(),
    );
    let (client, bg) = Client::new(Box::new(stream), sender, None).await.unwrap();

    // Run the client exchange in the background.
    tokio::spawn(bg);

    client
}

/// Creates a new DNS client that establishes a UDP connection to the nameserver at the given address.
pub async fn new_udp_client(addr: SocketAddr) -> Client {
    let stream =
        UdpClientStream::<TokioRuntimeProvider>::builder(addr, TokioRuntimeProvider::new()).build();
    let (client, bg) = Client::connect(stream).await.unwrap();

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
    client: &mut Client,
    name: Name,
    rr_type: RecordType,
    max_payload: u16,
) -> DnsResponse {
    // Build the request message.
    let mut message: Message = Message::new();
    message
        .add_query({
            let mut query = Query::query(name, rr_type);
            query.set_query_class(DNSClass::IN);
            query
        })
        .set_id(rand::random::<u16>())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .set_edns({
            let mut edns = Edns::new();
            edns.set_max_payload(max_payload).set_version(0);
            edns
        });

    // client.send(message).first_answer().await.unwrap()

    let mut options = DnsRequestOptions::default();
    options.use_edns = true;
    ClientResponse(client.send(DnsRequest::new(message, options)))
        .await
        .unwrap()
}

/// Copied from Trust-DNS async_client code to allow construction here.
struct ClientResponse<R>(pub(crate) R)
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static;

impl<R> Future for ClientResponse<R>
where
    R: Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin + 'static,
{
    type Output = Result<DnsResponse, ClientError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(
            match ready!(self.0.poll_next_unpin(cx)) {
                Some(r) => r,
                None => Err(ProtoError::from(ProtoErrorKind::Timeout)),
            }
            .map_err(ClientError::from),
        )
    }
}

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
pub fn server_request(msg: &Message, client_addr: SocketAddr, protocol: Protocol) -> Request {
    // Serialize the message.
    let wire_bytes = msg.to_vec().unwrap();

    // Deserialize into a server-side request.
    let msg_request = MessageRequest::from_bytes(&wire_bytes).unwrap();

    Request::new(msg_request, client_addr, protocol)
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
    let mut rc = ResolverConfig::new();
    rc.add_name_server(NameServerConfig {
        socket_addr: udp,
        protocol: Protocol::Udp,
        tls_dns_name: None,
        http_endpoint: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    rc.add_name_server(NameServerConfig {
        socket_addr: tcp,
        protocol: Protocol::Tcp,
        tls_dns_name: None,
        http_endpoint: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    rc
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
    ) -> Result<Answer, LookupError> {
        self.resolver.lookup(request).await
    }
}
#[async_trait::async_trait]
impl Resolver for TestDnsServer {
    async fn lookup(&self, request: &Request) -> Result<Answer, LookupError> {
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
    ) -> Result<Answer, LookupError> {
        let query = request.request_info()?.query;
        let name: Name = query.name().into();
        let utf = name.to_string();
        if let Some(ip) = utf.strip_suffix(".reflect.internal.") {
            // Magic to allow `ip.reflect.internal` to always return ip (like nip.io)
            return Ok(Answer::new(
                vec![a(query.name().into(), ip.parse().unwrap())],
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

        return Ok(Answer::new(out, false));
    }
}
