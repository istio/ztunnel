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

use crate::dns::forwarder::Forwarder;
use futures_util::ready;
use futures_util::stream::{Stream, StreamExt};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::net::{TcpStream, UdpSocket};
use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::error::ClientError;
use trust_dns_proto::error::{ProtoError, ProtoErrorKind};
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_proto::op::{Edns, Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::serialize::binary::BinDecodable;
use trust_dns_proto::tcp::TcpClientStream;
use trust_dns_proto::udp::UdpClientStream;
use trust_dns_proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
use trust_dns_proto::DnsHandle;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::server::{Protocol, Request};

const TTL: u32 = 5;

/// A short-hand helper for constructing a [Name].
pub fn n<S: AsRef<str>>(name: S) -> Name {
    Name::from_utf8(name).unwrap()
}

/// Creates an A record for the name and IP.
pub fn a(name: Name, addr: Ipv4Addr) -> Record {
    Record::from_rdata(name, TTL, RData::A(addr))
}

/// Creates an AAAA record for the name and IP.
pub fn aaaa(name: Name, addr: Ipv6Addr) -> Record {
    Record::from_rdata(name, TTL, RData::AAAA(addr))
}

/// Creates a CNAME record for the given canonical name.
pub fn cname(name: Name, canonical_name: Name) -> Record {
    Record::from_rdata(name, TTL, RData::CNAME(canonical_name))
}

#[cfg(any(unix, target_os = "windows"))]
/// Creates a [Forwarder] that uses the system configuration (e.g. /etc/resolv.conf).
pub fn system_forwarder() -> Forwarder {
    use trust_dns_resolver::system_conf::read_system_conf;
    let (cfg, opts) = read_system_conf().unwrap();
    Forwarder::new(cfg, opts).unwrap()
}

/// Creates a new DNS client that establishes a TCP connection to the nameserver at the given
/// address.
pub async fn new_tcp_client(addr: SocketAddr) -> AsyncClient {
    let (stream, sender) = TcpClientStream::<AsyncIoTokioAsStd<TcpStream>>::new(addr);
    let (client, bg) = AsyncClient::new(Box::new(stream), sender, None)
        .await
        .unwrap();

    // Run the client exchange in the background.
    tokio::spawn(bg);

    client
}

/// Creates a new DNS client that establishes a UDP connection to the nameserver at the given address.
pub async fn new_udp_client(addr: SocketAddr) -> AsyncClient {
    let stream = UdpClientStream::<UdpSocket>::new(addr);
    let (client, bg) = AsyncClient::connect(stream).await.unwrap();

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
    client: &mut AsyncClient,
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
