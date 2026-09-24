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

//! IPv6 client/server matrix: initiates different client types against local
//! servers (IPv4-only, IPv6-only, and ztunnel's dual-stack wildcard bind) and
//! asserts what the server observes.
//!
//! Flow per case (avoids a client/server read deadlock): the client writes
//! first, then the server accepts + reads + replies, then the client reads the
//! reply.
//!
//! The dual-stack case is the important one: ztunnel binds its wildcard
//! listeners on `[::]`, which on Linux serves both families by default
//! (`IPV6_V6ONLY=0`) but on Windows defaults to v6-only and would refuse IPv4
//! clients. `socket::tcp_bind` normalizes that; the `dualstack_wildcard...`
//! test is the regression coverage.

use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ztunnel::config::SocketConfig;
use ztunnel::proxy::{freebind_connect, DefaultSocketFactory, SocketFactory};

const MSG: &[u8] = b"ping";
const REPLY: &[u8] = b"pong";

/// Whether IPv6 is usable on this host, determined independently of the code
/// under test (a direct `[::1]` bind).
fn host_has_ipv6() -> bool {
    std::net::TcpListener::bind("[::1]:0").is_ok()
}

fn skip_unless_ipv6() -> bool {
    if host_has_ipv6() {
        return true;
    }
    eprintln!("IPv6 not available on this host; skipping");
    false
}

/// Accept one connection, read `MSG`, reply `REPLY`, and return the peer
/// address the server observed. The caller must have the client send `MSG`
/// first (see the module docs).
async fn server_accept_roundtrip(listener: &TcpListener) -> SocketAddr {
    let (mut stream, peer) = listener.accept().await.unwrap();
    let mut buf = [0u8; MSG.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, MSG);
    stream.write_all(REPLY).await.unwrap();
    peer
}

/// Read the server's `REPLY` after it accepted the client's `MSG`.
async fn client_read_reply(client: &mut TcpStream) {
    let mut buf = [0u8; REPLY.len()];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, REPLY);
}

/// Full roundtrip for an already-connected client: send, let the server
/// accept + read + reply, then verify the reply.
async fn roundtrip_after_connect(
    client: &mut TcpStream,
    listener: &TcpListener,
) -> SocketAddr {
    client.write_all(MSG).await.unwrap();
    let peer = server_accept_roundtrip(listener).await;
    client_read_reply(client).await;
    peer
}

fn v4_server_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn v6_server_addr() -> SocketAddr {
    "[::1]:0".parse().unwrap()
}

async fn bind_listener(addr: SocketAddr) -> TcpListener {
    TcpListener::bind(addr).await.unwrap()
}

#[tokio::test]
async fn plain_v4_client_ipv4_server() {
    let listener = bind_listener(v4_server_addr()).await;

    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let peer = roundtrip_after_connect(&mut client, &listener).await;

    assert_eq!(peer.ip(), IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
}

#[tokio::test]
async fn plain_v6_client_ipv6_server() {
    if !skip_unless_ipv6() {
        return;
    }
    let listener = bind_listener(v6_server_addr()).await;

    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let peer = roundtrip_after_connect(&mut client, &listener).await;

    assert_eq!(peer.ip(), IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
}

/// ztunnel's wildcard listeners bind on `[::]`; they must serve IPv4 clients
/// (observed as `::ffff:` mapped peers) as well as IPv6 ones, on Windows too.
#[tokio::test]
async fn dualstack_wildcard_serves_both_families() {
    if !skip_unless_ipv6() {
        return;
    }
    let factory = DefaultSocketFactory(SocketConfig::default());
    let listener = factory
        .tcp_bind("[::]:0".parse().unwrap())
        .unwrap()
        .inner();
    // The listener's local_addr is the wildcard `[::]:port`, which is not a
    // valid connect *destination*; clients connect to specific loopback
    // addresses on the wildcard listener's port.
    let port = listener.local_addr().unwrap().port();

    // IPv4 client: the dual-stack socket observes the mapped form, which
    // `to_canonical` normalizes back to the IPv4 address.
    let mut v4_client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let v4_peer = roundtrip_after_connect(&mut v4_client, &listener).await;
    assert!(
        matches!(v4_peer.ip(), IpAddr::V6(_)),
        "expected the ::ffff: mapped form, got {v4_peer}"
    );
    assert_eq!(
        v4_peer.ip().to_canonical(),
        IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );

    // IPv6 client: observed natively.
    let mut v6_client = TcpStream::connect(("[::1]", port)).await.unwrap();
    let v6_peer = roundtrip_after_connect(&mut v6_client, &listener).await;
    assert_eq!(v6_peer.ip(), IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
}

/// ztunnel's `freebind_connect` (the outbound connect path) works against both
/// server families with no source address.
#[tokio::test]
async fn ztunnel_freebind_connect_plain_both_families() {
    let factory = DefaultSocketFactory(SocketConfig::default());

    let v4_listener = bind_listener(v4_server_addr()).await;
    let mut client = freebind_connect(None, v4_listener.local_addr().unwrap(), &factory)
        .await
        .unwrap();
    roundtrip_after_connect(&mut client, &v4_listener).await;

    if !skip_unless_ipv6() {
        return;
    }
    let v6_listener = bind_listener(v6_server_addr()).await;
    let mut client = freebind_connect(None, v6_listener.local_addr().unwrap(), &factory)
        .await
        .unwrap();
    roundtrip_after_connect(&mut client, &v6_listener).await;
}

/// ztunnel's `freebind_connect` with a source address: the server must observe
/// the address the caller intended as source (the in-pod shape, where the
/// workload address is local to the process).
#[tokio::test]
async fn ztunnel_freebind_connect_source_both_families() {
    let factory = DefaultSocketFactory(SocketConfig::default());

    let v4_listener = bind_listener(v4_server_addr()).await;
    let src: IpAddr = "127.0.0.1".parse().unwrap();
    let mut client = freebind_connect(Some(src), v4_listener.local_addr().unwrap(), &factory)
        .await
        .unwrap();
    let peer = roundtrip_after_connect(&mut client, &v4_listener).await;
    assert_eq!(peer.ip(), src);

    if !skip_unless_ipv6() {
        return;
    }
    let v6_listener = bind_listener(v6_server_addr()).await;
    let src: IpAddr = "::1".parse().unwrap();
    let mut client = freebind_connect(Some(src), v6_listener.local_addr().unwrap(), &factory)
        .await
        .unwrap();
    let peer = roundtrip_after_connect(&mut client, &v6_listener).await;
    assert_eq!(peer.ip(), src);
}
