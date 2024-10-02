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

use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};

use crate::dns::resolver::Resolver;
use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use hickory_server::authority::MessageRequest;
use hickory_server::server::{Protocol, Request};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::drain::run_with_drain;
use crate::drain::DrainWatcher;
use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{util, Error, ProxyInputs, TraceParent};
use crate::{assertions, socket};

pub(super) struct Socks5 {
    pi: Arc<ProxyInputs>,
    listener: socket::Listener,
    drain: DrainWatcher,
}

impl Socks5 {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: DrainWatcher) -> Result<Socks5, Error> {
        let listener = pi
            .socket_factory
            .tcp_bind(pi.cfg.socks5_addr.unwrap())
            .map_err(|e| Error::Bind(pi.cfg.socks5_addr.unwrap(), e))?;

        let transparent = super::maybe_set_transparent(&pi, &listener)?;

        info!(
            address=%listener.local_addr(),
            component="socks5",
            transparent,
            "listener established",
        );

        Ok(Socks5 {
            pi,
            listener,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub async fn run(self) {
        let pi = self.pi.clone();
        let pool = crate::proxy::pool::WorkloadHBONEPool::new(
            self.pi.cfg.clone(),
            self.pi.socket_factory.clone(),
            self.pi.local_workload_information.clone(),
        );
        let accept = |drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
            async move {
                loop {
                    // Asynchronously wait for an inbound socket.
                    let socket = self.listener.accept().await;
                    let start = Instant::now();
                    let drain = drain.clone();
                    let mut force_shutdown = force_shutdown.clone();
                    match socket {
                        Ok((stream, _remote)) => {
                            let oc = OutboundConnection {
                                pi: self.pi.clone(),
                                id: TraceParent::new(),
                                pool: pool.clone(),
                                hbone_port: self.pi.cfg.inbound_addr.port(),
                            };
                            let span = info_span!("socks5", id=%oc.id);
                            let serve = (async move {
                                debug!(component="socks5", "connection started");
                                // Since this task is spawned, make sure we are guaranteed to terminate
                                tokio::select! {
                                    _ = force_shutdown.changed() => {
                                        debug!(component="socks5", "connection forcefully terminated");
                                    }
                                    _ = handle_socks_connection(oc, stream) => {}
                                }
                                // Mark we are done with the connection, so drain can complete
                                drop(drain);
                                debug!(component="socks5", dur=?start.elapsed(), "connection completed");
                            }).instrument(span);

                            assertions::size_between_ref(1000, 2000, &serve);
                            tokio::spawn(serve);
                        }
                        Err(e) => {
                            if util::is_runtime_shutdown(&e) {
                                return;
                            }
                            error!("Failed TCP handshake {}", e);
                        }
                    }
                }
            }
        };

        run_with_drain(
            "socks5".to_string(),
            self.drain,
            pi.cfg.self_termination_deadline,
            accept,
        )
        .await
    }
}
async fn handle_socks_connection(mut oc: OutboundConnection, mut stream: TcpStream) {
    match negotiate_socks_connection(&oc.pi, &mut stream).await {
        Ok(target) => {
            // TODO: ideally, we send the success after we connect. This allows us to actually give a
            // success only when we really succeeded, rather than if we completed the SOCKS handshake.
            // Additionally, it would allow us to get a proper address to send back/
            let dummy_addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0);
            if let Err(err) = send_success(&mut stream, dummy_addr).await {
                warn!("failed to send socks success response: {err}");
                return;
            }
            let remote_addr =
                socket::to_canonical(stream.peer_addr().expect("must receive peer addr"));
            oc.proxy_to(stream, remote_addr, target).await
        }
        Err(e) => {
            warn!("failed to negotiate socks connection: {e}");
            send_error(&e, &mut stream).await;
        }
    }
}

// negotiate_socks_connection will handle the negotiation of a SOCKS5 connection.
// This ultimately outputs the target socket address, if the handshake is successful.
// This supports a minimal subset of the protocol, sufficient to integrate with common clients:
// - only unauthenticated requests
// - only CONNECT, with IPv4/IPv6/Hostname
async fn negotiate_socks_connection(
    pi: &ProxyInputs,
    stream: &mut TcpStream,
) -> Result<SocketAddr, SocksError> {
    let remote_addr = socket::to_canonical(stream.peer_addr().expect("must receive peer addr"));

    // Version(5), Number of auth methods
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;

    if version[0] != 0x05 {
        return Err(SocksError::invalid_protocol(format!(
            "unsupported version {}",
            version[0]
        )));
    }

    let nmethods = version[1];

    if nmethods == 0 {
        return Err(SocksError::invalid_protocol(format!(
            "methods cannot be zero {}",
            version[0]
        )));
    }

    // List of supported auth methods
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Client must include 'unauthenticated' (0).
    if !methods.into_iter().any(|x| x == 0) {
        return Err(SocksError::invalid_protocol(
            "only unauthenticated is supported".to_string(),
        ));
    }

    // Select 'unauthenticated' (0).
    stream.write_all(&[0x05, 0x00]).await?;

    // Version(5), Command - only support CONNECT (1)
    let mut version_command = [0u8; 2];
    stream.read_exact(&mut version_command).await?;
    let version = version_command[0];

    if version != 0x05 {
        return Err(SocksError::invalid_protocol(format!(
            "unsupported version {}",
            version
        )));
    }

    if version_command[1] != 1 {
        return Err(SocksError::invalid_protocol(format!(
            "unsupported command {}",
            version_command[1]
        )));
    }

    // Skip RSV
    stream.read_exact(&mut [0]).await?;

    // Address type
    let mut atyp = [0u8];
    stream.read_exact(&mut atyp).await?;

    let ip = match atyp[0] {
        0x01 => {
            let mut hostb = [0u8; 4];
            stream.read_exact(&mut hostb).await?;
            IpAddr::V4(hostb.into())
        }
        0x04 => {
            let mut hostb = [0u8; 16];
            stream.read_exact(&mut hostb).await?;
            IpAddr::V6(hostb.into())
        }
        0x03 => {
            let mut domain_length = [0u8];
            stream.read_exact(&mut domain_length).await?;
            let mut domain = vec![0u8; domain_length[0] as usize];
            stream.read_exact(&mut domain).await?;

            let Ok(ds) = std::str::from_utf8(&domain) else {
                return Err(SocksError::invalid_protocol(format!(
                    "domain is not a valid utf8 string: {domain:?}"
                )));
            };
            let Some(resolver) = &pi.resolver else {
                return Err(SocksError::invalid_protocol(
                    "unsupported hostname lookup, requires DNS enabled".to_string(),
                ));
            };

            match dns_lookup(resolver.clone(), remote_addr, ds).await {
                Ok(ip) => ip,
                Err(e) => {
                    return Err(SocksError::HostUnreachable(e));
                }
            }
        }
        n => {
            return Err(SocksError::invalid_protocol(format!(
                "unsupported address type {n}",
            )));
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = BigEndian::read_u16(&port);

    let host = SocketAddr::new(ip, port);

    Ok(host)
}

async fn dns_lookup(
    resolver: Arc<dyn Resolver + Send + Sync>,
    client_addr: SocketAddr,
    hostname: &str,
) -> Result<IpAddr, Error> {
    fn new_message(name: Name, rr_type: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_id(rand::random());
        msg.set_message_type(MessageType::Query);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(name, rr_type));
        msg
    }
    /// Converts the given [Message] into a server-side [Request] with dummy values for
    /// the client IP and protocol.
    fn server_request(msg: &Message, client_addr: SocketAddr, protocol: Protocol) -> Request {
        let wire_bytes = msg.to_vec().unwrap();
        let msg_request = MessageRequest::from_bytes(&wire_bytes).unwrap();
        Request::new(msg_request, client_addr, protocol)
    }

    /// Creates a A-record [Request] for the given name.
    fn a_request(name: Name, client_addr: SocketAddr, protocol: Protocol) -> Request {
        server_request(&new_message(name, RecordType::A), client_addr, protocol)
    }

    /// Creates a AAAA-record [Request] for the given name.
    fn aaaa_request(name: Name, client_addr: SocketAddr, protocol: Protocol) -> Request {
        server_request(&new_message(name, RecordType::AAAA), client_addr, protocol)
    }

    // TODO: do we need to do the search?
    let name = Name::from_utf8(hostname)?;

    // TODO: we probably want to race them or something. Is there something higher level that can handle this for us?
    let req = if client_addr.is_ipv4() {
        a_request(name, client_addr, Protocol::Udp)
    } else {
        aaaa_request(name, client_addr, Protocol::Udp)
    };
    let answer = resolver.lookup(&req).await?;
    let response = answer
        .record_iter()
        .filter_map(|rec| rec.data().and_then(|d| d.ip_addr()))
        .next() // TODO: do not always use the first result
        .ok_or_else(|| Error::DnsEmpty)?;

    Ok(response)
}

/// send_error sends an error back to the SOCKS client
/// This may fail, but since there is nothing a caller can do about it, failures are simply logged and
/// not returned.
pub async fn send_error(err: &SocksError, source: &mut TcpStream) {
    // SOCKS response requires us to send a 'server bound address'.
    // It's supposed to be the local address we have bound to.
    // In many cases, when we are fail we don't have this.
    let dummy_addr = SocketAddr::new(Ipv4Addr::new(0, 0, 0, 0).into(), 0);
    if let Err(e) = send_response(Some(err), source, dummy_addr).await {
        warn!("failed to send socks error: {e}")
    }
}

/// send_success sends a success back to the SOCKS client.
pub async fn send_success(source: &mut TcpStream, local_addr: SocketAddr) -> Result<(), Error> {
    send_response(None, source, local_addr).await
}

async fn send_response(
    err: Option<&SocksError>,
    source: &mut TcpStream,
    local_addr: SocketAddr,
) -> Result<(), Error> {
    // https://www.rfc-editor.org/rfc/rfc1928#section-6
    let mut buf: Vec<u8> = Vec::with_capacity(10);
    buf.push(0x05); // version
                    // Status
    buf.push(match err {
        None => 0,
        Some(SocksError::General(_)) => 1,
        Some(SocksError::NotAllowed(_)) => 2,
        Some(SocksError::NetworkUnreachable(_)) => 3,
        Some(SocksError::HostUnreachable(_)) => 4,
        Some(SocksError::ConnectionRefused(_)) => 5,
        Some(SocksError::CommandNotSupported(_)) => 7,
    });
    buf.push(0); // RSV
    match local_addr {
        SocketAddr::V4(addr_v4) => {
            buf.push(0x01); // IPv4 address type
            buf.extend_from_slice(&addr_v4.ip().octets());
        }
        SocketAddr::V6(addr_v6) => {
            buf.push(0x04); // IPv6 address type
            buf.extend_from_slice(&addr_v6.ip().octets());
        }
    }
    // Add port in network byte order (big-endian)
    buf.extend_from_slice(&local_addr.port().to_be_bytes());
    source.write_all(&buf).await?;
    Ok(())
}

/// OutboundProxyError maps outbound errors to SOCKS5 protocol errors
/// See https://datatracker.ietf.org/doc/html/rfc1928#section-6.
/// While the socks protocol only allows the int error, we record the full error
/// for our own logging purposes.
#[derive(thiserror::Error, Debug)]
#[allow(dead_code)]
pub enum SocksError {
    #[error("General: {0}")]
    General(Error),
    #[error("NotAllowed: {0}")]
    NotAllowed(Error),
    #[error("NetworkUnreachable: {0}")]
    NetworkUnreachable(Error),
    #[error("HostUnreachable: {0}")]
    HostUnreachable(Error),
    #[error("ConnectionRefused: {0}")]
    ConnectionRefused(Error),
    #[error("CommandNotSupported: {0}")]
    CommandNotSupported(Error),
}

impl SocksError {
    pub fn into_inner(self) -> Error {
        match self {
            SocksError::General(e) => e,
            SocksError::NotAllowed(e) => e,
            SocksError::NetworkUnreachable(e) => e,
            SocksError::HostUnreachable(e) => e,
            SocksError::ConnectionRefused(e) => e,
            SocksError::CommandNotSupported(e) => e,
        }
    }
}

impl SocksError {
    pub fn invalid_protocol(reason: String) -> SocksError {
        SocksError::CommandNotSupported(Error::Anyhow(anyhow::anyhow!(reason)))
    }
}

impl From<std::io::Error> for SocksError {
    fn from(value: std::io::Error) -> Self {
        SocksError::General(Error::Io(value))
    }
}
