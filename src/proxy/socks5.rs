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
use drain::Watch;

use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use hickory_server::authority::MessageRequest;
use hickory_server::server::{Protocol, Request};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crate::dns::resolver::Resolver;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, error, info, info_span, Instrument};

use crate::proxy::outbound::OutboundConnection;
use crate::proxy::util::run_with_drain;
use crate::proxy::{util, Error, ProxyInputs, TraceParent};
use crate::{assertions, socket};

pub(super) struct Socks5 {
    pi: Arc<ProxyInputs>,
    listener: socket::Listener,
    drain: Watch,
    enable_orig_src: bool,
}

impl Socks5 {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: Watch) -> Result<Socks5, Error> {
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

        let inpod = pi.cfg.inpod_enabled;
        Ok(Socks5 {
            pi,
            listener,
            drain,
            // Do not need to spoof with inpod mode for outbound
            enable_orig_src: transparent && !inpod,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub async fn run(self) {
        let pi = self.pi.clone();
        let pool = crate::proxy::pool::WorkloadHBONEPool::new(
            self.pi.cfg.clone(),
            self.enable_orig_src,
            self.pi.socket_factory.clone(),
            self.pi.cert_manager.clone(),
        );
        let accept = |drain: Watch, force_shutdown: watch::Receiver<()>| {
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
                                enable_orig_src: self.enable_orig_src,
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
                                    _ = handle(oc, stream) => {}
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

        run_with_drain("socks5".to_string(), self.drain, &pi, accept).await
    }
}

// handle will process a SOCKS5 connection. This supports a minimal subset of the protocol,
// sufficient to integrate with common clients:
// - only unauthenticated requests
// - only CONNECT, with IPv4 or IPv6
async fn handle(mut oc: OutboundConnection, mut stream: TcpStream) -> Result<(), anyhow::Error> {
    let remote_addr = socket::to_canonical(stream.peer_addr().expect("must receive peer addr"));

    // Version(5), Number of auth methods
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;

    if version[0] != 0x05 {
        return Err(anyhow::anyhow!("Invalid version"));
    }

    let nmethods = version[1];

    if nmethods == 0 {
        return Err(anyhow::anyhow!("Invalid auth methods"));
    }

    // List of supported auth methods
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Client must include 'unauthenticated' (0).
    if !methods.into_iter().any(|x| x == 0) {
        return Err(anyhow::anyhow!("unsupported auth method"));
    }

    // Select 'unauthenticated' (0).
    stream.write_all(&[0x05, 0x00]).await?;

    // Version(5), Command - only support CONNECT (1)
    let mut version_command = [0u8; 2];
    stream.read_exact(&mut version_command).await?;
    let version = version_command[0];

    if version != 0x05 {
        return Err(anyhow::anyhow!("unsupported version"));
    }

    if version_command[1] != 1 {
        return Err(anyhow::anyhow!("unsupported command"));
    }

    // Skip RSV
    stream.read_exact(&mut [0]).await?;

    // Address type
    let mut atyp = [0u8];
    stream.read_exact(&mut atyp).await?;

    let ip;

    match atyp[0] {
        0x01 => {
            let mut hostb = [0u8; 4];
            stream.read_exact(&mut hostb).await?;
            ip = IpAddr::V4(hostb.into());
        }
        0x04 => {
            let mut hostb = [0u8; 16];
            stream.read_exact(&mut hostb).await?;
            ip = IpAddr::V6(hostb.into());
        }
        0x03 => {
            let mut domain_length = [0u8];
            stream.read_exact(&mut domain_length).await?;
            let mut domain = vec![0u8; domain_length[0] as usize];
            stream.read_exact(&mut domain).await?;
            // TODO: DNS lookup, if we want to integrate with HTTP-based apps without
            // a DNS server.
            let ds = std::str::from_utf8(&domain)?;
            let Some(resolver) = &oc.pi.resolver else {
                return Err(anyhow::anyhow!(
                    "unsupported hostname lookup, requires DNS enabled"
                ));
            };

            ip = dns_lookup(resolver.clone(), remote_addr, ds).await?;
            // oc.pi.resolver.lookup()
            // oc.pi.lookup_service_or_query(ds)
            // return Err(anyhow::anyhow!("unsupported host {ds:?}"));
        }
        _ => {
            return Err(anyhow::anyhow!("unsupported host"));
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = BigEndian::read_u16(&port);

    let host = SocketAddr::new(ip, port);

    // Send dummy values - the client generally ignores it.
    let buf = [
        0x05u8, // version
        // TODO: report appropriate error here. Unfortunately this needs to happen *after* we connect
        // That is, we need to do this within proxy_to().
        0x00, // Success.
        0x00, // reserved
        // Address. TODO: actually return the address instead of hardcoded 0.0.0.0
        0x01, 0x00, 0x00, 0x00, 0x00, // Port. TODO: actually return the port
        0x00, 0x00,
    ];
    stream.write_all(&buf).await?;

    debug!("accepted connection from {remote_addr} to {host}");
    oc.proxy_to(stream, remote_addr, host).await;
    Ok(())
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
