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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{error, info};
use outbound::OutboundProxyError;

use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{util, Error, ProxyInputs, TraceParent, outbound};
use crate::socket;

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

        let enable_orig_src = super::maybe_set_transparent(&pi, &listener)?;

        info!(
            address=%listener.local_addr(),
            component="socks5",
            transparent=enable_orig_src,
            "listener established",
        );

        Ok(Socks5 {
            pi,
            listener,
            drain,
            enable_orig_src,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub async fn run(self) {
        let inner_drain = self.drain.clone();
        let inpod = self.pi.cfg.inpod_enabled;
        let accept = async move {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let stream_drain = inner_drain.clone();
                // TODO creating a new HBONE pool for SOCKS5 here may not be ideal,
                // but ProxyInfo is overloaded and only `outbound` should ever use the pool.
                let pool = crate::proxy::pool::WorkloadHBONEPool::new(
                    self.pi.cfg.clone(),
                    self.enable_orig_src,
                    self.pi.socket_factory.clone(),
                    self.pi.cert_manager.clone(),
                );
                match socket {
                    Ok((stream, remote)) => {
                        info!("accepted outbound connection from {}", remote);
                        let oc = OutboundConnection {
                            pi: self.pi.clone(),
                            id: TraceParent::new(),
                            pool,
                            enable_orig_src: self.enable_orig_src,
                            hbone_port: self.pi.cfg.inbound_addr.port(),
                            send_socks5_success: true,
                        };
                        tokio::spawn(async move {
                            if let Err(err) = handle(oc, stream, stream_drain, inpod).await {
                                log::error!("handshake error: {}", err);
                            }
                        });
                    }
                    Err(e) => {
                        if util::is_runtime_shutdown(&e) {
                            return;
                        }
                        error!("Failed TCP handshake {}", e);
                    }
                }
            }
        };

        tokio::select! {
            res = accept => { res }
            _ = self.drain.signaled() => {
                // out_drain_signal.drain().await;
                info!("socks5 drained");
            }
        }
    }
}

pub fn respond(mut stream: TcpStream, res: Result<(), anyhow::Error>) {
    match res {
        Ok(_) => {}
        Err(_) => {}
    }
}

// handle will process a SOCKS5 connection. This supports a minimal subset of the protocol,
// sufficient to integrate with common clients:
// - only unauthenticated requests
// - only CONNECT, with IPv4 or IPv6
async fn handle(
    mut oc: OutboundConnection,
    mut stream: TcpStream,
    out_drain: Watch,
    is_inpod: bool,
) -> Result<(), anyhow::Error> {
    // Version(5), Number of auth methods
    let mut version = [0u8; 2];
    stream.read_exact(&mut version).await?;

    if version[0] != 0x05 {
        return Err(anyhow::anyhow!("Invalid version"));
    }

    let nmethods = version[1];

    if nmethods == 0 {
        return Err(OutboundProxyError::CommandNotSupported.into());
    }

    // List of supported auth methods
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    // Client must include 'unauthenticated' (0).
    if !methods.into_iter().any(|x| x == 0) {
        return Err(OutboundProxyError::CommandNotSupported.into());
    }

    // Select 'unauthenticated' (0).
    stream.write_all(&[0x05, 0x00]).await?;

    // Version(5), Command - only support CONNECT (1)
    let mut version_command = [0u8; 2];
    stream.read_exact(&mut version_command).await?;
    let version = version_command[0];

    if version != 0x05 {
        return Err(OutboundProxyError::CommandNotSupported.into());
    }

    if version_command[1] != 1 {
        return Err(OutboundProxyError::CommandNotSupported.into());
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
            return Err(OutboundProxyError::HostUnreachable.into());
        }
        _ => {
            return Err(OutboundProxyError::HostUnreachable.into());
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = BigEndian::read_u16(&port);

    let host = SocketAddr::new(ip, port);

    let remote_addr = socket::to_canonical(stream.peer_addr().expect("must receive peer addr"));

    // Send dummy values - the client generally ignores it.
    let buf = [
        0x05u8, // version
        0x00, //
        0x00, // reserved
        0x01, 0x00, 0x00, 0x00, 0x00, // IPv4
        0x00, 0x00, // port
    ];
    stream.write_all(&buf).await?;

    info!("accepted connection from {remote_addr} to {host}");
    // For inpod, we want this `spawn` to guaranteed-terminate when we drain - the workload is gone.
    // For non-inpod (shared instance for all workloads), let the spawned task run until the proxy process
    // itself is killed, or the connection terminates normally.
    let drain = match is_inpod {
        true => Some(out_drain),
        false => None,
    };
    oc.proxy_to_cancellable(stream, remote_addr, host, drain)
        .await
        .into()
}
