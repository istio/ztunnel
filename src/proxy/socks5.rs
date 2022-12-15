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
use hyper_util::client::pool::Pool;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::identity::CertificateProvider;
use crate::metrics::Metrics;
use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{util, Error, TraceParent};
use crate::socket;
use crate::workload::WorkloadInformation;

pub struct Socks5 {
    cfg: Config,
    cert_manager: Box<dyn CertificateProvider>,
    workloads: WorkloadInformation,
    hbone_port: u16,
    listener: TcpListener,
    drain: Watch,
    pub metrics: Arc<Metrics>,
    pub pool: Pool<super::outbound::PoolValue, super::outbound::Key>,
}

impl Socks5 {
    pub async fn new(
        cfg: Config,
        cert_manager: Box<dyn CertificateProvider>,
        hbone_port: u16,
        workloads: WorkloadInformation,
        metrics: Arc<Metrics>,
        drain: Watch,
    ) -> Result<Socks5, Error> {
        let listener: TcpListener = TcpListener::bind(cfg.socks5_addr)
            .await
            .map_err(|e| Error::Bind(cfg.socks5_addr, e))?;

        info!(
            address=%listener.local_addr().unwrap(),
            component="socks5",
            "listener established",
        );

        let pool: Pool<super::outbound::PoolValue, super::outbound::Key> =
            hyper_util::client::pool::Pool::new(
                hyper_util::client::pool::Config {
                    idle_timeout: Some(Duration::from_secs(90)),
                    max_idle_per_host: std::usize::MAX,
                },
                &hyper_util::common::exec::Exec::Default,
            );
        Ok(Socks5 {
            cfg,
            cert_manager,
            workloads,
            hbone_port,
            listener,
            drain,
            metrics,
            pool,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn run(self) {
        let accept = async move {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                match socket {
                    Ok((stream, remote)) => {
                        info!("accepted outbound connection from {}", remote);
                        let oc = OutboundConnection {
                            cert_manager: self.cert_manager.clone(),
                            workloads: self.workloads.clone(),
                            cfg: self.cfg.clone(),
                            hbone_port: self.hbone_port,
                            metrics: self.metrics.clone(),
                            id: TraceParent::new(),
                            pool: self.pool.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(err) = handle(oc, stream).await {
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
                info!("socks5 drained");
            }
        }
    }
}

// hande will process a SOCKS5 connection. This supports a minimnal subset of the protocol,
// sufficient to integrate with common clients:
// - only unauthenticated requests
// - only CONNECT, with IPv4 or IPv6
async fn handle(mut oc: OutboundConnection, mut stream: TcpStream) -> Result<(), anyhow::Error> {
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
            return Err(anyhow::anyhow!("unsupported host"));
        }
        _ => {
            return Err(anyhow::anyhow!("unsupported host"));
        }
    };

    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    let port = BigEndian::read_u16(&port);

    let host = SocketAddr::new(ip, port);

    let remote_addr = socket::to_canonical(stream.peer_addr().expect("must receive peer addr"));

    // Send dummy values - the client generally ignores it.
    let buf = [
        0x05u8, // versuib
        0x00, 0x00, // success, rsv
        0x01, 0x00, 0x00, 0x00, 0x00, // IPv4
        0x00, 0x00, // port
    ];
    stream.write_all(&buf).await?;

    info!("accepted connection from {remote_addr} to {host}");
    tokio::spawn(async move {
        let res = oc.proxy_to(stream, remote_addr.ip(), host).await;
        match res {
            Ok(_) => {}
            Err(ref e) => warn!("outbound proxy failed: {}", e),
        };
    });
    Ok(())
}
