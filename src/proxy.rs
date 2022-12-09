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

use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::{fmt, io};

use boring::error::ErrorStack;
use drain::Watch;
use rand::Rng;
use tokio::net::{TcpSocket, TcpStream};

use tracing::{error, trace, warn, info};

use inbound::Inbound;

use crate::identity::CertificateProvider;
use crate::metrics::Metrics;
use crate::proxy::inbound_passthrough::InboundPassthrough;
use crate::proxy::outbound::Outbound;
use crate::proxy::socks5::Socks5;
use crate::workload::WorkloadInformation;
use crate::{config, identity, tls, socket};
use hyper::{Body, Request};

mod inbound;
mod inbound_passthrough;
mod outbound;
mod socks5;
mod util;

pub struct Proxy {
    inbound: Inbound,
    inbound_passthrough: InboundPassthrough,
    outbound: Outbound,
    socks5: Socks5,
}

#[derive(Clone)]
pub(super) struct ProxyInputs {
    cfg: config::Config,
    cert_manager: Box<dyn CertificateProvider>,
    hbone_port: u16,
    workloads: WorkloadInformation,
    metrics: Arc<Metrics>,
}

impl Proxy {
    pub async fn new(
        cfg: config::Config,
        workloads: WorkloadInformation,
        cert_manager: Box<dyn CertificateProvider>,
        metrics: Arc<Metrics>,
        drain: Watch,
    ) -> Result<Proxy, Error> {
        let mut pi = ProxyInputs {
            cfg,
            workloads,
            cert_manager,
            metrics,
            hbone_port: 0,
        };
        // We setup all the listeners first so we can capture any errors that should block startup
        let inbound = Inbound::new(pi.clone(), drain.clone()).await?;
        pi.hbone_port = inbound.address().port();

        let inbound_passthrough = InboundPassthrough::new(pi.clone()).await?;
        let outbound = Outbound::new(pi.clone(), drain.clone()).await?;
        let socks5 = Socks5::new(pi.clone(), drain).await?;
        Ok(Proxy {
            inbound,
            inbound_passthrough,
            outbound,
            socks5,
        })
    }

    pub async fn run(self) {
        let tasks = vec![
            tokio::spawn(self.inbound_passthrough.run()),
            tokio::spawn(self.inbound.run()),
            tokio::spawn(self.outbound.run()),
            tokio::spawn(self.socks5.run()),
        ];

        futures::future::join_all(tasks).await;
    }

    pub fn addresses(&self) -> Addresses {
        Addresses {
            outbound: self.outbound.address(),
            inbound: self.inbound.address(),
            socks5: self.socks5.address(),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Addresses {
    pub outbound: SocketAddr,
    pub inbound: SocketAddr,
    pub socks5: SocketAddr,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to bind to address: {0}")]
    Bind(SocketAddr, io::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("tls handshake failed: {0:?}")]
    TlsHandshake(#[from] tokio_boring::HandshakeError<TcpStream>),

    #[error("http handshake failed: {0}")]
    HttpHandshake(#[source] hyper::Error),

    #[error("http failed: {0}")]
    Http(#[from] hyper::Error),

    #[error("http status: {0}")]
    HttpStatus(hyper::StatusCode),

    #[error("tls error: {0}")]
    Tls(#[from] tls::Error),

    #[error("ssl error: {0}")]
    Ssl(#[from] ErrorStack),

    #[error("identity error: {0}")]
    Identity(#[from] identity::Error),

    #[error("unknown source: {0}")]
    UnknownSource(IpAddr),

    #[error("unknown destination: {0}")]
    UnknownDestination(IpAddr),
}

// TLS record size max is 16k. But we also have a H2 frame header, so leave a bit of room for that.
const HBONE_BUFFER_SIZE: usize = 16_384 - 64;

pub async fn copy_hbone(
    upgraded: &mut hyper::upgrade::Upgraded,
    stream: &mut TcpStream,
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    let (mut ri, mut wi) = tokio::io::split(upgraded);
    let (mut ro, mut wo) = stream.split();

    let client_to_server = async {
        let mut ri = tokio::io::BufReader::with_capacity(HBONE_BUFFER_SIZE, &mut ri);
        let mut wo = tokio::io::BufWriter::with_capacity(HBONE_BUFFER_SIZE, &mut wo);
        let res = tokio::io::copy(&mut ri, &mut wo).await;
        trace!(?res, "hbone -> tcp");
        wo.shutdown().await
    };

    let server_to_client = async {
        let mut ro = tokio::io::BufReader::with_capacity(HBONE_BUFFER_SIZE, &mut ro);
        let mut wi = tokio::io::BufWriter::with_capacity(HBONE_BUFFER_SIZE, &mut wi);
        let res = tokio::io::copy(&mut ro, &mut wi).await;
        trace!(?res, "tcp -> hbone");
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client).map(|_| ())
}

/// Represents a traceparent, as defined by https://www.w3.org/TR/trace-context/
#[derive(Eq, PartialEq)]
pub struct TraceParent {
    version: u8,
    trace_id: u128,
    parent_id: u64,
    flags: u8,
}

pub const BAGGAGE_HEADER: &str = "baggage";
pub const TRACEPARENT_HEADER: &str = "traceparent";

impl TraceParent {
    pub fn header(&self) -> hyper::header::HeaderValue {
        hyper::header::HeaderValue::from_bytes(format!("{self:?}").as_bytes()).unwrap()
    }
}
impl TraceParent {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            version: 0,
            trace_id: rng.gen(),
            parent_id: rng.gen(),
            flags: 0,
        }
    }
}

impl fmt::Debug for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}-{:032x}-{:016x}-{:02x}",
            self.version, self.trace_id, self.parent_id, self.flags
        )
    }
}

impl fmt::Display for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:032x}", self.trace_id,)
    }
}

impl TryFrom<&str> for TraceParent {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 55 {
            anyhow::bail!("traceparent malformed length was {}", value.len())
        }

        let segs: Vec<&str> = value.split('-').collect();

        Ok(Self {
            version: u8::from_str_radix(segs[0], 16)?,
            trace_id: u128::from_str_radix(segs[1], 16)?,
            parent_id: u64::from_str_radix(segs[2], 16)?,
            flags: u8::from_str_radix(segs[3], 16)?,
        })
    }
}
pub fn get_original_src_from_xff(req: &Request<Body>) -> Option<IpAddr> {
    let value = req.headers().get("X-Forwarded-For")?;
    let ip = value
        .to_str()
        .unwrap_or("")
        .to_string()
        .split(',')
        .next()?
        .trim()
        .parse::<IpAddr>();

    match ip {
        Ok(ip) => Some(ip),
        Err(err) => {
            warn!("failed to parse XFF value: {:?}", err);
            None
        }
    }
}

pub fn get_original_src_from_stream(stream: &TcpStream) -> Option<IpAddr> {
    match stream.peer_addr() {
        Ok(sa) => Some(to_canonical_ip(sa)),
        _ => None
    }
}

pub async fn freebind_connect(local: Option<IpAddr>, addr: SocketAddr) -> io::Result<TcpStream> {
    match local {
        None => Ok(TcpStream::connect(addr).await?),
        Some(src) => {
            let socket = if src.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };

            let local_addr = SocketAddr::new(src, 0);
            match socket::set_freebind(&socket) {
                Err(err) => warn!("failed to set freebind: {:?}", err),
                _ => {
                    match socket.bind(local_addr) {
                        Err(err) => warn!("failed to bind local addr: {:?}", err),
                        _ => (),
                    };
                },

            };
            Ok(socket.connect(addr).await?)
        }
    }
}

const ERR_TOKIO_RUNTIME_SHUTDOWN: &str = "A Tokio 1.x context was found, but it is being shutdown.";
