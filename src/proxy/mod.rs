use boring::error::ErrorStack;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tracing::info;

use inbound::Inbound;

use crate::proxy::inbound_passthrough::InboundPassthrough;
use crate::proxy::outbound::Outbound;
use crate::workload::WorkloadInformation;
use crate::{config, identity, tls};

mod inbound;
mod inbound_passthrough;
mod outbound;

pub struct Proxy {
    inbound: Inbound,
    inbound_passthrough: InboundPassthrough,
    outbound: Outbound,
}

impl Proxy {
    pub async fn new(
        cfg: config::Config,
        workloads: Arc<Mutex<WorkloadInformation>>,
        secret_manager: identity::SecretManager,
    ) -> Result<Proxy, Error> {
        // We setup all the listeners first so we can capture any errors that should block startup
        let inbound_passthrough = InboundPassthrough::new(cfg.clone());
        let inbound = Inbound::new(cfg.clone(), workloads.clone(), secret_manager.clone()).await?;
        let outbound = Outbound::new(cfg.clone(), secret_manager, workloads).await?;
        Ok(Proxy {
            inbound,
            inbound_passthrough,
            outbound,
        })
    }

    pub async fn run(self) {
        let tasks = vec![
            tokio::spawn(self.inbound_passthrough.run()),
            tokio::spawn(self.inbound.run()),
            tokio::spawn(self.outbound.run()),
        ];

        futures::future::join_all(tasks).await;
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to bind to address: {0}")]
    Bind(#[source] io::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("tls handshake failed: {0}")]
    TlsHandshake(#[from] tokio_boring::HandshakeError<TcpStream>),

    #[error("http handshake failed: {0}")]
    HttpHandshake(#[source] hyper::Error),

    #[error("http failed: {0}")]
    Http(#[from] hyper::Error),

    #[error("tls error: {0}")]
    Tls(#[from] tls::Error),

    #[error("ssl error: {0}")]
    Ssl(#[from] ErrorStack),

    #[error("identity error: {0}")]
    Identity(#[from] identity::Error),
}

pub async fn copy_hbone(
    desc: &str,
    upgraded: &mut hyper::upgrade::Upgraded,
    stream: &mut TcpStream,
) -> Result<(), std::io::Error> {
    use tokio::io::AsyncWriteExt;
    let (mut ri, mut wi) = tokio::io::split(upgraded);
    let (mut ro, mut wo) = stream.split();

    let client_to_server = async {
        let res = tokio::io::copy(&mut ri, &mut wo).await;
        info!(?res, ?desc, "hbone -> tcp");
        res.expect("");
        wo.shutdown().await
    };

    let server_to_client = async {
        let res = tokio::io::copy(&mut ro, &mut wi).await;
        info!(?res, ?desc, "tcp -> hbone");
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client).map(|_| ())
    // TODO: Buffered may be faster, but couldn't get around the "WriteZero" errors
    // let (ri, mut wi) = tokio::io::split(upgraded);
    // let (ro, mut wo) = stream.split();
    //
    // // 16 mb buffers
    // let mut rib = tokio::io::BufReader::with_capacity(1048576 * 16, ri);
    // let mut rob = tokio::io::BufReader::with_capacity(1048576 * 16, ro);
    //
    // let client_to_server = async {
    //     let res = io::copy_buf(&mut rib, &mut wo).await;
    //     info!(?res, ?desc, "hbone -> tcp");
    //     res.expect("");
    //     wo.shutdown().await
    // };
    //
    // let server_to_client = async {
    //     let res = io::copy_buf(&mut rob, &mut wi).await;
    //     info!(?res, ?desc, "tcp -> hbone");
    //     wi.shutdown().await
    // };
    //
    // tokio::try_join!(client_to_server, server_to_client).map(|_| ())
}

fn to_canonical_ip(ip: SocketAddr) -> IpAddr {
    // For now we only support IPv4 but we are binding to IPv6 address; convert everything to IPv4
    // TODO: Support IPv6 fully
    match ip.ip() {
        IpAddr::V4(i) => IpAddr::V4(i),
        IpAddr::V6(i) => IpAddr::V4(i.to_ipv4().unwrap()),
    }
}
