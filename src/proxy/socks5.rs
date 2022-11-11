use crate::config::Config;
use crate::proxy::outbound::OutboundConnection;
use crate::proxy::Error;
use anyhow::Result;
use net::Ipv4Addr;
use std::net;
use byteorder::{BigEndian, ByteOrder};
use crate::workload::WorkloadInformation;
use crate::{identity, socket};
use std::net::{IpAddr, SocketAddr};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};
use tokio::io::AsyncWriteExt;

pub struct Socks5 {
    cfg: Config,
    cert_manager: identity::SecretManager,
    workloads: WorkloadInformation,
    listener: TcpListener,
}

impl Socks5 {
    pub async fn new(
        cfg: Config,
        cert_manager: identity::SecretManager,
        workloads: WorkloadInformation,
    ) -> Result<Socks5, Error> {
        let listener: TcpListener = TcpListener::bind("127.0.0.1:15080")
            .await
            .map_err(Error::Bind)?;
        match socket::set_transparent(&listener) {
            Err(_e) => info!("running without transparent mode"),
            _ => info!("running with transparent mode"),
        };

        Ok(Socks5 {
            cfg,
            cert_manager,
            workloads,
            listener,
        })
    }

    pub async fn run(self) {
        let addr = self.listener.local_addr().unwrap();
        info!("outbound listener established {}", addr);

        loop {
            // Asynchronously wait for an inbound socket.
            let socket = self.listener.accept().await;
            match socket {
                Ok((stream, remote)) => {
                    info!("accepted outbound connection from {}", remote);
                    //let cfg = self.cfg.clone();
                    let oc = OutboundConnection {
                        cert_manager: self.cert_manager.clone(),
                        workloads: self.workloads.clone(),
                        cfg: self.cfg.clone(),
                    };
                    tokio::spawn(async move {

                        match handle(oc, stream).await {
                            Err(err) => log::error!("handshake error: {}", err),
                            Ok(_) => {}
                        }
                    });
                }
                Err(e) => error!("Failed TCP handshake {}", e),
            }
        }
    }
}

async fn handle(oc: OutboundConnection, mut stream: TcpStream) -> Result<(), anyhow::Error> {

    let mut version = [0u8];
    //let (r, w) = stream.into_split();
    //read_exact(&r, &mut version).await?;
    stream.read_exact(&mut version).await?;

    if version[0] != 0x05 {
        return Err(anyhow::anyhow!("Invalid version"));
    }

    let mut nmethods = [0u8];
    stream.read_exact(&mut nmethods).await?;
    let nmethods = nmethods[0];

    if nmethods == 0 {
        return Err(anyhow::anyhow!("Invalid auth methods"));
    }

    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;

    let a =  methods.into_iter().find(|m| *m == 0);
    if a == None {
        return Err(anyhow::anyhow!("unsupported method"));
    }

    stream.write_all(&[0x05, 0x00]).await?;

    let mut version = [0u8];
    stream.read_exact(&mut version).await?;
    let version = version[0];

    if version != 0x05 {
        return Err(anyhow::anyhow!("unsupported auth"));
    }

    let mut command = [0u8];
    stream.read_exact(&mut command).await?;

    if command[0] != 1 {
        return Err(anyhow::anyhow!("unsupported command"));
    }

    // Skip RSV
    stream.read_exact(&mut [0]).await?;

    let mut atyp = [0u8];
    stream.read_exact(&mut atyp).await?;

    let mut ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

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

    let remote_addr =
        super::to_canonical_ip(stream.peer_addr().expect("must receive peer addr"));

    let buf = [
        0x05u8,
        0x00, 0x00, // success, rsv
        0x01, 0x00, 0x00, 0x00, 0x00, // IPv4
        0x00, 0x00
    ];
    stream.write_all(&buf).await?;

    tokio::spawn(async move {
        let res = oc.proxy_to(stream, remote_addr, host).await;
        match res {
            Ok(_) => {},
            Err(ref e) => warn!("outbound proxy failed: {}", e),
        };
    });
    return Ok(());
}

