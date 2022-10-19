use super::Error;

use tokio::io;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::socket;

pub struct InboundPassthrough {
    cfg: Config,
}

impl InboundPassthrough {
    pub(crate) fn new(cfg: Config) -> InboundPassthrough {
        InboundPassthrough { cfg }
    }
    pub(super) async fn run(self) {
        let tcp_listener: TcpListener = TcpListener::bind(self.cfg.inbound_plaintext_addr)
            .await
            .expect("failed to bind");
        match socket::set_transparent(&tcp_listener) {
            Err(_e) => info!("running without transparent mode"),
            _ => info!("running with transparent mode"),
        };

        info!(
            "inbound plaintext listener established {}",
            tcp_listener.local_addr().unwrap()
        );

        loop {
            // Asynchronously wait for an inbound socket.
            let socket = tcp_listener.accept().await;
            match socket {
                Ok((mut stream, remote)) => {
                    info!("accepted inbound plaintext connection from {}", remote);
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_inbound_plaintext(&mut stream).await {
                            warn!("plaintext proxying failed {}", e)
                        }
                    });
                }
                Err(e) => error!("Failed TCP handshake {}", e),
            }
        }
    }

    async fn proxy_inbound_plaintext(inbound: &mut TcpStream) -> Result<(), Error> {
        let orig = socket::orig_dst_addr(inbound).expect("must have original dst enabled");
        let mut outbound = TcpStream::connect(orig).await?;

        let (mut ri, mut wi) = inbound.split();
        let (mut ro, mut wo) = outbound.split();

        let client_to_server = async {
            io::copy(&mut ri, &mut wo).await?;
            wo.shutdown().await
        };

        let server_to_client = async {
            io::copy(&mut ro, &mut wi).await?;
            wi.shutdown().await
        };

        tokio::try_join!(client_to_server, server_to_client)?;

        info!("proxy inbound plaintext complete");
        Ok(())
    }
}
