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

use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::socket;
use crate::socket::relay;

use super::Error;

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
                Err(e) => {
                    if e.get_ref().unwrap().to_string().eq("shutdown") {
                        return;
                    }
                    error!("Failed TCP handshake {}", e);
                }
            }
        }
    }

    async fn proxy_inbound_plaintext(inbound: &mut TcpStream) -> Result<(), Error> {
        let orig = socket::orig_dst_addr_or_default(inbound);
        let mut outbound = TcpStream::connect(orig).await?;
        relay(inbound, &mut outbound).await?;
        info!("proxy inbound plaintext complete");
        Ok(())
    }
}
