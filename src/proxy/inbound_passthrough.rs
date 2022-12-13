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

use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::proxy::util;
use crate::proxy::Error;
use crate::socket;
use crate::socket::relay;

pub struct InboundPassthrough {
    listener: TcpListener,
}

impl InboundPassthrough {
    pub async fn new(cfg: Config) -> Result<InboundPassthrough, Error> {
        let listener: TcpListener = TcpListener::bind(cfg.inbound_plaintext_addr)
            .await
            .map_err(|e| Error::Bind(cfg.inbound_plaintext_addr, e))?;
        let transparent = socket::set_transparent(&listener).is_ok();

        info!(
            address=%listener.local_addr().unwrap(),
            component="inbound plaintext",
            transparent,
            "listener established",
        );
        Ok(InboundPassthrough { listener })
    }

    pub(super) async fn run(self) {
        loop {
            // Asynchronously wait for an inbound socket.
            let socket = self.listener.accept().await;
            match socket {
                Ok((mut stream, remote)) => {
                    tokio::spawn(async move {
                        if let Err(e) =
                            Self::proxy_inbound_plaintext(socket::to_canonical(remote), &mut stream)
                                .await
                        {
                            warn!("plaintext proxying failed: {}", e)
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
    }

    async fn proxy_inbound_plaintext(
        source: SocketAddr,
        inbound: &mut TcpStream,
    ) -> Result<(), Error> {
        let orig = socket::orig_dst_addr_or_default(inbound);
        info!(%source, destination=%orig, component="inbound plaintext", "accepted connection");
        let mut outbound = TcpStream::connect(orig).await?;
        relay(inbound, &mut outbound).await?;
        info!(%source, destination=%orig, component="inbound plaintext", "connection complete");
        Ok(())
    }
}
