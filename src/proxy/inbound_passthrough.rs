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

use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{util, ProxyInputs};
use crate::proxy::{Error, TraceParent};
use crate::socket;
use crate::socket::relay;

use crate::rbac;

pub(super) struct InboundPassthrough {
    listener: TcpListener,
    pi: ProxyInputs,
}

impl InboundPassthrough {
    pub(super) async fn new(pi: ProxyInputs) -> Result<InboundPassthrough, Error> {
        let listener: TcpListener = TcpListener::bind(pi.cfg.inbound_plaintext_addr)
            .await
            .map_err(|e| Error::Bind(pi.cfg.inbound_plaintext_addr, e))?;
        let transparent = socket::set_transparent(&listener).is_ok();

        info!(
            address=%listener.local_addr().unwrap(),
            component="inbound plaintext",
            transparent,
            "listener established",
        );
        Ok(InboundPassthrough { listener, pi })
    }

    pub(super) async fn run(self) {
        loop {
            // Asynchronously wait for an inbound socket.
            let socket = self.listener.accept().await;
            let pi = self.pi.clone();
            match socket {
                Ok((stream, remote)) => {
                    tokio::spawn(async move {
                        if let Err(e) = Self::proxy_inbound_plaintext(
                            pi.clone(),
                            socket::to_canonical(remote),
                            stream,
                        )
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
        pi: ProxyInputs,
        source: SocketAddr,
        mut inbound: TcpStream,
    ) -> Result<(), Error> {
        let orig = socket::orig_dst_addr_or_default(&inbound);
        let Some(upstream) = pi.workloads.fetch_workload(&orig.ip()).await else {
            return Err(Error::UnknownDestination(orig.ip()))
        };
        if !upstream.waypoint_addresses.is_empty() {
            // This is an inbound request not over HBONE, but we have a waypoint.
            // The request needs to go through the waypoint for policy enforcement.
            // This can happen from clients that are not part of the mesh; they won't know to send
            // to the waypoint.
            // To handle this, we forward it to the waypoint ourselves, which will hairpin back to us.
            let mut oc = OutboundConnection {
                pi: pi.clone(),
                id: TraceParent::new(),
            };
            return oc.proxy_to(inbound, source.ip(), orig).await;
        }

        // We enforce RBAC only for non-hairpin cases. This is because we may not be able to properly
        // enforce the policy (for example, if it has L7 attributes), while waypoint will.
        // Instead, we skip enforcement and forward to the waypoint to enforce.
        // On the inbound HBONE side, we will validate it came from the waypoint (and therefor had enforcemen).
        let conn = rbac::Connection {
            src_identity: None,
            src_ip: source.ip(),
            dst: orig,
        };
        if !pi.workloads.assert_rbac(&conn).await {
            info!(%conn, "RBAC rejected");
            return Ok(());
        }
        info!(%source, destination=%orig, component="inbound plaintext", "accepted connection");
        let orig_src = if pi.cfg.enable_original_source {
            super::get_original_src_from_stream(&inbound)
        } else {
            None
        };
        let mut outbound = super::freebind_connect(orig_src, orig).await?;
        relay(&mut inbound, &mut outbound, true).await?;
        info!(%source, destination=%orig, component="inbound plaintext", "connection complete");
        Ok(())
    }
}
