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

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use drain::Watch;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, trace, Instrument};

use crate::config::ProxyMode;
use crate::proxy::connection_manager::ConnectionManager;
use crate::proxy::metrics::Reporter;
use crate::proxy::Error;
use crate::proxy::{metrics, util, ProxyInputs};
use crate::rbac;
use crate::state::workload::NetworkAddress;
use crate::{proxy, socket};

pub(super) struct InboundPassthrough {
    listener: TcpListener,
    pi: ProxyInputs,
    drain: Watch,
}

impl InboundPassthrough {
    pub(super) async fn new(
        mut pi: ProxyInputs,
        drain: Watch,
    ) -> Result<InboundPassthrough, Error> {
        let listener: TcpListener = pi
            .socket_factory
            .tcp_bind(pi.cfg.inbound_plaintext_addr)
            .map_err(|e| Error::Bind(pi.cfg.inbound_plaintext_addr, e))?;

        let transparent = super::maybe_set_transparent(&pi, &listener)?;
        // Override with our explicitly configured setting
        pi.cfg.enable_original_source = Some(transparent);

        info!(
            address=%listener.local_addr().expect("local_addr available"),
            component="inbound plaintext",
            transparent,
            "listener established",
        );
        Ok(InboundPassthrough {
            listener,
            pi,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr().expect("local_addr available")
    }

    pub(super) async fn run(self, illegal_ports: Arc<HashSet<u16>>) {
        let accept = async move {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let pi = self.pi.clone();
                let illegal_ports = illegal_ports.clone();

                let connection_manager = self.pi.connection_manager.clone();
                match socket {
                    Ok((stream, remote)) => {
                        tokio::spawn(
                            async move {
                                Self::proxy_inbound_plaintext(
                                    pi, // pi cloned above; OK to move
                                    socket::to_canonical(remote),
                                    stream,
                                    illegal_ports,
                                    connection_manager,
                                )
                                .await
                            }
                            .in_current_span(),
                        );
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
        .in_current_span();
        // Stop accepting once we drain.
        // Note: we are *not* waiting for all connections to be closed. In the future, we may consider
        // this, but will need some timeout period, as we have no back-pressure mechanism on connections.
        tokio::select! {
            res = accept => { res }
            _ = self.drain.signaled() => {
                info!("inbound passthrough drained");
            }
        }
    }

    async fn proxy_inbound_plaintext(
        pi: ProxyInputs,
        source_addr: SocketAddr,
        mut inbound_stream: TcpStream,
        illegal_ports: Arc<HashSet<u16>>,
        connection_manager: ConnectionManager,
    ) {
        let start = Instant::now();
        let dest_addr = socket::orig_dst_addr_or_default(&inbound_stream);
        // Check if it is an illegal call to ourself, which could trampoline to illegal addresses or
        // lead to infinite loops
        let illegal_call = if pi.cfg.inpod_enabled {
            // User sent a request to pod:15006. This would forward to pod:15006 infinitely
            illegal_ports.contains(&dest_addr.port())
        } else {
            // User sent a request to the ztunnel directly. This isn't allowed
            pi.cfg.proxy_mode == ProxyMode::Shared && Some(dest_addr.ip()) == pi.cfg.local_ip
        };
        if illegal_call {
            metrics::log_early_deny(
                source_addr,
                dest_addr,
                Reporter::destination,
                Error::SelfCall,
            );
            return;
        }
        let network_addr = NetworkAddress {
            network: pi.cfg.network.clone(), // inbound request must be on our network
            address: dest_addr.ip(),
        };
        let Some((upstream, upstream_service)) =
            pi.state.fetch_workload_services(&network_addr).await
        else {
            metrics::log_early_deny(
                source_addr,
                dest_addr,
                Reporter::destination,
                Error::UnknownDestination(dest_addr.ip()),
            );
            return;
        };

        let rbac_ctx = crate::state::ProxyRbacContext {
            conn: rbac::Connection {
                src_identity: None,
                src: source_addr,
                // inbound request must be on our network since this is passthrough
                // rather than HBONE, which can be tunneled across networks through gateways.
                // by definition, without the gateway our source must be on our network.
                dst_network: pi.cfg.network.clone(),
                dst: dest_addr,
            },
            dest_workload_info: pi.proxy_workload_info.clone(),
        };

        // Find source info. We can lookup by XDS or from connection attributes
        let source_workload = {
            let network_addr_srcip = NetworkAddress {
                // inbound request must be on our network since this is passthrough
                // rather than HBONE, which can be tunneled across networks through gateways.
                // by definition, without the gateway our source must be on our network.
                network: pi.cfg.network.clone(),
                address: source_addr.ip(),
            };
            pi.state.fetch_workload(&network_addr_srcip).await
        };
        let derived_source = metrics::DerivedWorkload {
            identity: rbac_ctx.conn.src_identity.clone(),
            ..Default::default()
        };
        let ds = proxy::guess_inbound_service(&rbac_ctx.conn, upstream_service, &upstream);
        let connection_metrics = metrics::ConnectionOpen {
            reporter: Reporter::destination,
            source: source_workload,
            derived_source: Some(derived_source),
            destination: Some(upstream),
            connection_security_policy: metrics::SecurityPolicy::unknown,
            destination_service: ds,
        };
        let result_tracker = metrics::ConnectionResult::new(
            source_addr,
            dest_addr,
            None,
            start,
            &connection_metrics,
            pi.metrics,
        );

        let conn_guard = match connection_manager.assert_rbac(&pi.state, &rbac_ctx).await {
            Ok(cg) => cg,
            Err(e) => {
                result_tracker.record(Err(e));
                return;
            }
        };

        let orig_src = if pi.cfg.enable_original_source.unwrap_or_default() {
            Some(source_addr.ip())
        } else {
            None
        };

        let result_tracker = Arc::new(result_tracker);
        let send = async {
            let result_tracker = result_tracker.clone();
            trace!(%source_addr, %dest_addr, component="inbound plaintext", "connecting...");

            let mut outbound =
                super::freebind_connect(orig_src, dest_addr, pi.socket_factory.as_ref())
                    .await
                    .map_err(Error::ConnectionFailed)?;

            trace!(%source_addr, destination=%dest_addr, component="inbound plaintext", "connected");
            socket::copy_bidirectional(&mut inbound_stream, &mut outbound, &result_tracker).await
        };

        let res = conn_guard.handle_connection(send).await;
        result_tracker.record(res.map(|_| ()));
    }
}
