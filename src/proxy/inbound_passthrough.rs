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
use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::sync::watch;

use tracing::{Instrument, debug, error, info, trace};

use crate::drain::DrainWatcher;
use crate::drain::run_with_drain;
use crate::proxy::Error;
use crate::proxy::metrics::Reporter;
use crate::proxy::{ProxyInputs, metrics, util};
use crate::state::workload::NetworkAddress;
use crate::{assertions, copy, handle_connection, rbac, strng};
use crate::{proxy, socket};

pub(super) struct InboundPassthrough {
    listener: socket::Listener,
    pi: Arc<ProxyInputs>,
    drain: DrainWatcher,
    enable_orig_src: bool,
}

impl InboundPassthrough {
    pub(super) async fn new(
        pi: Arc<ProxyInputs>,
        drain: DrainWatcher,
    ) -> Result<InboundPassthrough, Error> {
        let mut listener = pi
            .socket_factory
            .tcp_bind(pi.cfg.inbound_plaintext_addr)
            .map_err(|e| Error::Bind(pi.cfg.inbound_plaintext_addr, e))?;
        listener.set_socket_options(Some(pi.cfg.socket_config));

        let enable_orig_src = super::maybe_set_transparent(&pi, &listener)?;

        info!(
            address=%listener.local_addr(),
            component="inbound plaintext",
            transparent=enable_orig_src,
            "listener established",
        );
        Ok(InboundPassthrough {
            listener,
            pi,
            drain,
            enable_orig_src,
        })
    }

    pub(super) async fn run(self) {
        let pi = self.pi.clone();
        let accept = async move |drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let start = Instant::now();
                let mut force_shutdown = force_shutdown.clone();
                let drain = drain.clone();
                let pi = self.pi.clone();
                match socket {
                    Ok((stream, remote)) => {
                        let socket_labels = metrics::SocketLabels {
                            reporter: Reporter::destination,
                        };
                        pi.metrics.record_socket_open(&socket_labels);

                        let metrics_for_socket_close = pi.metrics.clone();
                        let serve_client = async move {
                            let _socket_guard = metrics::SocketCloseGuard::new(
                                metrics_for_socket_close,
                                Reporter::destination,
                            );
                            debug!(component="inbound passthrough", "connection started");
                                // Since this task is spawned, make sure we are guaranteed to terminate
                            tokio::select! {
                                _ = force_shutdown.changed() => {
                                    debug!(component="inbound passthrough", "connection forcefully terminated");
                                }
                                _ = Self::proxy_inbound_plaintext(pi, socket::to_canonical(remote), stream, self.enable_orig_src) => {}
                            }
                            // Mark we are done with the connection, so drain can complete
                            drop(drain);
                            debug!(component="inbound passthrough", dur=?start.elapsed(), "connection completed");
                        }.in_current_span();

                        assertions::size_between_ref(1500, 3000, &serve_client);
                        tokio::spawn(serve_client);
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

        run_with_drain(
            "inbound passthrough".to_string(),
            self.drain,
            pi.cfg.self_termination_deadline,
            accept,
        )
        .await
    }

    async fn proxy_inbound_plaintext(
        pi: Arc<ProxyInputs>,
        source_addr: SocketAddr,
        inbound_stream: TcpStream,
        enable_orig_src: bool,
    ) {
        let start = Instant::now();
        let dest_addr = socket::orig_dst_addr_or_default(&inbound_stream);
        // Check if it is an illegal call to ourself, which could trampoline to illegal addresses or
        // lead to infinite loops
        let illegal_call = pi.cfg.illegal_ports.contains(&dest_addr.port());
        if illegal_call {
            metrics::log_early_deny(
                source_addr,
                dest_addr,
                Reporter::destination,
                Error::SelfCall,
            );
            return;
        }
        let upstream_workload = match pi.local_workload_information.get_workload().await {
            Ok(upstream_workload) => upstream_workload,
            Err(e) => {
                metrics::log_early_deny(source_addr, dest_addr, Reporter::destination, e);
                return;
            }
        };
        let upstream_services = pi.state.get_services_by_workload(&upstream_workload);

        let rbac_ctx = crate::state::ProxyRbacContext {
            conn: rbac::Connection {
                src_identity: None,
                src: source_addr,
                // inbound request must be on our network since this is passthrough
                // rather than HBONE, which can be tunneled across networks through gateways.
                // by definition, without the gateway our source must be on our network.
                dst_network: strng::new(&pi.cfg.network),
                dst: dest_addr,
            },
            dest_workload: upstream_workload.clone(),
        };

        // Find source info. We can lookup by XDS or from connection attributes
        let source_workload = {
            let network_addr_srcip = NetworkAddress {
                // inbound request must be on our network since this is passthrough
                // rather than HBONE, which can be tunneled across networks through gateways.
                // by definition, without the gateway our source must be on our network.
                network: pi.cfg.network.as_str().into(),
                address: source_addr.ip(),
            };
            pi.state
                .fetch_workload_by_address(&network_addr_srcip)
                .await
        };
        let derived_source = metrics::DerivedWorkload {
            identity: rbac_ctx.conn.src_identity.clone(),
            ..Default::default()
        };
        let ds = proxy::guess_inbound_service(
            &rbac_ctx.conn,
            &None,
            upstream_services,
            &upstream_workload,
        );
        let result_tracker = Box::new(
            metrics::ConnectionResultBuilder::new(
                source_addr,
                dest_addr,
                None,
                start,
                metrics::ConnectionOpen {
                    reporter: Reporter::destination,
                    source: source_workload,
                    derived_source: Some(derived_source),
                    destination: Some(upstream_workload),
                    connection_security_policy: metrics::SecurityPolicy::unknown,
                    destination_service: ds,
                },
                pi.metrics.clone(),
            )
            .build(),
        );

        let mut conn_guard = match pi
            .connection_manager
            .assert_rbac(&pi.state, &rbac_ctx, None)
            .await
        {
            Ok(cg) => cg,
            Err(e) => {
                result_tracker
                    .record_with_flag(Err(e), metrics::ResponseFlags::AuthorizationPolicyDenied);
                return;
            }
        };

        let orig_src = if enable_orig_src {
            Some(source_addr.ip())
        } else {
            None
        };

        let send = async {
            trace!(%source_addr, %dest_addr, component="inbound plaintext", "connecting...");

            let outbound = super::freebind_connect(orig_src, dest_addr, pi.socket_factory.as_ref())
                .await
                .map_err(Error::ConnectionFailed)?;

            trace!(%source_addr, destination=%dest_addr, component="inbound plaintext", "connected");
            copy::copy_bidirectional(
                copy::TcpStreamSplitter(inbound_stream),
                copy::TcpStreamSplitter(outbound),
                &result_tracker,
            )
            .await
        };

        let res = handle_connection!(conn_guard, send);
        result_tracker.record(res);
    }
}
