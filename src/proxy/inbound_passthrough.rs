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

use tokio::net::TcpStream;
use tracing::{error, info, warn};

use crate::proxy::outbound::OutboundConnection;
use crate::proxy::{util, ProxyInputs};
use crate::proxy::{Error, TraceParent};
use crate::socket;
use crate::socket::relay;

use crate::rbac;

pub(super) struct InboundPassthrough {
    listener: crate::extensions::WrappedTcpListener,
    pi: ProxyInputs,
}

impl InboundPassthrough {
    pub(super) async fn new(mut pi: ProxyInputs) -> Result<InboundPassthrough, Error> {
        let listener = pi
            .cfg
            .extensions
            .bind(
                pi.cfg.inbound_plaintext_addr,
                crate::extensions::ListenerType::InboundPassthrough,
            )
            .await
            .map_err(|e| Error::Bind(pi.cfg.inbound_plaintext_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, listener.as_ref())?;
        // Override with our explicitly configured setting
        pi.cfg.enable_original_source = Some(transparent);
        info!(
            address=%listener.as_ref().local_addr().unwrap(),
            component="inbound plaintext",
            transparent,
            "listener established",
        );
        Ok(InboundPassthrough { listener, pi })
    }

    #[cfg(test)]
    pub(super) fn address(&self) -> SocketAddr {
        self.listener.as_ref().local_addr().unwrap()
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
        let orig = orig_dst_addr_or_default(&inbound);
        info!(%source, destination=%orig, component="inbound plaintext", "accepted connection");
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
        let orig_src = if pi.cfg.enable_original_source.unwrap_or_default() {
            super::get_original_src_from_stream(&inbound)
        } else {
            None
        };

        let mut outbound = pi
            .cfg
            .extensions
            .connect(
                orig_src,
                orig,
                crate::extensions::UpstreamDestination::UpstreamServer,
            )
            .await?;

        relay(&mut inbound, outbound.as_mut(), true).await?;
        info!(%source, destination=%orig, component="inbound plaintext", "connection complete");
        Ok(())
    }
}

#[cfg(not(test))]
fn orig_dst_addr_or_default(stream: &tokio::net::TcpStream) -> std::net::SocketAddr {
    socket::orig_dst_addr_or_default(stream)
}

#[cfg(test)]
fn orig_dst_addr_or_default(_: &tokio::net::TcpStream) -> std::net::SocketAddr {
    "127.0.0.1:8182".parse().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    use crate::{identity, workload};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use bytes::Bytes;

    use crate::workload::WorkloadInformation;

    #[tokio::test]
    async fn extension_on_for_inbound_passthrough() {
        use std::sync::atomic::Ordering;
        let ext: crate::extensions::mock::MockExtension = Default::default();
        let state = ext.state.clone();
        let cfg = Config {
            extensions: crate::extensions::ExtensionManager::new(Some(Box::new(ext))),
            inbound_plaintext_addr: "127.0.0.1:0".parse().unwrap(),
            ..crate::config::parse_config(None).unwrap()
        };
        let source = XdsWorkload {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            address: Bytes::copy_from_slice(&[127, 0, 0, 1]),
            node: "local-node".to_string(),
            ..Default::default()
        };
        let xds = XdsWorkload {
            address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
            ..Default::default()
        };
        let wl = workload::WorkloadStore::test_store(vec![source, xds]).unwrap();

        let wi = WorkloadInformation {
            info: Arc::new(Mutex::new(wl)),
            demand: None,
        };
        let pi = ProxyInputs {
            cert_manager: Box::new(identity::mock::MockCaClient::new(Duration::from_secs(10))),
            workloads: wi,
            hbone_port: 15008,
            cfg,
            metrics: Arc::new(Default::default()),
        };
        let inbound = InboundPassthrough::new(pi).await.unwrap();
        let addr = inbound.address();

        tokio::spawn(inbound.run());

        let _s = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            tokio::net::TcpStream::connect(addr).await
        })
        .await
        .expect("timeout waiting for pre connect")
        .expect("failed to connect");

        // test that eventual (i.e. 1s) we get the metric incremented
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while state.on_pre_connect.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("timeout waiting for pre connect");

        assert_eq!(state.on_pre_connect.load(Ordering::SeqCst), 1);
    }
}
