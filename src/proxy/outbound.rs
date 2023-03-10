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

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use boring::ssl::ConnectConfiguration;
use drain::Watch;
use hyper::header::FORWARDED;
use hyper::StatusCode;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, info_span, trace, trace_span, warn, Instrument};

use crate::identity::Identity;
use crate::metrics::traffic;
use crate::metrics::traffic::Reporter;
use crate::proxy::inbound::{Inbound, InboundConnect};
use crate::proxy::{util, Error, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};
use crate::workload::{Protocol, Workload};
use crate::{proxy, rbac, socket};

pub struct Outbound {
    pi: ProxyInputs,
    drain: Watch,
    listener: TcpListener,
}

impl Outbound {
    pub(super) async fn new(mut pi: ProxyInputs, drain: Watch) -> Result<Outbound, Error> {
        let listener: TcpListener = TcpListener::bind(pi.cfg.outbound_addr)
            .await
            .map_err(|e| Error::Bind(pi.cfg.outbound_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, &listener)?;
        // Override with our explicitly configured setting
        pi.cfg.enable_original_source = Some(transparent);

        info!(
            address=%listener.local_addr().unwrap(),
            component="outbound",
            transparent,
            "listener established",
        );
        Ok(Outbound {
            pi,
            listener,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub(super) async fn run(self) {
        let accept = async move {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let start_outbound_instant = Instant::now();
                match socket {
                    Ok((stream, _remote)) => {
                        let mut oc = OutboundConnection {
                            pi: self.pi.clone(),
                            id: TraceParent::new(),
                        };
                        let span = info_span!("outbound", id=%oc.id);
                        tokio::spawn(
                            (async move {
                                let res = oc.proxy(stream).await;
                                match res {
                                    Ok(_) => info!(dur=?start_outbound_instant.elapsed(), "complete"),
                                    Err(e) => warn!(dur=?start_outbound_instant.elapsed(), err=%e, "failed")
                                };
                            })
                            .instrument(span),
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
        }.in_current_span();

        // Stop accepting once we drain.
        // Note: we are *not* waiting for all connections to be closed. In the future, we may consider
        // this, but will need some timeout period, as we have no back-pressure mechanism on connections.
        tokio::select! {
            res = accept => { res }
            _ = self.drain.signaled() => {
                info!("outbound drained");
            }
        }
    }
}

pub(super) struct OutboundConnection {
    pub(super) pi: ProxyInputs,
    pub(super) id: TraceParent,
}

impl OutboundConnection {
    async fn proxy(&mut self, stream: TcpStream) -> Result<(), Error> {
        let peer = socket::to_canonical(stream.peer_addr().expect("must receive peer addr"));
        let orig_dst_addr = socket::orig_dst_addr_or_default(&stream);
        self.proxy_to(stream, peer.ip(), orig_dst_addr, false).await
    }

    pub async fn proxy_to(
        &mut self,
        mut stream: TcpStream,
        remote_addr: IpAddr,
        orig_dst_addr: SocketAddr,
        block_passthrough: bool,
    ) -> Result<(), Error> {
        if Some(orig_dst_addr.ip()) == self.pi.cfg.local_ip {
            return Err(Error::SelfCall);
        }
        let req = self.build_request(remote_addr, orig_dst_addr).await?;
        debug!(
            "request from {} to {} via {} type {:#?} dir {:#?}",
            req.source.name, orig_dst_addr, req.gateway, req.request_type, req.direction
        );
        if block_passthrough && req.destination_workload.is_none() {
            // This is mostly used by socks5. For typical outbound calls, we need to allow calls to arbitrary
            // domains. But for socks5
            return Err(Error::SelfCall);
        }
        let can_fastpath = req.protocol == Protocol::HBONE
            && !req
                .destination_workload
                .as_ref()
                .map(|w| w.native_hbone)
                .unwrap_or(false);
        let connection_metrics = traffic::ConnectionOpen {
            reporter: Reporter::source,
            derived_source: None,
            source: Some(req.source.clone()),
            destination: req.destination_workload.clone(),
            connection_security_policy: if req.protocol == Protocol::HBONE {
                traffic::SecurityPolicy::mutual_tls
            } else {
                traffic::SecurityPolicy::unknown
            },
            destination_service: None,
            destination_service_namespace: None,
            destination_service_name: None,
        };

        if req.request_type == RequestType::DirectLocal && can_fastpath {
            // For same node, we just access it directly rather than making a full network connection.
            // Pass our `stream` over to the inbound handler, which will process as usual
            // We *could* apply this to all traffic, rather than just for destinations that are "captured"
            // However, we would then get inconsistent behavior where only node-local pods have RBAC enforced.
            info!("proxying to {} using node local fast path", req.destination);
            let origin_src = if self.pi.cfg.enable_original_source.unwrap_or_default() {
                super::get_original_src_from_stream(&stream)
            } else {
                None
            };
            let conn = rbac::Connection {
                src_identity: Some(req.source.identity()),
                src_ip: remote_addr,
                dst: req.destination,
            };
            if !self.pi.workloads.assert_rbac(&conn).await {
                info!(%conn, "RBAC rejected");
                return Err(Error::HttpStatus(StatusCode::UNAUTHORIZED));
            }
            // same as above but inverted, this is the "inbound" metric
            let inbound_connection_metrics = traffic::ConnectionOpen {
                reporter: Reporter::destination,
                derived_source: None,
                source: Some(req.source.clone()),
                destination: req.destination_workload.clone(),
                connection_security_policy: if req.protocol == Protocol::HBONE {
                    traffic::SecurityPolicy::mutual_tls
                } else {
                    traffic::SecurityPolicy::unknown
                },
                destination_service: None,
                destination_service_namespace: None,
                destination_service_name: None,
            };
            return Inbound::handle_inbound(
                InboundConnect::DirectPath(stream),
                origin_src,
                req.destination,
                self.pi.metrics.to_owned(), // self is a borrow so this clone is to return an owned
                connection_metrics,
                Some(inbound_connection_metrics),
            )
            .await
            .map_err(Error::Io);
        }

        let transferred_bytes = traffic::BytesTransferred::from(&connection_metrics);

        // _connection_close will record once dropped
        let _connection_close = self
            .pi
            .metrics
            .increment_defer::<_, traffic::ConnectionClose>(&connection_metrics);
        match req.protocol {
            Protocol::HBONE => {
                info!(
                    "proxy to {} using HBONE via {} type {:#?}",
                    req.destination, req.gateway, req.request_type
                );

                // Using the raw connection API, instead of client, is a bit annoying, but the only reasonable
                // way to work around https://github.com/hyperium/hyper/issues/2863
                // Eventually we will need to implement our own smarter pooling, TLS handshaking, etc anyways.
                let mut builder = hyper::client::conn::Builder::new();
                let builder = builder
                    .http2_only(true)
                    .http2_initial_stream_window_size(self.pi.cfg.window_size)
                    .http2_max_frame_size(self.pi.cfg.frame_size)
                    .http2_initial_connection_window_size(self.pi.cfg.connection_window_size);

                let mut f = http_types::proxies::Forwarded::new();
                f.add_for(remote_addr.to_string());

                let request = hyper::Request::builder()
                    .uri(&req.destination.to_string())
                    .method(hyper::Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .header(
                        BAGGAGE_HEADER,
                        baggage(&req, self.pi.cfg.cluster_id.clone()),
                    )
                    .header(FORWARDED, f.value().unwrap())
                    .header(TRACEPARENT_HEADER, self.id.header())
                    .body(hyper::Body::empty())
                    .unwrap();
                let local = self
                    .pi
                    .cfg
                    .enable_original_source
                    .unwrap_or_default()
                    .then_some(remote_addr);
                let id = &req.source.identity();
                let cert = self.pi.cert_manager.fetch_certificate(id).await?;
                let connector = cert
                    .connector(req.expected_identity.as_ref())?
                    .configure()
                    .expect("configure");
                let tcp_stream = super::freebind_connect(local, req.gateway).await?;
                tcp_stream.set_nodelay(true)?;
                let tls_stream = connect_tls(connector, tcp_stream).await?;
                let (mut request_sender, connection) = builder
                    .handshake(tls_stream)
                    .await
                    .map_err(Error::HttpHandshake)?;
                // spawn a task to poll the connection and drive the HTTP state
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!("Error in HBONE connection handshake: {:?}", e);
                    }
                });

                let response = request_sender.send_request(request).await?;

                let code = response.status();
                if code != 200 {
                    return Err(Error::HttpStatus(code));
                }
                let mut upgraded = hyper::upgrade::on(response).await?;
                let res = super::copy_hbone(
                    &mut upgraded,
                    &mut stream,
                    &self.pi.metrics,
                    transferred_bytes,
                )
                .instrument(trace_span!("hbone client"))
                .await;
                res
            }
            Protocol::TCP => {
                info!(
                    "Proxying to {} using TCP via {} type {:?}",
                    req.destination, req.gateway, req.request_type
                );
                // Create a TCP connection to upstream
                let local = if self.pi.cfg.enable_original_source.unwrap_or_default() {
                    super::get_original_src_from_stream(&stream)
                } else {
                    None
                };
                let mut outbound = super::freebind_connect(local, req.gateway).await?;
                // Proxying data between downstrean and upstream
                proxy::relay(
                    &mut stream,
                    &mut outbound,
                    &self.pi.metrics,
                    transferred_bytes,
                )
                .await
                .map(|_| ())
            }
        }
    }

    async fn build_request(
        &self,
        downstream: IpAddr,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        let source_workload = match self.pi.workloads.fetch_workload(&downstream).await {
            Some(wl) => wl,
            None => return Err(Error::UnknownSource(downstream)),
        };

        // TODO: we want a single lock for source and upstream probably...?
        let us = self
            .pi
            .workloads
            .find_upstream(target, self.pi.hbone_port)
            .await;
        if us.is_none() {
            // For case no upstream found, passthrough it
            return Ok(Request {
                protocol: Protocol::TCP,
                source: source_workload,
                destination: target,
                destination_workload: None,
                expected_identity: None,
                gateway: target,
                direction: Direction::Outbound,
                request_type: RequestType::Passthrough,
            });
        }

        let us = us.unwrap();
        // For case upstream server has enabled waypoint
        if !us.workload.waypoint_addresses.is_empty() {
            let waypoint_address = us.workload.choose_waypoint_address().unwrap();
            // Even in this case, we are picking a single upstream pod and deciding if it has a remote proxy.
            // Typically this is all or nothing, but if not we should probably send to remote proxy if *any* upstream has one.
            let waypoint_workload = match self.pi.workloads.fetch_workload(&waypoint_address).await
            {
                Some(wl) => wl,
                None => return Err(Error::UnknownWaypoint(waypoint_address, downstream)),
            };
            return Ok(Request {
                // Always use HBONE here
                protocol: Protocol::HBONE,
                source: source_workload,
                // Use the original VIP, not translated
                destination: target,
                destination_workload: Some(us.workload),
                expected_identity: Some(waypoint_workload.identity()),
                gateway: SocketAddr::from((waypoint_address, 15008)),
                // Let the client remote know we are on the inbound path.
                direction: Direction::Inbound,
                request_type: RequestType::ToServerWaypoint,
            });
        }
        if us.workload.gateway_address.is_none() {
            return Err(Error::NoGatewayAddress(Box::new(us.workload.clone())));
        }
        // For case source client and upstream server are on the same node
        if self.pi.cfg.enable_impersonated_identity
            && !us.workload.node.is_empty()
            && self.pi.cfg.local_node.as_ref() == Some(&us.workload.node) // looks weird but in Rust borrows can be compared and will behave the same as owned (https://doc.rust-lang.org/std/primitive.reference.html)
            && us.workload.protocol == Protocol::HBONE
        {
            trace!(
                workload_node = us.workload.node,
                local_node = self.pi.cfg.local_node,
                "select {:?}",
                RequestType::DirectLocal
            );
            return Ok(Request {
                protocol: Protocol::HBONE,
                source: source_workload,
                destination: SocketAddr::from((us.workload.workload_ip, us.port)),
                destination_workload: Some(us.workload.clone()),
                expected_identity: Some(us.workload.identity()),
                gateway: SocketAddr::from((
                    us.workload
                        .gateway_address
                        .expect("gateway address confirmed")
                        .ip(),
                    15008,
                )),
                direction: Direction::Outbound,
                // Sending to a node on the same node (ourselves).
                // In the future this could be optimized to avoid a full network traversal.
                request_type: RequestType::DirectLocal,
            });
        }
        // For case no waypoint for both side and direct to remote node proxy
        Ok(Request {
            protocol: us.workload.protocol,
            source: source_workload,
            destination: SocketAddr::from((us.workload.workload_ip, us.port)),
            destination_workload: Some(us.workload.clone()),
            expected_identity: Some(us.workload.identity()),
            gateway: us
                .workload
                .gateway_address
                .expect("gateway address confirmed"),
            direction: Direction::Outbound,
            request_type: RequestType::Direct,
        })
    }
}

fn baggage(r: &Request, cluster: String) -> String {
    format!("k8s.cluster.name={cluster},k8s.namespace.name={namespace},k8s.{workload_type}.name={workload_name},service.name={name},service.version={version}",
            namespace = r.source.namespace,
            workload_type = r.source.workload_type,
            workload_name = r.source.workload_name,
            name = r.source.canonical_name,
            version = r.source.canonical_revision,
    )
}

#[derive(Debug)]
struct Request {
    protocol: Protocol,
    direction: Direction,
    source: Workload,
    destination: SocketAddr,
    // The intended destination workload. This is always the original intended target, even in the case
    // of other proxies along the path.
    destination_workload: Option<Workload>,
    // The identity we will assert for the next hop; this may not be the same as destination_workload
    // in the case of proxies along the path.
    expected_identity: Option<Identity>,
    gateway: SocketAddr,
    request_type: RequestType,
}

#[derive(Debug)]
enum Direction {
    Inbound,
    Outbound,
}

#[derive(PartialEq, Debug)]
enum RequestType {
    /// ToServerWaypoint refers to requests targeting a server waypoint proxy
    ToServerWaypoint,
    /// Direct requests are made directly to a intended backend pod
    Direct,
    /// DirectLocal requests are made directly to an intended backend pod *on the same node*
    DirectLocal,
    /// Passthrough refers to requests with an unknown target
    Passthrough,
}

pub async fn connect_tls(
    mut connector: ConnectConfiguration,
    stream: TcpStream,
) -> Result<tokio_boring::SslStream<TcpStream>, tokio_boring::HandshakeError<TcpStream>> {
    connector.set_verify_hostname(false);
    connector.set_use_server_name_indication(false);
    tokio_boring::connect(connector, "", stream).await
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::Bytes;

    use crate::config::Config;
    use crate::workload::WorkloadInformation;
    use crate::xds::istio::workload::Protocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::{identity, workload};

    use super::*;

    async fn run_build_request(
        from: &str,
        to: &str,
        xds: XdsWorkload,
        expect: Option<ExpectedRequest<'_>>,
    ) {
        let cfg = Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        };
        let source = XdsWorkload {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            address: Bytes::copy_from_slice(&[127, 0, 0, 1]),
            node: "local-node".to_string(),
            ..Default::default()
        };
        let waypoint = XdsWorkload {
            name: "waypoint-workload".to_string(),
            namespace: "ns".to_string(),
            address: Bytes::copy_from_slice(&[127, 0, 0, 10]),
            node: "local-node".to_string(),
            ..Default::default()
        };
        let wl = workload::WorkloadStore::test_store(vec![source, waypoint, xds]).unwrap();

        let wi = WorkloadInformation {
            info: Arc::new(Mutex::new(wl)),
            demand: None,
        };
        let outbound = OutboundConnection {
            pi: ProxyInputs {
                cert_manager: identity::mock::new_secret_manager(Duration::from_secs(10)),
                workloads: wi,
                hbone_port: 15008,
                cfg,
                metrics: Arc::new(Default::default()),
            },
            id: TraceParent::new(),
        };

        let req = outbound
            .build_request(from.parse().unwrap(), to.parse().unwrap())
            .await
            .ok();
        if let Some(r) = req {
            assert_eq!(
                expect,
                Some(ExpectedRequest {
                    protocol: r.protocol,
                    destination: &r.destination.to_string(),
                    gateway: &r.gateway.to_string(),
                    request_type: r.request_type,
                })
            );
        } else {
            assert_eq!(expect, None);
        }
    }

    #[tokio::test]
    async fn build_request_unknown_dest() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsWorkload {
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                destination: "1.2.3.4:80",
                gateway: "1.2.3.4:80",
                request_type: RequestType::Passthrough,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Direct as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:80",
                request_type: RequestType::Direct,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Http as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:15008",
                request_type: RequestType::Direct,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Direct as i32,
                node: "local-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:80",
                request_type: RequestType::Direct,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Http as i32,
                node: "local-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:15008",
                request_type: RequestType::DirectLocal,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_unknown_source() {
        run_build_request(
            "1.2.3.4",
            "127.0.0.2:80",
            XdsWorkload {
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                ..Default::default()
            },
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_source_waypoint() {
        run_build_request(
            "127.0.0.2",
            "127.0.0.1:80",
            XdsWorkload {
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                waypoint_addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 10])],
                ..Default::default()
            },
            // Even though source has a waypoint, we don't use it
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                destination: "127.0.0.1:80",
                gateway: "127.0.0.1:80",
                request_type: RequestType::Direct,
            }),
        )
        .await;
    }
    #[tokio::test]
    async fn build_request_destination_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                waypoint_addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 10])],
                ..Default::default()
            },
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.10:15008",
                request_type: RequestType::ToServerWaypoint,
            }),
        )
        .await;
    }

    #[derive(PartialEq, Debug)]
    struct ExpectedRequest<'a> {
        protocol: Protocol,
        destination: &'a str,
        gateway: &'a str,
        request_type: RequestType,
    }
}
