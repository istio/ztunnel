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
use std::str::FromStr;

use std::time::Instant;

use bytes::Bytes;
use drain::Watch;
use http_body_util::Empty;
use hyper::header::FORWARDED;
use hyper::StatusCode;

use tokio::net::{TcpListener, TcpStream};

use tracing::{debug, error, info, info_span, trace, trace_span, warn, Instrument};

use crate::config::ProxyMode;
use crate::identity::Identity;
use crate::proxy::inbound::{Inbound, InboundConnect};
use crate::proxy::metrics::Reporter;
use crate::proxy::{metrics, pool};
use crate::proxy::{util, Error, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};

use crate::state::service::ServiceDescription;
use crate::state::set_gateway_address;
use crate::state::workload::gatewayaddress::Destination;
use crate::state::workload::{address::Address, NetworkAddress, Protocol, Workload};
use crate::{hyper_util, proxy, rbac, socket};

pub struct Outbound {
    pi: ProxyInputs,
    drain: Watch,
    listener: TcpListener,
}

impl Outbound {
    pub(super) async fn new(mut pi: ProxyInputs, drain: Watch) -> Result<Outbound, Error> {
        let listener: TcpListener = pi
            .socket_factory
            .tcp_bind(pi.cfg.outbound_addr)
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
        if self.pi.cfg.proxy_mode == ProxyMode::Shared
            && Some(orig_dst_addr.ip()) == self.pi.cfg.local_ip
        {
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
            return Err(Error::UnknownDestination(req.destination.ip()));
        }
        let can_fastpath = self.pi.cfg.proxy_mode == ProxyMode::Shared
            && req.protocol == Protocol::HBONE
            && !req
                .destination_workload
                .as_ref()
                .map(|w| w.native_tunnel)
                .unwrap_or(false);
        let connection_metrics = metrics::ConnectionOpen {
            reporter: Reporter::source,
            derived_source: None,
            source: Some(req.source.clone()),
            destination: req.destination_workload.clone(),
            connection_security_policy: if req.protocol == Protocol::HBONE {
                metrics::SecurityPolicy::mutual_tls
            } else {
                metrics::SecurityPolicy::unknown
            },
            destination_service: req.destination_service.clone(),
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
                dst_network: req.source.network.clone(), // since this is node local, it's the same network
                dst: req.destination,
            };

            let rbac_ctx = crate::state::ProxyRbacContext {
                conn,
                // Note: here we can't use `pi.proxy_workload_info` as the proxy instance presents the source and not the dest.
                // Note that fastpath is disabled in the inpod mode, so that's not a concern.
                dest_workload_info: None,
            };
            self.pi.connection_manager.register(&rbac_ctx).await;
            if !self.pi.state.assert_rbac(&rbac_ctx).await {
                self.pi.connection_manager.release(&rbac_ctx).await;
                info!(%rbac_ctx, "RBAC rejected");
                return Err(Error::HttpStatus(StatusCode::UNAUTHORIZED));
            }
            // same as above but inverted, this is the "inbound" metric
            let inbound_connection_metrics = metrics::ConnectionOpen {
                reporter: Reporter::destination,
                derived_source: None,
                source: Some(req.source.clone()),
                destination: req.destination_workload.clone(),
                connection_security_policy: if req.protocol == Protocol::HBONE {
                    metrics::SecurityPolicy::mutual_tls
                } else {
                    metrics::SecurityPolicy::unknown
                },
                destination_service: req.destination_service,
            };
            return Inbound::handle_inbound(
                InboundConnect::DirectPath(stream),
                origin_src,
                req.destination,
                self.pi.metrics.to_owned(), // self is a borrow so this clone is to return an owned
                connection_metrics,
                Some(inbound_connection_metrics),
                self.pi.socket_factory.as_ref(),
                self.pi.connection_manager.clone(),
                rbac_ctx,
            )
            .await
            .map_err(Error::Io);
        }

        let transferred_bytes = metrics::BytesTransferred::from(&connection_metrics);

        // _connection_close will record once dropped
        let _connection_close = self
            .pi
            .metrics
            .increment_defer::<_, metrics::ConnectionClose>(&connection_metrics);
        match req.protocol {
            Protocol::HBONE => {
                info!(
                    "proxy to {} using HBONE via {} type {:#?}",
                    req.destination, req.gateway, req.request_type
                );

                let mut allowed_sans: Vec<Identity> = Vec::new();
                for san in req.upstream_sans.iter() {
                    match Identity::from_str(san) {
                        Ok(ident) => allowed_sans.push(ident.clone()),
                        Err(err) => {
                            warn!("error parsing SAN {}: {}", san, err)
                        }
                    }
                }

                allowed_sans.push(req.expected_identity.clone().unwrap());
                let dst_identity = allowed_sans;

                let pool_key = pool::Key {
                    src_id: req.source.identity(),
                    dst_id: dst_identity.clone(),
                    dst: req.gateway,
                };

                // Setup our connection future. This won't always run if we have an existing connection
                // in the pool.
                let connect = async {
                    let mut builder =
                        hyper::client::conn::http2::Builder::new(hyper_util::TokioExecutor);
                    let builder = builder
                        .initial_stream_window_size(self.pi.cfg.window_size)
                        .max_frame_size(self.pi.cfg.frame_size)
                        .initial_connection_window_size(self.pi.cfg.connection_window_size);

                    let local = self
                        .pi
                        .cfg
                        .enable_original_source
                        .unwrap_or_default()
                        .then_some(remote_addr);
                    let id = &req.source.identity();
                    let cert = self.pi.cert_manager.fetch_certificate(id).await?;
                    let connector = cert.outbound_connector(dst_identity)?;
                    let tcp_stream = super::freebind_connect(
                        local,
                        req.gateway,
                        self.pi.socket_factory.as_ref(),
                    )
                    .await?;
                    tcp_stream.set_nodelay(true)?; // TODO: this is backwards of expectations
                    let tls_stream = connector.connect(tcp_stream).await?;
                    let (request_sender, connection) = builder
                        .handshake(::hyper_util::rt::TokioIo::new(tls_stream))
                        .await
                        .map_err(Error::HttpHandshake)?;
                    // spawn a task to poll the connection and drive the HTTP state
                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            error!("Error in HBONE connection handshake: {:?}", e);
                        }
                    });
                    Ok(request_sender)
                };
                let mut connection = self.pi.pool.connect(pool_key.clone(), connect).await?;

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
                    .body(Empty::<Bytes>::new())
                    .unwrap();

                let response = connection.send_request(request).await?;

                let code = response.status();
                if code != 200 {
                    return Err(Error::HttpStatus(code));
                }
                let mut upgraded = hyper::upgrade::on(response).await?;

                super::copy_hbone(
                    &mut upgraded,
                    &mut stream,
                    &self.pi.metrics,
                    transferred_bytes,
                )
                .instrument(trace_span!("hbone client"))
                .await
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
                let mut outbound =
                    super::freebind_connect(local, req.gateway, self.pi.socket_factory.as_ref())
                        .await?;
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
        let downstream_network_addr = NetworkAddress {
            network: self.pi.cfg.network.clone(),
            address: downstream,
        };
        let source_workload = match self.pi.state.fetch_workload(&downstream_network_addr).await {
            Some(wl) => wl,
            None => return Err(Error::UnknownSource(downstream)),
        };

        // If this is to-service traffic check for a service waypoint
        if let Some(Address::Service(s)) = self
            .pi
            .state
            .fetch_destination(&Destination::Address(NetworkAddress {
                network: self.pi.cfg.network.clone(),
                address: target.ip(),
            }))
            .await
        {
            // if we have a waypoint for this svc, use it; otherwise route traffic normally
            if let Some(wp) = s.waypoint.clone() {
                let waypoint_vip = match wp.destination {
                    Destination::Address(a) => a.address,
                    Destination::Hostname(_) => {
                        return Err(proxy::Error::UnknownWaypoint(
                            "hostname lookup not supported yet".to_string(),
                        ));
                    }
                };
                let waypoint_vip = SocketAddr::new(waypoint_vip, wp.hbone_mtls_port);
                let waypoint_us = self
                    .pi
                    .state
                    .fetch_upstream(&self.pi.cfg.network, waypoint_vip)
                    .await
                    .ok_or(proxy::Error::UnknownWaypoint(
                        "unable to determine waypoint upstream".to_string(),
                    ))?;

                let waypoint_workload = waypoint_us.workload;
                let waypoint_ip = self
                    .pi
                    .state
                    .load_balance(
                        &waypoint_workload,
                        &source_workload,
                        self.pi.metrics.clone(),
                    )
                    .await?; // if we can't load balance just return the error

                let waypoint_socket_address = SocketAddr::new(waypoint_ip, waypoint_us.port);

                return Ok(Request {
                    protocol: Protocol::HBONE,
                    direction: Direction::Outbound,
                    source: source_workload,
                    destination: target,
                    destination_workload: None, // this is to Service traffic with a wp... gateway will handle workload selection
                    destination_service: Some(ServiceDescription::from(&*s)),
                    expected_identity: Some(waypoint_workload.identity()),
                    gateway: waypoint_socket_address,
                    request_type: RequestType::ToServerWaypoint,
                    upstream_sans: waypoint_us.sans,
                });
            }
        }

        // TODO: we want a single lock for source and upstream probably...?
        let us = self
            .pi
            .state
            .fetch_upstream(&source_workload.network, target)
            .await;
        if us.is_none() {
            // For case no upstream found, passthrough it
            return Ok(Request {
                protocol: Protocol::TCP,
                source: source_workload,
                destination: target,
                destination_workload: None,
                destination_service: None,
                expected_identity: None,
                gateway: target,
                direction: Direction::Outbound,
                request_type: RequestType::Passthrough,
                upstream_sans: vec![],
            });
        }

        let mut mutable_us = us.unwrap();
        let workload_ip = self
            .pi
            .state
            .load_balance(
                &mutable_us.workload,
                &source_workload,
                self.pi.metrics.clone(),
            )
            .await?;

        // For case upstream server has enabled waypoint
        match self
            .pi
            .state
            .fetch_waypoint(&mutable_us.workload, workload_ip)
            .await
        {
            Ok(None) => {} // workload doesn't have a waypoint; this is fine
            Ok(Some(waypoint_us)) => {
                let waypoint_workload = waypoint_us.workload;
                let waypoint_ip = self
                    .pi
                    .state
                    .load_balance(
                        &waypoint_workload,
                        &source_workload,
                        self.pi.metrics.clone(),
                    )
                    .await?;
                let wp_socket_addr = SocketAddr::new(waypoint_ip, waypoint_us.port);
                return Ok(Request {
                    // Always use HBONE here
                    protocol: Protocol::HBONE,
                    source: source_workload,
                    // Use the original VIP, not translated
                    destination: target,
                    destination_workload: Some(mutable_us.workload),
                    destination_service: mutable_us.destination_service.clone(),
                    expected_identity: Some(waypoint_workload.identity()),
                    gateway: wp_socket_addr,
                    // Let the client remote know we are on the inbound path.
                    direction: Direction::Inbound,
                    request_type: RequestType::ToServerWaypoint,
                    upstream_sans: mutable_us.sans,
                });
            }
            // we expected the workload to have a waypoint, but could not find one
            Err(e) => return Err(Error::UnknownWaypoint(e.to_string())),
        }

        let us = match set_gateway_address(&mut mutable_us, workload_ip, self.pi.hbone_port) {
            Ok(_) => mutable_us,
            Err(e) => {
                debug!(%mutable_us.workload.workload_name, "failed to set gateway address for upstream: {}", e);
                return Err(Error::UnknownWaypoint(mutable_us.workload.workload_name));
            }
        };

        if us.workload.gateway_address.is_none() {
            return Err(Error::NoGatewayAddress(Box::new(us.workload)));
        }
        // For case source client and upstream server are on the same node.
        // This is disabled in inpod mode, as each pod processes connections in its own netns.
        // so if we use direct local here, the destination pod will see the connection as inbound
        // plain text and may wrongly reject it depending on policy.
        if !self.pi.cfg.inpod_enabled
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
                destination: SocketAddr::from((workload_ip, us.port)),
                destination_workload: Some(us.workload.clone()),
                destination_service: us.destination_service.clone(),
                expected_identity: Some(us.workload.identity()),
                gateway: SocketAddr::from((
                    us.workload
                        .gateway_address
                        .expect("gateway address confirmed")
                        .ip(),
                    self.pi.hbone_port,
                )),
                direction: Direction::Outbound,
                // Sending to a node on the same node (ourselves).
                // In the future this could be optimized to avoid a full network traversal.
                request_type: RequestType::DirectLocal,
                upstream_sans: us.sans,
            });
        }
        // For case no waypoint for both side and direct to remote node proxy
        Ok(Request {
            protocol: us.workload.protocol,
            source: source_workload,
            destination: SocketAddr::from((workload_ip, us.port)),
            destination_workload: Some(us.workload.clone()),
            destination_service: us.destination_service.clone(),
            expected_identity: Some(us.workload.identity()),
            gateway: us
                .workload
                .gateway_address
                .expect("gateway address confirmed"),
            direction: Direction::Outbound,
            request_type: RequestType::Direct,
            upstream_sans: us.sans,
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
    destination_service: Option<ServiceDescription>,
    // The identity we will assert for the next hop; this may not be the same as destination_workload
    // in the case of proxies along the path.
    expected_identity: Option<Identity>,
    gateway: SocketAddr,
    request_type: RequestType,

    upstream_sans: Vec<String>,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::config::Config;
    use crate::proxy::connection_manager::ConnectionManager;
    use crate::test_helpers::helpers::test_proxy_metrics;
    use crate::test_helpers::new_proxy_state;
    use crate::xds::istio::workload::address::Type as XdsAddressType;
    use crate::xds::istio::workload::NetworkAddress as XdsNetworkAddress;
    use crate::xds::istio::workload::Port;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::TunnelProtocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::{identity, xds};

    async fn run_build_request(
        from: &str,
        to: &str,
        xds: XdsAddressType,
        expect: Option<ExpectedRequest<'_>>,
    ) {
        let cfg = Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        };
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 1])],
            node: "local-node".to_string(),
            ..Default::default()
        };
        let waypoint = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/waypoint-workload".to_string(),
            name: "waypoint-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 10])],
            node: "local-node".to_string(),
            ..Default::default()
        };
        let state = match xds {
            XdsAddressType::Workload(wl) => new_proxy_state(&[source, waypoint, wl], &[], &[]),
            XdsAddressType::Service(svc) => new_proxy_state(&[source, waypoint], &[svc], &[]),
        };
        let outbound = OutboundConnection {
            pi: ProxyInputs {
                cert_manager: identity::mock::new_secret_manager(Duration::from_secs(10)),
                state,
                hbone_port: 15008,
                cfg,
                metrics: test_proxy_metrics(),
                pool: pool::Pool::new(),
                socket_factory: std::sync::Arc::new(crate::proxy::DefaultSocketFactory),
                proxy_workload_info: None,
                connection_manager: ConnectionManager::default(),
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
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                ..Default::default()
            }),
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
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
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
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
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
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
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
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
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
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                ..Default::default()
            }),
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_source_waypoint() {
        run_build_request(
            "127.0.0.2",
            "127.0.0.1:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                    hbone_single_tls_port: 15003,
                }),
                ..Default::default()
            }),
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
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                    hbone_single_tls_port: 15003,
                }),
                ..Default::default()
            }),
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

    #[tokio::test]
    async fn build_request_destination_svc_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.3:80",
            XdsAddressType::Service(XdsService {
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                }],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                    hbone_single_tls_port: 15003,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                destination: "127.0.0.3:80",
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
