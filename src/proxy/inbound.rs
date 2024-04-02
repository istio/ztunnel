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

use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use drain::Watch;
use futures::stream::StreamExt;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};

use tokio::net::{TcpListener, TcpStream};

use tracing::{debug, error, info, instrument, trace, trace_span, warn, Instrument};

use super::connection_manager::ConnectionManager;
use super::{Error, SocketFactory};
use crate::baggage::parse_baggage_header;
use crate::identity::{Identity, SecretManager};
use crate::metrics::Recorder;
use crate::proxy::inbound::InboundConnect::{DirectPath, Hbone, Proxy};
use crate::proxy::metrics::{ConnectionOpen, Metrics, Reporter};
use crate::proxy::{metrics, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};
use crate::rbac::Connection;
use crate::socket::to_canonical;
use crate::state::service::Service;
use crate::state::workload::address::Address;
use crate::state::workload::application_tunnel::Protocol as AppProtocol;
use crate::{proxy, tls};

use crate::state::workload::{self, NetworkAddress, Workload};
use crate::state::DemandProxyState;
use crate::tls::TlsError;

pub(super) struct Inbound {
    listener: TcpListener,
    drain: Watch,
    pi: ProxyInputs,
}

impl Inbound {
    pub(super) async fn new(mut pi: ProxyInputs, drain: Watch) -> Result<Inbound, Error> {
        let listener: TcpListener = pi
            .socket_factory
            .tcp_bind(pi.cfg.inbound_addr)
            .map_err(|e| Error::Bind(pi.cfg.inbound_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, &listener)?;
        // Override with our explicitly configured setting
        pi.cfg.enable_original_source = Some(transparent);
        info!(
            address=%listener.local_addr().unwrap(),
            component="inbound",
            transparent,
            "listener established",
        );
        Ok(Inbound {
            listener,
            drain,
            pi,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub(super) async fn run(self) {
        // let (tx, rx) = oneshot::channel();
        let acceptor = InboundCertProvider {
            state: self.pi.state.clone(),
            cert_manager: self.pi.cert_manager.clone(),
            network: self.pi.cfg.network.clone(),
        };
        let stream = crate::hyper_util::tls_server(acceptor, self.listener);
        let mut stream = stream.take_until(Box::pin(self.drain.signaled()));

        let (sub_drain_signal, sub_drain) = drain::channel();

        while let Some(tls) = stream.next().await {
            let (raw_socket, ssl) = tls.get_ref();
            let src_identity: Option<Identity> = tls::identity_from_connection(ssl);
            let dst = crate::socket::orig_dst_addr_or_default(raw_socket);
            let src = to_canonical(raw_socket.peer_addr().unwrap());
            let pi = self.pi.clone();
            let connection_manager = self.pi.connection_manager.clone();
            let drain = sub_drain.clone();
            let network = self.pi.cfg.network.clone();
            tokio::task::spawn(async move {
                let conn = Connection {
                    src_identity,
                    src,
                    dst_network: network, // inbound request must be on our network
                    dst,
                };
                debug!(%conn, "accepted connection");
                let enable_original_source = self.pi.cfg.enable_original_source;
                let serve = crate::hyper_util::http2_server()
                    .initial_stream_window_size(self.pi.cfg.window_size)
                    .initial_connection_window_size(self.pi.cfg.connection_window_size)
                    .max_frame_size(self.pi.cfg.frame_size)
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(tls),
                        service_fn(move |req| {
                            Self::serve_connect(
                                pi.clone(),
                                conn.clone(),
                                enable_original_source.unwrap_or_default(),
                                req,
                                connection_manager.clone(),
                            )
                        }),
                    );
                // Wait for drain to signal or connection serving to complete
                match futures_util::future::select(Box::pin(drain.signaled()), serve).await {
                    // We got a shutdown request. Start gracful shutdown and wait for the pending requests to complete.
                    futures_util::future::Either::Left((_shutdown, mut server)) => {
                        let drain = std::pin::Pin::new(&mut server);
                        drain.graceful_shutdown();
                        server.await
                    }
                    // Serving finished, just return the result.
                    futures_util::future::Either::Right((server, _shutdown)) => server,
                }
            });
        }
        info!("draining connections");
        drop(sub_drain); // sub_drain_signal.drain() will never resolve while sub_drain is valid, will deadlock if not dropped
        sub_drain_signal.drain().await;
        info!("all inbound connections drained");
    }

    /// handle_inbound serves an inbound connection with a target address `addr`.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn handle_inbound(
        request_type: InboundConnect,
        orig_src: Option<IpAddr>,
        addr: SocketAddr,
        metrics: Arc<Metrics>,
        connection_metrics: ConnectionOpen,
        extra_connection_metrics: Option<ConnectionOpen>,
        socket_factory: &(dyn SocketFactory + Send + Sync),
        connection_manager: ConnectionManager,
        rbac_ctx: crate::state::ProxyRbacContext,
    ) -> Result<(), std::io::Error> {
        let start = Instant::now();
        let stream = super::freebind_connect(orig_src, addr, socket_factory).await;
        match stream {
            Err(err) => {
                warn!(dur=?start.elapsed(), "connection to {} failed: {}", addr, err);
                Err(err)
            }
            Ok(stream) => {
                let mut stream = stream;
                stream.set_nodelay(true)?;
                trace!(dur=?start.elapsed(), "connected to: {addr}");
                tokio::task::spawn(
                    (async move {
                        let close = match connection_manager.track(&rbac_ctx).await {
                            Some(c) => c,
                            None => {
                                // if track returns None it means the connection was closed due to policy change
                                // between the intial assertion of policy and the spawinging of the task
                                error!(dur=?start.elapsed(), "internal server copy: connection close");
                                return;
                            }
                        };
                        let _connection_close = metrics
                            .increment_defer::<_, metrics::ConnectionClose>(&connection_metrics);

                        let _extra_conn_close = extra_connection_metrics
                            .as_ref()
                            .map(|co| metrics.increment_defer::<_, metrics::ConnectionClose>(co));

                        let transferred_bytes =
                            metrics::BytesTransferred::from(&connection_metrics);
                        match request_type {
                            DirectPath(mut incoming) => {
                                let res = tokio::select! {
                                r = proxy::relay(
                                    &mut incoming,
                                    &mut stream,
                                    &metrics,
                                    transferred_bytes,
                                ) => {r}
                                _c = close.signaled() => {
                                        error!(dur=?start.elapsed(), "internal server copy: connection close received");
                                        Ok((0,0))
                                    }
                                };
                                match res {
                                    Ok(transferred) => {
                                        if let Some(co) = extra_connection_metrics.as_ref() {
                                            metrics.record(
                                                &metrics::BytesTransferred::from(co),
                                                transferred,
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        error!(dur=?start.elapsed(), "internal server copy: {}", e)
                                    }
                                }
                            }
                            Hbone(req) => match hyper::upgrade::on(req).await {
                                Ok(mut upgraded) => {
                                    let res = tokio::select! {
                                        r =  super::copy_hbone(
                                        &mut upgraded,
                                        &mut stream,
                                        &metrics,
                                        transferred_bytes,
                                        ).instrument(trace_span!("hbone server")) => {r}
                                        _c = close.signaled() => {
                                            error!(dur=?start.elapsed(), "internal server copy: connection close received");
                                            Ok(())
                                        }
                                    };
                                    if let Err(e) = res
                                    {
                                        error!(dur=?start.elapsed(), "hbone server copy: {}", e);
                                    }
                                }
                                Err(e) => {
                                    // Not sure if this can even happen
                                    error!(dur=?start.elapsed(), "No upgrade {e}");
                                }
                            },
                            Proxy(req, (src, dst), src_id) => match hyper::upgrade::on(req).await {
                                Ok(mut upgraded) => {
                                     if let Err(e) =
                                        super::write_proxy_protocol(&mut stream, (src, dst), src_id)
                                            .instrument(trace_span!("proxy protocol"))
                                            .await
                                    {
                                        error!(dur=?start.elapsed(), "write proxy protocol: {}", e);
                                    } else if let Err(e) = super::copy_hbone(
                                        &mut upgraded,
                                        &mut stream,
                                        &metrics,
                                        transferred_bytes,
                                    )
                                    .instrument(trace_span!("hbone server"))
                                    .await
                                    {
                                        error!(dur=?start.elapsed(), "hbone server copy: {}", e);
                                    }
                                },
                                Err(e) => {
                                    // Not sure if this can even happen
                                    error!(dur=?start.elapsed(), "No upgrade {e}");
                                }
                            }
                        }
                        connection_manager.release(&rbac_ctx).await;
                    })
                    .in_current_span(),
                );
                // Send back our 200. We do this regardless of if our spawned task copies the data;
                // we need to respond with headers immediately once connection is established for the
                // stream of bytes to begin.
                Ok(())
            }
        }
    }

    fn extract_traceparent(req: &Request<Incoming>) -> TraceParent {
        req.headers()
            .get(TRACEPARENT_HEADER)
            .and_then(|b| b.to_str().ok())
            .and_then(|b| TraceParent::try_from(b).ok())
            .unwrap_or_else(TraceParent::new)
    }

    #[allow(clippy::too_many_arguments)]
    #[instrument(name="inbound", skip_all, fields(
        id=%Self::extract_traceparent(&req),
        peer=%conn.src,
        peer_id=%OptionDisplay(&conn.src_identity)
    ))]
    async fn serve_connect(
        pi: ProxyInputs,
        conn: Connection,
        enable_original_source: bool,
        req: Request<Incoming>,
        connection_manager: ConnectionManager,
    ) -> Result<Response<Empty<Bytes>>, hyper::Error> {
        match req.method() {
            &Method::CONNECT => {
                let uri = req.uri();
                info!("got {} request to {}", req.method(), uri);
                let hbone_addr: SocketAddr = match uri.to_string().as_str().parse() {
                    Ok(parsed) => parsed,
                    Err(e) => {
                        info!("Sending 400, {}", e);
                        return Ok(Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(Empty::new())
                            .unwrap());
                    }
                };

                // Determine the next hop.
                let (upstream_addr, upstream, upstream_service) =
                    match Self::find_inbound_upstream(pi.state.clone(), &conn, hbone_addr).await {
                        Ok(res) => res,
                        Err(e) => {
                            info!(%conn, "Sending 400, {}", e);
                            return Ok(Response::builder()
                                .status(StatusCode::BAD_REQUEST)
                                .body(Empty::new())
                                .unwrap());
                        }
                    };

                // Application tunnel may override the port.
                let (upstream_addr, inbound_protocol) = match upstream.application_tunnel.clone() {
                    Some(workload::ApplicationTunnel {
                        port: Some(port),
                        protocol,
                    }) => (SocketAddr::new(upstream_addr.ip(), port), protocol),
                    Some(workload::ApplicationTunnel {
                        port: None,
                        protocol,
                    }) => (upstream_addr, protocol),
                    None => (upstream_addr, workload::application_tunnel::Protocol::NONE),
                };

                // Connection has 15008, swap with the real port
                let conn = Connection {
                    dst: upstream_addr,
                    ..conn
                };
                let has_waypoint = upstream.waypoint.is_some();
                let from_waypoint = proxy::check_from_waypoint(
                    pi.state.clone(),
                    &upstream,
                    conn.src_identity.as_ref(),
                    &conn.src.ip(),
                )
                .await;
                let from_gateway = proxy::check_from_network_gateway(
                    pi.state.clone(),
                    &upstream,
                    conn.src_identity.as_ref(),
                )
                .await;

                if from_gateway {
                    debug!("request from gateway");
                }

                let rbac_ctx = crate::state::ProxyRbacContext {
                    conn,
                    dest_workload_info: pi.proxy_workload_info.clone(),
                };

                //register before assert_rbac to ensure the connection is tracked during it's entire valid span
                connection_manager.register(&rbac_ctx).await;
                if from_waypoint {
                    debug!("request from waypoint, skipping policy");
                } else if !pi.state.assert_rbac(&rbac_ctx).await {
                    info!(%rbac_ctx.conn, "RBAC rejected");
                    connection_manager.release(&rbac_ctx).await;
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Empty::new())
                        .unwrap());
                }
                if has_waypoint && !from_waypoint {
                    info!(%rbac_ctx.conn, "bypassed waypoint");
                    connection_manager.release(&rbac_ctx).await;
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Empty::new())
                        .unwrap());
                }
                let source_ip = if from_waypoint {
                    // If the request is from our waypoint, trust the Forwarded header.
                    // For other request types, we can only trust the source from the connection.
                    // Since our own waypoint is in the same trust domain though, we can use Forwarded,
                    // which drops the requirement of spoofing IPs from waypoints
                    super::get_original_src_from_fwded(&req).unwrap_or(rbac_ctx.conn.src.ip())
                } else {
                    rbac_ctx.conn.src.ip()
                };

                let baggage =
                    parse_baggage_header(req.headers().get_all(BAGGAGE_HEADER)).unwrap_or_default();

                let source = match from_gateway {
                    true => None, // we cannot lookup source workload since we don't know the network, see https://github.com/istio/ztunnel/issues/515
                    false => {
                        let src_network_addr = NetworkAddress {
                            // we can assume source network is our network because we did not traverse a gateway
                            network: rbac_ctx.conn.dst_network.to_string(),
                            address: source_ip,
                        };
                        // Find source info. We can lookup by XDS or from connection attributes
                        pi.state.fetch_workload(&src_network_addr).await
                    }
                };

                let derived_source = metrics::DerivedWorkload {
                    identity: rbac_ctx.conn.src_identity.clone(),
                    cluster_id: baggage.cluster_id,
                    namespace: baggage.namespace,
                    workload_name: baggage.workload_name,
                    revision: baggage.revision,
                    ..Default::default()
                };
                let ds = proxy::guess_inbound_service(&rbac_ctx.conn, upstream_service, &upstream);
                let connection_metrics = ConnectionOpen {
                    reporter: Reporter::destination,
                    source,
                    derived_source: Some(derived_source),
                    destination: Some(upstream),
                    connection_security_policy: metrics::SecurityPolicy::mutual_tls,
                    destination_service: ds,
                };

                let request_type = match inbound_protocol {
                    AppProtocol::PROXY => Proxy(
                        req,
                        (rbac_ctx.conn.src, rbac_ctx.conn.dst),
                        rbac_ctx.conn.src_identity.clone(),
                    ),
                    _ => Hbone(req),
                };

                let status_code = match Self::handle_inbound(
                    request_type,
                    enable_original_source.then_some(source_ip),
                    upstream_addr,
                    pi.metrics,
                    connection_metrics,
                    None,
                    pi.socket_factory.as_ref(),
                    connection_manager,
                    rbac_ctx,
                )
                .in_current_span()
                .await
                {
                    Ok(_) => StatusCode::OK,
                    Err(_) => StatusCode::SERVICE_UNAVAILABLE,
                };

                Ok(Response::builder()
                    .status(status_code)
                    .body(Empty::new())
                    .unwrap())
            }
            // Return the 404 Not Found for other routes.
            method => {
                info!("Sending 404, got {method}");
                Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Empty::new())
                    .unwrap())
            }
        }
    }

    async fn find_inbound_upstream(
        state: DemandProxyState,
        conn: &Connection,
        hbone_addr: SocketAddr,
    ) -> Result<(SocketAddr, Workload, Vec<Service>), Error> {
        let dst = &NetworkAddress {
            network: conn.dst_network.to_string(),
            address: hbone_addr.ip(),
        };

        // If the IPs match, this is not sandwich.
        if conn.dst.ip() == hbone_addr.ip() {
            let Some((us_wl, us_svc)) = state.fetch_workload_services(dst).await else {
                return Err(Error::UnknownDestination(hbone_addr.ip()));
            };
            return Ok((hbone_addr, us_wl, us_svc));
        }

        if let Some((us_wl, us_svc)) = Self::find_sandwich_upstream(state, conn, hbone_addr).await {
            let next_hop = SocketAddr::new(conn.dst.ip(), hbone_addr.port());
            return Ok((next_hop, us_wl, us_svc));
        }

        Err(Error::IPMismatch(conn.dst.ip(), hbone_addr.ip()))
    }

    async fn find_sandwich_upstream(
        state: DemandProxyState,
        conn: &Connection,
        hbone_addr: SocketAddr,
    ) -> Option<(Workload, Vec<Service>)> {
        let connection_dst = &NetworkAddress {
            network: conn.dst_network.to_string(),
            address: conn.dst.ip(),
        };
        let hbone_dst = &NetworkAddress {
            network: conn.dst_network.to_string(),
            address: hbone_addr.ip(),
        };

        // Outer option tells us whether or not we can retry
        // Some(None) means we have enough information to decide this isn't sandwich
        let lookup = || -> Option<Option<(Workload, Vec<Service>)>> {
            let state = state.read();

            // TODO Allow HBONE address to be a hostname. We have to respect rules about
            // hostname scoping. Can we use the client's namespace here to do that?
            let hbone_target = state.find_address(hbone_dst);

            // We can only sandwich a Workload waypoint
            let conn_wl = state.workloads.find_address(connection_dst);

            // on-demand fetch then retry
            let (Some(hbone_target), Some(conn_wl)) = (hbone_target, conn_wl) else {
                return None;
            };

            let Some(target_waypoint) = (match hbone_target {
                Address::Service(svc) => svc.waypoint.clone(),
                Address::Workload(wl) => wl.waypoint,
            }) else {
                // can't sandwich if the HBONE target doesn't want a Waypoint.
                return Some(None);
            };

            // Resolve the reference from our HBONE target
            let target_waypoint = state.find_destination(&target_waypoint.destination);

            let Some(target_waypoint) = target_waypoint else {
                // don't need to fetch/retry this; we found conn_wl and this must match conn_wl.
                return Some(None);
            };

            // Validate that the HBONE target references the Waypoint we're connecting to
            Some(match target_waypoint {
                Address::Service(svc) => {
                    if !svc.contains_endpoint(&conn_wl, Some(connection_dst)) {
                        // target points to a different waypoint
                        return Some(None);
                    }
                    Some((conn_wl, vec![*svc]))
                }
                Address::Workload(wl) => {
                    if !wl.workload_ips.contains(&conn.dst.ip()) {
                        // target points to a different waypoint
                        return Some(None);
                    }
                    let svc = state.services.get_by_workload(&wl);
                    Some((*wl, svc))
                }
            })
        };

        if let Some(res) = lookup() {
            return res;
        }

        tokio::join![
            state.fetch_on_demand(connection_dst.to_string()),
            state.fetch_on_demand(hbone_dst.to_string()),
        ];
        lookup().flatten()
    }
}

struct OptionDisplay<'a, T>(&'a Option<T>);

impl<'a, T: Display> Display for OptionDisplay<'a, T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            None => write!(f, "None"),
            Some(i) => write!(f, "{i}"),
        }
    }
}

pub(super) enum InboundConnect {
    /// DirectPath is an optimization when we are connecting to an endpoint on the same node.
    /// Rather than doing a full HBONE connection over the localhost network, we just pass the outbound
    /// context directly to the inbound handling in memory.
    DirectPath(TcpStream),
    /// Hbone is a standard HBONE request coming from the network.
    Hbone(Request<Incoming>),
    // PROXY adds source and dest headers and source identity before forwarding bytes.
    Proxy(
        Request<Incoming>,
        (SocketAddr, SocketAddr),
        Option<Identity>,
    ),
}

#[derive(Clone)]
struct InboundCertProvider {
    cert_manager: Arc<SecretManager>,
    state: DemandProxyState,
    network: String,
}

#[async_trait::async_trait]
impl crate::tls::ServerCertProvider for InboundCertProvider {
    async fn fetch_cert(&mut self, fd: &TcpStream) -> Result<Arc<rustls::ServerConfig>, TlsError> {
        let orig_dst_addr = crate::socket::orig_dst_addr_or_default(fd);
        let identity = {
            let wip = NetworkAddress {
                network: self.network.clone(), // inbound cert provider gets cert for the dest, which must be on our network
                address: orig_dst_addr.ip(),
            };
            self.state
                .fetch_workload(&wip)
                .await
                .ok_or(TlsError::CertificateLookup(wip))?
                .identity()
        };
        debug!(
            destination=?orig_dst_addr,
            %identity,
            "fetching cert"
        );
        let cert = self.cert_manager.fetch_certificate(&identity).await?;
        Ok(Arc::new(cert.server_config()?))
    }
}

#[cfg(test)]
mod tests {
    use super::Inbound;

    use std::{
        net::SocketAddr,
        sync::{Arc, RwLock},
    };

    use crate::{
        rbac::Connection,
        state::{
            self,
            service::{endpoint_uid, Endpoint, Service},
            workload::{
                gatewayaddress::Destination, GatewayAddress, NamespacedHostname, NetworkAddress,
                Protocol, Workload,
            },
            DemandProxyState,
        },
        test_helpers,
    };

    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use test_case::test_case;

    const CLIENT_POD_IP: &str = "10.0.0.1";

    const SERVER_POD_IP: &str = "10.0.0.2";
    const SERVER_SVC_IP: &str = "10.10.0.1";

    const WAYPOINT_POD_IP: &str = "10.0.0.3";
    const WAYPOINT_SVC_IP: &str = "10.10.0.2";

    const HBONE_TARGET_PORT: u16 = 8080;

    // Regular zTunnel workload traffic inbound
    #[test_case(Waypoint::None, SERVER_POD_IP, SERVER_POD_IP , Some((SERVER_POD_IP, HBONE_TARGET_PORT)); "to workload no waypoint")]
    // Waypoint is referenced directly by Pod IP
    #[test_case(Waypoint::Workload(WAYPOINT_POD_IP), WAYPOINT_POD_IP, SERVER_POD_IP , Some((WAYPOINT_POD_IP, HBONE_TARGET_PORT)); "to workload with waypoint pod")]
    #[test_case(Waypoint::Workload(WAYPOINT_SVC_IP), WAYPOINT_POD_IP, SERVER_POD_IP , Some((WAYPOINT_POD_IP, HBONE_TARGET_PORT)); "to workload with waypoint svc")]
    // Waypoint is referenced through it's service VIP
    #[test_case(Waypoint::Service(WAYPOINT_POD_IP), WAYPOINT_POD_IP, SERVER_SVC_IP , Some((WAYPOINT_POD_IP, HBONE_TARGET_PORT)); "to service with waypoint pod")]
    #[test_case(Waypoint::Service(WAYPOINT_SVC_IP), WAYPOINT_POD_IP, SERVER_SVC_IP , Some((WAYPOINT_POD_IP, HBONE_TARGET_PORT)); "to service with waypoint svc")]
    // Error cases
    #[test_case(Waypoint::None, SERVER_POD_IP, CLIENT_POD_IP, None; "to server ip mismatch" )]
    #[tokio::test]
    async fn test_find_inbound_upstream<'a>(
        target_waypoint: Waypoint<'a>,
        connection_dst: &str,
        hbone_dst: &str,
        want: Option<(&str, u16)>,
    ) {
        let state = test_state(target_waypoint).expect("state setup");
        let conn = Connection {
            src_identity: None,
            src: format!("{CLIENT_POD_IP:1234}").parse().unwrap(),
            dst_network: "".to_string(),
            dst: format!("{connection_dst}:15008").parse().unwrap(),
        };
        let res = Inbound::find_inbound_upstream(
            state,
            &conn,
            format!("{hbone_dst}:{HBONE_TARGET_PORT}").parse().unwrap(),
        )
        .await;

        match want {
            Some((ip, port)) => {
                let got_addr = res.expect("found upstream").0;
                assert_eq!(got_addr, SocketAddr::new(ip.parse().unwrap(), port))
            }
            None => {
                res.expect_err("did not find upstream");
            }
        }
    }

    fn test_state(server_waypoint: Waypoint) -> anyhow::Result<state::DemandProxyState> {
        let mut state = state::ProxyState::default();

        let services = vec![
            ("waypoint", WAYPOINT_SVC_IP, WAYPOINT_POD_IP, Waypoint::None),
            ("server", SERVER_SVC_IP, SERVER_POD_IP, server_waypoint),
        ]
        .into_iter()
        .map(|(name, vip, ep_ip, waypoint)| {
            let ep_uid = format!("cluster1//v1/Pod/default/{name}");
            let ep_addr = Some(NetworkAddress {
                address: ep_ip.parse().unwrap(),
                network: "".to_string(),
            });
            Service {
                name: name.to_string(),
                namespace: "default".to_string(),
                hostname: format!("{name}.default.svc.cluster.local"),
                vips: vec![NetworkAddress {
                    address: vip.parse().unwrap(),
                    network: "".to_string(),
                }],
                ports: std::collections::HashMap::new(),
                endpoints: vec![(
                    endpoint_uid(&ep_uid, ep_addr.as_ref()),
                    Endpoint {
                        workload_uid: ep_uid,
                        service: NamespacedHostname {
                            hostname: format!("{name}.default.svc.cluster.local"),
                            namespace: "default".to_string(),
                        },
                        address: ep_addr,
                        port: std::collections::HashMap::new(),
                    },
                )]
                .into_iter()
                .collect(),
                subject_alt_names: vec![format!("{name}.default.svc.cluster.local")],
                waypoint: waypoint.service_attached(),
            }
        });

        let workloads = vec![
            ("waypoint", WAYPOINT_POD_IP, Waypoint::None),
            ("client", CLIENT_POD_IP, Waypoint::None),
            ("server", SERVER_POD_IP, server_waypoint),
        ]
        .into_iter()
        .map(|(name, ip, waypoint): (&str, &str, Waypoint)| Workload {
            workload_ips: vec![ip.parse().unwrap()],
            waypoint: waypoint.workload_attached(),
            protocol: Protocol::HBONE,
            uid: format!("cluster1//v1/Pod/default/{name}"),
            name: format!("workload-{name}"),
            namespace: "default".to_string(),
            service_account: format!("service-account-{name}"),
            ..test_helpers::test_default_workload()
        });

        for svc in services {
            state.services.insert(svc);
        }
        for wl in workloads {
            state.workloads.insert(wl)?;
        }

        Ok(DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        ))
    }

    // tells the test if we're using workload-attached or svc-attached waypoints
    #[derive(Copy, Clone)]
    enum Waypoint<'a> {
        None,
        Service(&'a str),
        Workload(&'a str),
    }

    impl<'a> Waypoint<'a> {
        fn service_attached(&self) -> Option<GatewayAddress> {
            let Waypoint::Service(s) = self else {
                return None;
            };
            Some(GatewayAddress {
                destination: Destination::Address(NetworkAddress {
                    network: "".to_string(),
                    address: s.parse().expect("a valid waypoint IP"),
                }),
                hbone_mtls_port: 15008,
                hbone_single_tls_port: None,
            })
        }

        fn workload_attached(&self) -> Option<GatewayAddress> {
            let Waypoint::Workload(s) = self else {
                return None;
            };
            Some(GatewayAddress {
                destination: Destination::Address(NetworkAddress {
                    network: "".to_string(),
                    address: s.parse().expect("a valid waypoint IP"),
                }),
                hbone_mtls_port: 15008,
                hbone_single_tls_port: None,
            })
        }
    }
}
