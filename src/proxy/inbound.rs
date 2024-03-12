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
use crate::proxy::inbound::InboundConnect::{DirectPath, Hbone};
use crate::proxy::metrics::{ConnectionOpen, Metrics, Reporter};
use crate::proxy::{metrics, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};
use crate::rbac::Connection;
use crate::socket::to_canonical;
use crate::{proxy, tls};

use crate::state::workload::{address, GatewayAddress, NetworkAddress, Workload};
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
            let src_ip = to_canonical(raw_socket.peer_addr().unwrap()).ip();
            let pi = self.pi.clone();
            let connection_manager = self.pi.connection_manager.clone();
            let drain = sub_drain.clone();
            let network = self.pi.cfg.network.clone();
            tokio::task::spawn(async move {
                let conn = Connection {
                    src_identity,
                    src_ip,
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
        peer_ip=%conn.src_ip,
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
                let addr: Result<SocketAddr, _> = uri.to_string().as_str().parse();
                if addr.is_err() {
                    info!("Sending 400, {:?}", addr.err());
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Empty::new())
                        .unwrap());
                }

                let addr: SocketAddr = addr.unwrap();
                if addr.ip() != conn.dst.ip() {
                    info!("Sending 400, ip mismatch {addr} != {}", conn.dst);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Empty::new())
                        .unwrap());
                }
                // Orig has 15008, swap with the real port
                let conn = Connection { dst: addr, ..conn };
                let dst_network_addr = NetworkAddress {
                    network: conn.dst_network.to_string(), // dst must be on our network
                    address: addr.ip(),
                };
                let Some((upstream, upstream_service)) =
                    pi.state.fetch_workload_services(&dst_network_addr).await
                else {
                    info!(%conn, "unknown destination");
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Empty::new())
                        .unwrap());
                };
                let has_waypoint = upstream.waypoint.is_some();
                let from_waypoint = Self::check_waypoint(pi.state.clone(), &upstream, &conn).await;
                let from_gateway = Self::check_gateway(pi.state.clone(), &upstream, &conn).await;

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
                    super::get_original_src_from_fwded(&req).unwrap_or(rbac_ctx.conn.src_ip)
                } else {
                    rbac_ctx.conn.src_ip
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
                let status_code = match Self::handle_inbound(
                    Hbone(req),
                    enable_original_source.then_some(source_ip),
                    addr,
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

    async fn check_waypoint(
        state: DemandProxyState,
        upstream: &Workload,
        conn: &Connection,
    ) -> bool {
        Self::check_gateway_address(state, conn, upstream.waypoint.as_ref()).await
    }

    async fn check_gateway(
        state: DemandProxyState,
        upstream: &Workload,
        conn: &Connection,
    ) -> bool {
        Self::check_gateway_address(state, conn, upstream.network_gateway.as_ref()).await
    }

    async fn check_gateway_address(
        state: DemandProxyState,
        conn: &Connection,
        gateway_address: Option<&GatewayAddress>,
    ) -> bool {
        if let Some(gateway_address) = gateway_address {
            let from_gateway = match state.fetch_destination(&gateway_address.destination).await {
                Some(address::Address::Workload(wl)) => Some(wl.identity()) == conn.src_identity,
                Some(address::Address::Service(svc)) => {
                    for (_ep_uid, ep) in svc.endpoints.iter() {
                        // fetch workloads by workload UID since we may not have an IP for an endpoint (e.g., endpoint is just a hostname)
                        if state
                            .fetch_workload_by_uid(&ep.workload_uid)
                            .await
                            .map(|w| w.identity())
                            == conn.src_identity
                        {
                            return true;
                        }
                    }
                    false
                }
                None => false,
            };
            return from_gateway;
        }
        false // this occurs if gateway_address was None
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
mod test {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    use super::*;
    use crate::state::service::endpoint_uid;
    use crate::state::workload::NamespacedHostname;
    use crate::{
        identity::Identity,
        state::{
            self,
            service::{Endpoint, Service},
            workload::gatewayaddress::Destination,
        },
    };
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, SocketAddrV4},
        sync::RwLock,
    };

    #[tokio::test]
    async fn check_gateway() {
        let w = mock_default_gateway_workload();
        let s = mock_default_gateway_service();
        let mut state = state::ProxyState::default();
        if let Err(err) = state.workloads.insert(w) {
            panic!("received error inserting workload: {}", err);
        }
        state.services.insert(s);
        let state = state::DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let gateawy_id = Identity::Spiffe {
            trust_domain: "cluster.local".to_string(),
            namespace: "gatewayns".to_string(),
            service_account: "default".to_string(),
        };
        let from_gw_conn = Connection {
            src_identity: Some(gateawy_id),
            src_ip: IpAddr::V4(mock_default_gateway_ipaddr()),
            dst_network: "default".to_string(),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 10), 80)),
        };
        let not_from_gw_conn = Connection {
            src_identity: Some(Identity::default()),
            src_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst_network: "default".to_string(),
            dst: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 10), 80)),
        };

        let upstream_with_address = mock_wokload_with_gateway(Some(mock_default_gateway_address()));
        assert!(Inbound::check_gateway(state.clone(), &upstream_with_address, &from_gw_conn).await);
        assert!(
            !Inbound::check_gateway(state.clone(), &upstream_with_address, &not_from_gw_conn).await
        );

        // using hostname (will check the service variant of address::Address)
        let upstream_with_hostname =
            mock_wokload_with_gateway(Some(mock_default_gateway_hostname()));
        assert!(
            Inbound::check_gateway(state.clone(), &upstream_with_hostname, &from_gw_conn).await
        );
        assert!(!Inbound::check_gateway(state, &upstream_with_hostname, &not_from_gw_conn).await);
    }

    // private helpers
    fn mock_wokload_with_gateway(gw: Option<GatewayAddress>) -> Workload {
        Workload {
            workload_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            waypoint: None,
            network_gateway: gw,
            gateway_address: None,
            protocol: Default::default(),
            uid: "".to_string(),
            name: "app".to_string(),
            namespace: "appns".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            network: "".to_string(),
            workload_name: "app".to_string(),
            workload_type: "deployment".to_string(),
            canonical_name: "app".to_string(),
            canonical_revision: "".to_string(),
            hostname: "".to_string(),
            node: "".to_string(),
            status: Default::default(),
            cluster_id: "Kubernetes".to_string(),

            authorization_policies: Vec::new(),
            native_tunnel: false,
        }
    }

    fn mock_default_gateway_workload() -> Workload {
        Workload {
            workload_ips: vec![IpAddr::V4(mock_default_gateway_ipaddr())],
            waypoint: None,
            network_gateway: None,
            gateway_address: None,
            protocol: Default::default(),
            uid: "".to_string(),
            name: "gateway".to_string(),
            namespace: "gatewayns".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            network: "".to_string(),
            workload_name: "gateway".to_string(),
            workload_type: "deployment".to_string(),
            canonical_name: "".to_string(),
            canonical_revision: "".to_string(),
            hostname: "".to_string(),
            node: "".to_string(),
            status: Default::default(),
            cluster_id: "Kubernetes".to_string(),

            authorization_policies: Vec::new(),
            native_tunnel: false,
        }
    }

    fn mock_default_gateway_service() -> Service {
        let vip1 = NetworkAddress {
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 10, 1)),
            network: "".to_string(),
        };
        let vips = vec![vip1];
        let mut ports = HashMap::new();
        ports.insert(8080, 80);
        let mut endpoints = HashMap::new();
        let addr = Some(NetworkAddress {
            network: "".to_string(),
            address: IpAddr::V4(mock_default_gateway_ipaddr()),
        });
        endpoints.insert(
            endpoint_uid(&mock_default_gateway_workload().uid, addr.as_ref()),
            Endpoint {
                workload_uid: mock_default_gateway_workload().uid,
                service: NamespacedHostname {
                    namespace: "gatewayns".to_string(),
                    hostname: "gateway".to_string(),
                },
                address: addr,
                port: ports.clone(),
            },
        );
        Service {
            name: "gateway".to_string(),
            namespace: "gatewayns".to_string(),
            hostname: "gateway".to_string(),
            vips,
            ports,
            endpoints,
            subject_alt_names: vec![],
            waypoint: None,
        }
    }

    fn mock_default_gateway_address() -> GatewayAddress {
        GatewayAddress {
            destination: Destination::Address(NetworkAddress {
                network: "".to_string(),
                address: IpAddr::V4(mock_default_gateway_ipaddr()),
            }),
            hbone_mtls_port: 15008,
            hbone_single_tls_port: Some(15003),
        }
    }

    fn mock_default_gateway_hostname() -> GatewayAddress {
        GatewayAddress {
            destination: Destination::Hostname(state::workload::NamespacedHostname {
                namespace: "gatewayns".to_string(),
                hostname: "gateway".to_string(),
            }),
            hbone_mtls_port: 15008,
            hbone_single_tls_port: Some(15003),
        }
    }

    fn mock_default_gateway_ipaddr() -> Ipv4Addr {
        Ipv4Addr::new(127, 0, 0, 100)
    }
}
