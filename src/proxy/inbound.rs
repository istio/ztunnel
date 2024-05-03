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
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use drain::Watch;
use futures::stream::StreamExt;
use futures_util::{FutureExt, TryFutureExt};
use http_body_util::Empty;

use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{header, Method, Request, Response, StatusCode};

use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use tracing::{debug, error, info, instrument, trace_span, Instrument};

use super::connection_manager::ConnectionManager;
use super::Error;
use crate::baggage::parse_baggage_header;
use crate::identity::{Identity, SecretManager};

use crate::proxy::inbound::InboundConnect::{Hbone, Proxy};
use crate::proxy::metrics::{ConnectionOpen, Reporter};
use crate::proxy::{metrics, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};
use crate::rbac::Connection;
use crate::socket::to_canonical;
use crate::state::service::Service;
use crate::state::workload::address::Address;
use crate::state::workload::application_tunnel::Protocol as AppProtocol;
use crate::{assertions, proxy, socket, strng, tls};

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
        if pi.cfg.enable_original_source.is_none() {
            let mut cfg = (*pi.cfg).clone();
            cfg.enable_original_source = Some(transparent);
            pi.cfg = Arc::new(cfg);
        }
        info!(
            address=%listener.local_addr().expect("local_addr available"),
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
        self.listener.local_addr().expect("local_addr available")
    }

    pub(super) async fn run(self, illegal_ports: Arc<HashSet<u16>>) {
        let acceptor = InboundCertProvider {
            state: self.pi.state.clone(),
            cert_manager: self.pi.cert_manager.clone(),
            network: self.pi.cfg.network.clone(),
        };
        let stream = crate::hyper_util::tls_server(acceptor, self.listener);
        let mut stream = stream.take_until(Box::pin(self.drain.signaled()));

        let (sub_drain_signal, sub_drain) = drain::channel();

        let pi = Arc::new(self.pi);
        while let Some(tls) = stream.next().await {
            let pi = pi.clone();
            let (raw_socket, ssl) = tls.get_ref();
            let src_identity: Option<Identity> = tls::identity_from_connection(ssl);
            let dst = crate::socket::orig_dst_addr_or_default(raw_socket);
            let src = to_canonical(raw_socket.peer_addr().expect("peer_addr available"));
            let connection_manager = pi.connection_manager.clone();
            let drain = sub_drain.clone();
            let network = pi.cfg.network.clone();
            let illegal_ports = illegal_ports.clone();
            let drain_deadline = pi.cfg.self_termination_deadline;
            let serve_client = async move {
                let conn = Connection {
                    src_identity,
                    src,
                    dst_network: network, // inbound request must be on our network
                    dst,
                };
                debug!(%conn, "accepted connection");
                let enable_original_source = pi.cfg.enable_original_source;
                let serve = Box::pin(
                    crate::hyper_util::http2_server()
                        .initial_stream_window_size(pi.cfg.window_size)
                        .initial_connection_window_size(pi.cfg.connection_window_size)
                        // well behaved clients should close connections.
                        // not all clients are well-behaved. This will prune
                        // connections when the client is not responding, to keep
                        // us from holding many stale conns from deceased clients
                        .keep_alive_interval(Some(Duration::from_secs(10)))
                        .max_frame_size(pi.cfg.frame_size)
                        // 64KB max; default is 16MB driven from Golang's defaults
                        // Since we know we are going to recieve a bounded set of headers, more is overkill.
                        .max_header_list_size(65536)
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(tls),
                            service_fn(move |req| {
                                Self::serve_connect(
                                    pi.clone(),
                                    conn.clone(),
                                    enable_original_source.unwrap_or_default(),
                                    req,
                                    illegal_ports.clone(),
                                    connection_manager.clone(),
                                )
                                .map(|status| {
                                    let resp: Response<Empty<Bytes>> = Response::builder()
                                        .status(status)
                                        .body(Empty::new())
                                        .expect("builder with known status code should not fail");
                                    Ok::<_, hyper::Error>(resp)
                                })
                            }),
                        ),
                );
                // Wait for drain to signal or connection serving to complete
                match futures_util::future::select(Box::pin(drain.signaled()), serve).await {
                    // We got a shutdown request. Start gracful shutdown and wait for the pending requests to complete.
                    futures_util::future::Either::Left((_shutdown, mut server)) => {
                        debug!("inbound serve got drain {:?}", server);
                        let drain = std::pin::Pin::as_mut(&mut server);
                        drain.graceful_shutdown();
                        // There are scenarios where the http2 server never resolves after
                        // `graceful_shutdown`, which will hang the whole task.
                        //
                        // This seems to be a hyper bug, but either way, it's safer to have a deadline.
                        let timeout_res = timeout(drain_deadline, server).await;
                        let res = match timeout_res {
                            Ok(res) => res,
                            Err(e) => {
                                error!("inbound serve drain err: {e}");
                                Ok(())
                            }
                        };
                        debug!("inbound serve drain done");
                        res
                    }
                    // Serving finished, just return the result.
                    futures_util::future::Either::Right((server, _shutdown)) => {
                        debug!("inbound serve done {:?}", server);
                        server
                    }
                }
            };
            assertions::size_between_ref(1500, 2500, &serve_client);
            tokio::task::spawn(serve_client);
        }
        info!("draining connections");
        drop(sub_drain); // sub_drain_signal.drain() will never resolve while sub_drain is valid, will deadlock if not dropped
        sub_drain_signal.drain().await;
        info!("all inbound connections drained");
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
        pi: Arc<ProxyInputs>,
        conn: Connection,
        enable_original_source: bool,
        req: Request<Incoming>,
        illegal_ports: Arc<HashSet<u16>>,
        connection_manager: ConnectionManager,
    ) -> StatusCode {
        if req.method() != Method::CONNECT {
            metrics::log_early_deny(
                conn.src,
                conn.dst,
                Reporter::destination,
                Error::NonConnectMethod(req.method().to_string()),
            );
            return StatusCode::NOT_FOUND;
        }
        let start = Instant::now();
        let Ok(hbone_addr) = req.uri().to_string().as_str().parse::<SocketAddr>() else {
            metrics::log_early_deny(
                conn.src,
                conn.dst,
                Reporter::destination,
                Error::ConnectAddress(req.uri().to_string()),
            );
            return StatusCode::BAD_REQUEST;
        };

        // Determine the next hop.
        let (upstream_addr, inbound_protocol, upstream, upstream_service) =
            match Self::find_inbound_upstream(&pi.state, &conn, hbone_addr).await {
                Ok(res) => res,
                Err(e) => {
                    metrics::log_early_deny(conn.src, conn.dst, Reporter::destination, e);
                    return StatusCode::BAD_REQUEST;
                }
            };
        let illegal_call = if pi.cfg.inpod_enabled {
            // User sent a request to pod:15006. This would forward to pod:15006 infinitely
            // Use hbone_addr instead of upstream_addr to allow for sandwich mode, which intentionally
            // sends to 15008.
            illegal_ports.contains(&hbone_addr.port())
        } else {
            false // TODO: do we need any check here?
        };
        if illegal_call {
            metrics::log_early_deny(
                conn.src,
                upstream_addr,
                Reporter::destination,
                Error::SelfCall,
            );
            return StatusCode::BAD_REQUEST;
        }
        // Connection has 15008, swap with the real port
        let conn = Connection {
            dst: upstream_addr,
            ..conn
        };
        let from_gateway =
            proxy::check_from_network_gateway(&pi.state, &upstream, conn.src_identity.as_ref())
                .await;

        if from_gateway {
            debug!("request from gateway");
        }

        let rbac_ctx = crate::state::ProxyRbacContext {
            conn,
            dest_workload_info: pi.proxy_workload_info.clone(),
        };

        let source_ip = rbac_ctx.conn.src.ip();

        let for_host = parse_forwarded_host(&req);
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
        let ds =
            proxy::guess_inbound_service(&rbac_ctx.conn, &for_host, upstream_service, &upstream);
        let result_tracker = Arc::new(metrics::ConnectionResult::new(
            rbac_ctx.conn.src,
            rbac_ctx.conn.dst,
            Some(hbone_addr),
            start,
            ConnectionOpen {
                reporter: Reporter::destination,
                source,
                derived_source: Some(derived_source),
                destination: Some(upstream),
                connection_security_policy: metrics::SecurityPolicy::mutual_tls,
                destination_service: ds,
            },
            pi.metrics.clone(),
        ));

        let conn_guard = match connection_manager
            .assert_rbac(&pi.state, &rbac_ctx, for_host)
            .await
        {
            Ok(cg) => cg,
            Err(e) => {
                Arc::into_inner(result_tracker)
                    .expect("arc is not shared yet")
                    .record_with_flag(Err(e), metrics::ResponseFlags::AuthorizationPolicyDenied);
                return StatusCode::UNAUTHORIZED;
            }
        };

        let request_type = match inbound_protocol {
            AppProtocol::PROXY => Proxy(
                req,
                (rbac_ctx.conn.src, rbac_ctx.conn.dst),
                rbac_ctx.conn.src_identity.clone(),
            ),
            _ => Hbone(req),
        };

        let orig_src = enable_original_source.then_some(source_ip);
        let stream = super::freebind_connect(orig_src, upstream_addr, pi.socket_factory.as_ref())
            .await
            .and_then(|s| {
                s.set_nodelay(true)?;
                Ok(s)
            });
        let mut stream = match stream {
            Err(err) => {
                result_tracker.record(Err(err));
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            Ok(stream) => stream,
        };
        debug!("connected to: {upstream_addr}");

        tokio::task::spawn(
            (async move {
                let send = async {
                    let result_tracker = result_tracker.clone();
                    match request_type {
                        Hbone(req) => {
                            hyper::upgrade::on(req)
                                .map_err(Error::NoUpgrade)
                                .and_then(|upgraded| async move {
                                    socket::copy_bidirectional(
                                        &mut ::hyper_util::rt::TokioIo::new(upgraded),
                                        &mut stream,
                                        &result_tracker,
                                    )
                                    .instrument(trace_span!("hbone server"))
                                    .await
                                })
                                .await
                        }
                        Proxy(req, (src, dst), src_id) => {
                            Box::pin(hyper::upgrade::on(req).map_err(Error::NoUpgrade).and_then(
                                |upgraded| async move {
                                    super::write_proxy_protocol(&mut stream, (src, dst), src_id)
                                        .instrument(trace_span!("proxy protocol"))
                                        .await?;
                                    socket::copy_bidirectional(
                                        &mut ::hyper_util::rt::TokioIo::new(upgraded),
                                        &mut stream,
                                        &result_tracker,
                                    )
                                    .instrument(trace_span!("hbone server"))
                                    .await
                                },
                            ))
                            .await
                        }
                    }
                };
                let res = conn_guard.handle_connection(send).await;
                result_tracker.record(res);
            })
            .in_current_span(),
        );
        // Send back our 200. We do this regardless of if our spawned task copies the data;
        // we need to respond with headers immediately once connection is established for the
        // stream of bytes to begin.
        StatusCode::OK
    }

    async fn find_inbound_upstream(
        state: &DemandProxyState,
        conn: &Connection,
        hbone_addr: SocketAddr,
    ) -> Result<(SocketAddr, AppProtocol, Workload, Vec<Arc<Service>>), Error> {
        let dst = &NetworkAddress {
            network: conn.dst_network.to_string(),
            address: hbone_addr.ip(),
        };

        let (upstream_addr, upstream, services) = if conn.dst.ip() == hbone_addr.ip() {
            // If the IPs match, this is not sandwich.
            let Some((us_wl, us_svc)) = state.fetch_workload_services(dst).await else {
                return Err(Error::UnknownDestination(hbone_addr.ip()));
            };
            (hbone_addr, us_wl, us_svc)
        } else if let Some((us_wl, us_svc)) =
            // For sandwich, we redirect the connection to target this waypoint instance
            // and the HBONE target remains the same. Walk the WDS graph to see if they're related.
            Self::find_sandwich_upstream(state, conn, hbone_addr).await
        {
            let next_hop = SocketAddr::new(conn.dst.ip(), hbone_addr.port());
            (next_hop, us_wl, us_svc)
        } else {
            return Err(Error::IPMismatch(conn.dst.ip(), hbone_addr.ip()));
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
            None => (upstream_addr, AppProtocol::NONE),
        };

        Ok((upstream_addr, inbound_protocol, upstream, services))
    }

    async fn find_sandwich_upstream(
        state: &DemandProxyState,
        conn: &Connection,
        hbone_addr: SocketAddr,
    ) -> Option<(Workload, Vec<Arc<Service>>)> {
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
        let lookup = || -> Option<Option<(Workload, Vec<Arc<Service>>)>> {
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
                Address::Service(ref svc) => &svc.waypoint,
                Address::Workload(ref wl) => &wl.waypoint,
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
                    Some((conn_wl, vec![svc]))
                }
                Address::Workload(wl) => {
                    if !wl.workload_ips.contains(&conn.dst.ip()) {
                        // target points to a different waypoint
                        return Some(None);
                    }
                    let svc = state.services.get_by_workload(&wl);
                    // TODO: use Arc more pervasive and remove this clone.
                    Some((Arc::unwrap_or_clone(wl), svc))
                }
            })
        };

        if let Some(res) = lookup() {
            return res;
        }

        if !state.supports_on_demand() {
            return None;
        }
        tokio::join![
            state.fetch_on_demand(strng::new(connection_dst.to_string())),
            state.fetch_on_demand(strng::new(hbone_dst.to_string())),
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

pub fn parse_forwarded_host<T>(req: &Request<T>) -> Option<String> {
    req.headers()
        .get(header::FORWARDED)
        .and_then(|rh| rh.to_str().ok())
        .and_then(|rh| http_types::proxies::Forwarded::parse(rh).ok())
        .and_then(|ph| ph.host().map(|s| s.to_string()))
}

#[cfg(test)]
mod tests {
    use super::Inbound;
    use crate::strng;

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
                application_tunnel::Protocol as AppProtocol, gatewayaddress::Destination,
                ApplicationTunnel, GatewayAddress, NamespacedHostname, NetworkAddress, Protocol,
                Workload,
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

    const TARGET_PORT: u16 = 8080;
    const PROXY_PORT: u16 = 15088;

    const APP_TUNNEL_PROXY: Option<ApplicationTunnel> = Some(ApplicationTunnel {
        port: Some(PROXY_PORT),
        protocol: AppProtocol::PROXY,
    });

    // Regular zTunnel workload traffic inbound
    #[test_case(Waypoint::None, SERVER_POD_IP, SERVER_POD_IP, Some((SERVER_POD_IP, TARGET_PORT)); "to workload no waypoint")]
    // to workload traffic
    #[test_case(Waypoint::Workload(WAYPOINT_POD_IP, None), WAYPOINT_POD_IP, SERVER_POD_IP , Some((WAYPOINT_POD_IP, TARGET_PORT)); "to workload with waypoint referenced by pod")]
    #[test_case(Waypoint::Workload(WAYPOINT_SVC_IP, None), WAYPOINT_POD_IP, SERVER_POD_IP , Some((WAYPOINT_POD_IP, TARGET_PORT)); "to workload with waypoint referenced by vip")]
    #[test_case(Waypoint::Workload(WAYPOINT_SVC_IP, APP_TUNNEL_PROXY), WAYPOINT_POD_IP, SERVER_POD_IP , Some((WAYPOINT_POD_IP, PROXY_PORT)); "to workload with app tunnel")]
    // to service traffic
    #[test_case(Waypoint::Service(WAYPOINT_POD_IP, None), WAYPOINT_POD_IP, SERVER_SVC_IP , Some((WAYPOINT_POD_IP, TARGET_PORT)); "to service with waypoint referenced by pod")]
    #[test_case(Waypoint::Service(WAYPOINT_SVC_IP, None), WAYPOINT_POD_IP, SERVER_SVC_IP , Some((WAYPOINT_POD_IP, TARGET_PORT)); "to service with waypint referenced by vip")]
    #[test_case(Waypoint::Service(WAYPOINT_SVC_IP, APP_TUNNEL_PROXY), WAYPOINT_POD_IP, SERVER_SVC_IP , Some((WAYPOINT_POD_IP, PROXY_PORT)); "to service with app tunnel")]
    // Override port via app_protocol
    // Error cases
    #[test_case(Waypoint::None, SERVER_POD_IP, CLIENT_POD_IP, None; "to server ip mismatch" )]
    #[test_case(Waypoint::None, WAYPOINT_POD_IP, CLIENT_POD_IP, None; "to waypoint without attachment" )]
    #[test_case(Waypoint::Service(WAYPOINT_POD_IP, None), WAYPOINT_POD_IP, SERVER_POD_IP , None; "to workload via waypoint with wrong attachment")]
    #[test_case(Waypoint::Workload(WAYPOINT_POD_IP, None), WAYPOINT_POD_IP, SERVER_SVC_IP , None; "to service via waypoint with wrong attachment")]
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
            src: format!("{CLIENT_POD_IP}:1234").parse().unwrap(),
            dst_network: "".to_string(),
            dst: format!("{connection_dst}:15008").parse().unwrap(),
        };
        let res = Inbound::find_inbound_upstream(
            &state,
            &conn,
            format!("{hbone_dst}:{TARGET_PORT}").parse().unwrap(),
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
            (
                "server",
                SERVER_SVC_IP,
                SERVER_POD_IP,
                server_waypoint.clone(),
            ),
        ]
        .into_iter()
        .map(|(name, vip, ep_ip, waypoint)| {
            let ep_uid = strng::format!("cluster1//v1/Pod/default/{name}");
            let ep_addr = Some(NetworkAddress {
                address: ep_ip.parse().unwrap(),
                network: "".to_string(),
            });
            Service {
                name: name.into(),
                namespace: "default".into(),
                hostname: strng::format!("{name}.default.svc.cluster.local"),
                vips: vec![NetworkAddress {
                    address: vip.parse().unwrap(),
                    network: "".into(),
                }],
                ports: std::collections::HashMap::new(),
                endpoints: vec![(
                    endpoint_uid(&ep_uid, ep_addr.as_ref()),
                    Endpoint {
                        workload_uid: ep_uid,
                        service: NamespacedHostname {
                            hostname: strng::format!("{name}.default.svc.cluster.local"),
                            namespace: "default".into(),
                        },
                        address: ep_addr,
                        port: std::collections::HashMap::new(),
                    },
                )]
                .into_iter()
                .collect(),
                subject_alt_names: vec![strng::format!("{name}.default.svc.cluster.local")],
                waypoint: waypoint.service_attached(),
                load_balancer: None,
            }
        });

        let workloads = vec![
            (
                "waypoint",
                WAYPOINT_POD_IP,
                Waypoint::None,
                // the waypoint's _workload_ gets the app tunnel field
                server_waypoint.app_tunnel(),
            ),
            ("client", CLIENT_POD_IP, Waypoint::None, None),
            ("server", SERVER_POD_IP, server_waypoint, None),
        ]
        .into_iter()
        .map(|(name, ip, waypoint, app_tunnel)| Workload {
            workload_ips: vec![ip.parse().unwrap()],
            waypoint: waypoint.workload_attached(),
            protocol: Protocol::HBONE,
            uid: strng::format!("cluster1//v1/Pod/default/{name}"),
            name: strng::format!("workload-{name}"),
            namespace: "default".into(),
            service_account: strng::format!("service-account-{name}"),
            application_tunnel: app_tunnel,
            ..test_helpers::test_default_workload()
        });

        for svc in services {
            state.services.insert(svc);
        }
        for wl in workloads {
            state.workloads.insert(Arc::new(wl));
        }

        Ok(DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        ))
    }

    // tells the test if we're using workload-attached or svc-attached waypoints
    #[derive(Clone)]
    enum Waypoint<'a> {
        None,
        Service(&'a str, Option<ApplicationTunnel>),
        Workload(&'a str, Option<ApplicationTunnel>),
    }

    impl<'a> Waypoint<'a> {
        fn app_tunnel(&self) -> Option<ApplicationTunnel> {
            match self.clone() {
                Waypoint::Service(_, v) => v,
                Waypoint::Workload(_, v) => v,
                _ => None,
            }
        }
        fn service_attached(&self) -> Option<GatewayAddress> {
            let Waypoint::Service(s, _) = self else {
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
            let Waypoint::Workload(w, _) = self else {
                return None;
            };
            Some(GatewayAddress {
                destination: Destination::Address(NetworkAddress {
                    network: "".to_string(),
                    address: w.parse().expect("a valid waypoint IP"),
                }),
                hbone_mtls_port: 15008,
                hbone_single_tls_port: None,
            })
        }
    }
}
