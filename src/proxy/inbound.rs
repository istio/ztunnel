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

use futures::stream::StreamExt;
use futures_util::TryFutureExt;
use http::{Method, Response, StatusCode};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::watch;

use tracing::{debug, info, info_span, trace_span, Instrument};

use super::{ConnectionResult, Error, LocalWorkloadInformation, ResponseFlags};
use crate::baggage::parse_baggage_header;
use crate::identity::Identity;

use crate::config::Config;
use crate::drain::DrainWatcher;
use crate::proxy::h2::server::H2Request;
use crate::proxy::metrics::{ConnectionOpen, Reporter};
use crate::proxy::{metrics, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};
use crate::rbac::Connection;
use crate::socket::to_canonical;
use crate::state::service::Service;
use crate::state::workload::application_tunnel::Protocol as AppProtocol;
use crate::strng::Strng;
use crate::{assertions, copy, handle_connection, proxy, socket, strng, tls};

use crate::drain::run_with_drain;
use crate::proxy::h2;
use crate::state::workload::address::Address;
use crate::state::workload::{self, NamespacedHostname, NetworkAddress, Workload};
use crate::state::{DemandProxyState, ProxyRbacContext};
use crate::tls::TlsError;

pub(super) struct Inbound {
    listener: socket::Listener,
    drain: DrainWatcher,
    pi: Arc<ProxyInputs>,
    enable_orig_src: bool,
}

#[derive(Debug, Clone)]
pub enum HboneAddress {
    SocketAddr(SocketAddr),
    SvcHostname(Strng, u16),
}

impl HboneAddress {
    pub fn port(&self) -> u16 {
        match self {
            HboneAddress::SocketAddr(s) => s.port(),
            HboneAddress::SvcHostname(_, p) => *p,
        }
    }

    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            HboneAddress::SocketAddr(s) => Some(s.ip()),
            HboneAddress::SvcHostname(_, _) => None,
        }
    }

    pub fn svc_hostname(&self) -> Option<Strng> {
        match self {
            HboneAddress::SocketAddr(_) => None,
            HboneAddress::SvcHostname(s, _) => Some(s.into()),
        }
    }
}

impl std::fmt::Display for HboneAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HboneAddress::SocketAddr(addr) => write!(f, "{}", addr),
            HboneAddress::SvcHostname(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

impl From<SocketAddr> for HboneAddress {
    fn from(socket_addr: SocketAddr) -> Self {
        HboneAddress::SocketAddr(socket_addr)
    }
}

impl From<(Strng, u16)> for HboneAddress {
    fn from(svc_hostname: (Strng, u16)) -> Self {
        HboneAddress::SvcHostname(svc_hostname.0, svc_hostname.1)
    }
}

impl Inbound {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: DrainWatcher) -> Result<Inbound, Error> {
        let listener = pi
            .socket_factory
            .tcp_bind(pi.cfg.inbound_addr)
            .map_err(|e| Error::Bind(pi.cfg.inbound_addr, e))?;
        let enable_orig_src = super::maybe_set_transparent(&pi, &listener)?;

        info!(
            address=%listener.local_addr(),
            component="inbound",
            transparent=enable_orig_src,
            "listener established",
        );
        Ok(Inbound {
            listener,
            drain,
            pi,
            enable_orig_src,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub(super) async fn run(self) {
        let pi = self.pi.clone();
        let acceptor = InboundCertProvider {
            local_workload: self.pi.local_workload_information.clone(),
        };

        // Safety: we set nodelay directly in tls_server, so it is safe to convert to a normal listener.
        // Although, that is *after* the TLS handshake; in theory we may get some benefits to setting it earlier.
        let mut stream = crate::hyper_util::tls_server(acceptor, self.listener.inner());

        let accept = |drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
            async move {
                while let Some(tls) = stream.next().await {
                    let pi = self.pi.clone();
                    let (raw_socket, ssl) = tls.get_ref();
                    let src_identity: Option<Identity> = tls::identity_from_connection(ssl);
                    let dst = to_canonical(raw_socket.local_addr().expect("local_addr available"));
                    let src = to_canonical(raw_socket.peer_addr().expect("peer_addr available"));
                    let drain = drain.clone();
                    let force_shutdown = force_shutdown.clone();
                    let network = pi.cfg.network.clone();
                    let serve_client = async move {
                        let conn = Connection {
                            src_identity,
                            src,
                            dst_network: strng::new(&network), // inbound request must be on our network
                            dst,
                        };
                        debug!(%conn, "accepted connection");
                        let cfg = pi.cfg.clone();
                        let request_handler = move |req| {
                            let id = Self::extract_traceparent(&req);
                            let peer = conn.src;
                            let req_handler = Self::serve_connect(
                                pi.clone(),
                                conn.clone(),
                                self.enable_orig_src,
                                req,
                            )
                            .instrument(info_span!("inbound", %id, %peer));
                            // This is for each user connection, so most important to keep small
                            assertions::size_between_ref(1500, 2500, &req_handler);
                            req_handler
                        };

                        let serve_conn = h2::server::serve_connection(
                            cfg,
                            tls,
                            drain,
                            force_shutdown,
                            request_handler,
                        );
                        // This is per HBONE connection, so while would be nice to be small, at least it
                        // is pooled so typically fewer of these.
                        let serve = Box::pin(assertions::size_between(6000, 8000, serve_conn));
                        serve.await
                    };
                    // This is small since it only handles the TLS layer -- the HTTP2 layer is boxed
                    // and measured above.
                    assertions::size_between_ref(1000, 1500, &serve_client);
                    tokio::task::spawn(serve_client.in_current_span());
                }
            }
            .in_current_span()
        };

        run_with_drain(
            "inbound".to_string(),
            self.drain,
            pi.cfg.self_termination_deadline,
            accept,
        )
        .await
    }

    fn extract_traceparent(req: &H2Request) -> TraceParent {
        req.headers()
            .get(TRACEPARENT_HEADER)
            .and_then(|b| b.to_str().ok())
            .and_then(|b| TraceParent::try_from(b).ok())
            .unwrap_or_else(TraceParent::new)
    }

    /// serve_connect handles a single connection from a client.
    #[allow(clippy::too_many_arguments)]
    async fn serve_connect(
        pi: Arc<ProxyInputs>,
        conn: Connection,
        enable_original_source: bool,
        req: H2Request,
    ) {
        let src = conn.src;
        let dst = conn.dst;

        debug!(%conn, ?req, "received request");

        // In order to ensure we properly handle all errors, we split up serving inbound request into a few
        // phases.

        // Initial phase, build up context about the request.
        let ri = match Self::build_inbound_request(&pi, conn, &req).await {
            Ok(i) => i,
            Err(InboundError(e, code)) => {
                // At this point in processing, we never built up full context to log a complete access log.
                // Instead, just log a minimal error line.
                metrics::log_early_deny(src, dst, Reporter::destination, e);
                if let Err(err) = req.send_error(build_response(code)) {
                    tracing::warn!("failed to send HTTP response: {err}");
                }
                return;
            }
        };

        // Now we have enough context to properly report logs and metrics. Group everything else that
        // can fail before we send the OK response here.
        let rx = async {
            // Define a connection guard to ensure rbac conditions are maintained for the duration of the connection
            let conn_guard = pi
                .connection_manager
                .assert_rbac(&pi.state, &ri.rbac_ctx, ri.for_host)
                .await
                .map_err(InboundFlagError::build(
                    StatusCode::UNAUTHORIZED,
                    ResponseFlags::AuthorizationPolicyDenied,
                ))?;

            let orig_src = enable_original_source.then_some(ri.rbac_ctx.conn.src.ip());
            // Establish upstream connection between original source and destination
            // We are allowing a bind to the original source address locally even if the ip address isn't on this node.
            let stream =
                super::freebind_connect(orig_src, ri.upstream_addr, pi.socket_factory.as_ref())
                    .await
                    .map_err(Error::ConnectionFailed)
                    .map_err(InboundFlagError::build(
                        StatusCode::SERVICE_UNAVAILABLE,
                        ResponseFlags::ConnectionFailure,
                    ))?;
            debug!("connected to: {}", ri.upstream_addr);
            Ok((conn_guard, stream))
        };
        // Wait on establishing the upstream connection and connection guard before sending the 200 response to the client
        let (mut conn_guard, mut stream) = match rx.await {
            Ok(res) => res,
            Err(InboundFlagError(err, flag, code)) => {
                ri.result_tracker.record_with_flag(Err(err), flag);
                if let Err(err) = req.send_error(build_response(code)) {
                    tracing::warn!("failed to send HTTP response: {err}");
                }
                return;
            }
        };

        // At this point, we established the upstream connection and need to send a 200 back to the client.
        // we may still have failures at this point during the proxying, but we don't need to send these
        // at the HTTP layer.
        // After sending a 200 back to the client, write the proxy protocol to the stream. This ensures
        // that the server has all of the necessary information about the connection regardless of the protocol
        // See https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt for more information about the
        // proxy protocol.
        let send = req
            .send_response(build_response(StatusCode::OK))
            .and_then(|h2_stream| async {
                // Required for a custom waypoint so that it doesn't have to support HBONE
                if ri.inbound_protocol == AppProtocol::PROXY {
                    let Connection {
                        src, src_identity, ..
                    } = ri.rbac_ctx.conn;
                    let protocol_addr = match ri.hbone_addr {
                        HboneAddress::SocketAddr(addr) => addr,
                        HboneAddress::SvcHostname(_, _) => {
                            // If the hbone_addr includes service hostname, we need to use the resolved svc IP address
                            match ri.upstream_protocol_addr {
                                Some(addr) => addr,
                                None => {
                                    // This should never happen, as we should have already validated the destination
                                    // and resolved the hostname to an IP address.
                                    return Err(Error::ConnectAddress(ri.hbone_addr.to_string()));
                                }
                            }
                        }
                    };
                    // TODO(jaellio): Also include port?
                    let svc_hostname: Option<Strng> = ri.hbone_addr.svc_hostname();
                    super::write_proxy_protocol(
                        &mut stream,
                        (src, protocol_addr),
                        src_identity,
                        svc_hostname,
                    )
                    .instrument(trace_span!("proxy protocol"))
                    .await?;
                }
                copy::copy_bidirectional(
                    h2_stream,
                    copy::TcpStreamSplitter(stream),
                    &ri.result_tracker,
                )
                .instrument(trace_span!("hbone server"))
                .await
            });
        let res = handle_connection!(conn_guard, send);
        ri.result_tracker.record(res);
    }

    // build_inbound_request builds up the context for an inbound request.
    async fn build_inbound_request(
        pi: &Arc<ProxyInputs>,
        // HBONE connection
        conn: Connection,
        req: &H2Request,
    ) -> Result<InboundRequest, InboundError> {
        if req.method() != Method::CONNECT {
            let e = Error::NonConnectMethod(req.method().to_string());
            return Err(InboundError(e, StatusCode::BAD_REQUEST));
        }

        let start = Instant::now();

        // Extract the host or IP from the authority pseudo-header of the URI
        let hbone_addr = req
            .uri()
            .to_string()
            .parse::<SocketAddr>()
            .map(HboneAddress::SocketAddr)
            .unwrap_or_else(|_| {
                let hbone_host = req.uri().host().unwrap();
                let hbone_port = req.uri().port_u16().unwrap();
                HboneAddress::SvcHostname(hbone_host.into(), hbone_port)
            });

        // Get the destination workload information of the destination pods (wds) workload (not destination ztunnel)
        let destination_workload = pi
            .local_workload_information
            .get_workload()
            .await
            // At this point we already fetched the local workload for TLS, so it should be infallible.
            .map_err(InboundError::build(StatusCode::SERVICE_UNAVAILABLE))?;

        // Set to the service IP address if the hbone_addr is a hostname
        // Used for the proxy protocol header. The Address header does not support hostname.
        let mut upstream_protocol_addr = None;
        // Check the request is allowed by verifying the destination
        match hbone_addr {
            HboneAddress::SocketAddr(_) => Self::validate_destination(
                &pi.cfg,
                &pi.state,
                &conn,
                &destination_workload,
                hbone_addr.clone(),
            )
            .await
            .map_err(InboundError::build(StatusCode::BAD_REQUEST))?,
            HboneAddress::SvcHostname(_, _) => {
                // Get the service address by hostname
                let addr = Self::find_service_by_hostname(
                    &pi.state,
                    &destination_workload,
                    hbone_addr.clone(),
                )
                .await
                .map_err(InboundError::build(StatusCode::BAD_REQUEST))?;

                // Validate the destination pod is a member of the service
                match addr {
                    Address::Service(svc) => {
                        if !svc.contains_endpoint(&destination_workload) {
                            // TODO(jaellio): Update error msg/type
                            return Err(InboundError(
                                Error::NoResolvedAddresses(destination_workload.to_string()),
                                StatusCode::BAD_REQUEST,
                            ));
                        }
                        // TODO(jaellio): Intelligently select the VIP
                        let svc_address = svc.vips[0].address;
                        upstream_protocol_addr = format!("{}:{}", svc_address, hbone_addr.port())
                            .parse::<SocketAddr>()
                            .map_err(|e| Error::ConnectAddress(e.to_string()))
                            .ok();
                    }
                    Address::Workload(wl) => {
                        // TODO(jaellio): This scenario is currently not supported. When find_hostname returns
                        // a workload rather than a service it is most likely a stateful set or headless service.
                        return Err(InboundError(
                            Error::UnsupportedFeature(wl.to_string()),
                            StatusCode::BAD_REQUEST,
                        ));
                    }
                }
            }
        };

        // Determine the next hop.
        let hbone_addr_clone = hbone_addr.clone();
        let (upstream_addr, inbound_protocol, upstream_service) =
            Self::find_inbound_upstream(&pi.state, &conn, &destination_workload, hbone_addr_clone);

        let original_dst = conn.dst;
        // Connection has 15008, swap with the real port
        let conn = Connection {
            dst: upstream_addr,
            // copies the rest of the connection fields from conn
            ..conn
        };

        let rbac_ctx = ProxyRbacContext {
            conn,
            dest_workload: destination_workload.clone(),
        };

        let for_host = parse_forwarded_host(req);
        let baggage =
            parse_baggage_header(req.headers().get_all(BAGGAGE_HEADER)).unwrap_or_default();

        let from_gateway = proxy::check_from_network_gateway(
            &pi.state,
            &destination_workload,
            rbac_ctx.conn.src_identity.as_ref(),
        )
        .await;
        if from_gateway {
            debug!("request from gateway");
        }
        let source = match from_gateway {
            true => None, // we cannot lookup source workload since we don't know the network, see https://github.com/istio/ztunnel/issues/515
            false => {
                let src_network_addr = NetworkAddress {
                    // we can assume source network is our network because we did not traverse a gateway
                    network: rbac_ctx.conn.dst_network.clone(),
                    address: rbac_ctx.conn.src.ip(),
                };
                // Find source info. We can lookup by XDS or from connection attributes
                pi.state.fetch_workload_by_address(&src_network_addr).await
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
        let ds = proxy::guess_inbound_service(
            &rbac_ctx.conn,
            &for_host,
            upstream_service,
            &destination_workload,
        );
        let result_tracker = Box::new(metrics::ConnectionResult::new(
            rbac_ctx.conn.src,
            // For consistency with outbound logs, report the original destination (with 15008 port)
            // as dst.addr, and the target address as dst.hbone_addr
            original_dst,
            Some(hbone_addr.clone()),
            start,
            ConnectionOpen {
                reporter: Reporter::destination,
                source,
                derived_source: Some(derived_source),
                destination: Some(destination_workload),
                connection_security_policy: metrics::SecurityPolicy::mutual_tls,
                destination_service: ds,
            },
            pi.metrics.clone(),
        ));
        Ok(InboundRequest {
            for_host,
            rbac_ctx,
            result_tracker,
            upstream_addr,
            inbound_protocol,
            hbone_addr,
            upstream_protocol_addr,
        })
    }

    async fn find_service_by_hostname(
        state: &DemandProxyState,
        local_workload: &Workload,
        hbone_addr: HboneAddress,
    ) -> Result<Address, Error> {
        match hbone_addr {
            HboneAddress::SocketAddr(_) => Err(Error::UnsupportedFeature(
                "Not supported for socket address".into(),
            )),
            HboneAddress::SvcHostname(hbone_host, _) => {
                // Validate a service or workload exists for the hostname
                let parts: Vec<&str> = hbone_host.split('.').collect();
                if parts.len() <= 1 {
                    // TODO(jaellio): Update error msg/type
                    return Err(Error::ConnectAddress(hbone_host.to_string()));
                }
                let namespace = parts[1];
                if namespace != local_workload.namespace {
                    //TODO(jaellio): Update error msg/type. This is a namespace scoping issue.
                    return Err(Error::ConnectAddress(hbone_host.to_string()));
                }
                let namespaced_name = &NamespacedHostname {
                    namespace: namespace.into(),
                    hostname: hbone_host,
                };
                match state.read().find_hostname(namespaced_name) {
                    Some(addr) => Ok(addr),
                    None => Err(Error::ConnectAddress(namespaced_name.to_string())),
                }
            }
        }
    }

    /// validate_destination ensures the destination is an allowed request.
    async fn validate_destination(
        cfg: &Config,
        state: &DemandProxyState,
        conn: &Connection,
        local_workload: &Workload,
        hbone_addr: HboneAddress,
    ) -> Result<(), Error> {
        let illegal_call = cfg.illegal_ports.contains(&hbone_addr.port());
        if illegal_call {
            return Err(Error::SelfCall);
        }

        let hbone_ip = match hbone_addr.ip() {
            Some(ip) => ip,
            None => return Err(Error::ConnectAddress(hbone_addr.to_string())),
        };

        if conn.dst.ip() == hbone_ip {
            // Normal case: both the connection destination IP and the HBONE address from the authority header are aligned.
            // This is allowed (we really only need the HBONE address for the port.)
            // TODO(jaellio): note - HBONE address contains the original port, so we need that to update the port from 15008.
            return Ok(());
        }

        if local_workload.application_tunnel.is_some() {
            // In the case they have their own tunnel, they will get the HBONE target address in the PROXY
            // header, and their application can decide what to do with it; we don't validate this.
            // This is the case, for instance, with a waypoint using PROXY.
            return Ok(());
        }
        // There still may be the case where we are doing a "waypoint sandwich" but not using any tunnel.
        // Presumably, the waypoint is only matching on L7 attributes.
        // We want to make sure in this case we don't deny the requests just because the HBONE destination
        // mismatches (though we will, essentially, ignore the address).
        // To do this, we do a lookup to see if the HBONE target has us as its waypoint.
        let hbone_dst = &NetworkAddress {
            network: conn.dst_network.clone(),
            address: hbone_ip,
        };

        // None means we need to do on-demand lookup
        let lookup_is_destination_this_waypoint = || -> Option<bool> {
            let state = state.read();

            // hostname scoping. Can we use the client's namespace here to do that?
            let hbone_target = state.find_address(hbone_dst)?;

            // HBONE target can point to some service or workload. In either case, get the waypoint
            let Some(target_waypoint) = (match hbone_target {
                Address::Service(ref svc) => &svc.waypoint,
                Address::Workload(ref wl) => &wl.waypoint,
            }) else {
                // Target has no waypoint
                return Some(false);
            };

            // Resolve the reference from our HBONE target
            let Some(target_waypoint) = state.find_destination(&target_waypoint.destination) else {
                return Some(false);
            };

            // Validate that the HBONE target references the Waypoint we're connecting to
            Some(match target_waypoint {
                Address::Service(svc) => svc.contains_endpoint(local_workload),
                Address::Workload(wl) => wl.workload_ips.contains(&conn.dst.ip()),
            })
        };

        let res = match lookup_is_destination_this_waypoint() {
            Some(r) => Some(r),
            None => {
                if !state.supports_on_demand() {
                    None
                } else {
                    state
                        .fetch_on_demand(strng::new(hbone_dst.to_string()))
                        .await;
                    lookup_is_destination_this_waypoint()
                }
            }
        };

        if res.is_none() || res == Some(false) {
            return Err(Error::IPMismatch(conn.dst.ip(), hbone_ip));
        }
        Ok(())
    }

    /// find_inbound_upstream determines the next hop for an inbound request.
    fn find_inbound_upstream(
        state: &DemandProxyState,
        conn: &Connection,
        local_workload: &Workload,
        hbone_addr: HboneAddress,
    ) -> (SocketAddr, AppProtocol, Vec<Arc<Service>>) {
        let upstream_addr = SocketAddr::new(conn.dst.ip(), hbone_addr.port());

        // Application tunnel may override the port.
        let (upstream_addr, inbound_protocol) = match local_workload.application_tunnel.clone() {
            Some(workload::ApplicationTunnel { port, protocol }) => {
                // We may need to override the target port. For instance, we may send all PROXY
                // traffic over a dedicated port like 15088.
                let new_target =
                    SocketAddr::new(upstream_addr.ip(), port.unwrap_or(upstream_addr.port()));
                // Note: the logic to decide which destination address to set inside the PROXY headers
                // is handled outside of this call. This just determines that location we actually send the
                // connection to
                (new_target, protocol)
            }
            None => (upstream_addr, AppProtocol::NONE),
        };
        let services = state.get_services_by_workload(local_workload);

        (upstream_addr, inbound_protocol, services)
    }
}

struct InboundRequest {
    for_host: Option<String>,
    rbac_ctx: ProxyRbacContext,
    result_tracker: Box<ConnectionResult>,
    upstream_addr: SocketAddr,
    hbone_addr: HboneAddress,
    inbound_protocol: AppProtocol,
    // When the hbone_addr contains a hostname, we need to resolve it to an IP address
    // None when hbone_addr is an IP address
    upstream_protocol_addr: Option<SocketAddr>,
}

/// InboundError represents an error with an associated status code.
struct InboundError(Error, StatusCode);
impl InboundError {
    pub fn build(code: StatusCode) -> impl Fn(Error) -> Self {
        move |err| InboundError(err, code)
    }
}

struct InboundFlagError(Error, ResponseFlags, StatusCode);
impl InboundFlagError {
    pub fn build(code: StatusCode, flag: ResponseFlags) -> impl Fn(Error) -> Self {
        move |err| InboundFlagError(err, flag, code)
    }
}

#[derive(Clone)]
struct InboundCertProvider {
    local_workload: Arc<LocalWorkloadInformation>,
}

#[async_trait::async_trait]
impl crate::tls::ServerCertProvider for InboundCertProvider {
    async fn fetch_cert(&mut self) -> Result<Arc<rustls::ServerConfig>, TlsError> {
        debug!(
            identity=%self.local_workload.workload_info(),
            "fetching cert"
        );
        let cert = self.local_workload.fetch_certificate().await?;
        Ok(Arc::new(cert.server_config()?))
    }
}

pub fn parse_forwarded_host(req: &H2Request) -> Option<String> {
    req.headers()
        .get(http::header::FORWARDED)
        .and_then(|rh| rh.to_str().ok())
        .and_then(|rh| http_types::proxies::Forwarded::parse(rh).ok())
        .and_then(|ph| ph.host().map(|s| s.to_string()))
}

fn build_response(status: StatusCode) -> Response<()> {
    Response::builder()
        .status(status)
        .body(())
        .expect("builder with known status code should not fail")
}

#[cfg(test)]
mod tests {
    use super::Inbound;
    use crate::{config, proxy::inbound::HboneAddress, strng};

    use crate::{
        rbac::Connection,
        state::{
            self,
            service::{Endpoint, EndpointSet, Service},
            workload::{
                application_tunnel::Protocol as AppProtocol, gatewayaddress::Destination,
                ApplicationTunnel, GatewayAddress, NetworkAddress, Protocol, Workload,
            },
            DemandProxyState,
        },
        test_helpers,
    };
    use std::{
        net::SocketAddr,
        sync::{Arc, RwLock},
    };

    use crate::state::workload::HealthStatus;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use prometheus_client::registry::Registry;
    use test_case::test_case;

    const CLIENT_POD_IP: &str = "10.0.0.1";

    const SERVER_POD_IP: &str = "10.0.0.2";
    const SERVER_SVC_IP: &str = "10.10.0.1";

    // const SERVER_POD_HOSTNAME: &str = "server.default.svc.cluster.local";

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
    // Svc hostname
    // #[test_case(Waypoint::None, SERVER_POD_IP, SERVER_POD_HOSTNAME, Some((SERVER_POD_IP, TARGET_PORT, Some(SERVER_SVC_IP))); "svc hostname to workload no waypoint")]
    #[tokio::test]
    async fn test_find_inbound_upstream<'a>(
        target_waypoint: Waypoint<'a>,
        connection_dst: &str,
        hbone_dst: &str,
        want: Option<(&str, u16)>,
    ) {
        let state = test_state(target_waypoint).expect("state setup");
        let cfg = config::parse_config().unwrap();
        let conn = Connection {
            src_identity: None,
            src: format!("{CLIENT_POD_IP}:1234").parse().unwrap(),
            dst_network: "".into(),
            dst: format!("{connection_dst}:15008").parse().unwrap(),
        };
        let local_wl = state
            .fetch_workload_by_address(&NetworkAddress {
                network: "".into(),
                address: conn.dst.ip(),
            })
            .await
            .unwrap();
        let hbone_addr =
            if let Ok(addr) = format!("{hbone_dst}:{TARGET_PORT}").parse::<SocketAddr>() {
                HboneAddress::SocketAddr(addr)
            } else {
                HboneAddress::SvcHostname(hbone_dst.into(), TARGET_PORT)
            };
        // TODO(jaellio): Try not to clone the hbone_addr
        let validate_destination =
            Inbound::validate_destination(&cfg, &state, &conn, &local_wl, hbone_addr.clone()).await;
        let res = Inbound::find_inbound_upstream(&state, &conn, &local_wl, hbone_addr.clone());

        match want {
            Some((ip, port)) => {
                let got_addr = res.0;
                assert_eq!(got_addr, SocketAddr::new(ip.parse().unwrap(), port));
            }
            None => {
                validate_destination.expect_err("did not find upstream");
            }
        }
    }

    fn test_state(server_waypoint: Waypoint) -> anyhow::Result<state::DemandProxyState> {
        let mut state = state::ProxyState::new(None);

        let services = vec![
            ("waypoint", WAYPOINT_SVC_IP, Waypoint::None),
            ("server", SERVER_SVC_IP, server_waypoint.clone()),
        ]
        .into_iter()
        .map(|(name, vip, waypoint)| Service {
            name: name.into(),
            namespace: "default".into(),
            hostname: strng::format!("{name}.default.svc.cluster.local"),
            vips: vec![NetworkAddress {
                address: vip.parse().unwrap(),
                network: "".into(),
            }],
            ports: std::collections::HashMap::new(),
            endpoints: EndpointSet::from_list([Endpoint {
                workload_uid: strng::format!("cluster1//v1/Pod/default/{name}"),
                port: std::collections::HashMap::new(),
                status: HealthStatus::Healthy,
            }]),
            subject_alt_names: vec![strng::format!("{name}.default.svc.cluster.local")],
            waypoint: waypoint.service_attached(),
            load_balancer: None,
            ip_families: None,
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

        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        Ok(DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        ))
    }

    // tells the test if we're using workload-attached or svc-attached waypoints
    #[derive(Clone)]
    enum Waypoint<'a> {
        None,
        Service(&'a str, Option<ApplicationTunnel>),
        Workload(&'a str, Option<ApplicationTunnel>),
    }

    impl Waypoint<'_> {
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
                    network: strng::EMPTY,
                    address: s.parse().expect("a valid waypoint IP"),
                }),
                hbone_mtls_port: 15008,
            })
        }

        fn workload_attached(&self) -> Option<GatewayAddress> {
            let Waypoint::Workload(w, _) = self else {
                return None;
            };
            Some(GatewayAddress {
                destination: Destination::Address(NetworkAddress {
                    network: strng::EMPTY,
                    address: w.parse().expect("a valid waypoint IP"),
                }),
                hbone_mtls_port: 15008,
            })
        }
    }
}
