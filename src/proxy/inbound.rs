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
use std::time::Instant;

use drain::Watch;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tracing::{debug, error, info, instrument, trace, trace_span, warn, Instrument};

use crate::config::Config;
use crate::identity::CertificateProvider;
use crate::proxy::inbound::InboundConnect::Hbone;
use crate::proxy::{ProxyInputs, TraceParent, TRACEPARENT_HEADER};
use crate::rbac;
use crate::socket::{relay, to_canonical};
use crate::tls::TlsError;
use crate::workload::WorkloadInformation;

use super::Error;

pub(super) struct Inbound {
    cfg: Config,
    listener: TcpListener,
    cert_manager: Box<dyn CertificateProvider>,
    workloads: WorkloadInformation,
    drain: Watch,
}

impl Inbound {
    pub(super) async fn new(mut pi: ProxyInputs, drain: Watch) -> Result<Inbound, Error> {
        let listener: TcpListener = TcpListener::bind(pi.cfg.inbound_addr)
            .await
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
            cfg: pi.cfg,
            workloads: pi.workloads,
            listener,
            cert_manager: pi.cert_manager,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub(super) async fn run(self) {
        let (tx, rx) = oneshot::channel();
        let service = make_service_fn(|socket: &tokio_boring::SslStream<TcpStream>| {
            let dst = crate::socket::orig_dst_addr_or_default(socket.get_ref());
            let conn = rbac::Connection {
                src_identity: socket
                    .ssl()
                    .peer_certificate()
                    .and_then(|x| crate::tls::boring::extract_sans(&x).first().cloned()),
                src_ip: to_canonical(socket.get_ref().peer_addr().unwrap()).ip(),
                dst,
            };
            let workloads = self.workloads.clone();
            debug!(%conn, "accepted connection");
            let enable_original_source = self.cfg.enable_original_source;
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    Self::serve_connect(
                        workloads.clone(),
                        conn.clone(),
                        enable_original_source.unwrap_or_default(),
                        req,
                    )
                }))
            }
        });

        let acceptor = InboundCertProvider {
            workloads: self.workloads.clone(),
            cert_manager: self.cert_manager.clone(),
        };
        let tls_stream = crate::hyper_util::tls_server(acceptor, self.listener);
        let incoming = hyper::server::accept::from_stream(tls_stream);

        let server = Server::builder(incoming)
            .http2_only(true)
            .http2_initial_stream_window_size(self.cfg.window_size)
            .http2_initial_connection_window_size(self.cfg.connection_window_size)
            .http2_max_frame_size(self.cfg.frame_size)
            .serve(service)
            .with_graceful_shutdown(async {
                // Wait until the drain is signaled
                let shutdown = self.drain.signaled().await;
                // Once `shutdown` is dropped, we are declaring the drain is complete. Hyper will start draining
                // once with_graceful_shutdown function exists, so we need to exit the function but later
                // drop `shutdown`.
                if tx.send(shutdown).is_err() {
                    error!("HBONE receiver dropped")
                }
                info!("starting drain of inbound connections");
            });

        if let Err(e) = server.await {
            error!("server error: {}", e);
        }
        // Now that the server has gracefully exited, drop `shutdown` to allow draining to proceed
        match rx.await {
            Ok(shutdown) => drop(shutdown),
            Err(_) => info!("HBONE sender dropped"),
        }
    }

    /// handle_inbound serves an inbound connection with a target address `addr`.
    pub(super) async fn handle_inbound(
        request_type: InboundConnect,
        orig_src: Option<IpAddr>,
        addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let start = Instant::now();
        let stream = super::freebind_connect(orig_src, addr).await;
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
                        match request_type {
                            InboundConnect::DirectPath(mut incoming) => {
                                if let Err(e) = relay(&mut incoming, &mut stream, true).await {
                                    error!(dur=?start.elapsed(), "internal server copy: {}", e);
                                }
                            }
                            Hbone(req) => match hyper::upgrade::on(req).await {
                                Ok(mut upgraded) => {
                                    if let Err(e) = super::copy_hbone(&mut upgraded, &mut stream)
                                        .instrument(trace_span!("hbone server"))
                                        .await
                                    {
                                        error!(dur=?start.elapsed(), "hbone server copy: {}", e);
                                    } else {
                                        info!(dur=?start.elapsed(), "complete");
                                    }
                                }
                                Err(e) => {
                                    // Not sure if this can even happen
                                    error!(dur=?start.elapsed(), "No upgrade {e}");
                                }
                            },
                        }
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

    fn extract_traceparent(req: &Request<Body>) -> TraceParent {
        req.headers()
            .get(TRACEPARENT_HEADER)
            .and_then(|b| b.to_str().ok())
            .and_then(|b| TraceParent::try_from(b).ok())
            .unwrap_or_else(TraceParent::new)
    }

    #[instrument(name="inbound", skip_all, fields(
        id=%Self::extract_traceparent(&req),
        peer_ip=%conn.src_ip,
        peer_id=%OptionDisplay(&conn.src_identity)
    ))]
    async fn serve_connect(
        workloads: WorkloadInformation,
        conn: rbac::Connection,
        enable_original_source: bool,
        req: Request<Body>,
    ) -> Result<Response<Body>, hyper::Error> {
        match req.method() {
            &Method::CONNECT => {
                let uri = req.uri();
                info!("got {} request to {}", req.method(), uri);
                let addr: Result<SocketAddr, _> = uri.to_string().as_str().parse();
                if addr.is_err() {
                    info!("Sending 400, {:?}", addr.err());
                    return Ok(Response::builder()
                        .status(hyper::StatusCode::BAD_REQUEST)
                        .body(Body::empty())
                        .unwrap());
                }

                let addr: SocketAddr = addr.unwrap();
                if addr.ip() != conn.dst.ip() {
                    info!("Sending 400, ip mismatch {addr} != {}", conn.dst);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::empty())
                        .unwrap());
                }
                // Orig has 15008, swap with the real port
                let conn = rbac::Connection { dst: addr, ..conn };
                if !workloads.assert_rbac(&conn).await {
                    info!(%conn, "RBAC rejected");
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())
                        .unwrap());
                }
                let orig_src = enable_original_source.then_some(conn.src_ip);

                let Some(upstream) = workloads.fetch_workload(&addr.ip()).await else {
                    info!(%conn, "unknown destination");
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .unwrap());
                };
                // TODO: This only identifies the service account; we need a more reliable way
                // to identify specifically the waypoint proxy.
                let from_waypoint = conn
                    .src_identity
                    .as_ref()
                    .map(|i| i == &upstream.identity())
                    .unwrap_or(false);
                if !upstream.waypoint_addresses.is_empty() && !from_waypoint {
                    info!(%conn, "bypassed waypoint");
                    return Ok(Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(Body::empty())
                        .unwrap());
                }
                let orig_src = if orig_src.is_some() && from_waypoint {
                    // If the request is from our waypoint, trust the Forwarded header.
                    // For other request types, we can only trust the source from the connection.
                    // Since our own waypoint is in the same trust domain though, we can use Forwarded,
                    // which drops the requirement of spoofing IPs from waypoints
                    super::get_original_src_from_fwded(&req).or(orig_src)
                } else {
                    orig_src
                };
                let status_code = match Self::handle_inbound(Hbone(req), orig_src, addr)
                    .in_current_span()
                    .await
                {
                    Ok(_) => StatusCode::OK,
                    Err(_) => StatusCode::SERVICE_UNAVAILABLE,
                };

                Ok(Response::builder()
                    .status(status_code)
                    .body(Body::empty())
                    .unwrap())
            }
            // Return the 404 Not Found for other routes.
            method => {
                info!("Sending 404, got {method}");
                Ok(Response::builder()
                    .status(hyper::StatusCode::NOT_FOUND)
                    .body(Body::empty())
                    .unwrap())
            }
        }
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
    Hbone(Request<Body>),
}

#[derive(Clone)]
struct InboundCertProvider {
    cert_manager: Box<dyn CertificateProvider>,
    workloads: WorkloadInformation,
}

#[async_trait::async_trait]
impl crate::tls::CertProvider for InboundCertProvider {
    async fn fetch_cert(&mut self, fd: &TcpStream) -> Result<boring::ssl::SslAcceptor, TlsError> {
        let orig_dst_addr = crate::socket::orig_dst_addr_or_default(fd);
        let identity = {
            let wip = orig_dst_addr.ip();
            self.workloads
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
        let acc = cert.mtls_acceptor()?;
        Ok(acc)
    }
}
