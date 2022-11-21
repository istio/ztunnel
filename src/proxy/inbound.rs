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
use std::os::unix::io::RawFd;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

use crate::config::Config;

use crate::identity::CertificateProvider;
use crate::proxy::inbound::InboundConnect::Hbone;
use crate::tls::TlsError;
use crate::workload::WorkloadInformation;

use super::Error;

pub struct Inbound {
    cfg: Config,
    cert_manager: Box<dyn CertificateProvider>,
    workloads: WorkloadInformation,
}

impl Inbound {
    pub async fn new(
        cfg: Config,
        workloads: WorkloadInformation,
        cert_manager: Box<dyn CertificateProvider>,
    ) -> Result<Inbound, Error> {
        let listener: TcpListener = TcpListener::bind(cfg.inbound_addr)
            .await
            .map_err(|e| Error::Bind(cfg.inbound_addr, e))?;
        match crate::socket::set_transparent(&listener) {
            Err(_e) => info!("running without transparent mode"),
            _ => info!("running with transparent mode"),
        };
        Ok(Inbound {
            cfg,
            workloads,
            cert_manager,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.cfg.inbound_addr
    }

    pub(super) async fn run(self) {
        let addr = self.address();
        if self.cfg.tls {
            // TODO avoid duplication here
            let service = make_service_fn(|_| async {
                Ok::<_, hyper::Error>(service_fn(Self::serve_connect))
            });
            let boring_acceptor = crate::tls::BoringTlsAcceptor {
                acceptor: InboundCertProvider {
                    workloads: self.workloads.clone(),
                    cert_manager: self.cert_manager.clone(),
                },
            };
            let mut incoming_listener = hyper::server::conn::AddrIncoming::bind(&addr)
                .expect("hbone bind");
            incoming_listener.set_nodelay(true);
            let incoming = hyper::server::accept::from_stream(
                tls_listener::builder(boring_acceptor)
                    .listen(incoming_listener)
                    .filter(|conn| {
                        // Avoid 'By default, if a client fails the TLS handshake, that is treated as an error, and the TlsListener will return an Err'
                        if let Err(err) = conn {
                            warn!("TLS handshake error: {}", err);
                            false
                        } else {
                            info!("TLS handshake succeeded");
                            true
                        }
                    }),
            );

            let server = Server::builder(incoming)
                .http2_only(true)
                .http2_initial_stream_window_size(self.cfg.window_size)
                .http2_initial_connection_window_size(self.cfg.connection_window_size)
                .http2_max_frame_size(self.cfg.frame_size)
                .serve(service);

            info!("HBONE listener established {}", addr);

            if let Err(e) = server.await {
                error!("server error: {}", e);
            }
        } else {
            warn!("TLS disabled");
            let service = make_service_fn(|_| async {
                Ok::<_, hyper::Error>(service_fn(Self::serve_connect))
            });

            let server = hyper::server::conn::AddrIncoming::bind(&addr)
                .map(Server::builder)
                .expect("hbone bind")
                .http2_only(true)
                .http2_initial_stream_window_size(self.cfg.window_size)
                .http2_initial_connection_window_size(self.cfg.connection_window_size)
                .http2_max_frame_size(self.cfg.frame_size)
                .serve(service);

            info!("HBONE listener established {}", addr);

            if let Err(e) = server.await {
                error!("server error: {}", e);
            }
        }
    }

    /// handle_inbound serves an inbound connection with a target address `addr`.
    pub(super) async fn handle_inbound(
        request_type: InboundConnect,
        addr: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let stream = tokio::net::TcpStream::connect(addr).await;
        match stream {
            Err(err) => {
                warn!("connect to {} failed: {}", addr, err);
                Err(err)
            }
            Ok(stream) => {
                let mut stream = stream;
                tokio::task::spawn(async move {
                    match request_type {
                        InboundConnect::DirectPath(mut incoming) => {
                            tokio::io::copy_bidirectional(&mut incoming, &mut stream)
                                .await
                                .expect("internal server copy");
                        }
                        Hbone(req) => match hyper::upgrade::on(req).await {
                            Ok(mut upgraded) => {
                                super::copy_hbone("hbone server", &mut upgraded, &mut stream)
                                    .await
                                    .expect("hbone server copy");
                            }
                            Err(e) => {
                                // Not sure if this can even happen
                                error!("No upgrade {e}");
                            }
                        },
                    }
                });
                // Send back our 200. We do this regardless of if our spawned task copies the data;
                // we need to respond with headers immediately once connection is established for the
                // stream of bytes to begin.
                Ok(())
            }
        }
    }

    async fn serve_connect(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let mut res = Response::new(Body::empty());
        match req.method() {
            &Method::CONNECT => {
                let uri = req.uri();
                info!("Got {} request to {}", req.method(), uri);
                let addr: SocketAddr = uri.to_string().as_str().parse().expect("must be an addr");
                *res.status_mut() =
                    match Self::handle_inbound(InboundConnect::Hbone(req), addr).await {
                        Ok(_) => StatusCode::OK,
                        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
                    };
                Ok(res)
            }
            // Return the 404 Not Found for other routes.
            method => {
                info!("Sending 404, got {method}");
                let mut not_found = Response::default();
                *not_found.status_mut() = StatusCode::NOT_FOUND;
                Ok(not_found)
            }
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
    async fn fetch_cert(&mut self, fd: RawFd) -> Result<boring::ssl::SslAcceptor, TlsError> {
        let orig = crate::socket::orig_dst_addr_fd(fd).map_err(TlsError::DestinationLookup)?;
        let identity = {
            let remote_addr = super::to_canonical_ip(orig);
            self.workloads
                .find_workload(&remote_addr)
                .ok_or(TlsError::CertificateLookup(remote_addr))?
                .identity()
        };
        info!("tls: accepting connection to {:?} ({})", orig, identity);
        let cert = self.cert_manager.fetch_certificate(&identity).await?;
        let acc = cert.acceptor()?;
        Ok(acc)
    }
}
