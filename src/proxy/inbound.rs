use std::net::SocketAddr;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::net::TcpListener;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

use crate::config::Config;

use super::Error;

pub struct Inbound {
    cfg: Config,
    listener: TcpListener,
}

impl Inbound {
    pub async fn new(cfg: Config) -> Result<Inbound, Error> {
        let listener: TcpListener = TcpListener::bind(cfg.inbound_addr)
            .await
            .map_err(Error::Bind)?;
        match crate::socket::set_transparent(&listener) {
            Err(_e) => info!("running without transparent mode"),
            _ => info!("running with transparent mode"),
        };
        Ok(Inbound { cfg, listener })
    }
    pub(super) async fn run(self) {
        let addr = self.listener.local_addr().unwrap();
        if self.cfg.tls {
            // TODO avoid duplication here
            let service = make_service_fn(|_| async {
                Ok::<_, hyper::Error>(service_fn(Self::serve_connect))
            });
            let acc = crate::tls::test_certs().acceptor().unwrap();
            let incoming = hyper::server::accept::from_stream(
                tls_listener::builder(crate::tls::BoringTlsAcceptor(acc))
                    .listen(
                        hyper::server::conn::AddrIncoming::from_listener(self.listener)
                            .expect("hbone bind"),
                    )
                    .filter(|conn| {
                        // Avoid 'By default, if a client fails the TLS handshake, that is treated as an error, and the TlsListener will return an Err'
                        if let Err(err) = conn {
                            warn!("TLS handshake error: {:?}", err);
                            false
                        } else {
                            info!("TLS handshake succeeded: {:?}", conn);
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

            let server = hyper::server::conn::AddrIncoming::from_listener(self.listener)
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
    async fn serve_connect(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let mut res = Response::new(Body::empty());
        match req.method() {
            &Method::CONNECT => {
                // TODO: uri or host?
                let uri = req.uri();

                let addr: SocketAddr = uri.to_string().as_str().parse().expect("must be an addr");
                let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
                info!("Got {} request to {}", req.method(), uri);
                *res.status_mut() = StatusCode::OK;
                tokio::task::spawn(async move {
                    match hyper::upgrade::on(req).await {
                        Ok(mut upgraded) => {
                            super::copy_hbone("hbone server", &mut upgraded, &mut stream)
                                .await
                                .expect("hbone server copy");
                        }
                        Err(e) => {
                            // Not sure if this can even happen
                            error!("No upgrade {e}");
                        }
                    }
                });
                // Send back our 200. TODO: 503 on failure to connect
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
