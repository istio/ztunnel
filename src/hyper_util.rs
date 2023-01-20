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

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use drain::Watch;
use hyper::server::conn::AddrIncoming;
use hyper::{Body, Request, Response};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_stream::{Stream, StreamExt};
use tracing::{debug, error, info, warn};

use crate::signal;
use crate::tls::{BoringTlsAcceptor, CertProvider, TlsError};

pub fn tls_server<T: CertProvider + Clone + 'static>(
    acceptor: T,
    listener: TcpListener,
) -> impl Stream<
    Item = Result<tokio_boring::SslStream<TcpStream>, tls_listener::Error<io::Error, TlsError>>,
> {
    let boring_acceptor = BoringTlsAcceptor { acceptor };
    let mut listener = AddrIncoming::from_listener(listener).expect("server bind");
    listener.set_nodelay(true);

    tls_listener::builder(boring_acceptor)
        .listen(listener)
        .filter(|conn| {
            // Avoid 'By default, if a client fails the TLS handshake, that is treated as an error, and the TlsListener will return an Err'
            if let Err(err) = conn {
                warn!("TLS handshake error: {}", err);
                false
            } else {
                debug!("TLS handshake succeeded");
                true
            }
        })
}

pub fn empty_response(code: hyper::StatusCode) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(Body::default())
        .unwrap()
}

pub fn plaintext_response(code: hyper::StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(code)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(body.into())
        .unwrap()
}

/// Server implements a generic HTTP server with the follow behavior:
/// * HTTP/1.1 plaintext only
/// * Draining
/// * Triggers the app to shutdown on errors
pub struct Server<S> {
    name: String,
    addr: SocketAddr,
    server: hyper::server::Builder<AddrIncoming>,
    shutdown_trigger: signal::ShutdownTrigger,
    drain_rx: Watch,
    state: Arc<S>,
}

impl<S> Server<S> {
    pub fn bind(
        name: &str,
        addr: SocketAddr,
        shutdown_trigger: signal::ShutdownTrigger,
        drain_rx: Watch,
        s: S,
    ) -> hyper::Result<Self> {
        let bind = AddrIncoming::bind(&addr)?;
        let addr = bind.local_addr();
        let server = hyper::Server::builder(bind)
            .http1_half_close(true)
            .http1_header_read_timeout(Duration::from_secs(2))
            .http1_max_buf_size(8 * 1024);

        Ok(Server {
            name: name.to_string(),
            addr,
            server,
            shutdown_trigger,
            drain_rx,
            state: Arc::new(s),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn spawn<F, R>(self, f: F)
    where
        S: Send + Sync + 'static,
        F: Fn(Arc<S>, Request<Body>) -> R + Send + Sync + 'static,
        R: Future<Output = Result<Response<Body>, hyper::Error>> + Send + Sync + 'static,
    {
        let drain_rx = self.drain_rx;
        let name = self.name.clone();
        let (tx, rx) = oneshot::channel();
        let state = self.state.clone();
        let f = Arc::new(f);
        let server = self
            .server
            .serve(hyper::service::make_service_fn(move |_conn| {
                let state = state.clone();
                let f = f.clone();
                async {
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                        let state = state.clone();

                        f(state, req)
                    }))
                }
            }))
            .with_graceful_shutdown(async move {
                // Wait until the drain is signaled
                let shutdown = drain_rx.signaled().await;
                // Once `shutdown` is dropped, we are declaring the drain is complete. Hyper will start draining
                // once with_graceful_shutdown function exists, so we need to exit the function but later
                // drop `shutdown`.
                if tx.send(shutdown).is_err() {
                    error!("{name}: receiver dropped");
                }
                info!("starting drain of {name} server");
            });

        info!(
            address=%self.addr,
            component=self.name,
            "listener established",
        );
        let shutdown_trigger = self.shutdown_trigger;
        let name = self.name;
        tokio::spawn(async move {
            if let Err(err) = server.await {
                error!("Serving {name} start failed: {err}");
                shutdown_trigger.shutdown_now().await;
            } else {
                // Now that the server has gracefully exited, drop `shutdown` to allow draining to proceed
                match rx.await {
                    Ok(shutdown) => drop(shutdown),
                    Err(_) => info!("{name} sender dropped"),
                }
                info!("{name} server terminated");
            }
        });
    }
}
