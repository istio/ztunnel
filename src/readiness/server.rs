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

use crate::{config, readiness, signal};
use drain::Watch;
use hyper::server::conn::AddrIncoming;
use hyper::{Body, Request, Response};
use itertools::Itertools;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{error, info};

pub struct Builder {
    addr: SocketAddr,
    ready: readiness::Ready,
}

impl Builder {
    pub fn new(config: config::Config, ready: readiness::Ready) -> Self {
        Self {
            addr: config.readiness_addr,
            ready,
        }
    }

    pub fn bind(self, shutdown_trigger: signal::ShutdownTrigger) -> hyper::Result<Server> {
        let Self { addr, ready } = self;

        let bind = AddrIncoming::bind(&addr)?;
        let addr = bind.local_addr();
        let server = hyper::Server::builder(bind)
            .http1_half_close(true)
            .http1_header_read_timeout(Duration::from_secs(2))
            .http1_max_buf_size(8 * 1024);

        Ok(Server {
            addr,
            ready,
            server,
            shutdown_trigger,
        })
    }
}

pub struct Server {
    addr: SocketAddr,
    ready: readiness::Ready,
    server: hyper::server::Builder<hyper::server::conn::AddrIncoming>,
    shutdown_trigger: signal::ShutdownTrigger,
}

impl Server {
    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn spawn(self, drain_rx: Watch) {
        let _dx = drain_rx.clone();
        let ready = self.ready.clone();
        let (tx, rx) = oneshot::channel();
        let server = self
            .server
            .serve(hyper::service::make_service_fn(move |_conn| {
                let ready = ready.clone();
                async move {
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                        let ready = ready.clone();
                        async move {
                            match req.uri().path() {
                                "/healthz/ready" => {
                                    Ok::<_, hyper::Error>(handle_ready(&ready, req).await)
                                }
                                _ => Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(hyper::StatusCode::NOT_FOUND)
                                        .body(Body::default())
                                        .unwrap(),
                                ),
                            }
                        }
                    }))
                }
            }))
            .with_graceful_shutdown(async {
                // Wait until the drain is signaled
                let shutdown = drain_rx.signaled().await;
                // Once `shutdown` is dropped, we are declaring the drain is complete. Hyper will start draining
                // once with_graceful_shutdown function exists, so we need to exit the function but later
                // drop `shutdown`.
                if tx.send(shutdown).is_err() {
                    error!("readiness receiver dropped")
                }
                info!("starting drain of readiness server");
            });
        info!("Serving readiness server at {}", self.addr);
        let shutdown_trigger = self.shutdown_trigger;
        tokio::spawn(async move {
            if let Err(err) = server.await {
                error!("Serving readiness start failed: {err}");
                shutdown_trigger.shutdown_now().await;
            } else {
                // Now that the server has gracefully exited, drop `shutdown` to allow draining to proceed
                match rx.await {
                    Ok(shutdown) => drop(shutdown),
                    Err(_) => info!("readiness server sender dropped"),
                }
                info!("readiness server terminated");
            }
        });
    }
}

async fn handle_ready(ready: &readiness::Ready, req: Request<Body>) -> Response<Body> {
    match *req.method() {
        hyper::Method::GET | hyper::Method::HEAD => {
            let pending = ready.pending();
            if pending.is_empty() {
                return plaintext_response(hyper::StatusCode::OK, "ready\n".into());
            }
            plaintext_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "not ready, pending: {}\n",
                    pending.into_iter().sorted().join(", ")
                ),
            )
        }
        _ => empty_response(hyper::StatusCode::METHOD_NOT_ALLOWED),
    }
}

fn empty_response(code: hyper::StatusCode) -> Response<Body> {
    Response::builder()
        .status(code)
        .body(Body::default())
        .unwrap()
}

fn plaintext_response(code: hyper::StatusCode, body: String) -> Response<Body> {
    Response::builder()
        .status(code)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(body.into())
        .unwrap()
}
