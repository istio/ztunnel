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

// Forked from https://github.com/olix0r/kubert/blob/main/kubert/src/admin.rs

use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use drain::Watch;
use hyper::server::conn::AddrIncoming;
use hyper::{Body, Request, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use tokio::sync::oneshot;
use tracing::{error, info};

use crate::config::Config;

use crate::hyper_util::empty_response;
use crate::signal;

/// Supports configuring an admin server
pub struct Builder {
    addr: SocketAddr,
}

pub struct Server {
    addr: SocketAddr,
    server: hyper::server::Builder<AddrIncoming>,
    registry: Arc<Mutex<Registry>>,
    shutdown_trigger: signal::ShutdownTrigger,
}

impl Builder {
    pub fn new(config: Config) -> Self {
        Self {
            addr: config.stats_addr,
        }
    }

    pub fn bind(
        self,
        registry: Registry,
        shutdown_trigger: signal::ShutdownTrigger,
    ) -> hyper::Result<Server> {
        let Self { addr } = self;

        let bind = AddrIncoming::bind(&addr)?;
        let addr = bind.local_addr();
        let server = hyper::Server::builder(bind)
            .http1_half_close(true)
            .http1_header_read_timeout(Duration::from_secs(2))
            .http1_max_buf_size(8 * 1024);
        let registry = Arc::new(Mutex::new(registry));

        Ok(Server {
            addr,
            server,
            registry,
            shutdown_trigger,
        })
    }
}

impl Server {
    pub fn registry(&self) -> Arc<Mutex<Registry>> {
        Arc::clone(&self.registry)
    }

    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn spawn(self, drain_rx: Watch) {
        let _dx = drain_rx.clone();
        let (tx, rx) = oneshot::channel();
        let registry = self.registry.clone();
        let server = self
            .server
            .serve(hyper::service::make_service_fn(move |_conn| {
                let registry = registry.clone();
                async move {
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                        let registry = registry.clone();
                        async move {
                            match req.uri().path() {
                                "/metrics" => {
                                    Ok::<_, hyper::Error>(handle_metrics(registry, req).await)
                                }
                                _ => Ok::<_, hyper::Error>(empty_response(
                                    hyper::StatusCode::NOT_FOUND,
                                )),
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
                    error!("stats receiver dropped")
                }
                info!("starting drain of stats server");
            });

        info!(
            address=%self.addr,
            component="stats",
            "listener established",
        );
        let shutdown_trigger = self.shutdown_trigger;
        tokio::spawn(async move {
            if let Err(err) = server.await {
                error!("Serving stats start failed: {err}");
                shutdown_trigger.shutdown_now().await;
            } else {
                // Now that the server has gracefully exited, drop `shutdown` to allow draining to proceed
                match rx.await {
                    Ok(shutdown) => drop(shutdown),
                    Err(_) => info!("stats sender dropped"),
                }
                info!("stats server terminated");
            }
        });
    }
}

async fn handle_metrics(reg: Arc<Mutex<Registry>>, _req: Request<Body>) -> Response<Body> {
    let mut buf = String::new();
    let reg = reg.lock().unwrap();
    encode(&mut buf, &reg).unwrap();

    Response::builder()
        .status(hyper::StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/openmetrics-text;charset=utf-8;version=1.0.0",
        )
        .body(Body::from(buf))
        .unwrap()
}
