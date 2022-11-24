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

use std::collections::HashSet;
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use drain::Watch;
#[cfg(feature = "gperftools")]
use gperftools::heap_profiler::HEAP_PROFILER;
#[cfg(feature = "gperftools")]
use gperftools::profiler::PROFILER;
use hyper::server::conn::AddrIncoming;
use hyper::{Body, Request, Response};

use pprof::protos::Message;
#[cfg(feature = "gperftools")]
use tokio::fs::File;
#[cfg(feature = "gperftools")]
use tokio::io::AsyncReadExt;
use tracing::{error, info};

use crate::workload::WorkloadInformation;
use crate::{config, signal, telemetry};

/// Supports configuring an admin server
pub struct Builder {
    addr: SocketAddr,
    workload_info: WorkloadInformation,
    ready: Ready,
}

pub struct Server {
    addr: SocketAddr,
    ready: Ready,
    server: hyper::server::Builder<hyper::server::conn::AddrIncoming>,
    workload_info: WorkloadInformation,
}

/// Ready tracks whether the process is ready.
#[derive(Clone, Debug, Default)]
pub struct Ready(Arc<Mutex<HashSet<String>>>);

impl Ready {
    pub fn new() -> Ready {
        Ready(Default::default())
    }

    /// register_task allows a caller to add a dependency to be marked "ready".
    pub fn register_task(&self, name: &str) -> BlockReady {
        self.0.lock().unwrap().insert(name.to_string());
        BlockReady {
            parent: self.clone(),
            name: name.to_string(),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.0.lock().unwrap().len() == 0
    }
}

/// BlockReady blocks readiness until it is dropped.
pub struct BlockReady {
    parent: Ready,
    name: String,
}

impl BlockReady {
    pub fn subtask(&self, name: &str) -> BlockReady {
        self.parent.register_task(name)
    }
}

impl Drop for BlockReady {
    fn drop(&mut self) {
        let mut pending = self.parent.0.lock().unwrap();
        let removed = pending.remove(&self.name);
        debug_assert!(removed); // It is a bug to somehow remove something twice
        let left = pending.len();
        let dur = telemetry::APPLICATION_START_TIME.elapsed();
        if left == 0 {
            info!(
                "Task '{}' complete ({dur:?}), marking server ready",
                self.name
            );
        } else {
            info!(
                "Task '{}' complete ({dur:?}), still awaiting {left} tasks",
                self.name
            );
        }
    }
}

impl Builder {
    pub fn new(config: config::Config, workload_info: WorkloadInformation, ready: Ready) -> Self {
        Self {
            addr: config.admin_addr,
            ready,
            workload_info,
        }
    }

    pub fn bind(self) -> hyper::Result<Server> {
        let Self {
            addr,
            ready,
            workload_info,
        } = self;

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
            workload_info,
        })
    }
}

impl Server {
    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn spawn(self, shutdown: &signal::Shutdown, drain_rx: Watch) {
        let _dx = drain_rx.clone();
        let ready = self.ready.clone();
        let workload_info = self.workload_info.clone();
        let shutdown_trigger = shutdown.trigger();
        let server = self
            .server
            .serve(hyper::service::make_service_fn(move |_conn| {
                let ready = ready.clone();
                let workload_info = workload_info.clone();
                let shutdown_trigger = shutdown_trigger.clone();
                async move {
                    let workload_info = workload_info.clone();
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                        let ready = ready.clone();
                        let workload_info = workload_info.clone();
                        let shutdown_trigger = shutdown_trigger.clone();
                        async move {
                            match req.uri().path() {
                                "/healthz/ready" => {
                                    Ok::<_, hyper::Error>(handle_ready(&ready, req).await)
                                }
                                "/debug/pprof/profile" => {
                                    Ok::<_, hyper::Error>(handle_pprof(req).await)
                                }
                                "/debug/gprof/profile" => {
                                    Ok::<_, hyper::Error>(handle_gprof(req).await)
                                }
                                "/debug/gprof/heap" => {
                                    Ok::<_, hyper::Error>(handle_gprof_heap(req).await)
                                }
                                "/quitquitquit" => Ok::<_, hyper::Error>(
                                    handle_server_shutdown(shutdown_trigger, req).await,
                                ),
                                "/config_dump" => Ok::<_, hyper::Error>(
                                    handle_config_dump(workload_info, req).await,
                                ),
                                "/help" => Ok::<_, hyper::Error>(handle_help(req).await),
                                _ => Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(hyper::StatusCode::NOT_FOUND)
                                        .body("Invalid command.\nPlease use /help to get the command list\n".into())
                                        .unwrap(),
                                ),
                            }
                        }
                    }))
                }
            }))
            .with_graceful_shutdown(async {
                drop(drain_rx.signaled().await);
            });

        let shutdown_trigger = shutdown.trigger();
        tokio::spawn(async move {
            info!("Serving admin server at {}", self.addr);
            if let Err(err) = server.await {
                error!("Serving admin start failed: {err}");
                shutdown_trigger.shutdown_now().await;
            } else {
                info!("admin server terminated");
            }
        });
    }
}

async fn handle_ready(ready: &Ready, req: Request<Body>) -> Response<Body> {
    match *req.method() {
        hyper::Method::GET | hyper::Method::HEAD => {
            if ready.is_ready() {
                return Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "text/plain")
                    .body("ready\n".into())
                    .unwrap();
            }

            Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .header(hyper::header::CONTENT_TYPE, "text/plain")
                .body("not ready\n".into())
                .unwrap()
        }
        _ => Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::default())
            .unwrap(),
    }
}

async fn handle_pprof(_req: Request<Body>) -> Response<Body> {
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        // .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .unwrap();

    tokio::time::sleep(Duration::from_secs(10)).await;
    match guard.report().build() {
        Ok(report) => {
            let profile = report.pprof().unwrap();

            let body = profile.write_to_bytes().unwrap();

            Response::builder()
                .status(hyper::StatusCode::OK)
                .body(body.into())
                .unwrap()
        }
        Err(err) => Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(format!("failed to build profile: {}", err).into())
            .unwrap(),
    }
}

async fn handle_server_shutdown(
    shutdown_trigger: signal::ShutdownTrigger,
    _req: Request<Body>,
) -> Response<Body> {
    match *_req.method() {
        hyper::Method::POST => {
            shutdown_trigger.shutdown_now().await;
            Response::builder()
                .status(hyper::StatusCode::OK)
                .header(hyper::header::CONTENT_TYPE, "text/plain")
                .body("shutdown now\n".into())
                .unwrap()
        }
        _ => Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::default())
            .unwrap(),
    }
}

async fn handle_config_dump(dump: WorkloadInformation, _req: Request<Body>) -> Response<Body> {
    let vec = serde_json::to_vec(&dump).unwrap();
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body(vec.into())
        .unwrap()
}

async fn handle_help(_req: Request<Body>) -> Response<Body> {
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body("/healths/ready\t\t\tprint server state\n/debug/pprof/profile\t\tprint the profile data\n/debug/gprof/profile\t\tprint the gprof\n/debug/gprof/heap\t\tprint the heap profile\n/quitquitquit\t\t\texit the ztunnel\n/config_dump\t\t\tprint the workload information\n/help\t\t\t\tprint the command list\n".into())
        .unwrap()
}

#[cfg(feature = "gperftools")]
async fn handle_gprof(_req: Request<Body>) -> Response<Body> {
    const FILE_PATH: &str = "/tmp/profile.prof";
    PROFILER.lock().unwrap().start(FILE_PATH).unwrap();

    tokio::time::sleep(Duration::from_secs(10)).await;
    PROFILER.lock().unwrap().stop().unwrap();

    let mut buffer = Vec::new();
    File::open(FILE_PATH)
        .await
        .unwrap()
        .read_to_end(&mut buffer)
        .await
        .unwrap();
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body(buffer.into())
        .unwrap()
}

#[cfg(not(feature = "gperftools"))]
async fn handle_gprof(_req: Request<Body>) -> Response<Body> {
    Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .body("gperftools not enabled".into())
        .unwrap()
}

#[cfg(feature = "gperftools")]
async fn handle_gprof_heap(_req: Request<Body>) -> Response<Body> {
    const FILE_PATH: &str = "/tmp/profile.prof";
    HEAP_PROFILER.lock().unwrap().start(FILE_PATH).unwrap();

    tokio::time::sleep(Duration::from_secs(10)).await;
    HEAP_PROFILER.lock().unwrap().stop().unwrap();

    let mut buffer = Vec::new();
    File::open(FILE_PATH)
        .await
        .unwrap()
        .read_to_end(&mut buffer)
        .await
        .unwrap();
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body(buffer.into())
        .unwrap()
}

#[cfg(not(feature = "gperftools"))]
async fn handle_gprof_heap(_req: Request<Body>) -> Response<Body> {
    Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .body("gperftools not enabled".into())
        .unwrap()
}
