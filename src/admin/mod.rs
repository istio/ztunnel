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
use tokio::sync::oneshot;

use pprof::protos::Message;
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
#[cfg(feature = "gperftools")]
use tokio::fs::File;
#[cfg(feature = "gperftools")]
use tokio::io::AsyncReadExt;
use tracing::{error, warn, info, debug, trace};

use crate::config::Config;
use crate::version::BuildInfo;
use crate::workload::Workload;
use crate::workload::WorkloadInformation;
use crate::{config, signal, telemetry};

/// Supports configuring an admin server
pub struct Builder {
    addr: SocketAddr,
    workload_info: WorkloadInformation,
    ready: Ready,
    config: Config,
}

pub struct Server {
    addr: SocketAddr,
    ready: Ready,
    server: hyper::server::Builder<hyper::server::conn::AddrIncoming>,
    workload_info: WorkloadInformation,
    registry: Arc<Mutex<Registry>>,
    config: Config,
    shutdown_trigger: signal::ShutdownTrigger,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct ConfigDump {
    #[serde(flatten)]
    workload_info: WorkloadInformation,
    static_workloads: Vec<Workload>,
    version: BuildInfo,
    config: Config,
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
                task = self.name,
                ?dur,
                "Readiness blocker complete, marking server ready",
            );
        } else {
            info!(
                task = self.name,
                ?dur,
                "Readiness blocker complete, still awaiting {left} tasks",
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
            config,
        }
    }

    pub fn bind(
        self,
        registry: Registry,
        shutdown_trigger: signal::ShutdownTrigger,
    ) -> hyper::Result<Server> {
        let Self {
            addr,
            ready,
            workload_info,
            config,
        } = self;

        let bind = AddrIncoming::bind(&addr)?;
        let addr = bind.local_addr();
        let server = hyper::Server::builder(bind)
            .http1_half_close(true)
            .http1_header_read_timeout(Duration::from_secs(2))
            .http1_max_buf_size(8 * 1024);
        let registry = Arc::new(Mutex::new(registry));

        Ok(Server {
            addr,
            ready,
            server,
            workload_info,
            registry,
            config,
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
        let ready = self.ready.clone();
        let (tx, rx) = oneshot::channel();
        let workload_info = self.workload_info.clone();
        let registry = self.registry();
        let config: Config = self.config;
        let shutdown_trigger = self.shutdown_trigger.clone();
        let server = self
            .server
            .serve(hyper::service::make_service_fn(move |_conn| {
                let ready = ready.clone();
                let workload_info = workload_info.clone();
                let registry = Arc::clone(&registry);
                let shutdown_trigger = shutdown_trigger.clone();
                let config: Config = config.clone();
                async move {
                    let workload_info = workload_info.clone();
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                        let ready = ready.clone();
                        let workload_info = workload_info.clone();
                        let registry = Arc::clone(&registry);
                        let shutdown_trigger = shutdown_trigger.clone();
                        let config: Config = config.clone();

                        let config_dump: ConfigDump = ConfigDump {
                            workload_info: (workload_info),
                            static_workloads: ([].to_vec()),
                            version: BuildInfo::new(),
                            config,
                        };
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
                                    handle_config_dump(config_dump, req).await,
                                ),
                                "/metrics" => {
                                    Ok::<_, hyper::Error>(handle_metrics(registry, req).await)
                                }
                                "/logging" => Ok::<_, hyper::Error>(handle_logging(req).await),
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
                    error!("admin receiver dropped")
                }
                info!("starting drain of admin server");
            });

        info!(
            address=%self.addr,
            component="admin",
            "listener established",
        );
        let shutdown_trigger = self.shutdown_trigger;
        tokio::spawn(async move {
            if let Err(err) = server.await {
                error!("Serving admin start failed: {err}");
                shutdown_trigger.shutdown_now().await;
            } else {
                // Now that the server has gracefully exited, drop `shutdown` to allow draining to proceed
                match rx.await {
                    Ok(shutdown) => drop(shutdown),
                    Err(_) => info!("admin sender dropped"),
                }
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

async fn handle_config_dump(mut dump: ConfigDump, _req: Request<Body>) -> Response<Body> {
    if let Some(cfg) = dump.config.local_xds_config.clone() {
        match cfg.read_to_string().await {
            Ok(data) => match serde_yaml::from_str(&data) {
                Ok(raw_workloads) => dump.static_workloads = raw_workloads,
                Err(e) => error!(
                    "Failed to load static workloads from local XDS {:?}:{:?}",
                    dump.config.local_xds_config, e
                ),
            },
            Err(e) => error!(
                "Failed to read local XDS config {:?}:{:?}",
                dump.config.local_xds_config, e
            ),
        }
    }

    let vec = serde_json::to_vec(&dump).unwrap();
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body(vec.into())
        .unwrap()
}

async fn handle_metrics(reg: Arc<Mutex<Registry>>, _req: Request<Body>) -> Response<Body> {
    let mut buf: Vec<u8> = Vec::new();
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

//mirror envoy's behavior: https://www.envoyproxy.io/docs/envoy/latest/operations/admin#post--logging
//NOTE: mutilple query parameters is not supported, for example
//curl -X POST http://127.0.0.1:15021/logging?"tap=debug&router=debug"
static HELP_STRING: &str = "
usage: POST /logging\t\t\t\t\t\t(To list current level)
usage: POST /logging?level=<level>\t\t\t\t(To change global levels)
usage: POST /logging?level={mod1}:{level1},{mod2}:{level2}\t(To change specific mods' logging level)

hint: loglevel:\terror|warn|info|debug|trace|off
hint: mod_name:\tthe module name defined in the cargo.toml, i.e. ztunnel::proxy
";
async fn handle_logging(req: Request<Body>) -> Response<Body> {
    match *req.method() {
        hyper::Method::POST => {
            if let Some(params)  = req
                .uri()
                .query() {
                    let input = params.to_string().to_lowercase();
                    if input.contains("level=") {
                        change_log_level(input.replace("level=", ""))
                    } else {
                        Response::builder()
                        .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
                        .body(format!("only support changing levels\n {}", HELP_STRING).into())
                        .unwrap() 
                    }
            } else {
                list_loggers()
            }
        }
        _ => Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(format!("Invalid HTTP method\n {}", HELP_STRING).into())
            .unwrap(),
    }
}

fn list_loggers() -> Response<Body> {
    warn!("testing warn");
    info!("testing info");
    error!("testing error");
    trace!("testing trace");
    debug!("testing debug");

    if let Some(loglevel) = telemetry::get_current_loglevel() {
        Response::builder()
            .status(hyper::StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(format!("current log level is {}\n", loglevel.to_uppercase()).into())
            .unwrap()
    } else {
        Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body(format!("failed to get the log level\n {}", HELP_STRING).into())
            .unwrap()
    }
}

fn change_log_level(level: String) -> Response<Body> {
    match telemetry::set_mod_level(level) { 
        true => {
            list_loggers()
        }
        false => {
            Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(format!("failed to set new level, please check your parameters\n {}", HELP_STRING).into())
            .unwrap()
        }
    }
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
