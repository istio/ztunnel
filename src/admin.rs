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

use std::collections::HashMap;
use std::{net::SocketAddr, time::Duration};

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
use tokio::sync::oneshot;
use tracing::{error, info};

use crate::config::Config;
use crate::hyper_util::{empty_response, plaintext_response};
use crate::version::BuildInfo;
use crate::workload::LocalConfig;
use crate::workload::WorkloadInformation;
use crate::{config, signal, telemetry};

/// Supports configuring an admin server
pub struct Builder {
    addr: SocketAddr,
    workload_info: WorkloadInformation,
    config: Config,
}

pub struct Server {
    addr: SocketAddr,
    server: hyper::server::Builder<AddrIncoming>,
    workload_info: WorkloadInformation,
    config: Config,
    shutdown_trigger: signal::ShutdownTrigger,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct ConfigDump {
    #[serde(flatten)]
    workload_info: WorkloadInformation,
    static_config: LocalConfig,
    version: BuildInfo,
    config: Config,
}

impl Builder {
    pub fn new(config: config::Config, workload_info: WorkloadInformation) -> Self {
        Self {
            addr: config.admin_addr,
            workload_info,
            config,
        }
    }

    pub fn bind(self, shutdown_trigger: signal::ShutdownTrigger) -> hyper::Result<Server> {
        let Self {
            addr,
            workload_info,
            config,
        } = self;

        let bind = AddrIncoming::bind(&addr)?;
        let addr = bind.local_addr();
        let server = hyper::Server::builder(bind)
            .http1_half_close(true)
            .http1_header_read_timeout(Duration::from_secs(2))
            .http1_max_buf_size(8 * 1024);

        Ok(Server {
            addr,
            server,
            workload_info,
            config,
            shutdown_trigger,
        })
    }
}

impl Server {
    pub fn address(&self) -> SocketAddr {
        self.addr
    }

    pub fn spawn(self, drain_rx: Watch) {
        let _dx = drain_rx.clone();
        let (tx, rx) = oneshot::channel();
        let workload_info = self.workload_info.clone();
        let config: Config = self.config;
        let shutdown_trigger = self.shutdown_trigger.clone();
        let server = self
            .server
            .serve(hyper::service::make_service_fn(move |_conn| {
                let workload_info = workload_info.clone();
                let shutdown_trigger = shutdown_trigger.clone();
                let config: Config = config.clone();
                async move {
                    let workload_info = workload_info.clone();
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                        let workload_info = workload_info.clone();
                        let shutdown_trigger = shutdown_trigger.clone();
                        let config: Config = config.clone();

                        let config_dump: ConfigDump = ConfigDump {
                            workload_info,
                            static_config: Default::default(),
                            version: BuildInfo::new(),
                            config,
                        };
                        async move {
                            match req.uri().path() {
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
                                "/logging" => Ok::<_, hyper::Error>(handle_logging(req).await),
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
        Err(err) => plaintext_response(
            hyper::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to build profile: {err}\n"),
        ),
    }
}

async fn handle_server_shutdown(
    shutdown_trigger: signal::ShutdownTrigger,
    _req: Request<Body>,
) -> Response<Body> {
    match *_req.method() {
        hyper::Method::POST => {
            shutdown_trigger.shutdown_now().await;
            plaintext_response(hyper::StatusCode::OK, "shutdown now\n".into())
        }
        _ => empty_response(hyper::StatusCode::METHOD_NOT_ALLOWED),
    }
}

async fn handle_config_dump(mut dump: ConfigDump, _req: Request<Body>) -> Response<Body> {
    if let Some(cfg) = dump.config.local_xds_config.clone() {
        match cfg.read_to_string().await {
            Ok(data) => match serde_yaml::from_str(&data) {
                Ok(c) => dump.static_config = c,
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

//mirror envoy's behavior: https://www.envoyproxy.io/docs/envoy/latest/operations/admin#post--logging
//NOTE: multiple query parameters is not supported, for example
//curl -X POST http://127.0.0.1:15000/logging?"tap=debug&router=debug"
static HELP_STRING: &str = "
usage: POST /logging\t\t\t\t\t\t(To list current level)
usage: POST /logging?level=<level>\t\t\t\t(To change global levels)
usage: POST /logging?level={mod1}:{level1},{mod2}:{level2}\t(To change specific mods' logging level)

hint: loglevel:\terror|warn|info|debug|trace|off
hint: mod_name:\tthe module name, i.e. ztunnel::proxy
";
async fn handle_logging(req: Request<Body>) -> Response<Body> {
    match *req.method() {
        hyper::Method::POST => {
            let qp = req
                .uri()
                .query()
                .map(|v| {
                    url::form_urlencoded::parse(v.as_bytes())
                        .into_owned()
                        .collect()
                })
                .unwrap_or_else(HashMap::new);
            let level = qp.get("level").cloned();
            let reset = qp.get("reset").cloned();
            if level.is_some() || reset.is_some() {
                change_log_level(reset.is_some(), &level.unwrap_or_default())
            } else {
                list_loggers()
            }
        }
        _ => plaintext_response(
            hyper::StatusCode::METHOD_NOT_ALLOWED,
            format!("Invalid HTTP method\n {}", HELP_STRING),
        ),
    }
}

fn list_loggers() -> Response<Body> {
    match telemetry::get_current_loglevel() {
        Ok(loglevel) => plaintext_response(
            hyper::StatusCode::OK,
            format!("current log level is {}\n", loglevel),
        ),
        Err(err) => plaintext_response(
            hyper::StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to get the log level: {err}\n {HELP_STRING}"),
        ),
    }
}

fn change_log_level(reset: bool, level: &str) -> Response<Body> {
    match telemetry::set_level(reset, level) {
        Ok(_) => list_loggers(),
        Err(e) => plaintext_response(
            hyper::StatusCode::METHOD_NOT_ALLOWED,
            format!("failed to set new level: {e}\n{HELP_STRING}",),
        ),
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
