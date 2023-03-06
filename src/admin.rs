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

use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Arc;
use std::{net::SocketAddr, time::Duration};

use boring::x509::X509;
use drain::Watch;
#[cfg(feature = "gperftools")]
use gperftools::heap_profiler::HEAP_PROFILER;
#[cfg(feature = "gperftools")]
use gperftools::profiler::PROFILER;
use hyper::{Body, Request, Response};
use pprof::protos::Message;
#[cfg(feature = "gperftools")]
use tokio::fs::File;
#[cfg(feature = "gperftools")]
use tokio::io::AsyncReadExt;
use tracing::error;

use crate::config::Config;
use crate::hyper_util::{empty_response, plaintext_response, Server};
use crate::identity::SecretManager;
use crate::version::BuildInfo;
use crate::workload::LocalConfig;
use crate::workload::WorkloadInformation;
use crate::{signal, telemetry};

struct State {
    workload_info: WorkloadInformation,
    config: Config,
    shutdown_trigger: signal::ShutdownTrigger,
    cert_manager: Arc<SecretManager>,
}

pub struct Service {
    s: Server<State>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct ConfigDump {
    #[serde(flatten)]
    workload_info: WorkloadInformation,
    static_config: LocalConfig,
    version: BuildInfo,
    config: Config,
    certificates: Vec<CertsDump>,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct CertsDump {
    identity: String,
    leaf: String,
    chain: Vec<String>,
}

impl Service {
    pub fn new(
        config: Config,
        workload_info: WorkloadInformation,
        shutdown_trigger: signal::ShutdownTrigger,
        drain_rx: Watch,
        cert_manager: Arc<SecretManager>,
    ) -> hyper::Result<Self> {
        Server::<State>::bind(
            "admin",
            config.admin_addr,
            shutdown_trigger.clone(),
            drain_rx,
            State {
                config,
                workload_info,
                shutdown_trigger,
                cert_manager,
            },
        )
        .map(|s| Service { s })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        self.s.spawn(|state, req| async move {
            match req.uri().path() {
                "/debug/pprof/profile" => Ok(handle_pprof(req).await),
                "/debug/gprof/profile" => Ok(handle_gprof(req).await),
                "/debug/gprof/heap" => Ok(handle_gprof_heap(req).await),
                "/quitquitquit" => {
                    Ok(handle_server_shutdown(state.shutdown_trigger.clone(), req).await)
                }
                "/config_dump" => Ok(handle_config_dump(
                    ConfigDump {
                        workload_info: state.workload_info.clone(),
                        static_config: Default::default(),
                        version: BuildInfo::new(),
                        config: state.config.clone(),
                        certificates: dump_certs(state.cert_manager.borrow()).await,
                    },
                    req,
                )
                .await),
                "/logging" => Ok(handle_logging(req).await),
                _ => Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

fn x509_to_string(x509: &X509) -> String {
    match x509.to_pem() {
        Err(e) => format!("<pem construction error: {e}>"),
        Ok(vec) => match String::from_utf8(vec) {
            Err(e) => format!("<utf8 decode error: {e}>"),
            Ok(s) => s,
        },
    }
}

async fn dump_certs(cert_manager: &SecretManager) -> Vec<CertsDump> {
    cert_manager
        .collect_certs(|id, certs| CertsDump {
            identity: id.to_string(),
            leaf: x509_to_string(certs.x509()),
            chain: certs.iter_chain().map(x509_to_string).collect(),
        })
        .await
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
            format!("Invalid HTTP method\n {HELP_STRING}"),
        ),
    }
}

fn list_loggers() -> Response<Body> {
    match telemetry::get_current_loglevel() {
        Ok(loglevel) => plaintext_response(
            hyper::StatusCode::OK,
            format!("current log level is {loglevel}\n"),
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
