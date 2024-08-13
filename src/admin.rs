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

use crate::config::Config;
use crate::hyper_util::{empty_response, plaintext_response, Server};
use crate::identity::SecretManager;
use crate::state::DemandProxyState;
use crate::tls::Certificate;
use crate::version::BuildInfo;
use crate::xds::LocalConfig;
use crate::{signal, telemetry};

use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{header::HeaderValue, header::CONTENT_TYPE, Request, Response};
use pprof::protos::Message;
use std::borrow::Borrow;
use std::collections::HashMap;

use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use std::{net::SocketAddr, time::Duration};

use crate::drain::DrainWatcher;
use tokio::time;
use tracing::{error, info, warn};
use tracing_subscriber::filter;

pub trait AdminHandler: Sync + Send {
    fn path(&self) -> &'static str;
    fn description(&self) -> &'static str;
    // sadly can't use async trait because no Sync
    // see: https://github.com/dtolnay/async-trait/issues/248, https://github.com/dtolnay/async-trait/issues/142
    // we can't use FutureExt::shared because our result is not clonable
    fn handle(
        &self,
        req: Request<Incoming>,
    ) -> std::pin::Pin<Box<dyn futures_util::Future<Output = Response<Full<Bytes>>> + Sync + Send>>;
}

pub trait AdminHandler2: Sync + Send {
    fn key(&self) -> &'static str;
    // sadly can't use async trait because no Sync
    // see: https://github.com/dtolnay/async-trait/issues/248, https://github.com/dtolnay/async-trait/issues/142
    // we can't use FutureExt::shared because our result is not clonable
    fn handle(&self) -> anyhow::Result<serde_json::Value>;
}

struct State {
    proxy_state: DemandProxyState,
    config: Arc<Config>,
    shutdown_trigger: signal::ShutdownTrigger,
    cert_manager: Arc<SecretManager>,
    handlers: Vec<Arc<dyn AdminHandler2>>,
}

pub struct Service {
    s: Server<State>,
}

#[derive(serde::Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ConfigDump {
    #[serde(flatten)]
    proxy_state: DemandProxyState,
    static_config: LocalConfig,
    version: BuildInfo,
    config: Arc<Config>,
    certificates: Vec<CertsDump>,
}

#[derive(serde::Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CertDump {
    // Not available via Envoy, but still useful.
    pem: String,
    serial_number: String,
    valid_from: String,
    expiration_time: String,
}

#[derive(serde::Serialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct CertsDump {
    identity: String,
    state: String,
    cert_chain: Vec<CertDump>,
}

impl Service {
    pub async fn new(
        config: Arc<Config>,
        proxy_state: DemandProxyState,
        shutdown_trigger: signal::ShutdownTrigger,
        drain_rx: DrainWatcher,
        cert_manager: Arc<SecretManager>,
    ) -> anyhow::Result<Self> {
        Server::<State>::bind(
            "admin",
            config.admin_addr,
            drain_rx,
            State {
                config,
                proxy_state,
                shutdown_trigger,
                cert_manager,
                handlers: vec![],
            },
        )
        .await
        .map(|s| Service { s })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn add_handler(&mut self, handler: Arc<dyn AdminHandler2>) {
        self.s.state_mut().handlers.push(handler);
    }

    pub fn spawn(self) {
        self.s.spawn(|state, req| async move {
            match req.uri().path() {
                "/debug/pprof/profile" => handle_pprof(req).await,
                "/debug/pprof/heap" => handle_jemalloc_pprof_heapgen(req).await,
                "/quitquitquit" => Ok(handle_server_shutdown(
                    state.shutdown_trigger.clone(),
                    req,
                    state.config.self_termination_deadline,
                )
                .await),
                "/config_dump" => {
                    handle_config_dump(
                        &state.handlers,
                        ConfigDump {
                            proxy_state: state.proxy_state.clone(),
                            static_config: Default::default(),
                            version: BuildInfo::new(),
                            config: state.config.clone(),
                            certificates: dump_certs(state.cert_manager.borrow()).await,
                        },
                    )
                    .await
                }
                "/logging" => Ok(handle_logging(req).await),
                "/" => Ok(handle_dashboard(req).await),
                _ => Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

async fn handle_dashboard(_req: Request<Incoming>) -> Response<Full<Bytes>> {
    let apis = &[
        (
            "debug/pprof/profile",
            "build profile using the pprof profiler (if supported)",
        ),
        (
            "debug/pprof/heap",
            "collect heap profiling data (if supported, requires jmalloc)",
        ),
        ("quitquitquit", "shut down the server"),
        ("config_dump", "dump the current Ztunnel configuration"),
        ("logging", "query/changing logging levels"),
    ];

    let mut api_rows = String::new();

    for (index, (path, description)) in apis.iter().copied().enumerate() {
        api_rows.push_str(&format!(
            "<tr class=\"{row_class}\"><td class=\"home-data\"><a href=\"{path}\">{path}</a></td><td class=\"home-data\">{description}</td></tr>\n",
            row_class = if index % 2 == 1 { "gray" } else { "vert-space" },
            path = path,
            description = description
        ));
    }

    let html_str = include_str!("./assets/dashboard.html");
    let html_str = html_str.replace("<!--API_ROWS_PLACEHOLDER-->", &api_rows);

    let mut response = plaintext_response(hyper::StatusCode::OK, html_str);
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );

    response
}

fn rfc3339(t: SystemTime) -> String {
    use chrono::prelude::{DateTime, Utc};
    let dt: DateTime<Utc> = t.into();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn dump_cert(cert: &Certificate) -> CertDump {
    CertDump {
        pem: base64_encode(cert.as_pem()),
        serial_number: cert.serial(),
        valid_from: rfc3339(cert.expiration().not_before),
        expiration_time: rfc3339(cert.expiration().not_after),
    }
}

async fn dump_certs(cert_manager: &SecretManager) -> Vec<CertsDump> {
    let mut dump = cert_manager
        .collect_certs(|id, certs| {
            let mut dump = CertsDump {
                identity: id.to_string(),
                ..Default::default()
            };
            use crate::identity::CertState::*;
            match certs {
                Initializing(_) => dump.state = "Initializing".to_string(),
                Unavailable(err) => dump.state = format!("Unavailable: {err}"),
                Available(certs) => {
                    dump.state = "Available".to_string();
                    dump.cert_chain = std::iter::once(&certs.cert)
                        .chain(certs.chain.iter())
                        .map(dump_cert)
                        .collect();
                }
            };
            dump
        })
        .await;
    // Sort for determinism.
    dump.sort_by(|a, b| a.identity.cmp(&b.identity));
    dump
}

async fn handle_pprof(_req: Request<Incoming>) -> anyhow::Result<Response<Full<Bytes>>> {
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        // .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()?;

    tokio::time::sleep(Duration::from_secs(10)).await;
    let report = guard.report().build()?;
    let profile = report.pprof()?;

    let body = profile.write_to_bytes()?;

    Ok(Response::builder()
        .status(hyper::StatusCode::OK)
        .body(body.into())
        .expect("builder with known status code should not fail"))
}

async fn handle_server_shutdown(
    shutdown_trigger: signal::ShutdownTrigger,
    _req: Request<Incoming>,
    self_term_wait: Duration,
) -> Response<Full<Bytes>> {
    match *_req.method() {
        hyper::Method::POST => {
            match time::timeout(self_term_wait, shutdown_trigger.shutdown_now()).await {
                Ok(()) => info!("Shutdown completed gracefully"),
                Err(_) => warn!(
                    "Graceful shutdown did not complete in {:?}, terminating now",
                    self_term_wait
                ),
            }
            plaintext_response(hyper::StatusCode::OK, "shutdown now\n".into())
        }
        _ => empty_response(hyper::StatusCode::METHOD_NOT_ALLOWED),
    }
}

async fn handle_config_dump(
    handlers: &[Arc<dyn AdminHandler2>],
    mut dump: ConfigDump,
) -> anyhow::Result<Response<Full<Bytes>>> {
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

    let serde_json::Value::Object(mut kv) = serde_json::to_value(&dump)? else {
        anyhow::bail!("config dump is not a key-value pair")
    };

    for h in handlers {
        let x = h.handle()?;
        kv.insert(h.key().to_string(), x);
    }
    let body = serde_json::to_string_pretty(&kv)?;
    Ok(Response::builder()
        .status(hyper::StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(body.into())
        .expect("builder with known status code should not fail"))
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
async fn handle_logging(req: Request<Incoming>) -> Response<Full<Bytes>> {
    match *req.method() {
        hyper::Method::POST => {
            let qp: HashMap<String, String> = req
                .uri()
                .query()
                .map(|v| {
                    url::form_urlencoded::parse(v.as_bytes())
                        .into_owned()
                        .collect()
                })
                .unwrap_or_default();
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

fn list_loggers() -> Response<Full<Bytes>> {
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

fn validate_log_level(level: &str) -> anyhow::Result<()> {
    for clause in level.split(',') {
        // We support 2 forms, compared to the underlying library
        // <level>: supported, sets the default
        // <scope>:<level>: supported, sets a scope's level
        // <scope>: sets the scope to 'trace' level. NOT SUPPORTED.
        match clause {
            "off" | "error" | "warn" | "info" | "debug" | "trace" => continue,
            s if s.contains('=') => {
                filter::Targets::from_str(s)?;
            }
            s => anyhow::bail!("level {s} is invalid"),
        }
    }
    Ok(())
}

fn change_log_level(reset: bool, level: &str) -> Response<Full<Bytes>> {
    if !reset && level.is_empty() {
        return list_loggers();
    }
    if !level.is_empty() {
        if let Err(_e) = validate_log_level(level) {
            // Invalid level provided
            return plaintext_response(
                hyper::StatusCode::BAD_REQUEST,
                format!("Invalid level provided: {}\n{}", level, HELP_STRING),
            );
        };
    }
    match telemetry::set_level(reset, level) {
        Ok(_) => list_loggers(),
        Err(e) => plaintext_response(
            hyper::StatusCode::BAD_REQUEST,
            format!("Failed to set new level: {}\n{}", e, HELP_STRING),
        ),
    }
}

#[cfg(feature = "jemalloc")]
async fn handle_jemalloc_pprof_heapgen(
    _req: Request<Incoming>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let Some(prof_ctrl) = jemalloc_pprof::PROF_CTL.as_ref() else {
        return Ok(Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body("jemalloc profiling is not enabled".into())
            .expect("builder with known status code should not fail"));
    };
    let mut prof_ctl = prof_ctrl.lock().await;
    if !prof_ctl.activated() {
        return Ok(Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body("jemalloc not enabled".into())
            .expect("builder with known status code should not fail"));
    }
    let pprof = prof_ctl.dump_pprof()?;
    Ok(Response::builder()
        .status(hyper::StatusCode::OK)
        .body(Bytes::from(pprof).into())
        .expect("builder with known status code should not fail"))
}

#[cfg(not(feature = "jemalloc"))]
async fn handle_jemalloc_pprof_heapgen(
    _req: Request<Incoming>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    Ok(Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .body("jemalloc not enabled".into())
        .expect("builder with known status code should not fail"))
}

fn base64_encode(data: String) -> String {
    use base64::Engine;
    STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::change_log_level;
    use super::dump_certs;
    use super::handle_config_dump;
    use super::ConfigDump;
    use crate::admin::HELP_STRING;
    use crate::config::construct_config;
    use crate::config::ProxyConfig;
    use crate::identity;
    use crate::strng;
    use crate::test_helpers::{get_response_str, helpers, new_proxy_state};
    use crate::xds::istio::security::string_match::MatchType as XdsMatchType;
    use crate::xds::istio::security::Address as XdsAddress;
    use crate::xds::istio::security::Authorization as XdsAuthorization;
    use crate::xds::istio::security::Clause as XdsClause;
    use crate::xds::istio::security::Match as XdsMatch;
    use crate::xds::istio::security::Rule as XdsRule;
    use crate::xds::istio::security::StringMatch as XdsStringMatch;
    use crate::xds::istio::workload::gateway_address::Destination as XdsDestination;
    use crate::xds::istio::workload::GatewayAddress as XdsGatewayAddress;
    use crate::xds::istio::workload::LoadBalancing as XdsLoadBalancing;
    use crate::xds::istio::workload::Locality as XdsLocality;
    use crate::xds::istio::workload::NetworkAddress as XdsNetworkAddress;
    use crate::xds::istio::workload::Port as XdsPort;
    use crate::xds::istio::workload::PortList as XdsPortList;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::WorkloadType as XdsWorkloadType;
    use bytes::Bytes;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    fn diff_json<'a>(a: &'a serde_json::Value, b: &'a serde_json::Value) -> String {
        let mut ret = String::new();
        let a = serde_json::to_string_pretty(a).unwrap();
        let b = serde_json::to_string_pretty(b).unwrap();
        for diff in diff::lines(&a, &b) {
            use diff::Result::*;
            use std::fmt::Write;
            match diff {
                Left(l) => writeln!(ret, " - {l}"),
                Right(r) => writeln!(ret, " + {r}"),
                Both(s, _) => writeln!(ret, "{s}"),
            }
            .unwrap();
        }
        ret
    }

    // Not really much to test, mostly to make sure things format as expected.
    #[tokio::test(start_paused = true)]
    async fn test_dump_certs() {
        fn identity(s: impl AsRef<str>) -> identity::Identity {
            use std::str::FromStr;
            identity::Identity::from_str(s.as_ref()).unwrap()
        }

        let manager = identity::mock::new_secret_manager_cfg(identity::mock::SecretManagerConfig {
            cert_lifetime: Duration::from_secs(7 * 60 * 60),
            fetch_latency: Duration::from_secs(1),
            epoch: Some(
                // Arbitrary point in time used to ensure deterministic certificate generation.
                chrono::DateTime::parse_from_rfc3339("2023-03-11T05:57:26Z")
                    .unwrap()
                    .into(),
            ),
        });
        for i in 0..2 {
            manager
                .fetch_certificate(&identity::Identity::Spiffe {
                    trust_domain: "trust_domain".into(),
                    namespace: "namespace".into(),
                    service_account: strng::format!("sa-{i}"),
                })
                .await
                .unwrap();
            // Make sure certificates are a significant amount of time apart, for better
            // readability.
            tokio::time::sleep(Duration::from_secs(60 * 60 - 1)).await;
        }

        manager
            .fetch_certificate(&identity("spiffe://error/ns/forgotten/sa/sa-failed"))
            .await
            .unwrap_err();

        // Start a fetch asynchronously and proceed enough to have it pending, but not finish.
        let pending_manager = manager.clone();
        let pending_fetch = tokio::task::spawn(async move {
            pending_manager
                .fetch_certificate(&identity("spiffe://test/ns/test/sa/sa-pending"))
                .await
        });
        tokio::time::sleep(Duration::from_nanos(1)).await;

        let got = serde_json::to_value(dump_certs(&manager).await).unwrap();
        let want = serde_json::json!([
          {
            "certChain": [],
            "identity": "spiffe://error/ns/forgotten/sa/sa-failed",
            "state": "Unavailable: the identity is no longer needed"
          },
          {
            "certChain": [],
            "identity": "spiffe://test/ns/test/sa/sa-pending",
            "state": "Initializing"
          },
          {
            "certChain": [
              {
                "expirationTime": "2023-03-11T12:57:26Z",
                "pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNXekNDQVVPZ0F3SUJBZ0lVWnlUOTI5c3d0QjhPSG1qUmFURWFENnlqcWc0d0RRWUpLb1pJaHZjTgpBUUVMQlFBd0dERVdNQlFHQTFVRUNnd05ZMngxYzNSbGNpNXNiMk5oYkRBZUZ3MHlNekF6TVRFd05UVTMKTWpaYUZ3MHlNekF6TVRFeE1qVTNNalphTUJneEZqQVVCZ05WQkFvTURXTnNkWE4wWlhJdWJHOWpZV3d3CldUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSYXIyQm1JWUFndkptT3JTcENlRlE3OUpQeQo4Y3c0K3pFRThmcXI1N2svdW1NcDVqWFpFR0JwZWRCSVkrcWZtSlBYRWlyYTlFOTJkU21rZks1QUtNV3gKbzJnd1pqQTFCZ05WSFJFRUxqQXNoaXB6Y0dsbVptVTZMeTkwY25WemRGOWtiMjFoYVc0dmJuTXZibUZ0ClpYTndZV05sTDNOaEwzTmhMVEF3RGdZRFZSMFBBUUgvQkFRREFnV2dNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQkJnZ3JCZ0VGQlFjREFqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFjTzNlMjAvK0ZrRkwKUmttMTNtQlFNYjVPUmpTOGhwWjBRMkZKd2wrSXV4TGY2MUJDZS9RVlhOVklpSUdlMXRVRTh5UTRoMXZrCjhVb01sSmpTQkdiM3VDdHVLRFVKN0xOM1VBUmV4YU1uQkZobC9mWmQxU3ZZcmhlWjU3WDlrTElVa2hkSQpDUVdxOFVFcXBWZEloNGxTZjhoYnFRQksvUWhCN0I2bUJOSW5uMThZTEhiOEpmU0N2aXBWYTRuNXByTlYKbVNWc1JPMUtpY1FQYVhpUzJta0xBWVFRanROYkVJdnJwQldCYytmVWZPaEQ0YmhwUFVmSVFIN1dFcUZLCm5TMnQwSmh1d08zM2FoUDhLZVBWWDRDRkJ4VXc2SDhrd1dJUkh5dW9YbGFwMmVST1EycFRyYmtmVjJZbgpmWjZxV0huREJ5ZjN6bkFQQVM1ZnZ4b1RoKzBYTHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
                "serialNumber": "588850990443535479077311695632745359443207891470",
                "validFrom": "2023-03-11T05:57:26Z"
              },
              {
                "expirationTime": "2296-12-24T18:31:28Z",
                "pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURFekNDQWZ1Z0F3SUJBZ0lVQytjLzYwZStGMWVFKzdWcXhuYVdjT09abm1Fd0RRWUpLb1pJaHZjTgpBUUVMQlFBd0dERVdNQlFHQTFVRUNnd05ZMngxYzNSbGNpNXNiMk5oYkRBZ0Z3MHlNekF6TVRFeE9ETXgKTWpoYUdBOHlNamsyTVRJeU5ERTRNekV5T0Zvd0dERVdNQlFHQTFVRUNnd05ZMngxYzNSbGNpNXNiMk5oCmJEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1lQ1R4UEp0dWQwVXh3KwpDYWFkZFdEN2ErUUV1UVkrQlBUS0pkbk1lajBzQk1mVU1iVDE2SkxrWU5GZ3JqMVVWSEhjcFNvSUhvY3AKMnNkMzJTWTRiZGJva1Fjb3ArQmp0azU1alE0NktMWXNKZ2IyTnd2WW8xdDhFMWFldEpxRkdWN3JtZVpiCkZZZWFpKzZxN2lNamxiQ0dBdTcvVW5LSnNkR25hSlFnTjhkdTBUMUtEZ2pxS1B5SHFkc3U5a2JwQ3FpRQpYTVJtdzQvQkVoRkd6bUlEMm9VREtCMzZkdVZiZHpTRW01MVF2Z1U1SUxYSWd5VnJlak41Q0ZzQytXK3gKamVPWExFenRmSEZVb3FiM3dXaGtCdUV4bXI4MUoyaEdXOXBVTEoyd2tRZ2RmWFA3Z3RNa0I2RXlLdy94CkllYU5tTHpQSUdyWDAxelFZSWRaVHVEd01ZMENBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGRDhrNGYxYQpya3V3UitVUmhLQWUySVRaS1o3Vk1COEdBMVVkSXdRWU1CYUFGRDhrNGYxYXJrdXdSK1VSaEtBZTJJVFoKS1o3Vk1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFLcm5BZVNzClNTSzMvOHp4K2h6ajZTRlhkSkE5Q1EwMkdFSjdoSHJLaWpHV1ZZZGRhbDlkQWJTNXRMZC8vcUtPOXVJcwpHZXR5L09rMmJSUTZjcXFNbGdkTnozam1tcmJTbFlXbUlYSTB5SEdtQ2lTYXpIc1hWYkVGNkl3eTN0Y1IKNHZvWFdLSUNXUGgrQzJjVGdMbWVaMEV1ekZ4cTR3Wm5DZjQwd0tvQUo5aTFhd1NyQm5FOWpXdG5wNEY0CmhXbkpUcEdreTVkUkFMRTBsLzJBYnJsMzh3Z2ZNOHI0SW90bVBUaEZLbkZlSUhVN2JRMXJZQW9xcGJBaApDdjBCTjVQakFRUldNazZib28zZjBha1MwN25sWUlWcVhoeHFjWW5PZ3drZGxUdFg5TXFHSXEyNm44bjEKTldXd25tS09qTnNrNnFSbXVsRWdlR080dnhUdlNKWWIraFU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
                "serialNumber": "67955938755654933561614970125599055831405010529",
                "validFrom": "2023-03-11T18:31:28Z"
              }
            ],
            "identity": "spiffe://trust_domain/ns/namespace/sa/sa-0",
            "state": "Available"
          },
          {
            "certChain": [
              {
                "expirationTime": "2023-03-11T13:57:26Z",
                "pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNXekNDQVVPZ0F3SUJBZ0lVWElQK29ySVF3dDZFUGRLSFdRU0VMOTM0bjdFd0RRWUpLb1pJaHZjTgpBUUVMQlFBd0dERVdNQlFHQTFVRUNnd05ZMngxYzNSbGNpNXNiMk5oYkRBZUZ3MHlNekF6TVRFd05qVTMKTWpaYUZ3MHlNekF6TVRFeE16VTNNalphTUJneEZqQVVCZ05WQkFvTURXTnNkWE4wWlhJdWJHOWpZV3d3CldUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSYXIyQm1JWUFndkptT3JTcENlRlE3OUpQeQo4Y3c0K3pFRThmcXI1N2svdW1NcDVqWFpFR0JwZWRCSVkrcWZtSlBYRWlyYTlFOTJkU21rZks1QUtNV3gKbzJnd1pqQTFCZ05WSFJFRUxqQXNoaXB6Y0dsbVptVTZMeTkwY25WemRGOWtiMjFoYVc0dmJuTXZibUZ0ClpYTndZV05sTDNOaEwzTmhMVEV3RGdZRFZSMFBBUUgvQkFRREFnV2dNQjBHQTFVZEpRUVdNQlFHQ0NzRwpBUVVGQndNQkJnZ3JCZ0VGQlFjREFqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFHV2tCY1plUEhrZisKSEpoazY5NHhDaHZLVENkVlRoNE9QNTBvWC9TdE0vK3NsazU0Y2RkcnRpOG0rdEFnai8wK0FLaFhpSTJaCjBNRFZPaEpOWTVRT1VXdkVBUWNYVTlPR2NCWmsyRWNGVW9BOC9RRzFpcVB3ejJJRGluakYrb3lTWExEdApFRGxPdW1Sa3VETWtyME51TGNZTlJuYUI0LzMreDAvdVlRM2M3TXpvUEtUQmZQdW1DY0wzbG5mR1dGR3kKc1d3b1p5V01CK1ZFdjYzK2psdTZDZmwzUGN1NEtFNHVhQUJiWHVvRkhjeU8yMW5sZVVvT3Z2VXhLZDdGCkxvQWNsVDNaSUI3dzNUcXE2MFR3UlV6ZGZkQlA5UURabEVSL1JLTDZWbnBBUVZhbXZBWmNjZFVuTWZjOAppT0N6TWVqV2tweGxXL3MrMW1nMUxzQWxyYlJMdHc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
                "serialNumber": "528170730419860468572163268563070820131458817969",
                "validFrom": "2023-03-11T06:57:26Z"
              },
              {
                "expirationTime": "2296-12-24T18:31:28Z",
                "pem": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURFekNDQWZ1Z0F3SUJBZ0lVQytjLzYwZStGMWVFKzdWcXhuYVdjT09abm1Fd0RRWUpLb1pJaHZjTgpBUUVMQlFBd0dERVdNQlFHQTFVRUNnd05ZMngxYzNSbGNpNXNiMk5oYkRBZ0Z3MHlNekF6TVRFeE9ETXgKTWpoYUdBOHlNamsyTVRJeU5ERTRNekV5T0Zvd0dERVdNQlFHQTFVRUNnd05ZMngxYzNSbGNpNXNiMk5oCmJEQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU1lQ1R4UEp0dWQwVXh3KwpDYWFkZFdEN2ErUUV1UVkrQlBUS0pkbk1lajBzQk1mVU1iVDE2SkxrWU5GZ3JqMVVWSEhjcFNvSUhvY3AKMnNkMzJTWTRiZGJva1Fjb3ArQmp0azU1alE0NktMWXNKZ2IyTnd2WW8xdDhFMWFldEpxRkdWN3JtZVpiCkZZZWFpKzZxN2lNamxiQ0dBdTcvVW5LSnNkR25hSlFnTjhkdTBUMUtEZ2pxS1B5SHFkc3U5a2JwQ3FpRQpYTVJtdzQvQkVoRkd6bUlEMm9VREtCMzZkdVZiZHpTRW01MVF2Z1U1SUxYSWd5VnJlak41Q0ZzQytXK3gKamVPWExFenRmSEZVb3FiM3dXaGtCdUV4bXI4MUoyaEdXOXBVTEoyd2tRZ2RmWFA3Z3RNa0I2RXlLdy94CkllYU5tTHpQSUdyWDAxelFZSWRaVHVEd01ZMENBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGRDhrNGYxYQpya3V3UitVUmhLQWUySVRaS1o3Vk1COEdBMVVkSXdRWU1CYUFGRDhrNGYxYXJrdXdSK1VSaEtBZTJJVFoKS1o3Vk1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFLcm5BZVNzClNTSzMvOHp4K2h6ajZTRlhkSkE5Q1EwMkdFSjdoSHJLaWpHV1ZZZGRhbDlkQWJTNXRMZC8vcUtPOXVJcwpHZXR5L09rMmJSUTZjcXFNbGdkTnozam1tcmJTbFlXbUlYSTB5SEdtQ2lTYXpIc1hWYkVGNkl3eTN0Y1IKNHZvWFdLSUNXUGgrQzJjVGdMbWVaMEV1ekZ4cTR3Wm5DZjQwd0tvQUo5aTFhd1NyQm5FOWpXdG5wNEY0CmhXbkpUcEdreTVkUkFMRTBsLzJBYnJsMzh3Z2ZNOHI0SW90bVBUaEZLbkZlSUhVN2JRMXJZQW9xcGJBaApDdjBCTjVQakFRUldNazZib28zZjBha1MwN25sWUlWcVhoeHFjWW5PZ3drZGxUdFg5TXFHSXEyNm44bjEKTldXd25tS09qTnNrNnFSbXVsRWdlR080dnhUdlNKWWIraFU9Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
                "serialNumber": "67955938755654933561614970125599055831405010529",
                "validFrom": "2023-03-11T18:31:28Z"
              }
            ],
            "identity": "spiffe://trust_domain/ns/namespace/sa/sa-1",
            "state": "Available"
          }
        ]);
        assert_eq!(
            got,
            want,
            "Certificate lists do not match (-want, +got):\n{}",
            diff_json(&want, &got)
        );
        pending_fetch.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn test_dump_config() {
        let manager = identity::mock::new_secret_manager_cfg(identity::mock::SecretManagerConfig {
            cert_lifetime: Duration::from_secs(7 * 60 * 60),
            fetch_latency: Duration::from_secs(1),
            epoch: Some(
                // Arbitrary point in time used to ensure deterministic certificate generation.
                chrono::DateTime::parse_from_rfc3339("2023-03-11T05:57:26Z")
                    .unwrap()
                    .into(),
            ),
        });

        let wl = XdsWorkload {
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
            hostname: "".to_string(),
            waypoint: Some(XdsGatewayAddress {
                destination: Some(XdsDestination::Address(XdsNetworkAddress {
                    network: "defaultnw".to_string(),
                    address: [127, 0, 0, 10].to_vec(),
                })),
                hbone_mtls_port: 15008,
            }),
            network_gateway: Some(XdsGatewayAddress {
                destination: Some(XdsDestination::Address(XdsNetworkAddress {
                    network: "defaultnw".to_string(),
                    address: [127, 0, 0, 11].to_vec(),
                })),
                hbone_mtls_port: 15008,
            }),
            tunnel_protocol: Default::default(),
            network_mode: Default::default(),
            uid: "uid".to_string(),
            name: "name".to_string(),
            namespace: "namespace".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            network: "defaultnw".to_string(),
            workload_name: "workload_name".to_string(),
            canonical_name: "canonical_name".to_string(),
            canonical_revision: "canonical_revision".to_string(),
            node: "node".to_string(),
            status: Default::default(),
            cluster_id: "Kubernetes".to_string(),
            authorization_policies: Vec::new(),
            native_tunnel: false,
            application_tunnel: None,
            workload_type: XdsWorkloadType::Deployment.into(),
            services: HashMap::from([(
                "ns/svc1.ns.svc.cluster.local".to_string(),
                XdsPortList {
                    ports: vec![XdsPort {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            locality: Some(XdsLocality {
                region: "region".to_string(),
                zone: "zone".to_string(),
                subzone: "subezone".to_string(),
            }),
            // ..Default::default() // intentionally don't default. we want all fields populated
        };

        let svc = XdsService {
            name: "svc1".to_string(),
            namespace: "ns".to_string(),
            hostname: "svc1.ns.svc.cluster.local".to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "defaultnw".to_string(),
                address: [127, 0, 1, 1].to_vec(),
            }],
            ports: vec![XdsPort {
                service_port: 80,
                target_port: 80,
            }],
            subject_alt_names: vec!["SAN1".to_string(), "SAN2".to_string()],
            waypoint: None,
            load_balancing: Some(XdsLoadBalancing {
                routing_preference: vec![1, 2],
                mode: 1,
                health_policy: 1,
            }), // ..Default::default() // intentionally don't default. we want all fields populated
            ip_families: 0,
        };

        let auth = XdsAuthorization {
            name: "svc1".to_string(),
            namespace: "ns".to_string(),
            scope: 0,
            action: 0,
            rules: vec![XdsRule {
                clauses: vec![XdsClause {
                    matches: vec![XdsMatch {
                        destination_ports: vec![80],
                        not_destination_ports: vec![8080],
                        source_ips: vec![XdsAddress {
                            address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                            length: 32,
                        }],
                        not_source_ips: vec![XdsAddress {
                            address: Bytes::copy_from_slice(&[127, 0, 0, 1]),
                            length: 32,
                        }],
                        destination_ips: vec![XdsAddress {
                            address: Bytes::copy_from_slice(&[127, 0, 0, 3]),
                            length: 32,
                        }],
                        not_destination_ips: vec![XdsAddress {
                            address: Bytes::copy_from_slice(&[127, 0, 0, 4]),
                            length: 32,
                        }],
                        namespaces: vec![XdsStringMatch {
                            match_type: Some(XdsMatchType::Exact("ns".to_string())),
                        }],
                        not_namespaces: vec![XdsStringMatch {
                            match_type: Some(XdsMatchType::Exact("not-ns".to_string())),
                        }],
                        principals: vec![XdsStringMatch {
                            match_type: Some(XdsMatchType::Exact(
                                "spiffe://cluster.local/ns/ns/sa/sa".to_string(),
                            )),
                        }],
                        not_principals: vec![XdsStringMatch {
                            match_type: Some(XdsMatchType::Exact(
                                "spiffe://cluster.local/ns/ns/sa/not-sa".to_string(),
                            )),
                        }],
                    }],
                }],
            }],
            // ..Default::default() // intentionally don't default. we want all fields populated
        };

        let proxy_state = new_proxy_state(&[wl], &[svc], &[auth]);

        let default_config = construct_config(ProxyConfig::default())
            .expect("could not build Config without ProxyConfig");

        let dump = ConfigDump {
            proxy_state,
            static_config: Default::default(),
            version: Default::default(),
            config: Arc::new(default_config),
            certificates: dump_certs(&manager).await,
        };

        // if for some reason we can't serialize the config dump, this will fail.
        //
        // this could happen for a variety of reasons; for example some types
        // may need custom serialize/deserialize to be keys in a map, like NetworkAddress
        let resp = handle_config_dump(&[], dump).await.unwrap();

        let resp_bytes = resp
            .body()
            .clone()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap();
        let resp_str = String::from(std::str::from_utf8(&resp_bytes).unwrap());

        // quick sanity check that our workload is there and keyed properly.
        // avoid stronger checks since serialization is not determinstic, and
        // most of the value of this test is ensuring that we can serialize
        // the config dump at all from our internal types
        assert!(resp_str.contains("defaultnw/127.0.0.2"));
        // Check a waypoint
        assert!(resp_str.contains(
            r#"waypoint": {
        "destination": "defaultnw/127.0.0.10",
        "hboneMtlsPort": 15008
      }"#
        ));
    }

    // each of these tests assert that we can change the log level and the
    // appropriate response string is returned.
    //
    // Note: tests need to be combined into one test function to be sure that
    // individual tests don't affect each other by asynchronously changing
    // the log level before the matching assert is called.
    #[tokio::test(start_paused = true)]
    async fn test_change_log_level() {
        helpers::initialize_telemetry();

        // no changes
        let resp = change_log_level(false, "");
        let resp_str = get_response_str(resp).await;
        assert_eq!(
            resp_str,
            "current log level is hickory_server::server::server_future=off,info\n"
        );

        let resp = change_log_level(true, "");
        let resp_str = get_response_str(resp).await;
        assert_eq!(
            resp_str,
            "current log level is hickory_server::server::server_future=off,info\n"
        );

        let resp = change_log_level(true, "invalid_level");
        let resp_str = get_response_str(resp).await;
        assert!(
            resp_str.contains(HELP_STRING),
            "got {resp_str} want {HELP_STRING}"
        );

        let resp = change_log_level(true, "debug");
        let resp_str = get_response_str(resp).await;
        assert_eq!(
            resp_str,
            "current log level is hickory_server::server::server_future=off,debug\n"
        );

        let resp = change_log_level(true, "access=debug,info");
        let resp_str = get_response_str(resp).await;
        assert_eq!(
            resp_str,
            "current log level is hickory_server::server::server_future=off,access=debug,info\n"
        );

        let resp = change_log_level(true, "warn");
        let resp_str = get_response_str(resp).await;
        assert_eq!(
            resp_str,
            "current log level is hickory_server::server::server_future=off,warn\n"
        );

        let resp = change_log_level(true, "error");
        let resp_str = get_response_str(resp).await;
        assert_eq!(
            resp_str,
            "current log level is hickory_server::server::server_future=off,error\n"
        );

        let resp = change_log_level(true, "trace");
        let resp_str = get_response_str(resp).await;
        assert!(resp_str
            .contains("current log level is hickory_server::server::server_future=off,trace\n"));

        let resp = change_log_level(true, "info");
        let resp_str = get_response_str(resp).await;
        assert!(resp_str
            .contains("current log level is hickory_server::server::server_future=off,info\n"));

        let resp = change_log_level(true, "off");
        let resp_str = get_response_str(resp).await;
        assert!(resp_str
            .contains("current log level is hickory_server::server::server_future=off,off\n"));
    }
}
