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

use boring::asn1::Asn1TimeRef;
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
use crate::identity::{Identity, SecretManager};
use crate::tls::{asn1_time_to_system_time, Certs};
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
pub struct CertDump {
    // Not available via Envoy, but still useful.
    pem: String,
    serial_number: String,
    valid_from: String,
    expiration_time: String,
}

#[derive(serde::Serialize, Debug, Clone)]
pub struct CertsDump {
    identity: String,
    state: String,
    // Make it an array to keep compatibility with Envoy's config_dump.
    ca_cert: [CertDump; 1],
    cert_chain: Vec<CertDump>,
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

fn x509_to_pem(x509: &X509) -> String {
    match x509.to_pem() {
        Err(e) => format!("<pem construction error: {e}>"),
        Ok(vec) => match String::from_utf8(vec) {
            Err(e) => format!("<utf8 decode error: {e}>"),
            Ok(s) => s,
        },
    }
}

fn dump_cert(x509: &X509) -> CertDump {
    fn rfc3339(t: &Asn1TimeRef) -> String {
        use chrono::prelude::{DateTime, Utc};
        let dt: DateTime<Utc> = asn1_time_to_system_time(t).into();
        dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    CertDump {
        pem: x509_to_pem(x509),
        serial_number: x509.serial_number().to_bn().unwrap().to_string(),
        valid_from: rfc3339(x509.not_before()),
        expiration_time: rfc3339(x509.not_after()),
    }
}

async fn dump_certs(cert_manager: &SecretManager) -> Vec<CertsDump> {
    let mut dump = cert_manager
        .collect_certs(|id, certs, state| build_cert_dump(id, certs, state))
        .await;
    // Sort for determinism.
    dump.sort_by(|a, b| a.identity.cmp(&b.identity));
    dump
}

fn build_cert_dump(ident: &Identity, certs: Option<&Certs>, state: String) -> CertsDump {
    let mut dump = CertsDump {
        identity: ident.to_string(),
        state: state,
        ca_cert: [CertDump{pem: "".to_string(), serial_number: "".to_string(), valid_from: "".to_string(), expiration_time: "".to_string()}],
        cert_chain: Vec::new(),
    };
    if let Some(cert) = certs {
        dump.ca_cert = [dump_cert(cert.x509())];
        dump.cert_chain = cert.iter_chain().map(dump_cert).collect();
    }

    dump
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::identity;

    use super::dump_certs;

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
        let manager = identity::mock::new_secret_manager_cfg(identity::mock::SecretManagerConfig {
            cert_lifetime: Duration::from_secs(7 * 60 * 60),
            epoch: Some(
                // Arbitrary point in time used to ensure deterministic certificate generation.
                chrono::DateTime::parse_from_rfc3339("2023-03-11T05:57:27Z")
                    .unwrap()
                    .into(),
            ),
        });
        for i in 0..2 {
            manager
                .fetch_certificate(&identity::Identity::Spiffe {
                    trust_domain: "trust_domain".to_string(),
                    namespace: "namespace".to_string(),
                    service_account: format!("sa-{i}"),
                })
                .await
                .unwrap();
            // Make sure certificates are a significant amount of time apart, for better
            // readability.
            tokio::time::sleep(Duration::from_secs(60 * 60)).await;
        }
        let got = serde_json::to_value(dump_certs(&manager).await).unwrap();
        let want = serde_json::json!([
          {
            "ca_cert": [{
              "expiration_time": "2023-03-11T12:57:26Z",
              "pem": "-----BEGIN CERTIFICATE-----\n\
                      MIICdzCCAV+gAwIBAgIUZyT929swtB8OHmjRaTEaD6yjqg4wDQYJKoZIhvcNAQEL\n\
                      BQAwGDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDAeFw0yMzAzMTEwNTU3MjZaFw0y\n\
                      MzAzMTExMjU3MjZaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARar2BmIYAg\n\
                      vJmOrSpCeFQ79JPy8cw4+zEE8fqr57k/umMp5jXZEGBpedBIY+qfmJPXEira9E92\n\
                      dSmkfK5AKMWxo4GbMIGYMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF\n\
                      BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ/JOH9Wq5L\n\
                      sEflEYSgHtiE2Sme1TA4BgNVHREBAf8ELjAshipzcGlmZmU6Ly90cnVzdF9kb21h\n\
                      aW4vbnMvbmFtZXNwYWNlL3NhL3NhLTAwDQYJKoZIhvcNAQELBQADggEBAGdXco2B\n\
                      7kNK35Q20OsF0f26nJWLWzxjXWqs5LtuxgEnTF3IstnQgfp5R0K3Exl+U8fXcnV2\n\
                      SO8GPNGqH/6ILlC9vkPXyOtZBC0FRFgUj4v6VajiTFmQc2gKY8cFIKhF0thqnM7r\n\
                      L07C+KQI1EolGcfGpdO/49MhPC/F/LnqgKps9K4vXuAfKYmUmsPAeQvutre6gvIu\n\
                      s0wHYfpHdHjHOuHnIaNl93uZny0CCz/gl1+9ptr3/fEGCOdVDIJy0nSrl0wDicpX\n\
                      O0WeAc1UeK/LYBGeyfekZRxstll33TlIRI5qKyJqmv8xj8TdWcQzbM6iFGInGtaQ\n\
                      AJauM4JePEb8Fqw=\n\
                      -----END CERTIFICATE-----\n",
              "serial_number": "588850990443535479077311695632745359443207891470",
              "valid_from": "2023-03-11T05:57:26Z"
            }],
            "cert_chain": [{
              "expiration_time": "2296-12-24T18:31:28Z",
              "pem": "-----BEGIN CERTIFICATE-----\n\
                     MIIDEzCCAfugAwIBAgIUC+c/60e+F1eE+7VqxnaWcOOZnmEwDQYJKoZIhvcNAQEL\n\
                     BQAwGDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDAgFw0yMzAzMTExODMxMjhaGA8y\n\
                     Mjk2MTIyNDE4MzEyOFowGDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDCCASIwDQYJ\n\
                     KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMeCTxPJtud0Uxw+CaaddWD7a+QEuQY+\n\
                     BPTKJdnMej0sBMfUMbT16JLkYNFgrj1UVHHcpSoIHocp2sd32SY4bdbokQcop+Bj\n\
                     tk55jQ46KLYsJgb2NwvYo1t8E1aetJqFGV7rmeZbFYeai+6q7iMjlbCGAu7/UnKJ\n\
                     sdGnaJQgN8du0T1KDgjqKPyHqdsu9kbpCqiEXMRmw4/BEhFGzmID2oUDKB36duVb\n\
                     dzSEm51QvgU5ILXIgyVrejN5CFsC+W+xjeOXLEztfHFUoqb3wWhkBuExmr81J2hG\n\
                     W9pULJ2wkQgdfXP7gtMkB6EyKw/xIeaNmLzPIGrX01zQYIdZTuDwMY0CAwEAAaNT\n\
                     MFEwHQYDVR0OBBYEFD8k4f1arkuwR+URhKAe2ITZKZ7VMB8GA1UdIwQYMBaAFD8k\n\
                     4f1arkuwR+URhKAe2ITZKZ7VMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n\
                     BQADggEBAKrnAeSsSSK3/8zx+hzj6SFXdJA9CQ02GEJ7hHrKijGWVYddal9dAbS5\n\
                     tLd//qKO9uIsGety/Ok2bRQ6cqqMlgdNz3jmmrbSlYWmIXI0yHGmCiSazHsXVbEF\n\
                     6Iwy3tcR4voXWKICWPh+C2cTgLmeZ0EuzFxq4wZnCf40wKoAJ9i1awSrBnE9jWtn\n\
                     p4F4hWnJTpGky5dRALE0l/2Abrl38wgfM8r4IotmPThFKnFeIHU7bQ1rYAoqpbAh\n\
                     Cv0BN5PjAQRWMk6boo3f0akS07nlYIVqXhxqcYnOgwkdlTtX9MqGIq26n8n1NWWw\n\
                     nmKOjNsk6qRmulEgeGO4vxTvSJYb+hU=\n\
                     -----END CERTIFICATE-----\n",
              "serial_number": "67955938755654933561614970125599055831405010529",
              "valid_from": "2023-03-11T18:31:28Z"
            }],
            "identity": "spiffe://trust_domain/ns/namespace/sa/sa-0",
            "state": "Available"
          },
          {
            "ca_cert": [{
              "expiration_time": "2023-03-11T13:57:26Z",
              "pem": "-----BEGIN CERTIFICATE-----\n\
                      MIICdzCCAV+gAwIBAgIUXIP+orIQwt6EPdKHWQSEL934n7EwDQYJKoZIhvcNAQEL\n\
                      BQAwGDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDAeFw0yMzAzMTEwNjU3MjZaFw0y\n\
                      MzAzMTExMzU3MjZaMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARar2BmIYAg\n\
                      vJmOrSpCeFQ79JPy8cw4+zEE8fqr57k/umMp5jXZEGBpedBIY+qfmJPXEira9E92\n\
                      dSmkfK5AKMWxo4GbMIGYMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF\n\
                      BQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBQ/JOH9Wq5L\n\
                      sEflEYSgHtiE2Sme1TA4BgNVHREBAf8ELjAshipzcGlmZmU6Ly90cnVzdF9kb21h\n\
                      aW4vbnMvbmFtZXNwYWNlL3NhL3NhLTEwDQYJKoZIhvcNAQELBQADggEBACynE+zR\n\
                      H+Ktsys58NP67DGeh+D2/uxn3vG4SVCOThMM7DTwqfPUQqP4qJUqSx/rtXP2peN4\n\
                      daI+G1PZQ3a6hWdYdMCa2+qftf4VCaYYFF9V51z8MqXjrOh9yXYxOXL+z3gzglio\n\
                      buGLo7ou7T3SCCdQfPDOw3vSQWedPW9M2zEVOuuD2ZNGyDF3pC+4Jq31n0N9SL62\n\
                      NZ5BtZK4tJbAuXbsfrGBTfFLMwG5K9DKqzqoaZ4Iqr6iGc7cjxbw3nlRUpXe8732\n\
                      JOJf2IvOU6z4LO7YntAaSFohhYXMpCFjQkJFiX6voNoSfnfLN8sSqRIDpuBZ9G8R\n\
                      hozHmFldMalh6Ss=\n\
                      -----END CERTIFICATE-----\n",
              "serial_number": "528170730419860468572163268563070820131458817969",
              "valid_from": "2023-03-11T06:57:26Z"
            }],
            "cert_chain": [{
              "expiration_time": "2296-12-24T18:31:28Z",
              "pem": "-----BEGIN CERTIFICATE-----\n\
                      MIIDEzCCAfugAwIBAgIUC+c/60e+F1eE+7VqxnaWcOOZnmEwDQYJKoZIhvcNAQEL\n\
                      BQAwGDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDAgFw0yMzAzMTExODMxMjhaGA8y\n\
                      Mjk2MTIyNDE4MzEyOFowGDEWMBQGA1UECgwNY2x1c3Rlci5sb2NhbDCCASIwDQYJ\n\
                      KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMeCTxPJtud0Uxw+CaaddWD7a+QEuQY+\n\
                      BPTKJdnMej0sBMfUMbT16JLkYNFgrj1UVHHcpSoIHocp2sd32SY4bdbokQcop+Bj\n\
                      tk55jQ46KLYsJgb2NwvYo1t8E1aetJqFGV7rmeZbFYeai+6q7iMjlbCGAu7/UnKJ\n\
                      sdGnaJQgN8du0T1KDgjqKPyHqdsu9kbpCqiEXMRmw4/BEhFGzmID2oUDKB36duVb\n\
                      dzSEm51QvgU5ILXIgyVrejN5CFsC+W+xjeOXLEztfHFUoqb3wWhkBuExmr81J2hG\n\
                      W9pULJ2wkQgdfXP7gtMkB6EyKw/xIeaNmLzPIGrX01zQYIdZTuDwMY0CAwEAAaNT\n\
                      MFEwHQYDVR0OBBYEFD8k4f1arkuwR+URhKAe2ITZKZ7VMB8GA1UdIwQYMBaAFD8k\n\
                      4f1arkuwR+URhKAe2ITZKZ7VMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n\
                      BQADggEBAKrnAeSsSSK3/8zx+hzj6SFXdJA9CQ02GEJ7hHrKijGWVYddal9dAbS5\n\
                      tLd//qKO9uIsGety/Ok2bRQ6cqqMlgdNz3jmmrbSlYWmIXI0yHGmCiSazHsXVbEF\n\
                      6Iwy3tcR4voXWKICWPh+C2cTgLmeZ0EuzFxq4wZnCf40wKoAJ9i1awSrBnE9jWtn\n\
                      p4F4hWnJTpGky5dRALE0l/2Abrl38wgfM8r4IotmPThFKnFeIHU7bQ1rYAoqpbAh\n\
                      Cv0BN5PjAQRWMk6boo3f0akS07nlYIVqXhxqcYnOgwkdlTtX9MqGIq26n8n1NWWw\n\
                      nmKOjNsk6qRmulEgeGO4vxTvSJYb+hU=\n\
                      -----END CERTIFICATE-----\n",
              "serial_number": "67955938755654933561614970125599055831405010529",
              "valid_from": "2023-03-11T18:31:28Z"
            }],
            "identity": "spiffe://trust_domain/ns/namespace/sa/sa-1",
            "state": "Available"
          }
        ]);
        assert!(
            got == want,
            "Certificate lists do not match (-want, +got):\n{}",
            diff_json(&want, &got)
        );
    }
}
