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

use std::path::PathBuf;
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use tracing::{debug, warn};

use crate::config::Config;
use crate::drain::DrainWatcher;
use crate::hyper_util;
use crate::tls::{Error, ServerCertProvider, TlsError, WorkloadCertificate};
use rustls::ServerConfig;

// Add constants for metric paths to match those in hyper_util
const METRICS_PATH: &str = "/metrics";
const PROMETHEUS_PATH: &str = "/stats/prometheus";

/// Specialized error type for metrics server, following InboundError pattern
pub struct MetricsError(anyhow::Error, StatusCode);

impl MetricsError {
    /// Creates a builder function that wraps errors with the specified status code
    pub fn build(code: StatusCode) -> impl Fn(anyhow::Error) -> Self {
        move |err| MetricsError(err, code)
    }
    
    /// Converts the error to a Response
    pub fn to_response(&self) -> Response<Full<Bytes>> {
        build_response(self.1, &self.0.to_string())
    }
}

/// Builds a standard HTTP response, similar to build_response in inbound.rs
pub fn build_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    let body_bytes = Bytes::from(body.to_string());
    
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(body_bytes))
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("Error building response")))
                .unwrap()
        })
}

/// SecretBasedCertProvider loads certificates from Kubernetes secrets for the mTLS metrics server
pub struct SecretBasedCertProvider {
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl SecretBasedCertProvider {
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            cert_path,
            key_path,
        }
    }
}

#[async_trait::async_trait]
impl ServerCertProvider for SecretBasedCertProvider {
    async fn fetch_cert(&mut self) -> Result<Arc<ServerConfig>, TlsError> {
        debug!("Loading TLS certificate for metrics server from {:?} and {:?}", 
               self.cert_path, self.key_path);
               
        // Read cert file
        let cert = match tokio::fs::read(&self.cert_path).await {
            Ok(data) => data,
            Err(e) => {
                let msg = format!("Failed to read certificate from path {:?}: {}", self.cert_path, e);
                warn!("{}", msg);
                return Err(TlsError::SslError(Error::CertificateParseError(msg)));
            }
        };
        
        // Read key file 
        let key = match tokio::fs::read(&self.key_path).await {
            Ok(data) => data,
            Err(e) => {
                let msg = format!("Failed to read private key from path {:?}: {}", self.key_path, e);
                warn!("{}", msg);
                return Err(TlsError::SslError(Error::CertificateParseError(msg)));
            }
        };
        
        // Create workload certificate
        let cert = WorkloadCertificate::new(&key, &cert, vec![])?;
        let server_config = Arc::new(cert.server_config()?);
        
        debug!("Successfully loaded TLS certificate for metrics server");
        Ok(server_config)
    }
}

impl Clone for SecretBasedCertProvider {
    fn clone(&self) -> Self {
        Self {
            cert_path: self.cert_path.clone(),
            key_path: self.key_path.clone(),
        }
    }
}

/// Regular HTTP metrics server
pub struct Server {
    s: hyper_util::HTTPServer<Arc<Mutex<Registry>>>,
}

impl Server {
    pub async fn new(
        config: Arc<Config>,
        drain_rx: DrainWatcher,
        registry: Arc<Mutex<Registry>>,
    ) -> anyhow::Result<Self> {
        hyper_util::HTTPServer::<Arc<Mutex<Registry>>>::bind(
            "stats",
            config.stats_addr,
            drain_rx,
            registry,
        )
        .await
        .map(|s| Server { s })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        self.s.spawn(|registry, req| async move {
            match req.uri().path() {
                METRICS_PATH | PROMETHEUS_PATH => Ok(handle_metrics((*registry).clone(), req).await),
                _ => Ok(hyper_util::empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

/// MtlsMetricsServer serves metrics over mTLS with support for both direct connections and HBONE tunneling
/// 
/// Supports two connection modes:
/// 1. Direct mTLS: TCP → TLS → HTTP Request/Response
///    Client establishes TLS connection with mTLS authentication and sends HTTP/2 requests directly
/// 
/// 2. HBONE: TCP → TLS → HTTP/2 → CONNECT Tunnel → HTTP/1.1 Request/Response
///    Client establishes TLS connection with mTLS authentication
///    Client sends HTTP/2 CONNECT request to establish a tunnel
///    Once tunnel is established, client sends HTTP/1.1 requests through the tunnel
///    Server processes these requests through the same handler function and returns responses
///    through the established tunnel
///
/// The HBONE protocol provides an additional layer of HTTP-based tunneling which can be useful
/// for traversing certain network environments where direct connections might be restricted.
pub struct MtlsMetricsServer {
    s: hyper_util::TLSServer<Arc<Mutex<Registry>>>,
    cert_provider: SecretBasedCertProvider,
}

impl MtlsMetricsServer {
    /// Creates a new MtlsMetricsServer instance that supports both direct mTLS and HBONE connections
    ///
    /// The server uses TLS certificates from Kubernetes secrets for authenticating clients
    /// and is configured to handle both direct HTTP/2 requests and HTTP CONNECT tunneling (HBONE)
    pub async fn new(
        config: Arc<Config>,
        drain_rx: DrainWatcher,
        registry: Arc<Mutex<Registry>>,
    ) -> anyhow::Result<Self> {
        let cert_provider = SecretBasedCertProvider::new(
            PathBuf::from(&config.mtls_metrics_cert_path),
            PathBuf::from(&config.mtls_metrics_key_path),
        );

        hyper_util::TLSServer::<Arc<Mutex<Registry>>>::bind(
            "mtls-stats",
            config.mtls_metrics_addr,
            drain_rx,
            registry,
            cert_provider.clone(),
            config.clone(),
        )
        .await
        .map(|s| MtlsMetricsServer { s, cert_provider })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    /// Spawns the server to handle both direct mTLS and HBONE connections
    ///
    /// The server will:
    /// 1. Accept TLS connections with mutual authentication
    /// 2. Process both direct HTTP/2 requests and HTTP CONNECT requests for HBONE tunneling
    /// 3. Serve metrics through both connection types
    pub fn spawn(self) {
        self.s.spawn(self.cert_provider, |registry, req| async move {
            match req.uri().path() {
                METRICS_PATH | PROMETHEUS_PATH => Ok(handle_metrics((*registry).clone(), req).await),
                _ => Ok(hyper_util::empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

async fn handle_metrics<B>(
    reg: Arc<Mutex<Registry>>,
    req: Request<B>,
) -> Response<Full<Bytes>> 
where
    B: http_body::Body,
{
    let mut buf = String::new();
    let reg = reg.lock().expect("mutex");
    if let Err(err) = encode(&mut buf, &reg) {
        return build_response(
            StatusCode::INTERNAL_SERVER_ERROR, 
            &format!("Failed to encode metrics: {}", err)
        );
    }

    let response_content_type = content_type(&req);

    Response::builder()
        .status(StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, response_content_type)
        .body(buf.into())
        .unwrap_or_else(|_| {
            build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error building metrics response"
            )
        })
}

#[derive(Default)]
enum ContentType {
    #[default]
    PlainText,
    OpenMetrics,
}

impl From<ContentType> for &str {
    fn from(c: ContentType) -> Self {
        match c {
            ContentType::PlainText => "text/plain; charset=utf-8",
            ContentType::OpenMetrics => "application/openmetrics-text;charset=utf-8;version=1.0.0",
        }
    }
}

#[inline(always)]
fn content_type<T>(req: &Request<T>) -> &str {
    req.headers()
        .get_all(http::header::ACCEPT)
        .iter()
        .find_map(|v| {
            match v
                .to_str()
                .unwrap_or_default()
                .to_lowercase()
                .split(";")
                .collect::<Vec<_>>()
                .first()
            {
                Some(&"application/openmetrics-text") => Some(ContentType::OpenMetrics),
                _ => None,
            }
        })
        .unwrap_or_default()
        .into()
}

#[cfg(test)]
mod test {
    #[test]
    fn test_content_type() {
        let plain_text_req = http::Request::new("I want some plain text");
        assert_eq!(
            super::content_type(&plain_text_req),
            "text/plain; charset=utf-8"
        );

        let openmetrics_req = http::Request::builder()
            .header("X-Custom-Beep", "boop")
            .header("Accept", "application/json")
            .header("Accept", "application/openmetrics-text; other stuff")
            .body("I would like openmetrics")
            .unwrap();
        assert_eq!(
            super::content_type(&openmetrics_req),
            "application/openmetrics-text;charset=utf-8;version=1.0.0"
        );

        let unsupported_req_accept = http::Request::builder()
            .header("Accept", "application/json")
            .body("I would like some json")
            .unwrap();
        // asking for something we don't support, fall back to plaintext
        assert_eq!(
            super::content_type(&unsupported_req_accept),
            "text/plain; charset=utf-8"
        )
    }
}
