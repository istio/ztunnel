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

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use crate::drain::DrainWatcher;
use crate::{config, proxy};
use bytes::Bytes;
use futures_util::TryFutureExt;
use http_body_util::Full;
use hyper::client;
use hyper::rt::Sleep;
use hyper::server::conn::{http1, http2};
use hyper::{Request, Response};
use hyper_util::client::legacy::connect::HttpConnector;
use prometheus_client::{encoding, registry::Registry};
use std::sync::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::Stream;
use tracing::{Instrument, debug, info, warn};

use crate::tls::ServerCertProvider;

// Constants for metric paths
const METRICS_PATH: &str = "/metrics";
const PROMETHEUS_PATH: &str = "/stats/prometheus";

pub fn tls_server<T: ServerCertProvider + Clone + 'static>(
    cert_provider: T,
    listener: TcpListener,
) -> impl Stream<Item = tokio_rustls::server::TlsStream<TcpStream>> {
    use tokio_stream::StreamExt;

    tls_listener::builder(crate::tls::InboundAcceptor::new(cert_provider))
        .listen(listener)
        .take_while(|item| {
            !matches!(item, Err(tls_listener::Error::ListenerError(e)) if proxy::util::is_runtime_shutdown(e))
        })
        .filter_map(|conn| {
            match conn {
                Err(err) => {
                    warn!("TLS handshake error: {}", err);
                    None
                }
                Ok(s) => {
                    debug!("TLS handshake succeeded");
                    Some(s)
                }
            }
        })
        .map(|(conn, _)| {
            conn.get_ref().0.set_nodelay(true).unwrap();
            conn
        })
}

#[derive(Clone)]
/// An Executor that uses the tokio runtime.
pub struct TokioExecutor;

impl<F> hyper::rt::Executor<F> for TokioExecutor
where
    F: std::future::Future + Send + 'static,
    F::Output: Send + 'static,
{
    #[inline]
    fn execute(&self, fut: F) {
        tokio::task::spawn(fut.in_current_span());
    }
}

/// A Timer that uses the tokio runtime.

#[derive(Clone, Debug)]
pub struct TokioTimer;

impl hyper::rt::Timer for TokioTimer {
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Sleep>> {
        let s = tokio::time::sleep(duration);
        let hs = TokioSleep { inner: Box::pin(s) };
        Box::pin(hs)
    }

    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Sleep>> {
        Box::pin(TokioSleep {
            inner: Box::pin(tokio::time::sleep_until(deadline.into())),
        })
    }
}

struct TokioTimeout<T> {
    inner: Pin<Box<tokio::time::Timeout<T>>>,
}

impl<T> Future for TokioTimeout<T>
where
    T: Future,
{
    type Output = Result<T::Output, tokio::time::error::Elapsed>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(context)
    }
}

// Use TokioSleep to get tokio::time::Sleep to implement Unpin.
// see https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html
pub(crate) struct TokioSleep {
    pub(crate) inner: Pin<Box<tokio::time::Sleep>>,
}

impl Future for TokioSleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

// Use HasSleep to get tokio::time::Sleep to implement Unpin.
// see https://docs.rs/tokio/latest/tokio/time/struct.Sleep.html

impl Sleep for TokioSleep {}

pub fn http2_server() -> http2::Builder<TokioExecutor> {
    let mut b = http2::Builder::new(TokioExecutor);
    b.timer(TokioTimer);
    b
}

pub fn http1_server() -> http1::Builder {
    let mut b = http1::Builder::new();
    b.timer(TokioTimer);
    b
}

pub fn http2_client() -> client::conn::http2::Builder<TokioExecutor> {
    let mut b = client::conn::http2::Builder::new(TokioExecutor);
    b.timer(TokioTimer);
    b
}

pub fn pooling_client<B>() -> ::hyper_util::client::legacy::Client<HttpConnector, B>
where
    B: http_body::Body + Send,
    B::Data: Send,
{
    ::hyper_util::client::legacy::Client::builder(::hyper_util::rt::TokioExecutor::new())
        .timer(TokioTimer)
        .build_http()
}

pub fn empty_response(code: hyper::StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .body(Full::default())
        .unwrap()
}

pub fn plaintext_response(code: hyper::StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .header(hyper::header::CONTENT_TYPE, "text/plain")
        .body(body.into())
        .unwrap()
}

/// Helper function to serialize an HTTP/1.1 response to bytes
fn serialize_http1_response(status: hyper::StatusCode, body: &str, content_type: &str) -> Bytes {
    // Use Hyper's Response builder for proper HTTP/1.1 formatting
    let response = hyper::Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, content_type)
        .header(hyper::header::CONTENT_LENGTH, body.len())
        .header(hyper::header::CONNECTION, "close")
        .header(hyper::header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header(hyper::header::PRAGMA, "no-cache")
        .header("Expires", "0")
        .header(hyper::header::SERVER, "ztunnel")
        .header(hyper::header::DATE, chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string())
        .body(body.to_string())
        .expect("Failed to build response");

    // Serialize to bytes using http crate functionality
    serialize_response_to_bytes(response)
}

/// Helper function to serialize a Hyper Response to raw bytes
fn serialize_response_to_bytes(response: hyper::Response<String>) -> Bytes {
    let (parts, body) = response.into_parts();
    
    // Start with status line
    let mut bytes = Vec::with_capacity(body.len() + 512);
    let status_line = format!("HTTP/1.1 {} {}\r\n", 
                             parts.status.as_u16(), 
                             parts.status.canonical_reason().unwrap_or(""));
    bytes.extend_from_slice(status_line.as_bytes());
    
    // Add headers
    for (name, value) in parts.headers {
        if let Some(name) = name {
            if let Ok(value_str) = value.to_str() {
                let header_line = format!("{}: {}\r\n", name.as_str(), value_str);
                bytes.extend_from_slice(header_line.as_bytes());
            }
        }
    }
    
    // End headers
    bytes.extend_from_slice(b"\r\n");
    
    // Add body
    bytes.extend_from_slice(body.as_bytes());
    
    Bytes::from(bytes)
}

/// Helper function to create HTTP/1.1 response for metrics
fn create_metrics_http1_response(metrics_data: &str) -> Bytes {
    serialize_http1_response(
        hyper::StatusCode::OK,
        metrics_data,
        "text/plain; version=0.0.4; charset=utf-8" // OpenMetrics content type
    )
}

/// Helper function to create HTTP/1.1 error response
fn create_error_http1_response(status: hyper::StatusCode, message: &str) -> Bytes {
    serialize_http1_response(
        status,
        message,
        "text/plain; charset=utf-8"
    )
}

/// Helper function to generate metrics from state for HBONE implementation
fn generate_metrics_from_state<S>(state: &Arc<S>) -> Result<String, String> 
where 
    S: AsRef<Mutex<Registry>> + ?Sized
{
    let mut buf = String::new();
    let registry = state.as_ref().as_ref().lock().map_err(|e| format!("Failed to lock registry: {}", e))?;
    
    encoding::text::encode(&mut buf, &registry)
        .map_err(|e| format!("Failed to encode metrics: {}", e))?;
    
    Ok(buf)
}

/// HTTPServer implements a generic HTTP server with the following behavior:
/// * HTTP/1.1 plaintext only
/// * Draining
pub struct HTTPServer<S> {
    name: String,
    binds: Vec<TcpListener>,
    drain_rx: DrainWatcher,
    state: S,
}

impl<S> HTTPServer<S> {
    pub async fn bind(
        name: &str,
        addrs: config::Address,
        drain_rx: DrainWatcher,
        s: S,
    ) -> anyhow::Result<Self> {
        let mut binds = vec![];
        for addr in addrs.into_iter() {
            binds.push(TcpListener::bind(&addr).await?)
        }
        Ok(HTTPServer {
            name: name.to_string(),
            binds,
            drain_rx,
            state: s,
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.binds
            .first()
            .expect("must have at least one address")
            .local_addr()
            .expect("local address must be ready")
    }

    pub fn state_mut(&mut self) -> &mut S {
        &mut self.state
    }

    pub fn spawn<F, R>(self, f: F)
    where
        S: Send + Sync + 'static,
        F: Fn(Arc<S>, Request<hyper::body::Incoming>) -> R + Send + Sync + 'static,
        R: Future<Output = Result<Response<Full<Bytes>>, anyhow::Error>> + Send + Sync + 'static,
    {
        use futures_util::StreamExt as OtherStreamExt;
        let address = self.address();
        let drain = self.drain_rx;
        let state = Arc::new(self.state);
        let f = Arc::new(f);
        info!(
            %address,
            component=self.name,
            "HTTP listener established",
        );
        for bind in self.binds {
            let drain_stream = drain.clone();
            let drain_connections = drain.clone();
            let state = state.clone();
            let name = self.name.clone();
            let f = f.clone();
            tokio::spawn(async move {
                let stream = tokio_stream::wrappers::TcpListenerStream::new(bind);
                let mut stream = stream.take_until(Box::pin(drain_stream.wait_for_drain()));
                while let Some(Ok(socket)) = stream.next().await {
                    socket.set_nodelay(true).unwrap();
                    let drain = drain_connections.clone();
                    let f = f.clone();
                    let state = state.clone();
                    let name = name.clone();
                    tokio::spawn(async move {
                        let serve =
                            http1_server()
                                .half_close(true)
                                .header_read_timeout(Duration::from_secs(2))
                                .max_buf_size(8 * 1024)
                                .serve_connection(
                                    hyper_util::rt::TokioIo::new(socket),
                                    hyper::service::service_fn(move |req| {
                                        let state = state.clone();

                                        // Failures would abort the whole connection; we just want to return an HTTP error
                                        f(state, req).or_else(|err| async move {
                                            Ok::<Response<Full<Bytes>>, Infallible>(Response::builder()
                                                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(err.to_string().into())
                                                .expect("builder with known status code should not fail"))
                                        })
                                    }),
                                );
                        // Wait for drain to signal or connection serving to complete
                        let recv = async move {
                            let _ = drain.wait_for_drain().await;
                        };
                        let res = match futures_util::future::select(Box::pin(recv), serve).await {
                            futures_util::future::Either::Left((_shutdown, mut server)) => {
                                debug!("server drain starting...");
                                let drain = std::pin::Pin::new(&mut server);
                                drain.graceful_shutdown();
                                let _res = server.await;
                                debug!("server drain done");
                                Ok(())
                            }
                            // Serving finished, just return the result.
                            futures_util::future::Either::Right((res, _shutdown)) => {
                                debug!("inbound serve done {:?}", res);
                                res
                            }
                        };
                        if let Err(err) = res {
                            warn!(
                                error=%err,
                                component=%name,
                                "server error",
                            );
                        }
                    });
                }
            });
        }
    }
}

/// TLSServer implements a generic HTTPS server with the following behavior:
/// * HTTP/2 with TLS
/// * Draining
/// * Optional HBONE support (HTTP CONNECT tunneling)
pub struct TLSServer<S> {
    name: String,
    binds: Vec<TcpListener>,
    drain_rx: DrainWatcher,
    state: S,
    config: Arc<config::Config>,
}

impl<S> TLSServer<S> {
    pub async fn bind<T>(
        name: &str,
        addrs: config::Address,
        drain_rx: DrainWatcher,
        s: S,
        _cert_provider: T,
        config: Arc<config::Config>,
    ) -> anyhow::Result<Self>
    where
        T: ServerCertProvider + Clone + Send + Sync + 'static,
    {
        let mut binds = vec![];
        for addr in addrs.into_iter() {
            binds.push(TcpListener::bind(&addr).await?)
        }
        Ok(TLSServer {
            name: name.to_string(),
            binds,
            drain_rx,
            state: s,
            config,
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.binds
            .first()
            .expect("must have at least one address")
            .local_addr()
            .expect("local address must be ready")
    }

    pub fn spawn<F, R, T>(self, cert_provider: T, f: F)
    where
        S: Send + Sync + 'static + AsRef<Mutex<Registry>>,
        F: Fn(Arc<S>, Request<Full<Bytes>>) -> R + Clone + Send + Sync + 'static,
        R: Future<Output = Result<Response<Full<Bytes>>, anyhow::Error>> + Send + 'static,
        T: ServerCertProvider + Clone + Send + Sync + 'static,
    {
        use futures_util::StreamExt as OtherStreamExt;
        let address = self.address();
        let drain = self.drain_rx;
        let state = Arc::new(self.state);
        let config = self.config;
        
        info!(
            %address,
            component=self.name,
            "TLS listener established",
        );
        
        // Create shutdown signal channel
        let (_force_shutdown_tx, force_shutdown_rx) = tokio::sync::watch::channel(());
        
        for bind in self.binds {
            let drain_stream = drain.clone();
            let drain_connections = drain.clone();
            let state = state.clone();
            let name = self.name.clone();
            let f = f.clone();
            let cert_provider = cert_provider.clone();
            let force_shutdown_rx = force_shutdown_rx.clone();
            let config = config.clone();
            
            tokio::spawn(async move {
                let tls_stream = tls_server(cert_provider, bind);
                let mut stream = tls_stream.take_until(Box::pin(drain_stream.wait_for_drain()));
                
                while let Some(socket) = stream.next().await {
                    let drain = drain_connections.clone();
                    let f = f.clone();
                    let state = state.clone();
                    let name = name.clone();
                    let config = config.clone();
                    let force_shutdown_rx = force_shutdown_rx.clone();
                    
                    tokio::spawn(async move {
                        let h2_handler = move |h2_req: crate::proxy::h2_public::server::H2Request| {
                            let state_clone = state.clone();
                            let f_clone = f.clone();
                            
                            async move {
                                // Check if this is a CONNECT request (HBONE)
                                let parts = h2_req.get_request();
                                if parts.method == hyper::Method::CONNECT {
                                    debug!("Received HBONE CONNECT request: {:?}", parts.uri);
                                    
                                    // For CONNECT requests, send 200 OK to establish the tunnel
                                    let response = http::Response::builder()
                                        .status(hyper::StatusCode::OK)
                                        .body(())
                                        .unwrap();
                                    
                                    // Extract just the path from the request
                                    let path = parts.uri.path().to_string();
                                    
                                    // Generate metrics data based on path before sending response
                                    let metrics_data = if path == METRICS_PATH || path == PROMETHEUS_PATH {
                                        generate_metrics_from_state(&state_clone)
                                    } else {
                                        // For any other path, prepare an error
                                        debug!(
                                            path = %path,
                                            "Path not found in metrics request"
                                        );
                                        Err(format!("Path not found: {}", path))
                                    };
                                    
                                    match h2_req.send_response(response).await {
                                        Ok(mut h2_stream) => {
                                            if path == METRICS_PATH || path == PROMETHEUS_PATH {
                                                if let Err(e) = serve_metrics_connect(h2_stream, metrics_data, &state_clone).await {
                                                    debug!(path = %path, error = %e, "HBONE tunnel handling error");
                                                }
                                            } else {
                                                // For invalid paths, send 404 response
                                                let response_bytes = create_error_http1_response(
                                                    hyper::StatusCode::NOT_FOUND,
                                                    &format!("Path not found: {}", path)
                                                );
                                                
                                                let _ = h2_stream.write.send_stream.send_data(response_bytes, true);
                                                debug!(path = %path, "Sent 404 response for invalid path");
                                            }
                                        }
                                        Err(e) => {
                                            debug!("Failed to send response for HBONE: {}", e);
                                        }
                                    }
                                } else {
                                    // For regular HTTP/2 requests (non-CONNECT), adapt to hyper Request and call the handler
                                    // Build a hyper Request from the h2 request
                                    let mut builder = hyper::Request::builder()
                                        .method(parts.method.clone())
                                        .uri(parts.uri.clone())
                                        .version(parts.version);
                                    
                                    // Add headers from original request
                                    for (name, value) in parts.headers.iter() {
                                        builder = builder.header(name, value);
                                    }
                                    
                                    let req = builder.body(Full::new(Bytes::new()))
                                        .expect("Failed to build request");
                                    
                                    // Call the handler with the concrete type
                                    match f_clone(state_clone, req).await {
                                        Ok(response) => {
                                            // Convert hyper Response to http::Response
                                            let (parts, body) = response.into_parts();
                                            
                                            // Collect the body bytes
                                            let body_bytes = match http_body_util::BodyExt::collect(body).await {
                                                Ok(collected) => collected.to_bytes(),
                                                Err(_) => Bytes::new(),
                                            };
                                            
                                            // Build http::Response
                                            let mut builder = http::Response::builder()
                                                .status(parts.status)
                                                .version(parts.version);
                                            
                                            // Add headers
                                            for (name, value) in parts.headers {
                                                if let Some(name) = name {
                                                    builder = builder.header(name, value);
                                                }
                                            }
                                            
                                            let response = builder.body(()).unwrap();
                                            
                                            // Send the response through h2
                                            if let Ok(stream) = h2_req.send_response(response).await {
                                                let mut write = stream.write;
                                                let _ = write.send_stream.send_data(body_bytes, true);
                                            }
                                        }
                                        Err(err) => {
                                            // Build error response
                                            let response = http::Response::builder()
                                                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(())
                                                .expect("Failed to build error response");
                                            
                                            // Send error response
                                            if let Ok(stream) = h2_req.send_response(response).await {
                                                let mut write = stream.write;
                                                let _ = write.send_stream.send_data(Bytes::from(err.to_string()), true);
                                            }
                                        }
                                    }
                                }
                            }
                        };
                        
                        if let Err(err) = crate::proxy::h2_public::server::serve_connection(
                            config,
                            socket,
                            drain,
                            force_shutdown_rx,
                            h2_handler,
                        ).await {
                            warn!(
                                error=%err,
                                component=%name,
                                "server error",
                            );
                        }
                    });
                }
            });
        }
    }
}

/// Process a metrics request through an HBONE tunnel
async fn serve_metrics_connect<S>(
    h2_stream: crate::proxy::h2_public::H2Stream,
    metrics_data: Result<String, String>,
    state: &Arc<S>
) -> Result<(), String>
where
    S: AsRef<Mutex<Registry>> + ?Sized
{
    let mut write = h2_stream.write;
    
    // Process the metrics data
    match metrics_data {
        Ok(metrics_str) => {
            debug!("Successfully encoded metrics data");
            
            // Create a proper HTTP/1.1 response
            let response_bytes = create_metrics_http1_response(&metrics_str);
            
            // Write the response to the tunnel
            if let Err(e) = write.send_stream.send_data(response_bytes, true) {
                debug!(error = %e, "Error writing response to HBONE tunnel");
                return Err(format!("Failed to send metrics response: {}", e));
            }
            
            debug!("HBONE metrics response sent successfully");
        }
        Err(e) => {
            // Log the error with structured information
            debug!(error = %e, "Error encoding metrics");
            
            // Send error response
            let response_bytes = create_error_http1_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                &format!("Error encoding metrics: {}", e)
            );
            
            if let Err(send_err) = write.send_stream.send_data(response_bytes, true) {
                debug!(error = %send_err, "Error sending error response");
                return Err(format!("Failed to send error response: {}", send_err));
            }
            return Err(format!("Failed to encode metrics: {}", e));
        }
    }
    
    // Drain the client stream for connection termination
    let mut read = h2_stream.read;
    let remaining = &mut read.recv_stream;
    
    // Create a bounded drain future with a timeout
    let timeout_duration = tokio::time::Duration::from_millis(500);
    let drain_future = async {
        let mut buffer = [0u8; 8192];
        while let Some(result) = remaining.data().await {
            match result {
                Ok(chunk) => {
                    if let Err(e) = remaining.flow_control().release_capacity(chunk.len()) {
                        debug!(error = %e, "Error releasing capacity in HBONE tunnel");
                        break;
                    }
                }
                Err(e) => {
                    debug!(error = %e, "Error reading from HBONE tunnel");
                    break;
                }
            }
        }
        
        if let Ok(Some(trailers)) = remaining.trailers().await {
            debug!(
                trailers_count = %trailers.len(),
                "Received trailers from HBONE tunnel"
            );
        }
    };
    
    // Use timeout to ensure we don't hang forever draining the connection
    match tokio::time::timeout(timeout_duration, drain_future).await {
        Ok(_) => debug!("HBONE tunnel drained successfully"),
        Err(_) => debug!("Timeout while draining HBONE tunnel - this is normal with Connection: close"),
    }
    
    debug!("HBONE metrics exchange completed successfully with proper HTTP/1.1 connection closure");
    Ok(())
}
