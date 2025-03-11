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
use bytes::BytesMut;
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
use tokio::io::AsyncWriteExt;
use tokio_stream::Stream;
use tracing::{Instrument, debug, info, warn};

use crate::tls::ServerCertProvider;
use http_body_util::BodyExt;
use bytes::BufMut;
use std::io::Write;

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
            // Avoid 'By default, if a client fails the TLS handshake, that is treated as an error, and the TlsListener will return an Err'
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

// Helper function to generate metrics from state for HBONE implementation
// This is used in the TLSServer implementation for HBONE tunneling
fn generate_metrics_from_state<S>(state: &Arc<S>) -> Result<String, String> 
where 
    S: AsRef<Mutex<Registry>> + ?Sized
{
    let mut buf = String::new();
    let registry = state.as_ref().as_ref().lock().expect("mutex poisoned");
    
    encoding::text::encode(&mut buf, &registry)
        .map_err(|e| e.to_string())?;
    
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
}

impl<S> TLSServer<S> {
    pub async fn bind<T>(
        name: &str,
        addrs: config::Address,
        drain_rx: DrainWatcher,
        s: S,
        _cert_provider: T,
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
        F: Fn(Arc<S>, Request<hyper::body::Incoming>) -> R + Clone + Send + Sync + 'static,
        R: Future<Output = Result<Response<Full<Bytes>>, anyhow::Error>> + Send + 'static,
        T: ServerCertProvider + Clone + Send + Sync + 'static,
    {
        use futures_util::StreamExt as OtherStreamExt;
        let address = self.address();
        let drain = self.drain_rx;
        let state = Arc::new(self.state);
        info!(
            %address,
            component=self.name,
            "TLS listener established",
        );
        for bind in self.binds {
            let drain_stream = drain.clone();
            let drain_connections = drain.clone();
            let state = state.clone();
            let name = self.name.clone();
            let f = f.clone();
            let cert_provider = cert_provider.clone();
            tokio::spawn(async move {
                let tls_stream = tls_server(cert_provider, bind);
                let mut stream = tls_stream.take_until(Box::pin(drain_stream.wait_for_drain()));
                while let Some(socket) = stream.next().await {
                    let drain = drain_connections.clone();
                    let f = f.clone();
                    let state = state.clone();
                    let name = name.clone();
                    tokio::spawn(async move {
                        let serve = http2_server()
                                .max_frame_size(1024 * 1024)
                                .max_header_list_size(65536)
                                .serve_connection(
                                    hyper_util::rt::TokioIo::new(socket),
                                    hyper::service::service_fn(move |req| {
                                        let state = state.clone();
                                    let f = f.clone();
                                    async move {
                                        if req.method() == hyper::Method::CONNECT {
                                            debug!("Received HBONE CONNECT request: {:?}", req.uri());
                                            
                                            // For CONNECT requests, upgrade the connection
                                            let response = Response::builder()
                                                .status(hyper::StatusCode::OK)
                                                .body(Full::default())
                                                .unwrap();
                                                
                                            let state = state.clone();
                                            
                                            let uri_path = req.uri().path().to_string();
                                            
                                            // Perform the connection upgrade
                                            tokio::task::spawn(async move {
                                                match hyper::upgrade::on(req).await {
                                                    Ok(upgraded) => {
                                                        debug!("HBONE tunnel established");
                                                        
                                                        let mut upgraded_io = hyper_util::rt::TokioIo::new(upgraded);
                                                        
                                                        // Access the metrics directly via the state reference
                                                        let response_body = match uri_path.as_str() {
                                                            "/metrics" | "/stats/prometheus" => {
                                                                if let Ok(metrics_str) = generate_metrics_from_state(&state) {
                                                                    debug!("Successfully encoded metrics data");
                                                                    
                                                                    let response = Response::builder()
                                                                        .status(hyper::StatusCode::OK)
                                                                        .header("Content-Type", "text/plain")
                                                                        .body(Full::new(Bytes::from(metrics_str)))
                                                                        .expect("Failed to build metrics response");
                                                                    
                                                                    match serialize_http_response(response).await {
                                                                        Ok(bytes) => bytes.to_vec(),
                                                                        Err(e) => {
                                                                            debug!("Error serializing metrics response: {}", e);
                                                                            let error_response = Response::builder()
                                                                                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                                                                .header("Content-Type", "text/plain")
                                                                                .body(Full::new(Bytes::from("Error serializing response")))
                                                                                .expect("Failed to build error response");
                                                                                
                                                                            serialize_http_response(error_response).await
                                                                                .unwrap_or_else(|_| Bytes::from("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
                                                                                .to_vec()
                                                                        }
                                                                    }
                                                                } else {
                                                                    debug!("Error encoding metrics");
                                                                    
                                                                    let response = Response::builder()
                                                                        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                                                        .header("Content-Type", "text/plain")
                                                                        .body(Full::new(Bytes::from("Error encoding metrics")))
                                                                        .expect("Failed to build error response");
                                                                        
                                                                    serialize_http_response(response).await
                                                                        .unwrap_or_else(|_| Bytes::from("HTTP/1.1 500 Internal Server Error\r\n\r\n"))
                                                                        .to_vec()
                                                                }
                                                            },
                                                            _ => {
                                                                // For any other path, return 404
                                                                debug!("Path not found: {}", uri_path);
                                                                
                                                                let response = Response::builder()
                                                                    .status(hyper::StatusCode::NOT_FOUND)
                                                                    .header("Content-Type", "text/plain")
                                                                    .body(Full::new(Bytes::from("Not Found")))
                                                                    .expect("Failed to build 404 response");
                                                                    
                                                                serialize_http_response(response).await
                                                                    .unwrap_or_else(|_| Bytes::from("HTTP/1.1 404 Not Found\r\n\r\n"))
                                                                    .to_vec()
                                                            }
                                                        };
                                                        
                                                        debug!("Writing response ({} bytes) to HBONE tunnel", response_body.len());
                                                        if let Err(e) = upgraded_io.write_all(&response_body).await {
                                                            debug!("Error writing response to HBONE tunnel: {}", e);
                                                        } else {
                                                            debug!("HBONE response sent successfully");
                                                        }
                                                        
                                                        debug!("HBONE tunnel connection complete");
                                                    }
                                                    Err(e) => {
                                                        debug!("Failed to upgrade HBONE connection: {}", e);
                                                    }
                                                }
                                            });
                                            
                                            Ok::<_, Infallible>(response)
                                        } else {
                                            // For non-CONNECT requests, use the original handler
                                            f(state, req).await.or_else(|err| {
                                                Ok::<_, Infallible>(Response::builder()
                                                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                                                .body(err.to_string().into())
                                                .expect("builder with known status code should not fail"))
                                        })
                                        }
                                    }
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

// Helper function to properly serialize an HTTP/1.1 response to bytes
async fn serialize_http_response<B>(response: Response<B>) -> Result<Bytes, String> 
where 
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    // Create a buffer to store the serialized response
    let mut buf = BytesMut::with_capacity(1024).writer();
    
    // Write the status line
    write!(
        &mut buf, 
        "HTTP/1.1 {} {}\r\n", 
        response.status().as_u16(),
        response.status().canonical_reason().unwrap_or("")
    )
    .map_err(|e| e.to_string())?;
    
    // Write the headers
    for (name, value) in response.headers() {
        write!(&mut buf, "{}: ", name)
            .map_err(|e| e.to_string())?;
        buf.write_all(value.as_bytes())
            .map_err(|e| e.to_string())?;
        buf.write_all(b"\r\n")
            .map_err(|e| e.to_string())?;
    }
    
    // End of headers
    buf.write_all(b"\r\n")
        .map_err(|e| e.to_string())?;
    
    // Get the buffer so far
    let bytes = buf.into_inner().freeze();
    
    // Get the body
    let mut body = response.into_body();
    
    // Create a new buffer for the complete response
    let mut buffer = BytesMut::with_capacity(bytes.len() + 1024);
    buffer.extend_from_slice(&bytes);
    
    // Add the body data
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| e.to_string())?;
        if let Some(data) = frame.data_ref() {
            buffer.extend_from_slice(data);
        }
    }
    
    // Return the complete response as bytes
    Ok(buffer.freeze())
}
