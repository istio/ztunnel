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
use tokio::net::{TcpListener, TcpStream};
use tokio_stream::Stream;
use tracing::{Instrument, debug, info, warn};

use crate::tls::ServerCertProvider;

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

/// Server implements a generic HTTP server with the follow behavior:
/// * HTTP/1.1 plaintext only
/// * Draining
pub struct Server<S> {
    name: String,
    binds: Vec<TcpListener>,
    drain_rx: DrainWatcher,
    state: S,
}

impl<S> Server<S> {
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
        Ok(Server {
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
            "listener established",
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
                        match futures_util::future::select(Box::pin(drain.wait_for_drain()), serve)
                            .await
                        {
                            // We got a shutdown request. Start gracful shutdown and wait for the pending requests to complete.
                            futures_util::future::Either::Left((_shutdown, mut serve)) => {
                                let drain = std::pin::Pin::new(&mut serve);
                                drain.graceful_shutdown();
                                serve.await
                            }
                            // Serving finished, just return the result.
                            futures_util::future::Either::Right((serve, _shutdown)) => serve,
                        }
                    });
                }
                info!(
                    %address,
                    component=name,
                    "listener drained",
                );
            });
        }
    }
}
