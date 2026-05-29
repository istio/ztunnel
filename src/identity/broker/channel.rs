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

//! Minimal Unix Domain Socket gRPC channel used by the SPIFFE Broker
//! provider.
//!
//! Two flavours are exposed:
//!
//! * [`UdsGrpcChannel::new_plain`] — plain UDS, no TLS. Used to bootstrap
//!   ztunnel's own SVID via the SPIFFE Workload API socket, which is
//!   authenticated server-side via `SO_PEERCRED` + workload attestation.
//! * [`UdsGrpcChannel::new_mtls`] — UDS wrapped with rustls mTLS. Used
//!   for every call to the SPIFFE Broker, which requires the caller to
//!   present an SVID matching one of the broker's configured
//!   `brokers[].id` entries.
//!
//! Both share the same client+connector plumbing — the only difference
//! is whether the per-connection [`UdsConn`] is plain or TLS-wrapped.
//!
//! The channel is cheap to clone: it holds an `Arc`-shared hyper client
//! that multiplexes requests onto a single HTTP/2 connection, reopening
//! the socket as needed.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use http::Uri;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::Connected;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::net::UnixStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tonic::body::Body;

use crate::identity::Error;
use crate::identity::broker::svid_source::SvidSource;

/// One open UDS connection — possibly TLS-wrapped — adapted to hyper's
/// connection trait requirements.
pub enum UdsConn {
    /// Raw UDS, used for the unauthenticated Workload API bootstrap.
    Plain(TokioIo<UnixStream>),
    /// rustls-wrapped UDS, used for the mTLS-gated Broker channel.
    Tls(Box<TokioIo<TlsStream<UnixStream>>>),
}

impl hyper_util::client::legacy::connect::Connection for UdsConn {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl hyper::rt::Read for UdsConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UdsConn::Plain(s) => Pin::new(s).poll_read(cx, buf),
            UdsConn::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for UdsConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            UdsConn::Plain(s) => Pin::new(s).poll_write(cx, buf),
            UdsConn::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UdsConn::Plain(s) => Pin::new(s).poll_flush(cx),
            UdsConn::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            UdsConn::Plain(s) => Pin::new(s).poll_shutdown(cx),
            UdsConn::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Connector that resolves every URI to a connection to the same UDS path,
/// optionally wrapping the connection with rustls mTLS.
#[derive(Clone)]
struct UdsConnector {
    path: Arc<PathBuf>,
    /// When set, every connection is TLS-wrapped using a [`ClientConfig`]
    /// freshly built from the current SVID.
    svid_source: Option<Arc<SvidSource>>,
}

impl tower::Service<Uri> for UdsConnector {
    type Response = UdsConn;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let path = self.path.clone();
        let svid_source = self.svid_source.clone();
        Box::pin(async move {
            let stream = UnixStream::connect(path.as_path()).await?;
            match svid_source {
                None => Ok(UdsConn::Plain(TokioIo::new(stream))),
                Some(src) => {
                    let cfg = src.client_config().map_err(|e| {
                        std::io::Error::other(format!("svid source: {e}"))
                    })?;
                    let connector = TlsConnector::from(Arc::new(cfg));
                    // The broker server's cert authority is irrelevant —
                    // our custom verifier ignores the requested name and
                    // authenticates by SPIFFE ID. We just need *some*
                    // syntactically-valid ServerName here.
                    let server_name = ServerName::try_from("spiffe-broker.local")
                        .expect("static server name parses");
                    let tls = connector.connect(server_name, stream).await.map_err(|e| {
                        std::io::Error::other(format!("tls handshake to broker UDS: {e}"))
                    })?;
                    Ok(UdsConn::Tls(Box::new(TokioIo::new(tls))))
                }
            }
        })
    }
}

/// Cloneable gRPC channel over a Unix Domain Socket. Implements
/// `tower::Service<http::Request<Body>>` so it can be handed directly to
/// any tonic-generated client.
#[derive(Clone)]
pub struct UdsGrpcChannel {
    /// Synthetic authority used in the outbound `:authority` header — the
    /// broker server ignores it but tonic requires a valid URI.
    uri: Uri,
    client: hyper_util::client::legacy::Client<UdsConnector, Body>,
}

impl std::fmt::Debug for UdsGrpcChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdsGrpcChannel")
            .field("uri", &self.uri)
            .finish_non_exhaustive()
    }
}

impl UdsGrpcChannel {
    /// Build a plain (un-encrypted) channel rooted at `socket_path`. No
    /// connection is opened until the first RPC.
    pub fn new_plain(socket_path: PathBuf) -> Result<Self, Error> {
        Self::build(socket_path, None)
    }

    /// Build an mTLS channel rooted at `socket_path`, using `svid_source`
    /// to mint a fresh rustls [`ClientConfig`] on every dial.
    pub fn new_mtls(socket_path: PathBuf, svid_source: Arc<SvidSource>) -> Result<Self, Error> {
        Self::build(socket_path, Some(svid_source))
    }

    fn build(
        socket_path: PathBuf,
        svid_source: Option<Arc<SvidSource>>,
    ) -> Result<Self, Error> {
        let connector = UdsConnector {
            path: Arc::new(socket_path),
            svid_source,
        };
        let client =
            hyper_util::client::legacy::Client::builder(crate::hyper_util::TokioExecutor)
                .http2_only(true)
                .timer(crate::hyper_util::TokioTimer)
                .build(connector);
        // Authority is irrelevant for UDS; use a stable placeholder.
        let uri = Uri::from_static("http://spiffe-broker.local/");
        Ok(Self { uri, client })
    }
}

impl tower::Service<http::Request<Body>> for UdsGrpcChannel {
    type Response = http::Response<Body>;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut req: http::Request<Body>) -> Self::Future {
        // Rewrite the request URI so its scheme/authority point at our
        // placeholder; tonic-generated clients leave these unset.
        let mut uri = Uri::builder();
        if let Some(scheme) = self.uri.scheme() {
            uri = uri.scheme(scheme.to_owned());
        }
        if let Some(authority) = self.uri.authority() {
            uri = uri.authority(authority.to_owned());
        }
        if let Some(path_and_query) = req.uri().path_and_query() {
            uri = uri.path_and_query(path_and_query.to_owned());
        }
        let uri = uri.build().expect("uri must be valid");
        *req.uri_mut() = uri;

        let client = self.client.clone();
        Box::pin(async move {
            let resp = client.request(req).await?;
            // Adapt hyper's `Incoming` body to tonic's `Body` so the
            // resulting type matches `Service::Response` above.
            Ok(resp.map(adapt_body))
        })
    }
}

fn adapt_body(body: Incoming) -> Body {
    Body::new(body.map_err(|e| tonic::Status::from_error(Box::new(e))))
}
