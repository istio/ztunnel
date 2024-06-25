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

use crate::config;
use crate::proxy::Error;
use bytes::Bytes;
use futures_util::FutureExt;
use http::request::Parts;
use http::Response;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::{oneshot, watch};
use tracing::{debug, warn};

pub struct H2Request {
    request: Parts,
    recv: h2::RecvStream,
    send: h2::server::SendResponse<Bytes>,
}

impl H2Request {
    /// The request's method
    pub fn method(&self) -> &http::Method {
        &self.request.method
    }

    /// The request's URI
    pub fn uri(&self) -> &http::Uri {
        &self.request.uri
    }

    /// The request's headers
    pub fn headers(&self) -> &http::HeaderMap<http::HeaderValue> {
        &self.request.headers
    }

    pub fn send_error(mut self, resp: Response<()>) -> Result<(), Error> {
        let _ = self.send.send_response(resp, true)?;
        Ok(())
    }

    pub async fn send_response(
        self,
        resp: Response<()>,
    ) -> Result<crate::proxy::h2::H2Stream, Error> {
        let H2Request { recv, mut send, .. } = self;
        let send = send.send_response(resp, false)?;
        let read = crate::proxy::h2::H2StreamReadHalf {
            recv_stream: recv,
            _dropped: None, // We do not need to track on the server
        };
        let write = crate::proxy::h2::H2StreamWriteHalf {
            send_stream: send,
            _dropped: None, // We do not need to track on the server
        };
        let h2 = crate::proxy::h2::H2Stream { read, write };
        Ok(h2)
    }
}

pub async fn serve_connection<F, Fut>(
    cfg: Arc<config::Config>,
    s: tokio_rustls::server::TlsStream<TcpStream>,
    drain: drain::Watch,
    mut force_shutdown: watch::Receiver<()>,
    handler: F,
) -> Result<(), Error>
where
    F: Fn(H2Request) -> Fut,
    Fut: Future + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    let mut conn = builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        // 64KB max; default is 16MB driven from Golang's defaults
        // Since we know we are going to receive a bounded set of headers, more is overkill.
        .max_header_list_size(65536)
        // 400kb, default from hyper
        .max_send_buffer_size(1024 * 400)
        // default from hyper
        .max_concurrent_streams(200)
        .handshake(s)
        .await?;

    let ping_pong = conn
        .ping_pong()
        .expect("new connection should have ping_pong");
    // for ping to inform this fn to drop the connection
    let (ping_drop_tx, mut ping_drop_rx) = oneshot::channel::<()>();
    // for this fn to inform ping to give up when it is already dropped
    let dropped = Arc::new(AtomicBool::new(false));
    tokio::task::spawn(crate::proxy::h2::do_ping_pong(
        ping_pong,
        ping_drop_tx,
        dropped.clone(),
    ));

    let handler = |req| handler(req).map(|_| ());
    loop {
        let drain = drain.clone();
        tokio::select! {
            request = conn.accept() => {
                let Some(request) = request else {
                    // done!
                    // Signal to the ping_pong it should also stop.
                    dropped.store(true, Ordering::Relaxed);
                    return Ok(());
                };
                let (request, send) = request?;
                let (request, recv) = request.into_parts();
                let req = H2Request {
                    request,
                    recv,
                    send,
                };
                let handle = handler(req);
                // Serve the stream in a new task
                tokio::task::spawn(handle);
            }
            _ = &mut ping_drop_rx => {
                warn!("HBONE ping timeout/error");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                break
            }
            _shutdown = drain.signaled() => {
                debug!("starting graceful drain...");
                conn.graceful_shutdown();
                break;
            }
        }
    }
    // Signal to the ping_pong it should also stop.
    dropped.store(true, Ordering::Relaxed);
    let poll_closed = futures_util::future::poll_fn(move |cx| conn.poll_closed(cx));
    tokio::select! {
        _ = force_shutdown.changed() => {
            return Err(Error::DrainTimeOut)
        }
        _ = poll_closed => {}
    }
    // Mark we are done with the connection
    drop(drain);
    Ok(())
}
