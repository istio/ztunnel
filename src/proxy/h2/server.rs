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
use crate::drain::DrainWatcher;
use crate::proxy::Error;
use crate::tls::revocation::{self, RevocationHandle};
use bytes::Bytes;
use futures_util::FutureExt;
use http::Response;
use http::request::Parts;
use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{oneshot, watch};
use tracing::{Instrument, debug};

pub struct H2Request {
    request: Parts,
    recv: h2::RecvStream,
    send: h2::server::SendResponse<Bytes>,
}

impl Debug for H2Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Request")
            .field("request", &self.request)
            .finish()
    }
}

impl H2Request {
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

    pub fn get_request(&self) -> &Parts {
        &self.request
    }

    pub fn headers(&self) -> &http::HeaderMap<http::HeaderValue> {
        self.request.headers()
    }
}

pub trait RequestParts {
    fn uri(&self) -> &http::Uri;
    fn method(&self) -> &http::Method;
    fn headers(&self) -> &http::HeaderMap<http::HeaderValue>;
}

impl RequestParts for Parts {
    fn uri(&self) -> &http::Uri {
        &self.uri
    }

    fn method(&self) -> &http::Method {
        &self.method
    }

    fn headers(&self) -> &http::HeaderMap<http::HeaderValue> {
        &self.headers
    }
}

pub async fn serve_connection<F, Fut>(
    cfg: Arc<config::Config>,
    s: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    drain: DrainWatcher,
    mut force_shutdown: watch::Receiver<()>,
    mut revocation: Option<RevocationHandle>,
    handler: F,
) -> Result<(), Error>
where
    F: Fn(H2Request) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        // 64KB max; default is 16MB driven from Golang's defaults
        // Since we know we are going to receive a bounded set of headers, more is overkill.
        .max_header_list_size(65536)
        // 400kb, default from hyper
        .max_send_buffer_size(1024 * 400)
        // default from hyper
        .max_concurrent_streams(200);
    if let Some(budget) = cfg.h2_data_frame_budget {
        builder.data_frame_budget(budget);
    }
    let mut conn = builder.handshake(s).await?;

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
                tokio::task::spawn(handle.in_current_span());
            }
            _ = &mut ping_drop_rx => {
                // Ideally this would be a warning/error message. However, due to an issue during shutdown,
                // by the time pods with in-pod know to shut down, the network namespace is destroyed.
                // This blocks the ability to send a GOAWAY and gracefully shutdown.
                // See https://github.com/istio/ztunnel/issues/1191.
                debug!("HBONE ping timeout/error, peer may have shutdown");
                conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                break
            }
            _shutdown = drain.wait_for_drain() => {
                debug!("starting graceful drain...");
                conn.graceful_shutdown();
                break;
            }
            // CRL update: revocation is a security event, abruptly terminate (GOAWAY) rather than gracefully drain
            _ = revocation::wait_for_revocation(revocation.as_mut()) => {
                if let Some(rev) = revocation.as_ref() {
                    debug!(
                        peer = %rev.peer(),
                        "terminating inbound connection: peer certificate revoked by CRL update"
                    );
                    conn.abrupt_shutdown(h2::Reason::NO_ERROR);
                    break;
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drain;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const DATA: u8 = 0x0;
    const HEADERS: u8 = 0x1;
    const SETTINGS: u8 = 0x4;
    const PING: u8 = 0x6;
    const GOAWAY: u8 = 0x7;
    const END_HEADERS: u8 = 0x4;
    const ACK: u8 = 0x1;

    fn frame(buf: &mut Vec<u8>, typ: u8, flags: u8, stream: u32, payload: &[u8]) {
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        buf.push(typ);
        buf.push(flags);
        buf.extend_from_slice(&stream.to_be_bytes());
        buf.extend_from_slice(payload);
    }

    /// Reads frames from the server until a PING ACK (Ok) or GOAWAY (Err with the error code).
    async fn read_until_ping_ack(r: &mut (impl AsyncRead + Unpin)) -> Result<(), u32> {
        loop {
            let mut hdr = [0u8; 9];
            r.read_exact(&mut hdr).await.expect("connection closed");
            let len = u32::from_be_bytes([0, hdr[0], hdr[1], hdr[2]]) as usize;
            let mut payload = vec![0u8; len];
            r.read_exact(&mut payload).await.unwrap();
            match (hdr[3], hdr[4]) {
                (PING, ACK) => return Ok(()),
                (GOAWAY, _) => {
                    return Err(u32::from_be_bytes(payload[4..8].try_into().unwrap()));
                }
                _ => {}
            }
        }
    }

    /// A stream sending many small DATA frames that the application has not yet read should
    /// not exceed the h2 data frame budget. h2 0.4.18 used a fixed 25,600 byte budget,
    /// exhausted by ~100 unread 1-byte frames, which closed the connection with ENHANCE_YOUR_CALM.
    /// Newer versions scale the default budget with the connection window.
    #[tokio::test]
    async fn many_small_data_frames_within_budget() {
        // 32000 1-byte frames => ~7.8MB of accounted framing overhead
        const FRAMES: usize = 32000;

        let cfg = Arc::new(crate::test_helpers::test_config());
        let (client, server) = tokio::io::duplex(1024 * 1024);
        let (_drain_trigger, drain) = drain::new();
        let (_force_tx, force_rx) = watch::channel(());
        // Hold on to requests without reading their bodies, so all DATA frames stay buffered.
        let (req_tx, _req_rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(serve_connection(
            cfg,
            server,
            drain,
            force_rx,
            None,
            move |req: H2Request| {
                let _ = req_tx.send(req);
                async {}
            },
        ));

        let mut buf = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        frame(&mut buf, SETTINGS, 0, 0, &[]);
        // HPACK literals without indexing: `:method: CONNECT`, `:authority: 127.0.0.1:8080`
        let mut block = vec![0x02, 7];
        block.extend_from_slice(b"CONNECT");
        block.extend_from_slice(&[0x01, 14]);
        block.extend_from_slice(b"127.0.0.1:8080");
        frame(&mut buf, HEADERS, END_HEADERS, 1, &block);
        for _ in 0..FRAMES {
            frame(&mut buf, DATA, 0, 1, b"x");
        }
        // Frames are processed in order, so a PING ACK means every DATA frame was accepted.
        frame(&mut buf, PING, 0, 0, &[0u8; 8]);

        let (mut r, mut w) = tokio::io::split(client);
        tokio::spawn(async move {
            // The server may close the connection before we finish writing.
            let _ = w.write_all(&buf).await;
            let _ = w.flush().await;
            // Keep the write half open so the connection stays up.
            std::future::pending::<()>().await;
        });

        let res = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            read_until_ping_ack(&mut r),
        )
        .await
        .expect("timed out waiting for server");
        assert_eq!(
            res,
            Ok(()),
            "server sent GOAWAY (0xb = ENHANCE_YOUR_CALM) for small DATA frames"
        );
    }
}
