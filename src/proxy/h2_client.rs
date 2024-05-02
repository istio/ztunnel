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

// This code draws major inspiration from 2 Apache-2.0 licensed codebases:
// * https://github.com/cloudflare/pingora/blob/main/pingora-core/src/protocols/http/v2/client.rs
// * https://github.com/hyperium/hyper/blob/master/src/proto/h2/client.rs

use crate::config;
use crate::proxy::Error;
use bytes::Buf;
use bytes::Bytes;
use futures_core::ready;
use h2::client::{Connection, SendRequest};
use h2::{Reason, SendStream};
use http::Request;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::watch::Receiver;
use tokio_rustls::client::TlsStream;
use tracing::{debug, error, trace, warn};

// H2Stream represents an active HTTP2 stream. Consumers can only Read/Write
pub struct H2Stream {
    send_stream: h2::SendStream<SendBuf>,
    recv_stream: h2::RecvStream,
    buf: Bytes,
    active_count: Arc<AtomicU16>,
}

impl H2Stream {
    fn write_slice(&mut self, buf: &[u8], end_of_stream: bool) -> Result<(), std::io::Error> {
        let send_buf: SendBuf = Cursor::new(buf.into());
        self.send_stream
            .send_data(send_buf, end_of_stream)
            .map_err(h2_to_io_error)
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        let left = self.active_count.fetch_sub(1, Ordering::SeqCst);
        trace!("dropping h2stream, has {} active streams left", left - 1);
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        read_buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.buf.is_empty() {
            self.buf = loop {
                match ready!(self.recv_stream.poll_data(cx)) {
                    None => return Poll::Ready(Ok(())),
                    Some(Ok(buf)) if buf.is_empty() && !self.recv_stream.is_end_stream() => {
                        continue
                    }
                    Some(Ok(buf)) => {
                        // TODO: Hyper and Go make their pinging data aware and don't send pings when data is received
                        // Pingora, and our implementation, currently don't do this.
                        // We may want to; if so, modify here.
                        // self.ping.record_data(buf.len());
                        break buf;
                    }
                    Some(Err(e)) => {
                        return Poll::Ready(match e.reason() {
                            Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(()),
                            Some(Reason::STREAM_CLOSED) => {
                                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                            }
                            _ => Err(h2_to_io_error(e)),
                        })
                    }
                }
            };
        }
        let cnt = std::cmp::min(self.buf.len(), read_buf.remaining());
        read_buf.put_slice(&self.buf[..cnt]);
        self.buf.advance(cnt);
        let _ = self.recv_stream.flow_control().release_capacity(cnt);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.send_stream.reserve_capacity(buf.len());

        // We ignore all errors returned by `poll_capacity` and `write`, as we
        // will get the correct from `poll_reset` anyway.
        let cnt = match ready!(self.send_stream.poll_capacity(cx)) {
            None => Some(0),
            Some(Ok(cnt)) => self.write_slice(&buf[..cnt], false).ok().map(|()| cnt),
            Some(Err(_)) => None,
        };

        if let Some(cnt) = cnt {
            return Poll::Ready(Ok(cnt));
        }

        Poll::Ready(Err(h2_to_io_error(
            match ready!(self.send_stream.poll_reset(cx)) {
                Ok(Reason::NO_ERROR) | Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                }
                Ok(reason) => reason.into(),
                Err(e) => e,
            },
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        if self.write_slice(&[], true).is_ok() {
            return Poll::Ready(Ok(()));
        }

        Poll::Ready(Err(h2_to_io_error(
            match ready!(self.send_stream.poll_reset(cx)) {
                Ok(Reason::NO_ERROR) => return Poll::Ready(Ok(())),
                Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
                }
                Ok(reason) => reason.into(),
                Err(e) => e,
            },
        )))
    }
}

pub type SendBuf = Cursor<Box<[u8]>>;

fn h2_to_io_error(e: h2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io().unwrap()
    } else {
        std::io::Error::new(std::io::ErrorKind::Other, e)
    }
}

pub async fn spawn_connection(
    cfg: Arc<config::Config>,
    s: TlsStream<TcpStream>,
    driver_drain: Receiver<bool>,
) -> Result<H2ConnectClient, Error> {
    let mut builder = h2::client::Builder::new();
    builder
        .initial_window_size(cfg.window_size)
        .initial_connection_window_size(cfg.connection_window_size)
        .max_frame_size(cfg.frame_size)
        .initial_max_send_streams(cfg.pool_max_streams_per_conn as usize)
        .max_header_list_size(1024 * 16)
        .max_send_buffer_size(1024 * 1024)
        .enable_push(false);

    let (send_req, connection) = builder
        .handshake::<_, SendBuf>(s)
        .await
        .map_err(Error::Http2Handshake)?;

    // We store max as u16, so if they report above that max size we just cap at u16::MAX
    let max_allowed_streams = std::cmp::min(
        cfg.pool_max_streams_per_conn,
        connection
            .max_concurrent_send_streams()
            .try_into()
            .unwrap_or(u16::MAX),
    );
    // spawn a task to poll the connection and drive the HTTP state
    // if we got a drain for that connection, respect it in a race
    // it is important to have a drain here, or this connection will never terminate
    tokio::spawn(async move {
        drive_connection(connection, driver_drain).await;
    });

    let c = H2ConnectClient {
        sender: send_req,
        stream_count: Arc::new(AtomicU16::new(0)),
        max_allowed_streams,
    };
    Ok(c)
}

#[derive(Debug, Clone)]
// H2ConnectClient is a wrapper abstracting h2
pub struct H2ConnectClient {
    sender: SendRequest<SendBuf>,
    pub max_allowed_streams: u16,
    stream_count: Arc<AtomicU16>,
}

impl H2ConnectClient {
    // will_be_at_max_streamcount checks if a stream will be maxed out if we send one more request on it
    pub fn will_be_at_max_streamcount(&self) -> bool {
        let future_count = self.stream_count.load(Ordering::Relaxed) + 1;
        trace!(
            "checking streamcount: {future_count} >= {}",
            self.max_allowed_streams
        );
        future_count >= self.max_allowed_streams
    }

    pub fn ready_to_use(&mut self) -> bool {
        let cx = &mut Context::from_waker(futures::task::noop_waker_ref());
        match self.sender.poll_ready(cx) {
            Poll::Ready(Ok(_)) => true,
            // We may have gotten GoAway, etc
            Poll::Ready(Err(_)) => false,
            Poll::Pending => {
                // Given our current usage, I am not sure this can ever be the case.
                // If it is, though, err on the safe side and do not use the connection
                warn!("checked out connection is Pending, skipping");
                false
            }
        }
    }

    pub async fn send_request(&mut self, req: http::Request<()>) -> Result<H2Stream, Error> {
        let cur = self.stream_count.fetch_add(1, Ordering::SeqCst);
        trace!(current_streams = cur, "sending request");
        let (send, recv) = match self.internal_send(req).await {
            Ok(r) => r,
            Err(e) => {
                // Request failed, so drop the stream now
                self.stream_count.fetch_sub(1, Ordering::SeqCst);
                return Err(e);
            }
        };

        let h2 = H2Stream {
            send_stream: send,
            recv_stream: recv,
            buf: Bytes::new(),
            active_count: self.stream_count.clone(),
        };
        Ok(h2)
    }

    // helper to allow us to handle errors once
    async fn internal_send(
        &mut self,
        req: Request<()>,
    ) -> Result<(SendStream<SendBuf>, h2::RecvStream), Error> {
        let (response, stream) = self.sender.send_request(req, false)?;
        let response = response.await?;
        if response.status() != 200 {
            return Err(Error::HttpStatus(response.status()));
        }
        Ok((stream, response.into_body()))
    }
}

async fn drive_connection<S, B>(mut conn: Connection<S, B>, mut driver_drain: Receiver<bool>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    B: Buf,
{
    let ping_pong = conn
        .ping_pong()
        .expect("ping_pong should only be called once");
    // for ping to inform this fn to drop the connection
    let (ping_drop_tx, ping_drop_rx) = oneshot::channel::<()>();
    // for this fn to inform ping to give up when it is already dropped
    let dropped = Arc::new(AtomicBool::new(false));
    tokio::task::spawn(do_ping_pong(ping_pong, ping_drop_tx, dropped.clone()));

    tokio::select! {
        _ = driver_drain.changed() => {
            debug!("draining outer HBONE connection");
        }
        _ = ping_drop_rx => {
            warn!("HBONE ping timeout/error");
        }
        res = conn => {
            match res {
                Err(e) => {
                    error!("Error in HBONE connection handshake: {:?}", e);
                }
                Ok(_) => {
                    debug!("done with HBONE connection handshake: {:?}", res);
                }
            }
        }
    }
    // Signal to the ping_pong it should also stop.
    dropped.store(true, Ordering::Relaxed);
}

async fn do_ping_pong(
    mut ping_pong: h2::PingPong,
    tx: oneshot::Sender<()>,
    dropped: Arc<AtomicBool>,
) {
    const PING_INTERVAL: Duration = Duration::from_secs(10);
    const PING_TIMEOUT: Duration = Duration::from_secs(20);
    // delay before sending the first ping, no need to race with the first request
    tokio::time::sleep(PING_INTERVAL).await;
    loop {
        if dropped.load(Ordering::Relaxed) {
            return;
        }
        let ping_fut = ping_pong.ping(h2::Ping::opaque());
        log::debug!("ping sent");
        match tokio::time::timeout(PING_TIMEOUT, ping_fut).await {
            Err(_) => {
                log::error!("ping timeout");
                let _ = tx.send(());
                return;
            }
            Ok(r) => match r {
                Ok(_) => {
                    log::debug!("pong received");
                    tokio::time::sleep(PING_INTERVAL).await;
                }
                Err(e) => {
                    if dropped.load(Ordering::Relaxed) {
                        // drive_connection() exits first, no need to error again
                        return;
                    }
                    log::error!("ping error: {e}");
                    let _ = tx.send(());
                    return;
                }
            },
        }
    }
}
