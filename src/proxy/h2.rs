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

use crate::copy;
use bytes::{Buf, Bytes};
use futures_core::ready;
use h2::Reason;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncWrite;
use tokio::sync::oneshot;
use tracing::trace;

pub mod client;
pub mod server;

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

// H2Stream represents an active HTTP2 stream. Consumers can only Read/Write
pub struct H2Stream {
    pub read: H2StreamReadHalf,
    pub write: H2StreamWriteHalf,
}

pub struct H2StreamReadHalf {
    pub recv_stream: h2::RecvStream,
    pub buf: Bytes,
    pub half_dropped: Arc<()>,
    pub active_count: Arc<AtomicU16>,
}

pub struct H2StreamWriteHalf {
    pub send_stream: h2::SendStream<SendBuf>,
    pub half_dropped: Arc<()>,
    pub active_count: Arc<AtomicU16>,
}

impl crate::copy::BufferedSplitter for H2Stream {
    type R = H2StreamReadHalf;
    type W = H2StreamWriteHalf;
    fn split_into_buffered_reader(self) -> (H2StreamReadHalf, H2StreamWriteHalf) {
        let H2Stream { read, write } = self;
        (read, write)
    }
}

impl H2StreamWriteHalf {
    fn write_slice(&mut self, buf: &[u8], end_of_stream: bool) -> Result<(), std::io::Error> {
        let send_buf: SendBuf = Cursor::new(buf.into());
        self.send_stream
            .send_data(send_buf, end_of_stream)
            .map_err(h2_to_io_error)
    }
}

impl Drop for H2StreamReadHalf {
    fn drop(&mut self) {
        let mut half_dropped = Arc::new(());
        std::mem::swap(&mut self.half_dropped, &mut half_dropped);
        if Arc::into_inner(half_dropped).is_none() {
            // other half already dropped
            let left = self.active_count.fetch_sub(1, Ordering::SeqCst);
            trace!(
                "dropping H2StreamReadHalf, has {} active streams left",
                left - 1
            );
        } else {
            trace!("dropping H2StreamReadHalf, write half remains");
        }
    }
}

impl Drop for H2StreamWriteHalf {
    fn drop(&mut self) {
        let mut half_dropped = Arc::new(());
        std::mem::swap(&mut self.half_dropped, &mut half_dropped);
        if Arc::into_inner(half_dropped).is_none() {
            // other half already dropped
            let left = self.active_count.fetch_sub(1, Ordering::SeqCst);
            trace!(
                "dropping H2StreamWriteHalf, has {} active streams left",
                left - 1
            );
        } else {
            trace!("dropping H2StreamWriteHalf, read half remains");
        }
    }
}

impl copy::ResizeBufRead for H2StreamReadHalf {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>> {
        const EOF: Poll<std::io::Result<&[u8]>> = Poll::Ready(Ok(&[]));
        let this = self.get_mut();
        let self_buf = &mut this.buf;
        loop {
            {
                if !self_buf.chunk().is_empty() {
                    let chunk = (*self_buf).chunk();
                    return Poll::Ready(Ok(chunk));
                }
            }
            match ready!(this.recv_stream.poll_data(cx)) {
                None => return EOF,
                Some(Ok(buf)) if buf.is_empty() && !this.recv_stream.is_end_stream() => continue,
                Some(Ok(buf)) => {
                    // TODO: Hyper and Go make their pinging data aware and don't send pings when data is received
                    // Pingora, and our implementation, currently don't do this.
                    // We may want to; if so, modify here.
                    // this.ping.record_data(buf.len());
                    let _ = this.recv_stream.flow_control().release_capacity(buf.len());
                    *self_buf = buf;
                }
                Some(Err(e)) => {
                    return Poll::Ready(match e.reason() {
                        Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => Ok(&[]),
                        Some(Reason::STREAM_CLOSED) => {
                            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
                        }
                        _ => Err(h2_to_io_error(e)),
                    })
                }
            }
        }
    }

    fn consume(mut self: Pin<&mut Self>, amt: usize) {
        self.as_mut().buf.advance(amt)
    }

    fn resize(self: Pin<&mut Self>) {
        // NOP, we don't need to resize as we are abstracting the h2 buffer
    }
}

impl AsyncWrite for H2StreamWriteHalf {
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
