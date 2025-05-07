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

use crate::proxy;
use crate::proxy::ConnectionResult;
use crate::proxy::Error::{BackendDisconnected, ClientDisconnected, ReceiveError, SendError};
use bytes::{Buf, Bytes, BytesMut};
use pin_project_lite::pin_project;
use std::future::Future;
use std::io::Error;
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::trace;

// BufferedSplitter is a trait to expose splitting an IO object into a buffered reader and a writer
pub trait BufferedSplitter: Unpin {
    type R: ResizeBufRead + Unpin;
    type W: AsyncWriteBuf + Unpin;
    fn split_into_buffered_reader(self) -> (Self::R, Self::W);
}

// Generic BufferedSplitter for anything that can Read/Write.
impl<I> BufferedSplitter for I
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    type R = BufReader<io::ReadHalf<I>>;
    type W = WriteAdapter<io::WriteHalf<I>>;
    fn split_into_buffered_reader(self) -> (Self::R, Self::W) {
        let (rh, wh) = tokio::io::split(self);
        let rb = BufReader::new(rh);
        (rb, WriteAdapter(wh))
    }
}

// TcpStreamSplitter is a specialized BufferedSplitter for TcpStream, which is more efficient than the generic
// `tokio::io::split`. The generic method involves locking to access the read and write halves
pub struct TcpStreamSplitter(pub TcpStream);

impl BufferedSplitter for TcpStreamSplitter {
    type R = BufReader<OwnedReadHalf>;
    type W = WriteAdapter<OwnedWriteHalf>;

    fn split_into_buffered_reader(self) -> (Self::R, Self::W) {
        let (rh, wh) = self.0.into_split();
        let rb = BufReader::new(rh);
        (rb, WriteAdapter(wh))
    }
}

// AsyncWriteBuf is like AsyncWrite, but writes a Bytes instead of &[u8]. This allows avoiding copies.
pub trait AsyncWriteBuf {
    fn poll_write_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: Bytes,
    ) -> Poll<std::io::Result<usize>>;
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;
    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>>;
}

// Allow &T to be AsyncWriteBuf
impl<T: ?Sized + AsyncWriteBuf + Unpin> AsyncWriteBuf for &mut T {
    fn poll_write_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: Bytes,
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut **self).poll_write_buf(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut **self).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut **self).poll_shutdown(cx)
    }
}

// Allow anything that is AsyncWrite to be AsyncWriteBuf.
pub struct WriteAdapter<T>(T);

impl<T: AsyncWrite + Unpin> AsyncWriteBuf for WriteAdapter<T> {
    fn poll_write_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: Bytes,
    ) -> Poll<std::io::Result<usize>> {
        tokio_util::io::poll_write_buf(Pin::new(&mut self.0), cx, &mut buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

// ResizeBufRead is like AsyncBufRead, but allows triggering a resize.
pub trait ResizeBufRead {
    fn poll_bytes(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<Bytes>>;
    fn resize(self: Pin<&mut Self>, new_size: usize);
}

// Initially we create a 1k buffer for each connection. Note currently there are 3 buffers per connection.
// Outbound: downstream to app. Upstream HBONE is optimized to avoid.
// Inbound: downstream HBONE, upstream to app. Downstream HBONE can be optimized, but is not yet.
const INITIAL_BUFFER_SIZE: usize = 1024;
// We increase up to 16k for high traffic connections.
// TLS record size max is 16k. But we also have an H2 frame header, so leave a bit of room for that.
const LARGE_BUFFER_SIZE: usize = 16_384 - 64;
// For ultra-high bandwidth connections, increase up to 256Kb
const JUMBO_BUFFER_SIZE: usize = (16 * 16_384) - 64;
// After 128k of data we will trigger a resize from INITIAL to LARGE
// Loosely inspired by https://github.com/golang/go/blame/5122a6796ef98e3453c994c95abd640596540bea/src/crypto/tls/conn.go#L873
const RESIZE_THRESHOLD_LARGE: u64 = 128 * 1024;
// After 10Mb of data we will trigger a resize from LARGE to JUMBO
const RESIZE_THRESHOLD_JUMBO: u64 = 10 * 1024 * 1024;

pub async fn copy_bidirectional<A, B>(
    downstream: A,
    upstream: B,
    stats: &ConnectionResult,
) -> Result<(), crate::proxy::Error>
where
    A: BufferedSplitter,
    B: BufferedSplitter,
{
    let (mut rd, mut wd) = downstream.split_into_buffered_reader();
    let (mut ru, mut wu) = upstream.split_into_buffered_reader();
    let downstream_to_upstream = async {
        let translate_error = |e: io::Error| {
            SendError(Box::new(match e.kind() {
                io::ErrorKind::NotConnected => BackendDisconnected,
                io::ErrorKind::WriteZero => BackendDisconnected,
                io::ErrorKind::UnexpectedEof => ClientDisconnected,
                _ => e.into(),
            }))
        };
        let res = ignore_io_errors(copy_buf(&mut rd, &mut wu, stats, false).await)
            .map_err(translate_error);
        trace!(?res, "send");
        ignore_shutdown_errors(shutdown(&mut wu).await)
            .map_err(translate_error)
            .map_err(|e| proxy::Error::ShutdownError(Box::new(e)))?;
        res
    };

    let upstream_to_downstream = async {
        let translate_error = |e: io::Error| {
            ReceiveError(Box::new(match e.kind() {
                io::ErrorKind::NotConnected => ClientDisconnected,
                io::ErrorKind::WriteZero => ClientDisconnected,
                _ => e.into(),
            }))
        };
        let res = ignore_io_errors(copy_buf(&mut ru, &mut wd, stats, true).await)
            .map_err(translate_error);
        trace!(?res, "receive");
        ignore_shutdown_errors(shutdown(&mut wd).await)
            .map_err(translate_error)
            .map_err(|e| proxy::Error::ShutdownError(Box::new(e)))?;
        res
    };

    // join!() them rather than try_join!() so that we keep complete either end once one side is complete.
    let (sent, received) = tokio::join!(downstream_to_upstream, upstream_to_downstream);

    // Convert some error messages to easier to understand
    let sent = sent?;
    let received = received?;
    trace!(sent, received, "copy complete");
    Ok(())
}

// During copying, we may encounter errors from either side closing their connection. Typically, we
// get a fully graceful shutdown with no errors on either end, but can if one end sends a RST directly,
// or if we have other non-graceful behavior, we may see errors. This is generally ok - a TCP connection
// can close at any time, really. Avoid reporting these as errors, as generally users expect errors to
// occur only when we cannot connect to the backend at all.
fn ignore_io_errors<T: Default>(res: Result<T, io::Error>) -> Result<T, io::Error> {
    use io::ErrorKind::*;
    match &res {
        Err(e) => match e.kind() {
            NotConnected | UnexpectedEof | ConnectionReset | BrokenPipe => {
                trace!(err=%e, "io terminated ungracefully");
                // Returning Default here is very hacky, but the data we are returning isn't critical so its no so bad to lose it.
                // Changing this would require refactoring all the interfaces to always return the bytes written even on error.
                Ok(Default::default())
            }
            _ => res,
        },
        _ => res,
    }
}

// During shutdown, the other end may have already disconnected. That is fine, they shutdown for us.
// Ignore it.
fn ignore_shutdown_errors(res: Result<(), io::Error>) -> Result<(), io::Error> {
    match &res {
        Err(e)
            if e.kind() == io::ErrorKind::NotConnected
                || e.kind() == io::ErrorKind::UnexpectedEof =>
        {
            trace!(err=%e, "failed to shutdown peer, they already shutdown");
            Ok(())
        }
        _ => res,
    }
}

// CopyBuf is a fork of Tokio's same struct, with additional support for resizing and metrics reporting.
#[must_use = "futures do nothing unless you `.await` or poll them"]
struct CopyBuf<'a, R: ?Sized, W: ?Sized> {
    send: bool,
    reader: &'a mut R,
    writer: &'a mut W,
    buf: Option<Bytes>,
    metrics: &'a ConnectionResult,
    amt: u64,
}

async fn copy_buf<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    metrics: &ConnectionResult,
    is_send: bool,
) -> std::io::Result<u64>
where
    R: ResizeBufRead + Unpin + ?Sized,
    W: AsyncWriteBuf + Unpin + ?Sized,
{
    CopyBuf {
        send: is_send,
        reader,
        writer,
        buf: None,
        metrics,
        amt: 0,
    }
    .await
}

impl<R, W> Future for CopyBuf<'_, R, W>
where
    R: ResizeBufRead + Unpin + ?Sized,
    W: AsyncWriteBuf + Unpin + ?Sized,
{
    type Output = std::io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let me = &mut *self;

            // Get our stored buffer if there is any remaining, or fetch some more.
            let buffer = if let Some(buffer) = me.buf.take() {
                buffer
            } else {
                ready!(Pin::new(&mut *me.reader).poll_bytes(cx))?
            };
            if buffer.is_empty() {
                ready!(AsyncWriteBuf::poll_flush(Pin::new(&mut self.writer), cx))?;
                return Poll::Ready(Ok(self.amt));
            }

            // This is just a reference counter. Hold onto it in case the write() is not complete.
            let mut our_copy = buffer.clone();
            let i = match Pin::new(&mut *me.writer).poll_write_buf(cx, buffer) {
                Poll::Ready(written) => written?,
                Poll::Pending => {
                    me.buf = Some(our_copy);
                    return Poll::Pending;
                }
            };
            if i == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            if i < our_copy.len() {
                // We only partially consumed it; store it back for a future call, skipping the number of bytes we did read.
                our_copy.advance(i);
                me.buf = Some(our_copy);
            }
            if me.send {
                me.metrics.increment_send(i as u64);
            } else {
                me.metrics.increment_recv(i as u64);
            }
            let old = self.amt;
            self.amt += i as u64;

            // If we were below the resize threshold before but are now above it, trigger the buffer to resize
            if old < RESIZE_THRESHOLD_LARGE && RESIZE_THRESHOLD_LARGE <= self.amt {
                Pin::new(&mut *self.reader).resize(LARGE_BUFFER_SIZE);
            }
            if old < RESIZE_THRESHOLD_JUMBO && RESIZE_THRESHOLD_JUMBO <= self.amt {
                Pin::new(&mut *self.reader).resize(JUMBO_BUFFER_SIZE);
            }
        }
    }
}

// BufReader is a fork of Tokio's type with resize support
pin_project! {
    pub struct BufReader<R> {
        #[pin]
        inner: R,
        buf: BytesMut,
        buffer_size: usize
    }
}

impl<R: AsyncRead> BufReader<R> {
    /// Creates a new `BufReader` with a default buffer capacity. The default is currently INITIAL_BUFFER_SIZE
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(INITIAL_BUFFER_SIZE),
            buffer_size: INITIAL_BUFFER_SIZE,
        }
    }
}

impl<R: AsyncRead> ResizeBufRead for BufReader<R> {
    fn poll_bytes(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
        let me = self.project();

        // Give us enough space to read a full chunk
        me.buf.reserve(*me.buffer_size);
        ready!(tokio_util::io::poll_read_buf(me.inner, cx, me.buf))?;
        Poll::Ready(Ok(me.buf.split().freeze()))
    }

    fn resize(self: Pin<&mut Self>, new_size: usize) {
        let me = self.project();
        *me.buffer_size = new_size;
    }
}

pin_project! {
    /// A future used to shutdown an I/O object.
    ///
    /// Created by the [`AsyncWriteExt::shutdown`][shutdown] function.
    /// [shutdown]: [`crate::io::AsyncWriteExt::shutdown`]
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    #[derive(Debug)]
    pub struct Shutdown<'a, A: ?Sized> {
        a: &'a mut A,
        // Make this future `!Unpin` for compatibility with async trait methods.
        #[pin]
        _pin: PhantomPinned,
    }
}

/// Creates a future which will shutdown an I/O object.
pub(super) fn shutdown<A>(a: &mut A) -> Shutdown<'_, A>
where
    A: AsyncWriteBuf + Unpin + ?Sized,
{
    Shutdown {
        a,
        _pin: PhantomPinned,
    }
}

impl<A> Future for Shutdown<'_, A>
where
    A: AsyncWriteBuf + Unpin + ?Sized,
{
    type Output = std::io::Result<()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.project();
        AsyncWriteBuf::poll_shutdown(Pin::new(me.a), cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::helpers::initialize_telemetry;
    use rand::Rng;
    use tokio::io::AsyncWriteExt;
    use tokio::io::{AsyncReadExt, ReadBuf};

    #[tokio::test]
    async fn copy() {
        initialize_telemetry();
        let (mut client, ztunnel_downsteam) = tokio::io::duplex(32000);
        let (mut server, ztunnel_upsteam) = tokio::io::duplex(32000);

        // Spawn copy
        tokio::task::spawn(async move {
            let mut registry = prometheus_client::registry::Registry::default();
            let metrics = std::sync::Arc::new(crate::proxy::Metrics::new(
                crate::metrics::sub_registry(&mut registry),
            ));
            let source_addr = "127.0.0.1:12345".parse().unwrap();
            let dest_addr = "127.0.0.1:34567".parse().unwrap();
            let cr = ConnectionResult::new(
                source_addr,
                dest_addr,
                None,
                std::time::Instant::now(),
                crate::proxy::metrics::ConnectionOpen {
                    reporter: crate::proxy::Reporter::destination,
                    source: None,
                    derived_source: None,
                    destination: None,
                    connection_security_policy: crate::proxy::metrics::SecurityPolicy::unknown,
                    destination_service: None,
                },
                metrics.clone(),
            );
            copy_bidirectional(ztunnel_downsteam, ztunnel_upsteam, &cr).await
        });
        const ITERS: usize = 1000;
        const REPEATS: usize = 6400;
        // Make sure we write enough to trigger the resize
        if ITERS * REPEATS < JUMBO_BUFFER_SIZE {
            panic!("not enough writing to test")
        }
        for i in 0..ITERS {
            let body = [1, 2, 3, 4, i as u8].repeat(REPEATS);
            let mut res = vec![0; body.len()];
            tokio::try_join!(client.write_all(&body), server.read_exact(&mut res)).unwrap();
            assert_eq!(res.as_slice(), body);
        }
    }

    #[tokio::test]
    async fn copystress() {
        initialize_telemetry();
        let (mut client, ztunnel_downsteam) = tokio::io::duplex(32000);
        let (mut server, ztunnel_upsteam) = tokio::io::duplex(32000);

        // Spawn copy
        tokio::task::spawn(async move {
            let mut registry = prometheus_client::registry::Registry::default();
            let metrics = std::sync::Arc::new(crate::proxy::Metrics::new(
                crate::metrics::sub_registry(&mut registry),
            ));
            let source_addr = "127.0.0.1:12345".parse().unwrap();
            let dest_addr = "127.0.0.1:34567".parse().unwrap();
            let cr = ConnectionResult::new(
                source_addr,
                dest_addr,
                None,
                std::time::Instant::now(),
                crate::proxy::metrics::ConnectionOpen {
                    reporter: crate::proxy::Reporter::destination,
                    source: None,
                    derived_source: None,
                    destination: None,
                    connection_security_policy: crate::proxy::metrics::SecurityPolicy::unknown,
                    destination_service: None,
                },
                metrics.clone(),
            );
            copy_bidirectional(WeirdIO(ztunnel_downsteam), WeirdIO(ztunnel_upsteam), &cr).await
        });
        const WRITES: usize = 2560;
        // Do a bunch of writes of various size, and expect the other end to receive them
        let writer = tokio::task::spawn(async move {
            for d in 0..WRITES {
                let body: Vec<u8> = (0..d).map(|v| (v % 255) as u8).collect();
                client.write_all(&body).await.unwrap();
            }
        });
        let reader = tokio::task::spawn(async move {
            for d in 0..WRITES {
                let want: Vec<u8> = (0..d).map(|v| (v % 255) as u8).collect();
                let mut got = vec![0; d];
                server.read_exact(&mut got).await.unwrap();
                assert_eq!(got.as_slice(), want);
            }
        });
        tokio::try_join!(reader, writer).unwrap();
    }

    struct WeirdIO<I>(I);
    impl<I: AsyncWrite + std::marker::Unpin> AsyncWrite for WeirdIO<I> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, Error>> {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let mut rng = rand::rng();
            let end = rng.random_range(1..=buf.len()); // Ensure at least 1 byte is written
            Pin::new(&mut self.0).poll_write(cx, &buf[0..end])
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Result<(), Error>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
    impl<I: AsyncRead + std::marker::Unpin> AsyncRead for WeirdIO<I> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            // TODO
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }
}
