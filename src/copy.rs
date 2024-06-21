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

use crate::proxy::ConnectionResult;
use crate::proxy::Error::{BackendDisconnected, ClientDisconnected, ReceiveError, SendError};
use pin_project_lite::pin_project;
use std::cmp;
use std::future::Future;
use std::io::{Error, IoSlice};
use std::marker::PhantomPinned;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use bytes::{Buf, Bytes, BytesMut};
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tracing::{error, trace};

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

pub trait AsyncWriteBuf {
    fn poll_write_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: Bytes,
    ) -> Poll<std::io::Result<usize>>;
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>>;
}

impl<T: ?Sized + AsyncWriteBuf + Unpin> AsyncWriteBuf for &mut T {
    fn poll_write_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: Bytes) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut **self).poll_write_buf(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut **self).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut **self).poll_shutdown(cx)
    }
}

pub struct WriteAdapter<T>(T);

impl<T: AsyncWrite + Unpin> AsyncWriteBuf for WriteAdapter<T> {
    fn poll_write_buf(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: Bytes) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf.chunk())
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
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<Bytes>>;
    fn consume(self: Pin<&mut Self>, amt: usize);
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
const RESIZE_THRESHOLD: u64 = 128 * 1024;
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
    use tokio::io::AsyncWriteExt;
    let (mut rd, mut wd) = downstream.split_into_buffered_reader();
    let (mut ru, mut wu) = upstream.split_into_buffered_reader();

    let downstream_to_upstream = async {
        let res = copy_buf(&mut rd, &mut wu, stats, false).await;
        trace!(?res, "send");
        ignore_shutdown_errors(shutdown(&mut wu).await)?;
        res
    };

    let upstream_to_downstream = async {
        let res = copy_buf(&mut ru, &mut wd, stats, true).await;
        trace!(?res, "receive");
        ignore_shutdown_errors(shutdown(&mut wd).await)?;
        res
    };

    // join!() them rather than try_join!() so that we keep complete either end once one side is complete.
    let (sent, received) = tokio::join!(downstream_to_upstream, upstream_to_downstream);

    // Convert some error messages to easier to understand
    let sent = sent
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotConnected => BackendDisconnected,
            io::ErrorKind::UnexpectedEof => ClientDisconnected,
            _ => e.into(),
        })
        .map_err(|e| SendError(Box::new(e)))?;
    let received = received
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotConnected => ClientDisconnected,
            _ => e.into(),
        })
        .map_err(|e| ReceiveError(Box::new(e)))?;
    trace!(sent, received, "copy complete");
    Ok(())
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
            let mut buffer = ready!(Pin::new(&mut *me.reader).poll_fill_buf(cx))?;
            if buffer.is_empty() {
                ready!(AsyncWriteBuf::poll_shutdown(Pin::new(&mut self.writer), cx))?;
                return Poll::Ready(Ok(self.amt));
            }

            let i = ready!(Pin::new(&mut *me.writer).poll_write_buf(cx, buffer))?;
            if i == 0 {
                return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
            }
            if me.send {
                me.metrics.increment_send(i as u64);
            } else {
                me.metrics.increment_recv(i as u64);
            }
            let old = self.amt;
            self.amt += i as u64;

            // If we were below the resize threshold before but are now above it, trigger the buffer to resize
            if old < RESIZE_THRESHOLD && RESIZE_THRESHOLD <= self.amt {
                Pin::new(&mut *self.reader).resize(LARGE_BUFFER_SIZE);
            }
            if old < RESIZE_THRESHOLD_JUMBO && RESIZE_THRESHOLD_JUMBO <= self.amt {
                Pin::new(&mut *self.reader).resize(JUMBO_BUFFER_SIZE);
            }
            Pin::new(&mut *self.reader).consume(i);
        }
    }
}

// BufReader is a fork of Tokio's type with resize support
pin_project! {
    pub struct BufReader<R> {
        #[pin]
        inner: R,
        buf: Option<Bytes>,
        buffer_size: usize
    }
}

impl<R: AsyncRead> BufReader<R> {
    /// Creates a new `BufReader` with a default buffer capacity. The default is currently INITIAL_BUFFER_SIZE
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: None,
            buffer_size: INITIAL_BUFFER_SIZE
        }
    }

    fn get_ref(&self) -> &R {
        &self.inner
    }

    fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut R> {
        self.project().inner
    }
}

impl<R: AsyncRead> ResizeBufRead for BufReader<R> {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
        let me = self.project();

        if me.buf.is_none() {
            // TODO: do not alloc every time?
            let mut buf = BytesMut::with_capacity(*me.buffer_size);
            ready!(tokio_util::io::poll_read_buf(me.inner, cx, &mut buf))?;
            *me.buf = Some(buf.freeze());
        }
        let b = me.buf.as_ref().map(|x| x.clone()).unwrap();
        Poll::Ready(Ok(b))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        let mut b = me.buf.take().unwrap();
        b.advance(amt);
        if b.remaining() > 0 {
            *me.buf = Some(b);
        } else {
            *me.buf = None;
        }
        // *me.pos = cmp::min(*me.pos + amt, *me.cap);
    }

    fn resize(self: Pin<&mut Self>, new_size: usize) {
        let me = self.project();
        *me.buffer_size = new_size;
        //  TODO
        // me.buf.resize(new_size, 0);
        // trace!("resized buffer to {}", new_size)
    }
}

impl<R: AsyncRead + AsyncWrite> AsyncWrite for BufReader<R> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_pin_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_pin_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_pin_mut().poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_pin_mut().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.get_ref().is_write_vectored()
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
