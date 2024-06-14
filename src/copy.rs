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
use crate::proxy::Error::{BackendDisconnected, ClientDisconnected};
use pin_project_lite::pin_project;
use std::cmp;
use std::future::Future;
use std::io::IoSlice;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::trace;

// BufferedSplitter is a trait to expose splitting an IO object into a buffered reader and a writer
pub trait BufferedSplitter: Unpin {
    type R: ResizeBufRead + Unpin;
    type W: AsyncWrite + Unpin;
    fn split_into_buffered_reader(self) -> (Self::R, Self::W);
}

// Generic BufferedSplitter for anything that can Read/Write.
impl<I> BufferedSplitter for I
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    type R = BufReader<io::ReadHalf<I>>;
    type W = io::WriteHalf<I>;
    fn split_into_buffered_reader(self) -> (Self::R, Self::W) {
        let (rh, wh) = tokio::io::split(self);
        let rb = BufReader::new(rh);
        (rb, wh)
    }
}

// ResizeBufRead is like AsyncBufRead, but allows triggering a resize.
pub trait ResizeBufRead {
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<&[u8]>>;
    fn consume(self: Pin<&mut Self>, amt: usize);
    fn resize(self: Pin<&mut Self>);
}

// Initially we create a 1k buffer for each connection. Note currently there are 3 buffers per connection.
// Outbound: downstream to app. Upstream HBONE is optimized to avoid.
// Inbound: downstream HBONE, upstream to app. Downstream HBONE can be optimized, but is not yet.
const INITIAL_BUFFER_SIZE: usize = 1024;
// We increase up to 16k for high traffic connections.
// TLS record size max is 16k. But we also have an H2 frame header, so leave a bit of room for that.
const LARGE_BUFFER_SIZE: usize = 16_384 - 64;
// After 128k of data we will trigger a resize from INITIAL to LARGE
// Loosely inspired by https://github.com/golang/go/blame/5122a6796ef98e3453c994c95abd640596540bea/src/crypto/tls/conn.go#L873
const RESIZE_THRESHOLD: u64 = 128 * 1024;

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
        ignore_shutdown_errors(wu.shutdown().await)?;
        res
    };

    let upstream_to_downstream = async {
        let res = copy_buf(&mut ru, &mut wd, stats, true).await;
        trace!(?res, "receive");
        ignore_shutdown_errors(wd.shutdown().await)?;
        res
    };

    // join!() them rather than try_join!() so that we keep complete either end once one side is complete.
    let (sent, received) = tokio::join!(downstream_to_upstream, upstream_to_downstream);

    // Convert some error messages to easier to understand
    let sent = sent.map_err(|e| match e.kind() {
        io::ErrorKind::NotConnected => BackendDisconnected,
        io::ErrorKind::UnexpectedEof => ClientDisconnected,
        _ => e.into(),
    })?;
    let received = received.map_err(|e| match e.kind() {
        io::ErrorKind::NotConnected => ClientDisconnected,
        _ => e.into(),
    })?;
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
    W: tokio::io::AsyncWrite + Unpin + ?Sized,
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
    W: AsyncWrite + Unpin + ?Sized,
{
    type Output = std::io::Result<u64>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let me = &mut *self;
            let buffer = ready!(Pin::new(&mut *me.reader).poll_fill_buf(cx))?;
            if buffer.is_empty() {
                ready!(Pin::new(&mut self.writer).poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }

            let i = ready!(Pin::new(&mut *me.writer).poll_write(cx, buffer))?;
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
                Pin::new(&mut *self.reader).resize();
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
        buf: Box<[u8]>,
        pos: usize,
        cap: usize,
    }
}

impl<R: AsyncRead> BufReader<R> {
    /// Creates a new `BufReader` with a default buffer capacity. The default is currently INITIAL_BUFFER_SIZE
    pub fn new(inner: R) -> Self {
        let buffer = vec![0; INITIAL_BUFFER_SIZE];
        Self {
            inner,
            buf: buffer.into_boxed_slice(),
            pos: 0,
            cap: 0,
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
    fn poll_fill_buf(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<&[u8]>> {
        let me = self.project();

        // If we've reached the end of our internal buffer then we need to fetch
        // some more data from the underlying reader.
        // Branch using `>=` instead of the more correct `==`
        // to tell the compiler that the pos..cap slice is always valid.
        if *me.pos >= *me.cap {
            debug_assert!(*me.pos == *me.cap);
            let mut buf = tokio::io::ReadBuf::new(me.buf);
            ready!(me.inner.poll_read(cx, &mut buf))?;
            *me.cap = buf.filled().len();
            *me.pos = 0;
        }
        Poll::Ready(Ok(&me.buf[*me.pos..*me.cap]))
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        let me = self.project();
        *me.pos = cmp::min(*me.pos + amt, *me.cap);
    }

    fn resize(self: Pin<&mut Self>) {
        let me = self.project();
        // If we don't hit this, we somehow called resize twice unexpectedly
        debug_assert_eq!(me.buf.len(), INITIAL_BUFFER_SIZE);
        // Make a new buffer of the large size, and swap it into place
        let mut now = vec![0u8; LARGE_BUFFER_SIZE].into_boxed_slice();
        std::mem::swap(me.buf, &mut now);
        // Now copy over any data from the old buffer.
        me.buf[0..now.len()].copy_from_slice(&now);
        trace!("resized buffer to {}", LARGE_BUFFER_SIZE)
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
