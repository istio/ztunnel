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

use crate::proxy::Error::{BackendDisconnected, ClientDisconnected, ReceiveError, SendError};
use crate::proxy::TeardownCause;
use crate::proxy::{self, ConnectionResult};
use bytes::{Buf, Bytes, BytesMut};
use pin_project_lite::pin_project;
use std::future::Future;
use std::io::Error;
use std::marker::PhantomPinned;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};
use tokio::io;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::trace;

// BufferedSplitter is a trait to expose splitting an IO object into a buffered reader and a writer
pub trait BufferedSplitter: Unpin {
    type R: ResizeBufRead + Unpin;
    type W: AsyncWriteBuf + Unpin;
    fn split_into_buffered_reader(self) -> (Self::R, Self::W);
    /// Closes the halves abortively, so the peer sees a reset rather than an orderly close.
    /// By default the halves are just dropped.
    fn reset(r: Self::R, w: Self::W) {
        drop((r, w));
    }
    /// The teardown cause of the HBONE connection carrying this side, if it is a tunnel.
    fn teardown_cause(_r: &Self::R) -> Option<TeardownCause> {
        None
    }
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
        (rb, WriteAdapter(wh, None))
    }
}

// TcpStreamSplitter is a specialized BufferedSplitter for TcpStream, which is more efficient than the generic
// `tokio::io::split`. The generic method involves locking to access the read and write halves
pub struct TcpStreamSplitter(pub TcpStream);

impl BufferedSplitter for TcpStreamSplitter {
    type R = BufReader<OwnedReadHalf>;
    type W = WriteAdapter<OwnedWriteHalf>;

    fn split_into_buffered_reader(self) -> (Self::R, Self::W) {
        let watch = AbortWatch::new(self.0.as_raw_fd());
        let (rh, wh) = self.0.into_split();
        let rb = BufReader::new(rh);
        (rb, WriteAdapter(wh, Some(watch)))
    }

    fn reset(r: Self::R, w: Self::W) {
        // Reuniting skips the write half's shutdown on drop, so no FIN precedes the RST that
        // closing with a zero linger sends.
        if let Ok(stream) = r.inner.reunite(w.0)
            && let Err(e) = stream.set_zero_linger()
        {
            trace!(err=%e, "failed to set zero linger");
        }
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
    // Resolves with an error if the peer aborted the writer, without a write having to find out.
    // A copy waiting on its reader would otherwise not notice, e.g. an HBONE stream reset after
    // the stream's receive side finished. Never resolves for a writer that cannot tell.
    fn poll_aborted(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Error> {
        Poll::Pending
    }
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

    fn poll_aborted(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Error> {
        Pin::new(&mut **self).poll_aborted(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut **self).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut **self).poll_shutdown(cx)
    }
}

// Allow anything that is AsyncWrite to be AsyncWriteBuf.
pub struct WriteAdapter<T>(T, Option<AbortWatch>);

// AbortWatch notices that the peer of a TCP connection aborted it (sent a RST), which a connection
// that has nothing left to read, because the peer half-closed, does not otherwise find out about
// until it next writes. Only a watched connection that is half-closed pays for it: the watch
// registers a duplicate of the socket with the reactor when it is first polled.
//
// The watched socket must outlive the watch, so it is only used by the halves of a copy.
pub struct AbortWatch {
    fd: RawFd,
    watch: Option<Pin<Box<dyn Future<Output = Error> + Send + Sync>>>,
}

impl AbortWatch {
    fn new(fd: RawFd) -> Self {
        Self { fd, watch: None }
    }

    fn start(&self) -> io::Result<Pin<Box<dyn Future<Output = Error> + Send + Sync>>> {
        // SAFETY: the socket outlives the copy, and so this watch.
        let fd: OwnedFd = unsafe { BorrowedFd::borrow_raw(self.fd) }.try_clone_to_owned()?;
        let fd = AsyncFd::with_interest(fd, Interest::ERROR)?;
        Ok(Box::pin(async move {
            // An error on a connection that the peer half-closed is the peer's reset.
            let _ = fd.ready(Interest::ERROR).await;
            Error::from(io::ErrorKind::ConnectionReset)
        }))
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Error> {
        if self.watch.is_none() {
            self.watch = Some(self.start().unwrap_or_else(|e| {
                trace!(err=%e, "failed to watch for an abort");
                Box::pin(std::future::pending())
            }));
        }
        self.watch.as_mut().expect("just set").as_mut().poll(cx)
    }
}

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

    fn poll_aborted(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Error> {
        match &mut self.1 {
            Some(watch) => watch.poll(cx),
            None => Poll::Pending,
        }
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
    // Dropping the copy before it completes (e.g. on a late policy rejection) aborts it too, so
    // the sides are reset unless the copy closes them gracefully.
    let mut sides = ResetOnDrop::<A, B>(Some((
        downstream.split_into_buffered_reader(),
        upstream.split_into_buffered_reader(),
    )));
    let ((rd, wd), (ru, wu)) = sides
        .0
        .as_mut()
        .expect("sides are only taken once copying ends");
    // A tunnel's teardown only reaches the copy through h2 I/O, which it may not be doing, e.g.
    // once the tunnel has finished sending and the copy waits on the other side. So the copy
    // watches for it too. A copy has at most one tunnel side. The watch is boxed so that it does
    // not grow every copy future.
    let torn_down = A::teardown_cause(rd)
        .or_else(|| B::teardown_cause(ru))
        .map(|cause| Box::pin(async move { cause.torn_down().await }));
    let (send_done, receive_done) = (AtomicBool::new(false), AtomicBool::new(false));
    let downstream_to_upstream = copy_direction(
        rd,
        wu,
        stats,
        false,
        &receive_done,
        &send_done,
        |e: io::Error| {
            SendError(Box::new(match e.kind() {
                io::ErrorKind::NotConnected => BackendDisconnected,
                io::ErrorKind::WriteZero => BackendDisconnected,
                io::ErrorKind::UnexpectedEof => ClientDisconnected,
                _ => e.into(),
            }))
        },
    );
    let upstream_to_downstream = copy_direction(
        ru,
        wd,
        stats,
        true,
        &send_done,
        &receive_done,
        |e: io::Error| {
            ReceiveError(Box::new(match e.kind() {
                io::ErrorKind::NotConnected => ClientDisconnected,
                io::ErrorKind::WriteZero => ClientDisconnected,
                _ => e.into(),
            }))
        },
    );

    // Join the directions so that we keep completing either end once one side is complete; only
    // an abort stops the other direction. A teardown aborts both. On an abort, dropping the sides
    // resets them.
    let (sent, received) = tokio::select! {
        res = async { tokio::try_join!(downstream_to_upstream, upstream_to_downstream) } => match res {
            Ok(results) => results,
            Err(res) => return res,
        },
        teardown = async {
            match torn_down {
                Some(torn_down) => torn_down.await,
                None => std::future::pending().await,
            }
        } => {
            trace!(%teardown, "copy aborted");
            return Err(teardown.into());
        }
    };
    // Copying ended on its own, so the sides close gracefully rather than being reset.
    drop(sides.0.take());

    // Convert some error messages to easier to understand
    let sent = sent?;
    let received = received?;
    trace!(sent, received, "copy complete");
    Ok(())
}

// Copies one direction of a copy and then shuts down its writer. `other_done` and `done` are whether the other direction and
// this one are done. A connection aborted error means a transport failed out from under the copy (e.g. an HBONE ping timeout),
// and a connection reset means a peer aborted its connection. Rather than closing gracefully, which the other peer would
// take as a clean end of stream, the other direction is stopped and both sides are reset. So the
// direction completes with `Ok` and its own result, or, when it aborts, with `Err` and the result
// of the whole copy.
async fn copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    stats: &ConnectionResult,
    upstream_to_downstream: bool,
    other_done: &AtomicBool,
    done: &AtomicBool,
    translate_error: impl Fn(io::Error) -> proxy::Error + Copy,
) -> Result<Result<u64, proxy::Error>, Result<(), proxy::Error>>
where
    R: ResizeBufRead + Unpin,
    W: AsyncWriteBuf + Unpin,
{
    let name = if upstream_to_downstream {
        "receive"
    } else {
        "send"
    };
    let res = copy_buf(reader, writer, stats, upstream_to_downstream, other_done).await;
    if matches!(&res, Err(e) if matches!(e.kind(), io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset))
    {
        trace!(?res, "{name} aborted");
        return Err(aborted_result(res, translate_error));
    }
    done.store(true, Ordering::Relaxed);
    // Let the other direction know, it may be waiting on its reader
    tokio::task::yield_now().await;
    let res = ignore_io_errors(res).map_err(translate_error);
    trace!(?res, "{name}");
    let shutdown = ignore_shutdown_errors(shutdown(writer).await)
        .map_err(translate_error)
        .map_err(|e| proxy::Error::ShutdownError(Box::new(e)));
    Ok(shutdown.and(res))
}

// The result of a copy that a direction aborted. An abort caused by an HBONE teardown is reported
// as the teardown itself, whichever direction it surfaced in, while a peer's reset is still not
// reported as an error (see `ignore_io_errors`).
fn aborted_result(
    res: io::Result<u64>,
    translate_error: impl FnOnce(io::Error) -> proxy::Error,
) -> Result<(), proxy::Error> {
    ignore_io_errors(res)
        .map(drop)
        .map_err(|e| proxy::Error::from_teardown(&e).unwrap_or_else(|| translate_error(e)))
}

type Halves<S> = (<S as BufferedSplitter>::R, <S as BufferedSplitter>::W);

// ResetOnDrop holds the sides of a copy and resets them when dropped, unless they were taken.
struct ResetOnDrop<A: BufferedSplitter, B: BufferedSplitter>(Option<(Halves<A>, Halves<B>)>);

impl<A: BufferedSplitter, B: BufferedSplitter> Drop for ResetOnDrop<A, B> {
    fn drop(&mut self) {
        if let Some(((rd, wd), (ru, wu))) = self.0.take() {
            A::reset(rd, wd);
            B::reset(ru, wu);
        }
    }
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
                || e.kind() == io::ErrorKind::BrokenPipe
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
    // Whether the copy's other direction is done, so only this one is left to notice an abort.
    other_done: &'a AtomicBool,
    amt: u64,
}

async fn copy_buf<'a, R, W>(
    reader: &'a mut R,
    writer: &'a mut W,
    metrics: &ConnectionResult,
    is_send: bool,
    other_done: &AtomicBool,
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
        other_done,
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
                match Pin::new(&mut *me.reader).poll_bytes(cx) {
                    Poll::Ready(res) => res?,
                    Poll::Pending => {
                        // Waiting on the reader, so a write won't find out if the peer aborted. While the
                        // other direction is running, it finds out for both.
                        if me.other_done.load(Ordering::Relaxed)
                            && let Poll::Ready(err) = Pin::new(&mut *me.writer).poll_aborted(cx)
                        {
                            return Poll::Ready(Err(err));
                        }
                        return Poll::Pending;
                    }
                }
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
pub(crate) mod tests {
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
            let source_addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
            let dest_addr: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
            let cr = crate::proxy::metrics::ConnectionResultBuilder::new(
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
            )
            .build();
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
            let source_addr: std::net::SocketAddr = "127.0.0.1:12345".parse().unwrap();
            let dest_addr: std::net::SocketAddr = "127.0.0.1:34567".parse().unwrap();
            let cr = crate::proxy::metrics::ConnectionResultBuilder::new(
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
            )
            .build();
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

    pub(crate) fn connection_result() -> ConnectionResult {
        let mut registry = prometheus_client::registry::Registry::default();
        let metrics = std::sync::Arc::new(crate::proxy::Metrics::new(
            crate::metrics::sub_registry(&mut registry),
        ));
        crate::proxy::metrics::ConnectionResultBuilder::new(
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1:34567".parse().unwrap(),
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
            metrics,
        )
        .build()
    }

    // An upstream whose reads fail with `kind`, standing in for a transport torn down underneath it.
    struct FailingRead(io::ErrorKind);
    impl AsyncRead for FailingRead {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(self.0.into()))
        }
    }
    impl AsyncWrite for FailingRead {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, Error>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }
    }

    // Copies between an idle TCP client and an upstream whose reads fail with `kind`, returning
    // what the client observes on its first read and then the copy result once the client closes.
    async fn copy_with_failing_upstream(
        kind: io::ErrorKind,
    ) -> (std::io::Result<usize>, Result<(), proxy::Error>) {
        initialize_telemetry();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (downstream, _) = listener.accept().await.unwrap();
        let copy = tokio::spawn(async move {
            let cr = connection_result();
            copy_bidirectional(TcpStreamSplitter(downstream), FailingRead(kind), &cr).await
        });
        let read = client.read(&mut [0; 16]).await;
        drop(client);
        (read, copy.await.unwrap())
    }

    #[tokio::test]
    async fn aborted_upstream_resets_downstream() {
        let (read, res) = copy_with_failing_upstream(io::ErrorKind::ConnectionAborted).await;
        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn reset_upstream_resets_downstream_quietly() {
        let (read, res) = copy_with_failing_upstream(io::ErrorKind::ConnectionReset).await;
        assert_eq!(read.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn broken_upstream_closes_downstream() {
        let (read, res) = copy_with_failing_upstream(io::ErrorKind::BrokenPipe).await;
        assert_eq!(read.unwrap(), 0);
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn app_reset_after_half_close_ends_copy() {
        initialize_telemetry();
        async fn tcp_pair() -> (TcpStream, TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            (a, listener.accept().await.unwrap().0)
        }
        let (mut app, downstream) = tcp_pair().await;
        let (upstream, mut backend) = tcp_pair().await;
        let copy = tokio::spawn(async move {
            let cr = connection_result();
            copy_bidirectional(
                TcpStreamSplitter(downstream),
                TcpStreamSplitter(upstream),
                &cr,
            )
            .await
        });
        app.shutdown().await.unwrap();
        assert_eq!(backend.read(&mut [0; 16]).await.unwrap(), 0);

        app.set_zero_linger().unwrap();
        drop(app);

        tokio::time::timeout(std::time::Duration::from_secs(5), copy)
            .await
            .expect("the copy never saw the reset")
            .unwrap()
            .unwrap();
    }

    struct ReadOnce(Option<Bytes>);
    impl ResizeBufRead for ReadOnce {
        fn poll_bytes(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<Bytes>> {
            match self.0.take() {
                Some(b) => Poll::Ready(Ok(b)),
                None => Poll::Pending,
            }
        }
        fn resize(self: Pin<&mut Self>, _: usize) {}
    }

    // A writer that resets on write if `reset_on_write`, and records whether it was shut down.
    struct RecordingWriter {
        reset_on_write: bool,
        shutdown: std::sync::Arc<AtomicBool>,
    }
    impl AsyncWriteBuf for RecordingWriter {
        fn poll_write_buf(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            b: Bytes,
        ) -> Poll<io::Result<usize>> {
            if self.reset_on_write {
                Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
            } else {
                Poll::Ready(Ok(b.len()))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shutdown.store(true, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    struct Side(ReadOnce, RecordingWriter);
    impl BufferedSplitter for Side {
        type R = ReadOnce;
        type W = RecordingWriter;
        fn split_into_buffered_reader(self) -> (Self::R, Self::W) {
            (self.0, self.1)
        }
    }

    #[tokio::test]
    async fn reset_does_not_shutdown_surviving_peer() {
        let downstream_shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let downstream = Side(
            ReadOnce(Some(Bytes::from_static(b"request"))),
            RecordingWriter {
                reset_on_write: false,
                shutdown: downstream_shutdown.clone(),
            },
        );
        // The upstream has half-closed, so its read is EOF, and its write finds that it was reset.
        let upstream = Side(
            ReadOnce(Some(Bytes::new())),
            RecordingWriter {
                reset_on_write: true,
                shutdown: Default::default(),
            },
        );
        copy_bidirectional(downstream, upstream, &connection_result())
            .await
            .unwrap();
        assert!(!downstream_shutdown.load(Ordering::SeqCst));
    }
}
