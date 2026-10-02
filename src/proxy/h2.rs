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
use bytes::Bytes;
use futures_core::ready;
use h2::Reason;
use std::io::Error;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::trace;

pub mod client;
pub mod server;

/// Why an HBONE connection was torn down or failed. Its streams report this in place of the
/// incidental error h2 hands them (a broken pipe, or a GOAWAY that reads as a clean close), so the
/// access log shows the real cause and the copy propagates the abort to the other side.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Teardown {
    #[error("HBONE ping timeout")]
    PingTimeout,
    #[error("HBONE ping error: {0}")]
    PingError(String),
    #[error("peer certificate revoked by CRL")]
    CertificateRevoked,
    #[error("HBONE transport error: {0}")]
    Transport(String),
}

impl Teardown {
    fn into_io(self) -> Error {
        Error::new(std::io::ErrorKind::ConnectionAborted, self)
    }
}

/// The teardown cause of one HBONE connection, set once by its driver before it tears the
/// connection down. A tunnel carried inside another tunnel's stream also reports the outer cause,
/// since the outer teardown only reaches the inner streams as an opaque transport error.
#[derive(Clone, Debug, Default)]
pub struct TeardownCause {
    cause: Arc<OnceLock<Teardown>>,
    outer: Option<Arc<TeardownCause>>,
}

impl TeardownCause {
    pub fn nested(outer: TeardownCause) -> Self {
        Self {
            cause: Default::default(),
            outer: Some(Arc::new(outer)),
        }
    }

    pub(crate) fn set(&self, teardown: Teardown) {
        let _ = self.cause.set(teardown);
    }

    fn get(&self) -> Option<&Teardown> {
        self.cause
            .get()
            .or_else(|| self.outer.as_ref().and_then(|o| o.get()))
    }

    /// Reports `e` as the teardown, if there was one.
    pub(crate) fn attribute(&self, e: impl Into<crate::proxy::Error>) -> crate::proxy::Error {
        match self.get() {
            Some(teardown) => teardown.clone().into(),
            None => e.into(),
        }
    }
}

/// do_ping_pong sends the teardown on `tx` if a ping times out or errors.
async fn do_ping_pong(
    mut ping_pong: h2::PingPong,
    tx: oneshot::Sender<Teardown>,
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
        log::trace!("ping sent");
        match tokio::time::timeout(PING_TIMEOUT, ping_fut).await {
            Err(_) => {
                // We will log this again up in drive_connection, so don't worry about a high log level
                log::trace!("ping timeout");
                let _ = tx.send(Teardown::PingTimeout);
                return;
            }
            Ok(r) => match r {
                Ok(_) => {
                    log::trace!("pong received");
                    tokio::time::sleep(PING_INTERVAL).await;
                }
                Err(e) => {
                    if dropped.load(Ordering::Relaxed) {
                        // drive_connection() exits first, no need to error again
                        return;
                    }
                    // If this was a broken pipe error, then the connection is already closed and we
                    // we can't ping it. This isn't an error, but more of a race condition we cannot
                    // catch.
                    if Some(std::io::ErrorKind::BrokenPipe) != e.get_io().map(|io| io.kind()) {
                        log::error!("ping error: {e}");
                    }

                    let _ = tx.send(Teardown::PingError(e.to_string()));
                    return;
                }
            },
        }
    }
}

// H2Stream represents an active HTTP2 stream. Consumers can only Read/Write
pub struct H2Stream {
    read: H2StreamReadHalf,
    write: H2StreamWriteHalf,
}

pub struct H2StreamReadHalf {
    recv_stream: h2::RecvStream,
    _dropped: Option<DropCounter>,
    teardown: TeardownCause,
}

pub struct H2StreamWriteHalf {
    send_stream: h2::SendStream<Bytes>,
    _dropped: Option<DropCounter>,
    teardown: TeardownCause,
}

pub struct TokioH2Stream {
    stream: H2Stream,
    buf: Bytes,
}

struct DropCounter {
    // Whether the other end of this shared counter has already dropped.
    // We only decrement if they have, so we do not double count
    half_dropped: Arc<()>,
    active_count: Arc<AtomicU16>,
}

impl DropCounter {
    pub fn new(active_count: Arc<AtomicU16>) -> (Option<DropCounter>, Option<DropCounter>) {
        let half_dropped = Arc::new(());
        let d1 = DropCounter {
            half_dropped: half_dropped.clone(),
            active_count: active_count.clone(),
        };
        let d2 = DropCounter {
            half_dropped,
            active_count,
        };
        (Some(d1), Some(d2))
    }
}

impl H2Stream {
    /// The teardown cause of the connection carrying this stream.
    pub fn teardown_cause(&self) -> TeardownCause {
        self.read.teardown.clone()
    }
}

impl crate::copy::BufferedSplitter for H2Stream {
    type R = H2StreamReadHalf;
    type W = H2StreamWriteHalf;
    fn split_into_buffered_reader(self) -> (H2StreamReadHalf, H2StreamWriteHalf) {
        let H2Stream { read, write } = self;
        (read, write)
    }

    fn reset(_r: H2StreamReadHalf, mut w: H2StreamWriteHalf) {
        // RFC 9113 section 8.5: a CONNECT tunnel whose TCP connection fails is reset with
        // CONNECT_ERROR, which the peer turns back into a TCP reset.
        w.send_stream.send_reset(Reason::CONNECT_ERROR);
    }
}

impl H2StreamWriteHalf {
    fn write_slice(&mut self, buf: Bytes, end_of_stream: bool) -> Result<(), std::io::Error> {
        self.send_stream
            .send_data(buf, end_of_stream)
            .map_err(h2_to_io_error)
    }
}

impl Drop for DropCounter {
    fn drop(&mut self) {
        let mut half_dropped = Arc::new(());
        std::mem::swap(&mut self.half_dropped, &mut half_dropped);
        if Arc::into_inner(half_dropped).is_none() {
            // other half already dropped
            let left = self.active_count.fetch_sub(1, Ordering::SeqCst);
            trace!("dropping H2Stream, has {} active streams left", left - 1);
        } else {
            trace!("dropping H2Stream, other half remains");
        }
    }
}

// We can't directly implement tokio::io::{AsyncRead, AsyncWrite} for H2Stream because
// then the specific implementation will conflict with the generic one.
impl TokioH2Stream {
    pub fn new(stream: H2Stream) -> Self {
        Self {
            stream,
            buf: Bytes::new(),
        }
    }
}

impl tokio::io::AsyncRead for TokioH2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Just return the bytes we have left over and don't poll the stream because
        // its unclear what to do if there are bytes left over from the previous read, and when we
        // poll, we get an error.
        if self.buf.is_empty() {
            // If we have no unread bytes, we can poll the stream
            // and fill self.buf with the bytes we read.
            let pinned = std::pin::Pin::new(&mut self.stream.read);
            let res = ready!(copy::ResizeBufRead::poll_bytes(pinned, cx))?;
            self.buf = res;
        }
        // Copy as many bytes as we can from self.buf.
        let cnt = Ord::min(buf.remaining(), self.buf.len());
        buf.put_slice(&self.buf[..cnt]);
        self.buf = self.buf.split_off(cnt);
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for TokioH2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, tokio::io::Error>> {
        let pinned = std::pin::Pin::new(&mut self.stream.write);
        let buf = Bytes::copy_from_slice(buf);
        copy::AsyncWriteBuf::poll_write_buf(pinned, cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let pinned = std::pin::Pin::new(&mut self.stream.write);
        copy::AsyncWriteBuf::poll_flush(pinned, cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let pinned = std::pin::Pin::new(&mut self.stream.write);
        copy::AsyncWriteBuf::poll_shutdown(pinned, cx)
    }
}

impl copy::ResizeBufRead for H2StreamReadHalf {
    fn poll_bytes(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<Bytes>> {
        self.get_mut().poll_bytes_inner(cx)
    }

    fn resize(self: Pin<&mut Self>, _new_size: usize) {
        // NOP, we don't need to resize as we are abstracting the h2 buffer
    }
}

impl H2StreamReadHalf {
    fn poll_bytes_inner(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<Bytes>> {
        let this = self;
        loop {
            match ready!(this.recv_stream.poll_data(cx)) {
                None => return Poll::Ready(Ok(Bytes::new())),
                Some(Ok(buf)) if buf.is_empty() && !this.recv_stream.is_end_stream() => continue,
                Some(Ok(buf)) => {
                    // TODO: Hyper and Go make their pinging data aware and don't send pings when data is received
                    // Pingora, and our implementation, currently don't do this.
                    // We may want to; if so, modify here.
                    // this.ping.record_data(buf.len());
                    let _ = this.recv_stream.flow_control().release_capacity(buf.len());
                    return Poll::Ready(Ok(buf));
                }
                Some(Err(e)) => {
                    // Once the connection is torn down on purpose, whatever h2 hands the stream is a
                    // consequence of it; only a reset the peer sent is the stream's own cause.
                    if let Some(teardown) = this.teardown.get()
                        && !(e.is_reset() && e.is_remote())
                    {
                        return Poll::Ready(Err(teardown.clone().into_io()));
                    }
                    return Poll::Ready(match e.reason() {
                        Some(Reason::NO_ERROR) | Some(Reason::CANCEL) => {
                            return Poll::Ready(Ok(Bytes::new()));
                        }
                        Some(Reason::STREAM_CLOSED) => {
                            Err(Error::new(std::io::ErrorKind::BrokenPipe, e))
                        }
                        _ => Err(stream_error(e)),
                    });
                }
            }
        }
    }
}

impl copy::AsyncWriteBuf for H2StreamWriteHalf {
    fn poll_write_buf(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: Bytes,
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let wanted = buf.len();
        let res = ready!(this.poll_write_buf_inner(cx, buf));
        Poll::Ready(match this.teardown.get() {
            // h2 reports a torn down connection as no capacity or as one of several errors.
            Some(teardown) if res.is_err() || (wanted > 0 && matches!(res, Ok(0))) => {
                Err(teardown.clone().into_io())
            }
            _ => res,
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let this = self.get_mut();
        let res = ready!(this.poll_shutdown_inner(cx));
        Poll::Ready(match this.teardown.get() {
            Some(teardown) if res.is_err() => Err(teardown.clone().into_io()),
            _ => res,
        })
    }
}

impl H2StreamWriteHalf {
    fn poll_write_buf_inner(
        &mut self,
        cx: &mut Context<'_>,
        buf: Bytes,
    ) -> Poll<std::io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        self.send_stream.reserve_capacity(buf.len());

        // We ignore all errors returned by `poll_capacity` and `write`, as we
        // will get the correct from `poll_reset` anyway.
        let cnt = match ready!(self.send_stream.poll_capacity(cx)) {
            None => Some(0),
            Some(Ok(cnt)) => self.write_slice(buf.slice(..cnt), false).ok().map(|()| cnt),
            Some(Err(_)) => None,
        };

        if let Some(cnt) = cnt {
            return Poll::Ready(Ok(cnt));
        }

        Poll::Ready(Err(match ready!(self.send_stream.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) | Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => {
                std::io::ErrorKind::BrokenPipe.into()
            }
            Ok(reason) => peer_reset_error(reason),
            Err(e) => stream_error(e),
        }))
    }

    fn poll_shutdown_inner(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let r = self.write_slice(Bytes::new(), true);
        if r.is_ok() {
            return Poll::Ready(Ok(()));
        }

        Poll::Ready(Err(match ready!(self.send_stream.poll_reset(cx)) {
            Ok(Reason::NO_ERROR) => return Poll::Ready(Ok(())),
            Ok(Reason::CANCEL) | Ok(Reason::STREAM_CLOSED) => std::io::ErrorKind::BrokenPipe.into(),
            Ok(reason) => peer_reset_error(reason),
            Err(e) => stream_error(e),
        }))
    }
}

// Per RFC 9113 section 8.5, an error with a stream or its HTTP/2 connection aborts the TCP
// connection the stream carries. So a transport failure, or an error the peer sent, is reported as
// connection aborted. A broken pipe is left alone: it is also how a stream sees its connection
// dropped while draining.
fn stream_error(e: h2::Error) -> std::io::Error {
    match e.get_io().map(|io| io.kind()) {
        // Already an abort, e.g. from the tunnel carrying this connection.
        Some(std::io::ErrorKind::BrokenPipe) | Some(std::io::ErrorKind::ConnectionAborted) => {
            h2_to_io_error(e)
        }
        Some(_) => Teardown::Transport(e.to_string()).into_io(),
        None if e.is_reset() && e.is_remote() => peer_reset_error(e),
        None if e.is_remote() => Error::new(std::io::ErrorKind::ConnectionAborted, e),
        None => h2_to_io_error(e),
    }
}

// A reset the peer sent with an error aborts the stream, see `stream_error`. CONNECT_ERROR is how
// the peer relays a TCP reset, so it is reported the same way as a reset of a local connection.
fn peer_reset_error(e: impl Into<h2::Error>) -> std::io::Error {
    let e = e.into();
    let kind = match e.reason() {
        Some(Reason::CONNECT_ERROR) => std::io::ErrorKind::ConnectionReset,
        _ => std::io::ErrorKind::ConnectionAborted,
    };
    Error::new(kind, e)
}

fn h2_to_io_error(e: h2::Error) -> std::io::Error {
    if e.is_io() {
        e.into_io().unwrap()
    } else {
        std::io::Error::other(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::copy::{AsyncWriteBuf, ResizeBufRead};
    use futures_util::future::poll_fn;

    // Opens a single client stream against an in-memory h2 server, returning the stream halves
    // wired to `teardown` and the client connection driver so the test can drop it. When
    // `reset` is set, the server resets the stream with that reason right after responding.
    async fn client_stream(
        teardown: TeardownCause,
        reset: Option<Reason>,
    ) -> (
        H2StreamReadHalf,
        H2StreamWriteHalf,
        tokio::task::JoinHandle<()>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((req, mut respond))) = conn.accept().await {
                let resp = http::Response::builder().status(200).body(()).unwrap();
                let mut stream = respond.send_response(resp, false).unwrap();
                match reset {
                    // Reset once the client sends data, so the client holds the stream first.
                    Some(reason) => {
                        tokio::spawn(async move {
                            let _ = req.into_body().data().await;
                            stream.send_reset(reason);
                        });
                    }
                    // Keep the response stream open; the test tears down the client side.
                    None => std::mem::forget(stream),
                }
            }
        });
        let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("http://example.com")
            .body(())
            .unwrap();
        let (resp, send_stream) = send_req.send_request(req, false).unwrap();
        let recv_stream = resp.await.unwrap().into_body();
        let read = H2StreamReadHalf {
            recv_stream,
            _dropped: None,
            teardown: teardown.clone(),
        };
        let write = H2StreamWriteHalf {
            send_stream,
            _dropped: None,
            teardown,
        };
        (read, write, driver)
    }

    #[tokio::test]
    async fn dropped_connection_without_failure_is_broken_pipe() {
        let (mut read, _write, driver) = client_stream(TeardownCause::default(), None).await;
        driver.abort();
        let _ = driver.await;
        let err = poll_fn(|cx| Pin::new(&mut read).poll_bytes(cx))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn dropped_connection_reports_ping_failure() {
        let failure = TeardownCause::default();
        let (mut read, mut write, driver) = client_stream(failure.clone(), None).await;
        failure.set(Teardown::PingTimeout);
        driver.abort();
        let _ = driver.await;

        let err = poll_fn(|cx| Pin::new(&mut read).poll_bytes(cx))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
        assert_eq!(err.to_string(), "HBONE ping timeout");

        let err = poll_fn(|cx| Pin::new(&mut write).poll_write_buf(cx, Bytes::from_static(b"hi")))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
        assert_eq!(err.to_string(), "HBONE ping timeout");
    }

    #[tokio::test]
    async fn stream_error_is_not_attributed_to_connection_failure() {
        let failure = TeardownCause::default();
        let (mut read, mut write, _driver) =
            client_stream(failure.clone(), Some(Reason::INTERNAL_ERROR)).await;
        // The connection failure is recorded before the stream observes its own reset.
        failure.set(Teardown::PingTimeout);
        poll_fn(|cx| Pin::new(&mut write).poll_write_buf(cx, Bytes::from_static(b"hi")))
            .await
            .unwrap();

        let err = poll_fn(|cx| Pin::new(&mut read).poll_bytes(cx))
            .await
            .unwrap_err();
        // The peer's reset still aborts, but is reported as the peer's error.
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
        let reason = err
            .get_ref()
            .and_then(|e| e.downcast_ref::<h2::Error>())
            .and_then(|e| e.reason());
        assert_eq!(reason, Some(Reason::INTERNAL_ERROR));
    }

    #[tokio::test]
    async fn peer_reset_with_cancel_is_eof() {
        let (mut read, mut write, _driver) =
            client_stream(TeardownCause::default(), Some(Reason::CANCEL)).await;
        poll_fn(|cx| Pin::new(&mut write).poll_write_buf(cx, Bytes::from_static(b"hi")))
            .await
            .unwrap();
        let read = poll_fn(|cx| Pin::new(&mut read).poll_bytes(cx)).await;
        assert!(read.unwrap().is_empty());
    }

    #[tokio::test]
    async fn nested_connection_reports_outer_teardown() {
        let outer = TeardownCause::default();
        let (mut read, _write, driver) =
            client_stream(TeardownCause::nested(outer.clone()), None).await;
        outer.set(Teardown::CertificateRevoked);
        driver.abort();
        let _ = driver.await;

        let err = poll_fn(|cx| Pin::new(&mut read).poll_bytes(cx))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(matches!(
            err.get_ref().and_then(|e| e.downcast_ref::<Teardown>()),
            Some(Teardown::CertificateRevoked)
        ));
    }

    // Accepts a single stream on an in-memory h2 server and shuts the connection down abruptly,
    // the way the server tears down a connection, returning what the server's stream reads next.
    async fn read_after_abrupt_shutdown(teardown: Option<Teardown>) -> std::io::Result<Bytes> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (mut send_req, client_conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = client_conn.await;
        });
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("http://example.com")
            .body(())
            .unwrap();
        let (_resp, _send_stream) = send_req.send_request(req, false).unwrap();

        let mut conn = h2::server::handshake(server_io).await.unwrap();
        let (req, _respond) = conn.accept().await.unwrap().unwrap();
        let cause = TeardownCause::default();
        let mut read = H2StreamReadHalf {
            recv_stream: req.into_body(),
            _dropped: None,
            teardown: cause.clone(),
        };
        if let Some(teardown) = teardown {
            cause.set(teardown);
        }
        conn.abrupt_shutdown(Reason::NO_ERROR);
        tokio::spawn(poll_fn(move |cx| conn.poll_closed(cx)));
        poll_fn(|cx| Pin::new(&mut read).poll_bytes(cx)).await
    }

    #[tokio::test]
    async fn abrupt_shutdown_without_teardown_is_eof() {
        assert!(read_after_abrupt_shutdown(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn abrupt_shutdown_reports_teardown() {
        let err = read_after_abrupt_shutdown(Some(Teardown::CertificateRevoked))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
        assert_eq!(err.to_string(), "peer certificate revoked by CRL");
    }

    #[tokio::test]
    async fn teardown_resets_copy_and_reports_cause() {
        use tokio::io::AsyncReadExt;
        let teardown = TeardownCause::default();
        let (read, write, driver) = client_stream(teardown.clone(), None).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (downstream, _) = listener.accept().await.unwrap();
        let copy = tokio::spawn(async move {
            let cr = crate::copy::tests::connection_result();
            crate::copy::copy_bidirectional(
                crate::copy::TcpStreamSplitter(downstream),
                H2Stream { read, write },
                &cr,
            )
            .await
        });

        teardown.set(Teardown::CertificateRevoked);
        driver.abort();

        let err = client.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(matches!(
            copy.await.unwrap(),
            Err(crate::proxy::Error::Teardown(Teardown::CertificateRevoked))
        ));
    }

    // A transport whose reads start failing with `kind` once `fail` is set.
    struct FailingTransport {
        inner: tokio::io::DuplexStream,
        fail: Arc<std::sync::Mutex<(Option<std::io::ErrorKind>, Option<std::task::Waker>)>>,
    }

    impl tokio::io::AsyncRead for FailingTransport {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let mut fail = self.fail.lock().unwrap();
            if let Some(kind) = fail.0 {
                return Poll::Ready(Err(kind.into()));
            }
            fail.1 = Some(cx.waker().clone());
            drop(fail);
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for FailingTransport {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn transport_failure_aborts_stream() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let fail = Arc::new(std::sync::Mutex::new((None, None)));
        let client_io = FailingTransport {
            inner: client_io,
            fail: fail.clone(),
        };
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            while let Some(Ok((_req, mut respond))) = conn.accept().await {
                let resp = http::Response::builder().status(200).body(()).unwrap();
                std::mem::forget(respond.send_response(resp, false).unwrap());
            }
        });
        let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("http://example.com")
            .body(())
            .unwrap();
        let (resp, _send_stream) = send_req.send_request(req, false).unwrap();
        let mut read = H2StreamReadHalf {
            recv_stream: resp.await.unwrap().into_body(),
            _dropped: None,
            teardown: TeardownCause::default(),
        };

        // e.g. TCP keepalive giving up on the HBONE connection
        let waker = {
            let mut fail = fail.lock().unwrap();
            fail.0 = Some(std::io::ErrorKind::TimedOut);
            fail.1.take()
        };
        waker.unwrap().wake();

        let err = poll_fn(|cx| Pin::new(&mut read).poll_bytes(cx))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionAborted);
        assert!(matches!(
            err.get_ref().and_then(|e| e.downcast_ref::<Teardown>()),
            Some(Teardown::Transport(_))
        ));
    }

    // Tunnels a TCP client to a TCP backend through a client and a server HBONE stream, the way
    // the outbound and inbound proxies do, returning the TCP ends and the server side copy.
    async fn tunnel() -> (
        tokio::net::TcpStream,
        tokio::net::TcpStream,
        tokio::task::JoinHandle<Result<(), crate::proxy::Error>>,
    ) {
        use crate::copy::{TcpStreamSplitter, copy_bidirectional, tests::connection_result};
        async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            (a, listener.accept().await.unwrap().0)
        }
        let (app, app_side) = tcp_pair().await;
        let (backend_side, backend) = tcp_pair().await;

        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (server_tx, server_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            let resp = http::Response::builder().status(200).body(()).unwrap();
            let stream = H2Stream {
                read: H2StreamReadHalf {
                    recv_stream: req.into_body(),
                    _dropped: None,
                    teardown: TeardownCause::default(),
                },
                write: H2StreamWriteHalf {
                    send_stream: respond.send_response(resp, false).unwrap(),
                    _dropped: None,
                    teardown: TeardownCause::default(),
                },
            };
            let copy = tokio::spawn(async move {
                let cr = connection_result();
                copy_bidirectional(stream, TcpStreamSplitter(backend_side), &cr).await
            });
            let _ = server_tx.send(copy);
            // drive the connection
            while conn.accept().await.is_some() {}
        });
        let (send_stream, recv_stream, driver) = {
            let (mut send_req, conn) = h2::client::handshake(client_io).await.unwrap();
            let driver = tokio::spawn(async move {
                let _ = conn.await;
            });
            let req = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("http://example.com")
                .body(())
                .unwrap();
            let (resp, send_stream) = send_req.send_request(req, false).unwrap();
            (send_stream, resp.await.unwrap().into_body(), driver)
        };
        let client_stream = H2Stream {
            read: H2StreamReadHalf {
                recv_stream,
                _dropped: None,
                teardown: TeardownCause::default(),
            },
            write: H2StreamWriteHalf {
                send_stream,
                _dropped: None,
                teardown: TeardownCause::default(),
            },
        };
        tokio::spawn(async move {
            let _driver = driver;
            let cr = connection_result();
            copy_bidirectional(TcpStreamSplitter(app_side), client_stream, &cr).await
        });
        (app, backend, server_rx.await.unwrap())
    }

    #[tokio::test]
    async fn dropped_copy_resets_both_ends_of_the_tunnel() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut app, mut backend, server_copy) = tunnel().await;
        app.write_all(b"hi").await.unwrap();
        let mut buf = [0; 2];
        backend.read_exact(&mut buf).await.unwrap();

        // e.g. a late policy rejection drops the server side copy
        server_copy.abort();

        let err = backend.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        let err = app.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    #[tokio::test]
    async fn closed_tunnel_closes_both_ends() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut app, mut backend, server_copy) = tunnel().await;
        app.write_all(b"hi").await.unwrap();
        app.shutdown().await.unwrap();
        let mut buf = Vec::new();
        backend.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hi");
        drop(backend);
        assert_eq!(app.read(&mut [0; 16]).await.unwrap(), 0);
        assert!(server_copy.await.unwrap().is_ok());
    }

    // Aborts `from`'s TCP connection, sending a reset.
    fn reset(from: tokio::net::TcpStream) {
        from.set_zero_linger().unwrap();
        drop(from);
    }

    #[tokio::test]
    async fn app_reset_resets_backend() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut app, mut backend, server_copy) = tunnel().await;
        app.write_all(b"hi").await.unwrap();
        let mut buf = [0; 2];
        backend.read_exact(&mut buf).await.unwrap();

        reset(app);

        let err = backend.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        // A peer's reset is propagated, but not reported as an error.
        assert!(server_copy.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn backend_reset_resets_app() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut app, mut backend, server_copy) = tunnel().await;
        backend.write_all(b"hi").await.unwrap();
        let mut buf = [0; 2];
        app.read_exact(&mut buf).await.unwrap();

        reset(backend);

        let err = app.read(&mut [0; 16]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
        // A peer's reset is propagated, but not reported as an error.
        assert!(server_copy.await.unwrap().is_ok());
    }
}
