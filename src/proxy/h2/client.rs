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
use bytes::{Buf, Bytes};
use h2::client::{Connection, SendRequest};
use h2::SendStream;
use http::Request;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::sync::watch::Receiver;
use tokio_rustls::client::TlsStream;
use tracing::{debug, error, trace, warn, Instrument};

#[derive(Debug, Clone)]
// H2ConnectClient is a wrapper abstracting h2
pub struct H2ConnectClient {
    sender: SendRequest<Bytes>,
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

    pub async fn send_request(
        &mut self,
        req: http::Request<()>,
    ) -> Result<crate::proxy::h2::H2Stream, Error> {
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

        let (dropped1, dropped2) = crate::proxy::h2::DropCounter::new(self.stream_count.clone());
        let read = crate::proxy::h2::H2StreamReadHalf {
            recv_stream: recv,
            _dropped: dropped1,
        };
        let write = crate::proxy::h2::H2StreamWriteHalf {
            send_stream: send,
            _dropped: dropped2,
        };
        let h2 = crate::proxy::h2::H2Stream { read, write };
        Ok(h2)
    }

    // helper to allow us to handle errors once
    async fn internal_send(
        &mut self,
        req: Request<()>,
    ) -> Result<(SendStream<Bytes>, h2::RecvStream), Error> {
        // "This function must return `Ready` before `send_request` is called"
        // We should always be ready though, because we make sure we don't go over the max stream limit out of band.
        futures::future::poll_fn(|cx| self.sender.poll_ready(cx)).await?;
        let (response, stream) = self.sender.send_request(req, false)?;
        let response = response.await?;
        if response.status() != 200 {
            return Err(Error::HttpStatus(response.status()));
        }
        Ok((stream, response.into_body()))
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
        // 256kb. Aligned with copy.rs to avoid fragmentation
        .max_send_buffer_size(16_384 * 16_384)
        .enable_push(false);

    let (send_req, connection) = builder
        .handshake::<_, Bytes>(s)
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
    tokio::spawn(
        async move {
            drive_connection(connection, driver_drain).await;
        }
        .in_current_span(),
    );

    let c = H2ConnectClient {
        sender: send_req,
        stream_count: Arc::new(AtomicU16::new(0)),
        max_allowed_streams,
    };
    Ok(c)
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
    tokio::task::spawn(
        super::do_ping_pong(ping_pong, ping_drop_tx, dropped.clone()).in_current_span(),
    );

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
