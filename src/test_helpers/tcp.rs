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
use bytes::Bytes;
use futures::StreamExt;
use http_body_util::Full;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use std::{cmp, io};

use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, error, info};

use crate::hyper_util::TokioExecutor;
use crate::{identity, tls};

#[derive(Copy, Clone, Debug)]
pub enum Mode {
    ReadDoubleWrite,
    ReadWrite,
    Write,
    Read,
    // Forward acts as a TCP proxy.
    // Currently, this hard-codes an assumption the backend is in ReadDoubleWrite mode
    Forward(SocketAddr),
}

/// run_client reads and/or writes data as fast as possible
pub async fn run_client(
    stream: &mut TcpStream,
    target: usize,
    mode: Mode,
) -> Result<(), io::Error> {
    let mut buf = vec![0; cmp::min(BUFFER_SIZE, target)];
    let start = Instant::now();
    let (mut r, mut w) = stream.split();
    let mut transferred = 0;
    while transferred < target {
        let length = cmp::min(buf.len(), target - transferred);
        match mode {
            Mode::ReadWrite => {
                let written = w.write(&buf[..length]).await?;
                transferred += written;
                r.read_exact(&mut buf[..written]).await?;
            }
            Mode::ReadDoubleWrite | Mode::Forward(_) => {
                let written = w.write(&buf[..length]).await?;
                transferred += written;
                r.read_exact(&mut buf[..written * 2]).await?;
            }
            Mode::Write => {
                transferred += w.write(&buf[..length]).await?;
            }
            Mode::Read => {
                transferred += r.read(&mut buf[..length]).await?;
            }
        }
        debug!(
            "throughput: {:.3} Gb/s, transferred {} Gb ({:.3}%) in {:?} ({:?})",
            transferred as f64 / (start.elapsed().as_micros() as f64 / 1_000_000.0) / 0.125e9,
            transferred as f64 / 0.125e9,
            100.0 * transferred as f64 / target as f64,
            start.elapsed(),
            mode
        );
    }
    let elapsed = start.elapsed().as_micros() as f64 / 1_000_000.0;
    let throughput = transferred as f64 / elapsed / 0.125e9;
    info!(
        "throughput: {:.3} Gb/s, transferred {transferred} in {:?} ({:?})",
        throughput,
        start.elapsed(),
        mode
    );
    Ok(())
}

pub struct TestServer {
    listener: TcpListener,
    mode: Mode,
}

static BUFFER_SIZE: usize = 2 * 1024 * 1024;

impl TestServer {
    pub async fn new(mode: Mode, port: u16) -> TestServer {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port);
        let listener = TcpListener::bind(addr).await.unwrap();
        TestServer { listener, mode }
    }

    pub fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn run(self) {
        loop {
            let (mut socket, _) = self.listener.accept().await.unwrap();
            socket.set_nodelay(true).unwrap();

            tokio::spawn(async move {
                handle_stream(self.mode, &mut socket).await;
            });
        }
    }
}

pub async fn handle_stream<IO>(mode: Mode, rw: &mut IO)
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    match mode {
        Mode::ReadWrite => {
            let (r, mut w) = tokio::io::split(rw);
            let mut r = tokio::io::BufReader::with_capacity(BUFFER_SIZE, r);
            tokio::io::copy_buf(&mut r, &mut w).await.expect("tcp copy");
        }
        Mode::ReadDoubleWrite => {
            let (mut r, mut w) = tokio::io::split(rw);
            let mut buffer = vec![0; BUFFER_SIZE];
            loop {
                let read = r.read(&mut buffer).await.expect("tcp ready");
                if read == 0 {
                    break;
                }
                let wrote = w.write(&buffer[..read]).await.expect("tcp ready");
                if wrote == 0 {
                    break;
                }
                let wrote = w.write(&buffer[..read]).await.expect("tcp ready");
                if wrote == 0 {
                    break;
                }
            }
        }
        Mode::Write => {
            let (_r, mut w) = tokio::io::split(rw);
            let buffer = vec![0; BUFFER_SIZE];
            loop {
                let wrote = w.write(&buffer).await.expect("tcp ready");
                if wrote == 0 {
                    break;
                }
            }
        }
        Mode::Read => {
            let (mut r, _w) = tokio::io::split(rw);
            let mut buffer = vec![0; BUFFER_SIZE];
            loop {
                let read = r.read(&mut buffer).await.expect("tcp ready");
                if read == 0 {
                    break;
                }
            }
        }
        Mode::Forward(addr) => {
            let mut outbound = TcpStream::connect(addr).await.expect("tcp ready");

            let res = tokio::io::copy_bidirectional(rw, &mut outbound).await;
            error!("done with {res:?}");
        }
    }
}

/// HboneTestServer is like TestServer but listens over HBONE. Unlike the plain TCP test server, it will
/// always write "waypoint/n" to allow tests to assert they reached the HBONE server.
pub struct HboneTestServer {
    listener: TcpListener,
    mode: Mode,
    name: String,
}

impl HboneTestServer {
    pub async fn new(mode: Mode, name: &str) -> Self {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15008);
        let listener = TcpListener::bind(addr).await.unwrap();
        Self {
            listener,
            mode,
            name: name.to_string(),
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn run(self) {
        let certs = tls::mock::generate_test_certs(
            &identity::Identity::Spiffe {
                trust_domain: "cluster.local".into(),
                namespace: "default".into(),
                service_account: self.name.into(),
            }
            .into(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let acceptor = tls::mock::MockServerCertProvider::new(certs);
        let mut tls_stream = crate::hyper_util::tls_server(acceptor, self.listener);
        let mode = self.mode;
        while let Some(socket) = tls_stream.next().await {
            if let Err(err) = http2::Builder::new(TokioExecutor)
                .serve_connection(
                    TokioIo::new(socket),
                    service_fn(move |req| async move {
                        info!("waypoint: received request");
                        tokio::task::spawn(async move {
                            match hyper::upgrade::on(req).await {
                                Ok(upgraded) => {
                                    let mut io = TokioIo::new(upgraded);
                                    // let (mut ri, mut wi) = tokio::io::split(TokioIo::new(upgraded));
                                    // Signal we are the waypoint so tests can validate this
                                    io.write_all(b"waypoint\n").await.unwrap();
                                    handle_stream(mode, &mut io).await;
                                }
                                Err(e) => error!("No upgrade {e}"),
                            }
                        });
                        Ok::<_, Infallible>(Response::new(Full::<Bytes>::from("streaming...")))
                    }),
                )
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        }
    }
}
