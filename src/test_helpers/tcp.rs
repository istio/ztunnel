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

use std::convert::Infallible;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;
use std::{cmp, io};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Response, Server};
use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use rand::Rng;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, error, info};

use crate::{identity, tls};

#[derive(Copy, Clone, Debug)]
pub enum Mode {
    ReadWrite,
    Write,
    Read,
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

            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                handle_stream(self.mode, &mut r, &mut w).await;
            });
        }
    }
}

pub async fn handle_stream<R, W>(mode: Mode, r: &mut R, w: &mut W)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match mode {
        Mode::ReadWrite => {
            let mut r = tokio::io::BufReader::with_capacity(BUFFER_SIZE, r);
            tokio::io::copy_buf(&mut r, w).await.expect("tcp copy");
        }
        Mode::Write => {
            let buffer = vec![0; BUFFER_SIZE];
            loop {
                let read = w.write(&buffer).await.expect("tcp ready");
                if read == 0 {
                    break;
                }
            }
        }
        Mode::Read => {
            let mut buffer = vec![0; BUFFER_SIZE];
            loop {
                let read = r.read(&mut buffer).await.expect("tcp ready");
                if read == 0 {
                    break;
                }
            }
        }
    }
}

/// HboneTestServer is like TestServer but listens over HBONE. Unlike the plain TCP test server, it will
/// always write "waypoint/n" to allow tests to assert they reached the HBONE server.
pub struct HboneTestServer {
    listener: TcpListener,
    mode: Mode,
}

impl HboneTestServer {
    pub async fn new(mode: Mode) -> Self {
        // Waypoints are assumed to always run on 15008, but we need to have a unique ip:port
        // Linux doesn't offer a way to pick a random free ip, so we iterate until we find an open one
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            // lo has 127.0.0.1/8, so we will generate 2 u8's. That is enough to give us 65k
            let attempt = SocketAddr::new(IpAddr::from([127, 137, rng.gen(), rng.gen()]), 15008);
            let Ok(listener) = TcpListener::bind(attempt).await else {
                // Try again...
                continue
            };
            return Self { listener, mode };
        }
        panic!("failed to find a free IP after 1000 attempts");
    }

    pub fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn run(self) {
        let certs = tls::generate_test_certs(
            &identity::Identity::Spiffe {
                trust_domain: "cluster.local".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
            }
            .into(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let acceptor = tls::ControlPlaneCertProvider(certs);
        let tls_stream = crate::hyper_util::tls_server(acceptor, self.listener);
        let incoming = hyper::server::accept::from_stream(tls_stream);
        let mode = self.mode;
        Server::builder(incoming)
            .http2_only(true)
            .serve(make_service_fn(|_| async move {
                let mode = mode;
                Ok::<_, Infallible>(service_fn(move |req| async move {
                    info!("waypoint: received request");
                    let mode = mode;
                    tokio::task::spawn(async move {
                        match hyper::upgrade::on(req).await {
                            Ok(upgraded) => {
                                let (mut ri, mut wi) = tokio::io::split(upgraded);
                                // Signal we are the waypoint so tests can validate this
                                wi.write_all(b"waypoint\n").await.unwrap();
                                handle_stream(mode, &mut ri, &mut wi).await;
                            }
                            Err(e) => error!("No upgrade {e}"),
                        }
                    });
                    Ok::<_, Infallible>(Response::new(Body::from("streaming...")))
                }))
            }))
            .await
            .unwrap();
    }
}
