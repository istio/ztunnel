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

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, trace};

pub struct TestServer {
    listener: TcpListener,
}

impl TestServer {
    pub async fn new() -> TestServer {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        TestServer { listener }
    }

    pub fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub async fn run(self) {
        loop {
            let (mut socket, _) = self.listener.accept().await.unwrap();

            tokio::spawn(async move {
                let mut buf = vec![0; 2*1024*1024];

                // In a loop, read data from the socket and write the data back.
                loop {
                    let n = socket
                        .read(&mut buf)
                        .await
                        .expect("failed to read data from socket");

                    trace!("echo received {n}: {:?}", &buf[0..n]);
                    if n == 0 {
                        return;
                    }

                    socket
                        .write_all(&buf[0..n])
                        .await
                        .expect("failed to write data to socket");
                }
            });
        }
    }
}
