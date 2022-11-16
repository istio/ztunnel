use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

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
                let mut buf = vec![0; 1024];

                // In a loop, read data from the socket and write the data back.
                loop {
                    let n = socket
                        .read(&mut buf)
                        .await
                        .expect("failed to read data from socket");

                    info!("echo received {n}: {:?}", &buf[0..n]);
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
