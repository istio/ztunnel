use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use hyper::{Body, Client, Method, Request, Response};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::helpers::*;
use crate::*;

pub struct TestApp {
    admin_address: SocketAddr,
    proxy_addresses: proxy::Addresses,
}

pub async fn with_app<F, Fut, FO>(cfg: config::Config, f: F)
where
    F: Fn(TestApp) -> Fut,
    Fut: Future<Output = FO>,
{
    initialize_telemetry();

    let app = app::build(cfg).await.unwrap();
    let shutdown = app.shutdown.trigger().clone();

    let ta = TestApp {
        admin_address: app.admin_address,
        proxy_addresses: app.proxy_addresses,
    };
    let run_and_shutdown = async {
        f(ta).await;
        shutdown.shutdown_now().await;
    };
    let (app, _shutdown) = tokio::join!(app.spawn(), run_and_shutdown);
    app.expect("app exits without error");
}

impl TestApp {
    pub async fn admin_request(&self, path: &str) -> Response<Body> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "http://localhost:{}/{path}",
                self.admin_address.port()
            ))
            .header("content-type", "application/json")
            .body(Body::default())
            .unwrap();
        let client = Client::new();
        client.request(req).await.expect("admin request")
    }

    pub async fn socks5_connect(&self, addr: SocketAddr) -> TcpStream {
        // let addr = net::lookup_host(addr)
        //     .await
        //     .expect("must get localhost address")
        //     .next()
        //     .expect("must get at least one localhost address");
        // Always use IPv4 address. In theory, we can resolve `localhost` to pick to support any machine
        // However, we need to make sure the WorkloadStore knows about both families then.
        let socks_addr = with_ip(
            self.proxy_addresses.socks5,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );

        let mut stream = TcpStream::connect(socks_addr).await.expect("must connect");

        let addr_type = if addr.ip().is_ipv4() { 0x01u8 } else { 0x04u8 };
        stream
            .write_all(&[
                0x05u8, // socks5
                0x1u8,  // 1 auth method
                0x0u8,  // unauthenticated auth method
            ])
            .await
            .unwrap();
        let mut auth = [0u8; 2];
        stream.read_exact(&mut auth).await.unwrap();

        let mut cmd = vec![
            0x05u8, // socks5
            0x1u8,  // establish tcp stream
            0x0u8,  // RSV
            addr_type,
        ];
        match proxy::to_canonical_ip(addr) {
            IpAddr::V6(ip) => cmd.extend_from_slice(&ip.octets()),
            IpAddr::V4(ip) => cmd.extend_from_slice(&ip.octets()),
        };
        cmd.extend_from_slice(&addr.port().to_be_bytes());
        stream.write_all(&cmd).await.unwrap();

        // We don't care about response but need to clear out the stream
        let mut resp = [0u8; 10];
        stream.read_exact(&mut resp).await.unwrap();

        stream
    }
}
