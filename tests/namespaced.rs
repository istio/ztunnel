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

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use hyper::{Body, Method};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{error, info};

use ztunnel::identity;
use ztunnel::identity::CertificateProvider;

use ztunnel::test_helpers::components::WorkloadManager;
use ztunnel::test_helpers::helpers::initialize_telemetry;
use ztunnel::test_helpers::netns::{Namespace, Resolver};
use ztunnel::test_helpers::*;

macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
}

/// setup_netns_test prepares a test using network namespaces. This checks we have root,
/// and automatically setups up a namespace based on the test name (to avoid conflicts).
macro_rules! setup_netns_test {
    () => {{
        if unsafe { libc::getuid() } != 0 {
            if std::env::var("CI").is_ok() {
                panic!("CI tests should run as root to have full coverage");
            }
            eprintln!("This test requires root; skipping");
            return Ok(());
        }
        initialize_telemetry();
        let f = function!()
            .strip_prefix(module_path!())
            .unwrap()
            .strip_prefix("::")
            .unwrap()
            .strip_suffix("::{{closure}}")
            .unwrap();
        WorkloadManager::new(f)?
    }};
}

const TEST_VIP: &str = "10.10.0.1";

const SERVER_PORT: u16 = 8080;

const DEFAULT_NODE: &str = "node";
const REMOTE_NODE: &str = "remote-node";

#[tokio::test]
async fn test_vip_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    run_tcp_server(
        manager
            .workload_builder("server1", REMOTE_NODE)
            .vip(TEST_VIP, 80, SERVER_PORT)
            .register()?,
    )?;
    run_tcp_server(
        manager
            .workload_builder("server2", REMOTE_NODE)
            .hbone()
            .vip(TEST_VIP, 80, SERVER_PORT)
            .register()?,
    )?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    manager.deploy_ztunnel(REMOTE_NODE)?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    run_tcp_client(client, manager.resolver(), &format!("{TEST_VIP}:80"))?;
    Ok(())
}

#[tokio::test]
async fn test_tcp_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    run_tcp_server(manager.workload_builder("server", REMOTE_NODE).register()?)?;
    manager.deploy_ztunnel(REMOTE_NODE)?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    run_tcp_client(client, manager.resolver(), "server")?;
    Ok(())
}

#[tokio::test]
async fn test_tcp_local_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    run_tcp_server(
        manager
            .workload_builder("server", DEFAULT_NODE)
            .register()?,
    )?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    run_tcp_client(client, manager.resolver(), "server")?;
    Ok(())
}

#[tokio::test]
async fn test_hbone_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    run_tcp_server(
        manager
            .workload_builder("server", REMOTE_NODE)
            .hbone()
            .register()?,
    )?;
    manager.deploy_ztunnel(REMOTE_NODE)?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    run_tcp_client(client, manager.resolver(), "server")?;
    Ok(())
}

#[tokio::test]
async fn test_hbone_local_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    run_tcp_server(
        manager
            .workload_builder("server", DEFAULT_NODE)
            .hbone()
            .register()?,
    )?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    run_tcp_client(client, manager.resolver(), "server")?;
    Ok(())
}

#[tokio::test]
async fn test_waypoint() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let waypoint = manager.register_waypoint("waypoint", DEFAULT_NODE)?;
    let ip = waypoint.ip();
    run_hbone_server(waypoint)?;
    manager
        .workload_builder("server", DEFAULT_NODE)
        .hbone()
        .waypoint(ip)
        .register()?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    run_tcp_to_hbone_client(client, manager.resolver(), "server")?;
    Ok(())
}

#[tokio::test]
async fn test_waypoint_hairpin() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let waypoint = manager.register_waypoint("waypoint", REMOTE_NODE)?;
    let ip = waypoint.ip();
    run_hbone_server(waypoint)?;
    manager
        .workload_builder("server", DEFAULT_NODE)
        .hbone()
        .waypoint(ip)
        .register()?;
    let client = manager
        .workload_builder("client", REMOTE_NODE)
        .uncaptured()
        .register()?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    run_tcp_to_hbone_client(client, manager.resolver(), "server")?;
    Ok(())
}

#[tokio::test]
async fn test_waypoint_bypass() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let waypoint = manager.register_waypoint("waypoint", DEFAULT_NODE)?;
    let ip = waypoint.ip();
    run_hbone_server(waypoint)?;
    let _ = manager
        .workload_builder("server", DEFAULT_NODE)
        .waypoint(ip)
        .register()?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .uncaptured()
        .register()?;
    let app = manager.deploy_ztunnel(DEFAULT_NODE)?;

    let srv = resolve_target(manager.resolver(), "server");
    client
        .run(move || async move {
            let mut builder = hyper::client::conn::Builder::new();
            let builder = builder.http2_only(true);

            let request = hyper::Request::builder()
                .uri(&srv.to_string())
                .method(Method::CONNECT)
                .version(hyper::Version::HTTP_2)
                .body(Body::empty())
                .unwrap();

            let id = &identity::Identity::default();
            let cert = app.cert_manager.fetch_certificate(id).await?;
            let mut connector = cert
                .connector(None)
                .unwrap()
                .configure()
                .expect("configure");
            connector.set_verify_hostname(false);
            connector.set_use_server_name_indication(false);
            let hbone = SocketAddr::new(srv.ip(), 15008);
            let tcp_stream = TcpStream::connect(hbone).await.unwrap();
            let tls_stream = tokio_boring::connect(connector, "", tcp_stream)
                .await
                .unwrap();
            let (mut request_sender, connection) = builder.handshake(tls_stream).await.unwrap();
            // spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in HBONE connection handshake: {:?}", e);
                }
            });

            let response = request_sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::UNAUTHORIZED);
            Ok(())
        })?
        .join()
        .unwrap()?;
    Ok(())
}

#[tokio::test]
async fn test_hbone_ip_mismatch() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let _ = manager
        .workload_builder("server", DEFAULT_NODE)
        .register()?;
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    let app = manager.deploy_ztunnel(DEFAULT_NODE)?;

    let srv = resolve_target(manager.resolver(), "server");
    client
        .run(move || async move {
            let mut builder = hyper::client::conn::Builder::new();
            let builder = builder.http2_only(true);

            let request = hyper::Request::builder()
                .uri(&srv.to_string())
                .method(Method::CONNECT)
                .version(hyper::Version::HTTP_2)
                .body(Body::empty())
                .unwrap();

            let id = &identity::Identity::default();
            let cert = app.cert_manager.fetch_certificate(id).await?;
            let mut connector = cert
                .connector(None)
                .unwrap()
                .configure()
                .expect("configure");
            connector.set_verify_hostname(false);
            connector.set_use_server_name_indication(false);
            let tcp_stream = TcpStream::connect(app.proxy_addresses.inbound)
                .await
                .unwrap();
            let tls_stream = tokio_boring::connect(connector, "", tcp_stream)
                .await
                .unwrap();
            let (mut request_sender, connection) = builder.handshake(tls_stream).await.unwrap();
            // spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                if let Err(e) = connection.await {
                    error!("Error in HBONE connection handshake: {:?}", e);
                }
            });

            let response = request_sender.send_request(request).await.unwrap();
            // We sent to ztunnel IP directly but requested server IP. Should be rejected
            assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
            Ok(())
        })?
        .join()
        .unwrap()?;
    Ok(())
}

fn resolve_target(resolver: Resolver, target: &str) -> SocketAddr {
    // We accept a ip:port, ip, or name (which is resolved).
    target.parse::<SocketAddr>().unwrap_or_else(|_| {
        let ip = target
            .parse::<IpAddr>()
            .unwrap_or_else(|_| resolver.resolve(target).unwrap());
        SocketAddr::new(ip, SERVER_PORT)
    })
}

/// run_tcp_client runs a simple client that reads and writes some data, asserting it flows end to end
fn run_tcp_client(client: Namespace, resolver: Resolver, target: &str) -> anyhow::Result<()> {
    let srv = resolve_target(resolver, target);
    client
        .run(move || async move {
            info!("Running client to {srv}");
            let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(srv))
                .await
                .unwrap()
                .unwrap();
            timeout(Duration::from_secs(5), read_write_stream(&mut stream))
                .await
                .unwrap();
            Ok(())
        })?
        .join()
        .unwrap()
}

/// run_tcp_client runs a simple client that reads and writes some data, asserting it flows end to end
fn run_tcp_to_hbone_client(
    client: Namespace,
    resolver: Resolver,
    target: &str,
) -> anyhow::Result<()> {
    let srv = resolve_target(resolver, target);
    client
        .run(move || async move {
            info!("Running client to {srv}");
            let mut stream = TcpStream::connect(srv).await.unwrap();
            hbone_read_write_stream(&mut stream).await;
            Ok(())
        })?
        .join()
        .unwrap()
}

/// run_tcp_server deploys a simple echo server in the provided namespace
fn run_tcp_server(server: Namespace) -> anyhow::Result<()> {
    server.run_ready(|ready| async move {
        let echo = tcp::TestServer::new(tcp::Mode::ReadWrite, SERVER_PORT).await;
        info!("Running echo server");
        ready.set_ready();
        echo.run().await;
        Ok(())
    })?;
    Ok(())
}

/// run_hbone_server deploys a simple echo server, deployed over HBONE, in the provided namespace
fn run_hbone_server(server: Namespace) -> anyhow::Result<()> {
    server.run_ready(|ready| async move {
        let echo = tcp::HboneTestServer::new(tcp::Mode::ReadWrite).await;
        info!("Running echo server");
        ready.set_ready();
        echo.run().await;
        Ok(())
    })?;
    Ok(())
}

// TODO: dedupe
async fn read_write_stream(stream: &mut TcpStream) -> usize {
    const BODY: &[u8] = b"hello world";
    stream.write_all(BODY).await.unwrap();
    let mut buf: [u8; BODY.len()] = [0; BODY.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(BODY, buf);
    BODY.len()
}

async fn hbone_read_write_stream(stream: &mut TcpStream) {
    const BODY: &[u8] = b"hello world";
    const WAYPOINT_MESSAGE: &[u8] = b"waypoint\n";
    stream.write_all(BODY).await.unwrap();
    let mut buf = [0; BODY.len() + WAYPOINT_MESSAGE.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!([WAYPOINT_MESSAGE, BODY].concat(), buf);
}

#[tokio::test]
async fn test_direct_ztunnel_call() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let client = manager
        .workload_builder("client", DEFAULT_NODE)
        .register()?;
    manager.deploy_ztunnel(DEFAULT_NODE)?;

    #[derive(PartialEq, Copy, Clone, Debug)]
    enum Failure {
        /// Cannot even connect
        Connection,
        /// Can connect, but cannot send bytes
        Request,
        /// Can connect, but get a HTTP error
        Http,
    }
    use Failure::*;
    async fn send_traffic(stream: &mut TcpStream) -> anyhow::Result<()> {
        const BODY: &[u8] = b"hello world\r\n\r\n";
        stream.write_all(BODY).await?;
        let mut buf: [u8; BODY.len()] = [0; BODY.len()];
        stream.read_exact(&mut buf).await?;
        if &buf[..12] != b"HTTP/1.1 400" {
            anyhow::bail!(
                "expected http error, got {}",
                std::str::from_utf8(&buf).unwrap()
            );
        }
        Ok(())
    }
    // Test calling sensitive ports on ztunnel, to ensure we are robust against (usually malicious) calls
    // directly to ztunnel.
    client
        .run(move || async move {
            let tests = [
                (15001, Request),    // Outbound: should be blocked due to recursive call
                (15006, Request),    // Inbound: should be blocked due to recursive call
                (15008, Request),    // HBONE: expected TLS, reject
                (15080, Request),    // Socks5: expected socks5, reject
                (15000, Connection), // Admin: only localhost
                (15020, Http),       // Stats: accept connection and returns a HTTP error
                (15021, Http),       // Readiness: accept connection and returns a HTTP error
            ];
            for (port, failure) in tests {
                info!("send to {port}, want {failure:?} error");
                let tgt = SocketAddr::from((manager.resolve("ztunnel-node").unwrap(), port));
                let stream = timeout(Duration::from_secs(1), TcpStream::connect(tgt))
                    .await
                    .unwrap();
                if failure == Connection {
                    assert!(stream.is_err());
                    continue;
                }
                let mut stream = stream.unwrap();

                let res = timeout(Duration::from_secs(1), send_traffic(&mut stream))
                    .await
                    .unwrap();
                if failure == Request {
                    assert!(res.is_err());
                    continue;
                }
                res.unwrap();
            }
            // Same thing, but over socks5
            for (port, _failure) in tests {
                // For socks5, the socks5 listener will accept everything... but make sure we don't get loops or HTTP response
                let failure = Request;
                info!("send to socks5 {port}, want {failure:?} error");
                let socks_tgt = SocketAddr::from((manager.resolve("ztunnel-node").unwrap(), 15080));
                let tgt = SocketAddr::from((manager.resolve("ztunnel-node").unwrap(), port));
                let socks_stream = TcpStream::connect(socks_tgt).await.unwrap();
                let stream = timeout(
                    Duration::from_secs(1),
                    app::socks5_connect(socks_stream, tgt),
                )
                .await
                .unwrap();
                if failure == Connection {
                    assert!(stream.is_err());
                    continue;
                }
                let mut stream = stream.unwrap();

                let res = timeout(Duration::from_secs(1), send_traffic(&mut stream))
                    .await
                    .unwrap();
                if failure == Request {
                    assert!(res.is_err());
                    continue;
                }
                res.unwrap();
            }
            // Same thing, but over socks5 and requesting localhost
            for (port, _failure) in tests {
                // For socks5, the socks5 listener will accept everything... but make sure we don't get loops or HTTP response
                let failure = Request;
                info!("send to socks5 over localhost {port}, want {failure:?} error");
                let socks_tgt = SocketAddr::from((manager.resolve("ztunnel-node").unwrap(), 15080));
                let tgt = SocketAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), port));
                let socks_stream = TcpStream::connect(socks_tgt).await.unwrap();
                let stream = timeout(
                    Duration::from_secs(1),
                    app::socks5_connect(socks_stream, tgt),
                )
                .await
                .unwrap();
                if failure == Connection {
                    assert!(stream.is_err());
                    continue;
                }
                let mut stream = stream.unwrap();

                let res = timeout(Duration::from_secs(1), send_traffic(&mut stream))
                    .await
                    .unwrap();
                if failure == Request {
                    assert!(res.is_err());
                    continue;
                }
                res.unwrap();
            }
            Ok(())
        })?
        .join()
        .unwrap()?;
    Ok(())
}
