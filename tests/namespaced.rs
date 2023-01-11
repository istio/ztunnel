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

use std::net::{IpAddr, SocketAddr};

use hyper::{Body, Method};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
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

#[tokio::test]
async fn test_vip_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let server1 = manager
        .workload_builder("server1")
        .vip(TEST_VIP, 80, SERVER_PORT)
        .register()?;
    let server2 = manager
        .workload_builder("server2")
        .hbone()
        .vip(TEST_VIP, 80, SERVER_PORT)
        .register()?;
    let client = manager
        .workload_builder("client")
        .on_local_node()
        .register()?;
    manager.deploy_ztunnel()?;

    run_tcp_server(server1)?;
    run_tcp_server(server2)?;
    run_tcp_client(client, manager.resolver(), &format!("{TEST_VIP}:80"))?;
    Ok(())
}

#[tokio::test]
async fn test_tcp_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let server = manager.workload_builder("server").register()?;
    client_server_test(manager, server)
}

#[tokio::test]
async fn test_tcp_local_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let server = manager
        .workload_builder("server")
        .on_local_node()
        .register()?;
    client_server_test(manager, server)
}

#[tokio::test]
async fn test_hbone_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let server = manager.workload_builder("server").hbone().register()?;
    client_server_test(manager, server)
}

#[tokio::test]
async fn test_hbone_local_request() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let server = manager
        .workload_builder("server")
        .hbone()
        .on_local_node()
        .register()?;
    client_server_test(manager, server)
}

#[tokio::test]
async fn test_waypoint() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let waypoint = manager.register_waypoint("waypoint")?;
    let ip = waypoint.ip();
    run_hbone_server(waypoint)?;
    let _ = manager
        .workload_builder("server")
        .hbone()
        .waypoint(ip)
        .on_local_node()
        .register()?;
    let client = manager
        .workload_builder("client")
        .on_local_node()
        .register()?;
    manager.deploy_ztunnel()?;

    run_tcp_to_hbone_client(client, manager.resolver(), "server")?;
    Ok(())
}

#[tokio::test]
#[ignore]
// This is currently broken since our redirection hacks are not sophisticated enough to bypass the outbound
// but not inbound
async fn test_waypoint_bypass() -> anyhow::Result<()> {
    let mut manager = setup_netns_test!();
    let waypoint = manager.register_waypoint("waypoint")?;
    let ip = waypoint.ip();
    run_hbone_server(waypoint)?;
    let _ = manager
        .workload_builder("server")
        .waypoint(ip)
        .on_local_node()
        .register()?;
    let client = manager.workload_builder("client").register()?;
    let app = manager.deploy_ztunnel()?;

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
    let _ = manager.workload_builder("server").register()?;
    let client = manager.workload_builder("client").register()?;
    let app = manager.deploy_ztunnel()?;

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
            let mut stream = TcpStream::connect(srv).await.unwrap();
            read_write_stream(&mut stream).await;
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

/// client_server_test runs a simple test sending a single request from the client and asserting it is received.
fn client_server_test(mut manager: WorkloadManager, server: Namespace) -> anyhow::Result<()> {
    let client = manager
        .workload_builder("client")
        .on_local_node()
        .register()?;
    manager.deploy_ztunnel()?;

    run_tcp_server(server)?;
    run_tcp_client(client, manager.resolver(), "server")?;
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
