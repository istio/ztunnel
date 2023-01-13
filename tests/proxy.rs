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

use std::fmt::Debug;
use std::future::Future;
use std::net::SocketAddr;
use std::ops::Add;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use hyper::{Body, Client, Method, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time;
use tokio::time::timeout;
use tracing::{error, trace};

use ztunnel::identity::mock::MockCaClient;
use ztunnel::identity::CertificateProvider;
use ztunnel::test_helpers::app as testapp;
use ztunnel::test_helpers::app::TestApp;
use ztunnel::test_helpers::tcp::HboneTestServer;
use ztunnel::test_helpers::*;
use ztunnel::{config, identity};

#[tokio::test]
async fn test_shutdown_lifecycle() {
    helpers::initialize_telemetry();

    let app = ztunnel::app::build(test_config()).await.unwrap();

    let shutdown = app.shutdown.trigger().clone();
    let (app, _shutdown) = tokio::join!(
        time::timeout(Duration::from_secs(5), app.wait_termination()),
        shutdown.shutdown_now()
    );
    app.expect("app shuts down")
        .expect("app exits without error")
}

// Check that port conflicts on any address results in the app failing instead of silently failing
async fn test_bind_conflict<F: FnOnce(&mut ztunnel::config::Config) -> &mut SocketAddr>(f: F) {
    helpers::initialize_telemetry();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = test_config();
    let sa = f(&mut cfg);
    *sa = l.local_addr().unwrap();

    assert!(ztunnel::app::build(cfg).await.is_err());
}

#[tokio::test]
async fn test_conflicting_bind_error_inbound() {
    test_bind_conflict(|c| &mut c.inbound_addr).await;
}

#[tokio::test]
async fn test_conflicting_bind_error_inbound_plaintext() {
    test_bind_conflict(|c| &mut c.inbound_plaintext_addr).await;
}

#[tokio::test]
async fn test_conflicting_bind_error_outbound() {
    test_bind_conflict(|c| &mut c.outbound_addr).await;
}

#[tokio::test]
async fn test_conflicting_bind_error_socks5() {
    test_bind_conflict(|c| &mut c.socks5_addr).await;
}

#[tokio::test]
async fn test_conflicting_bind_error_admin() {
    test_bind_conflict(|c| &mut c.admin_addr).await;
}

#[tokio::test]
async fn test_shutdown_drain() {
    helpers::initialize_telemetry();

    let cert_manager = MockCaClient::new(Duration::from_secs(10));
    let app = ztunnel::app::build_with_cert(test_config(), cert_manager.clone())
        .await
        .unwrap();
    let ta = TestApp {
        admin_address: app.admin_address,
        proxy_addresses: app.proxy_addresses,
        readiness_address: app.readiness_address,
        cert_manager,
    };
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite).await;
    let echo_addr = echo.address();
    tokio::spawn(echo.run());
    let shutdown = app.shutdown.trigger().clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        app.wait_termination().await.unwrap();
        // Notify we shut down
        shutdown_tx.send(()).unwrap();
    });
    // we shouldn't be shutdown yet
    assert!(shutdown_rx.try_recv().is_err());
    let dst = helpers::with_ip(echo_addr, TEST_WORKLOAD_HBONE.parse().unwrap());
    let mut stream = ta.socks5_connect(dst).await;
    read_write_stream(&mut stream).await;
    // Since we are connected, the app shouldn't shutdown
    shutdown.shutdown_now().await;
    assert!(shutdown_rx.try_recv().is_err());
    // Give it some time, make sure we still aren't shut down
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(shutdown_rx.try_recv().is_err());

    // Now close the stream, we should shutdown
    drop(stream);
    timeout(Duration::from_secs(1), shutdown_rx)
        .await
        .expect("app should shutdown")
        .unwrap();
}

#[tokio::test]
async fn test_shutdown_forced_drain() {
    helpers::initialize_telemetry();

    let mut cfg = test_config();
    cfg.termination_grace_period = Duration::from_millis(10);

    let cert_manager = MockCaClient::new(Duration::from_secs(10));
    let app = ztunnel::app::build_with_cert(cfg, cert_manager.clone())
        .await
        .unwrap();
    let ta = TestApp {
        admin_address: app.admin_address,
        proxy_addresses: app.proxy_addresses,
        readiness_address: app.readiness_address,
        cert_manager,
    };
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite).await;
    let echo_addr = echo.address();
    tokio::spawn(echo.run());
    let shutdown = app.shutdown.trigger().clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        app.wait_termination().await.unwrap();
        // Notify we shut down
        shutdown_tx.send(()).unwrap();
    });
    // we shouldn't be shutdown yet
    assert!(shutdown_rx.try_recv().is_err());
    let dst = helpers::with_ip(echo_addr, TEST_WORKLOAD_HBONE.parse().unwrap());
    let mut stream = ta.socks5_connect(dst).await;
    const BODY: &[u8] = "hello world".as_bytes();
    stream.write_all(BODY).await.unwrap();

    // Since we are connected, the app shouldn't shutdown... but it will hit the max time and forcefully exit
    shutdown.shutdown_now().await;
    // It shouldn't shut down immediately, but checking that will cause flakes. Just make sure it exits within 1s.
    timeout(Duration::from_secs(1), shutdown_rx)
        .await
        .expect("app should shutdown")
        .unwrap();
}

#[tokio::test]
async fn test_quit_lifecycle() {
    helpers::initialize_telemetry();

    let app = ztunnel::app::build(test_config()).await.unwrap();
    let addr = app.admin_address;

    let (app, _shutdown) = tokio::join!(
        time::timeout(Duration::from_secs(5), app.wait_termination()),
        admin_shutdown(addr)
    );
    app.expect("app shuts down")
        .expect("app exits without error");
}

#[track_caller]
async fn run_request_test(target: &str, node: &str) {
    // Test a round trip outbound call (via socks5)
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite).await;
    let echo_addr = echo.address();
    let cfg = config::Config {
        local_node: (!node.is_empty()).then(|| node.to_string()),
        ..test_config_with_port(echo_addr.port())
    };
    tokio::spawn(echo.run());
    testapp::with_app(cfg, |app| async move {
        let dst = SocketAddr::from_str(target)
            .unwrap_or_else(|_| helpers::with_ip(echo_addr, target.parse().unwrap()));
        let mut stream = app.socks5_connect(dst).await;
        read_write_stream(&mut stream).await;
    })
    .await;
}

#[track_caller]
async fn run_waypoint_test(target: &str, node: &str) {
    // Test a round trip outbound call (via socks5)
    // Verifies the request goes through a waypoint
    // Note: the waypoint here is a test waypoint which echos back to us; it does not do a full next-hop proxy.
    // As such, we only run the waypoint, and not any test app
    let waypoint = HboneTestServer::new(tcp::Mode::ReadWrite).await;
    let cfg = config::Config {
        local_node: (!node.is_empty()).then(|| node.to_string()),
        ..test_config_with_waypoint(waypoint.address().ip())
    };
    tokio::spawn(waypoint.run());
    testapp::with_app(cfg, |app| async move {
        let dst = SocketAddr::from_str(target).unwrap();
        let mut stream = app.socks5_connect(dst).await;
        hbone_read_write_stream(&mut stream).await;
    })
    .await;
}

#[tokio::test]
async fn test_hbone_request() {
    run_request_test(TEST_WORKLOAD_HBONE, "").await;
}

#[tokio::test]
async fn test_tcp_request() {
    run_request_test(TEST_WORKLOAD_TCP, "").await;
}

#[tokio::test]
async fn test_vip_request() {
    run_request_test(&format!("{TEST_VIP}:80"), "").await;
}

#[tokio::test]
async fn test_hbone_request_local() {
    run_request_test(TEST_WORKLOAD_HBONE, "local").await;
}

#[tokio::test]
async fn test_tcp_request_local() {
    run_request_test(TEST_WORKLOAD_TCP, "local").await;
}

#[tokio::test]
async fn test_vip_request_local() {
    run_request_test(&format!("{TEST_VIP}:80"), "local").await;
}

#[tokio::test]
async fn test_waypoint() {
    // Port doesn't matter, we will only go to the fake waypoint.
    run_waypoint_test(&format!("{TEST_WORKLOAD_WAYPOINT}:1234"), "").await;
    // Also test when client and server are on the same node; we still need to go through the waypoint.
    run_waypoint_test(&format!("{TEST_WORKLOAD_WAYPOINT}:1234"), "local").await;
}

// TODO: this test doesn't work since sending direct inbound requests still requires redirection support to terminate the TLS
// Find a way to simulate this and re-enable
#[tokio::test]
#[ignore]
async fn test_inbound_waypoint_bypass() {
    let cfg = config::Config {
        ..test_config_with_waypoint(TEST_WORKLOAD_WAYPOINT.parse().unwrap())
    };
    testapp::with_app(cfg, |app| async move {
        let mut builder = hyper::client::conn::Builder::new();
        let builder = builder.http2_only(true);

        let request = hyper::Request::builder()
            .uri(format!("https://{TEST_WORKLOAD_WAYPOINT}:12345"))
            .method(Method::CONNECT)
            .version(hyper::Version::HTTP_2)
            .body(Body::empty())
            .unwrap();

        let id = &identity::Identity::default();
        let cert = app.cert_manager.fetch_certificate(id).await.unwrap();
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
        assert_eq!(response.status(), hyper::StatusCode::UNAUTHORIZED);
    })
    .await;
}

#[tokio::test]
async fn test_stats_exist() {
    testapp::with_app(test_config(), |app| async move {
        let metrics = app.metrics().await;
        for metric in &[
            ("istio_build"),
            ("istio_connection_terminations"),
            ("istio_tcp_connections_opened"),
            ("istio_tcp_connections_closed"),
        ] {
            assert!(
                metrics.query(metric, Default::default()).is_some(),
                "expected metric {}",
                metric
            );
        }
    })
    .await;
}

#[tokio::test]
async fn test_tcp_connections_metrics() {
    // Test a round trip outbound call (via socks5)
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite).await;
    let echo_addr = echo.address();
    tokio::spawn(echo.run());
    testapp::with_app(test_config(), |app| async move {
        let dst = helpers::with_ip(echo_addr, TEST_WORKLOAD_TCP.parse().unwrap());
        let mut stream = app.socks5_connect(dst).await;
        read_write_stream(&mut stream).await;

        // We should have 1 open connection but 0 closed connections
        let metrics = app.metrics().await;
        assert_eq!(
            metrics.query_sum("istio_tcp_connections_opened_total", Default::default()),
            1,
            "metrics: {}",
            metrics.dump()
        );
        assert_eq!(
            metrics.query_sum("istio_tcp_connections_closed_total", Default::default()),
            0,
            "metrics: {}",
            metrics.dump()
        );

        // Drop the connection...
        drop(stream);

        // Eventually we should also have 1 closed connection
        assert_eventually(
            Duration::from_secs(2),
            || async {
                app.metrics()
                    .await
                    .query_sum("istio_tcp_connections_opened_total", Default::default())
            },
            1,
        )
        .await;
        assert_eventually(
            Duration::from_secs(2),
            || async {
                app.metrics()
                    .await
                    .query_sum("istio_tcp_connections_closed_total", Default::default())
            },
            1,
        )
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_tcp_bytes_metrics() {
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite).await;
    let echo_addr = echo.address();
    tokio::spawn(echo.run());
    let mut cfg = test_config();
    cfg.zero_copy_enabled = false;
    testapp::with_app(cfg, |app| async move {
        let dst = helpers::with_ip(echo_addr, TEST_WORKLOAD_TCP.parse().unwrap());
        let mut stream = app.socks5_connect(dst).await;
        let size = read_write_stream(&mut stream).await as u64;
        drop(stream);

        // Verify the bytes sent and received counters are correct
        assert_eventually(
            Duration::from_secs(2),
            || async {
                app.metrics()
                    .await
                    .query_sum("istio_tcp_received_bytes_total", Default::default())
            },
            size,
        )
        .await;
        assert_eventually(
            Duration::from_secs(2),
            || async {
                app.metrics()
                    .await
                    .query_sum("istio_tcp_sent_bytes_total", Default::default())
            },
            size,
        )
        .await;
    })
    .await;
}

async fn assert_eventually<F, T, Fut>(dur: Duration, f: F, expected: T)
where
    F: Fn() -> Fut,
    Fut: Future<Output = T>,
    T: Eq + Debug,
{
    let mut delay = Duration::from_millis(10);
    let end = SystemTime::now().add(dur);
    let mut last: T;
    let mut attempts = 0;
    loop {
        attempts += 1;
        last = f().await;
        if last == expected {
            return;
        }
        trace!("attempt {attempts} with delay {delay:?}");
        if SystemTime::now().add(delay) > end {
            panic!("assert_eventually failed after {attempts}: last response: {last:?}")
        }
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
}

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

/// admin_shutdown triggers a shutdown - from the admin server
async fn admin_shutdown(addr: SocketAddr) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:{}/quitquitquit", addr.port()))
        .header("content-type", "application/json")
        .body(Body::default())
        .unwrap();
    let client = Client::new();
    let resp = client.request(req).await.expect("admin shutdown request");
    assert_eq!(resp.status(), hyper::StatusCode::OK);
}
