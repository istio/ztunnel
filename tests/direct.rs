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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::{Method, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::time;
use tokio::time::timeout;

use ztunnel::config;
use ztunnel::identity::mock::new_secret_manager;
use ztunnel::test_helpers::app::{self as testapp, ParsedMetrics};
use ztunnel::test_helpers::app::{DestinationAddr, TestApp};
use ztunnel::test_helpers::assert_eventually;
use ztunnel::test_helpers::dns::run_dns;
use ztunnel::test_helpers::helpers::initialize_telemetry;
use ztunnel::test_helpers::*;

#[tokio::test]
async fn test_shutdown_lifecycle() {
    helpers::initialize_telemetry();

    let app = ztunnel::app::build(Arc::new(test_config())).await.unwrap();

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

    assert!(ztunnel::app::build(Arc::new(cfg)).await.is_err());
}

// Check that port conflicts on any address results in the app failing instead of silently failing
async fn test_bind_conflict_address<
    F: FnOnce(&mut ztunnel::config::Config) -> &mut config::Address,
>(
    f: F,
) {
    helpers::initialize_telemetry();
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut cfg = test_config();
    let sa = f(&mut cfg);
    *sa = config::Address::SocketAddr(l.local_addr().unwrap());

    assert!(ztunnel::app::build(Arc::new(cfg)).await.is_err());
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
async fn test_conflicting_bind_error_admin() {
    test_bind_conflict_address(|c| &mut c.admin_addr).await;
}

#[tokio::test]
async fn test_shutdown_drain() {
    helpers::initialize_telemetry();

    let cert_manager = new_secret_manager(Duration::from_secs(10));
    let app = ztunnel::app::build_with_cert(Arc::new(test_config()), cert_manager.clone())
        .await
        .unwrap();
    let ta = TestApp::from((&app, cert_manager));
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite, 0).await;
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
    let mut stream = ta
        .socks5_connect(
            DestinationAddr::Ip(dst),
            TEST_WORKLOAD_SOURCE.parse().unwrap(),
        )
        .await;
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

    let cfg = test_config();

    let cert_manager = new_secret_manager(Duration::from_secs(10));
    let app = ztunnel::app::build_with_cert(Arc::new(cfg), cert_manager.clone())
        .await
        .unwrap();
    let ta = TestApp::from((&app, cert_manager));
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite, 0).await;
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
    let mut stream = ta
        .socks5_connect(
            DestinationAddr::Ip(dst),
            TEST_WORKLOAD_SOURCE.parse().unwrap(),
        )
        .await;
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

    let app = ztunnel::app::build(Arc::new(test_config())).await.unwrap();
    let addr = app.admin_address;

    let (app, _shutdown) = tokio::join!(
        time::timeout(Duration::from_secs(5), app.wait_termination()),
        admin_shutdown(addr)
    );
    app.expect("app shuts down")
        .expect("app exits without error");
}

fn process_metrics_assertions(metrics: &ParsedMetrics) {
    for metric in ["process_open_fds", "process_max_fds"] {
        let metric = &(metric);
        let m = metrics.query(metric, &Default::default());
        assert!(m.is_some(), "expected metric {metric}");
        assert!(
            m.to_owned().unwrap().len() == 1,
            "expected metric {metric} to have len(1)"
        );
        let value = m.unwrap()[0].value.clone();
        match value {
            prometheus_parse::Value::Gauge(v) => {
                assert!(
                    v > 0.0,
                    "expected metric {metric} to be positive, was {value:?}",
                );
            }
            _ => {
                panic!("unexpected metric type");
            }
        }
    }
}

fn base_metrics_assertions(metrics: ParsedMetrics) {
    process_metrics_assertions(&metrics);
}

async fn run_request_test(target: &str, node: &str) {
    run_requests_test(target, node, 1, Some(base_metrics_assertions), false).await
}

async fn run_requests_test(
    target: &str,
    node: &str,
    num_queries: u8,
    metrics_assertions: Option<fn(metrics: ParsedMetrics)>,
    dns: bool,
) {
    initialize_telemetry();
    // Test a round trip outbound call (via socks5)
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite, 0).await;
    let echo_addr = echo.address();
    let mut cfg = config::Config {
        local_node: (!node.is_empty()).then(|| node.to_string()),
        ..test_config_with_port(echo_addr.port())
    };
    let _dns = if dns {
        let dns_server = run_dns(HashMap::new()).await.unwrap();
        cfg.dns_resolver_cfg = dns_server.resolver_config();
        Some(dns_server)
    } else {
        None
    };
    tokio::spawn(echo.run());
    testapp::with_app(cfg, async move |app| {
        let dst = match SocketAddr::from_str(target) {
            Ok(s) => DestinationAddr::Ip(s),
            Err(_) if target.contains(':') => {
                let (h, port) = target.split_once(':').unwrap();
                DestinationAddr::Hostname(h.to_string(), port.parse().unwrap())
            }
            _ => DestinationAddr::Ip(helpers::with_ip(echo_addr, target.parse().unwrap())),
        };
        for _ in 0..num_queries {
            let mut stream = app
                .socks5_connect(dst.clone(), TEST_WORKLOAD_SOURCE.parse().unwrap())
                .await;
            read_write_stream(&mut stream).await;
        }
        if let Some(assertions) = metrics_assertions {
            let metrics = app.metrics().await.unwrap();
            assertions(metrics);
        }
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

fn on_demand_dns_assertions(metrics: ParsedMetrics) {
    let metric = &("istio_on_demand_dns_total");
    let m = metrics.query(metric, &Default::default());
    assert!(m.is_some(), "expected metric {metric}");
    // expecting one cache hit and one cache miss
    assert!(
        m.to_owned().unwrap().len() == 1,
        "expected metric {metric} to have len(1)"
    );
    let value = m.unwrap()[0].value.clone();
    let expected = match *metric {
        "istio_on_demand_dns_total" => prometheus_parse::Value::Untyped(2.0),
        &_ => {
            panic!("dev error; unexpected metric");
        }
    };
    assert!(
        value == expected,
        "expected metric {metric} to be 1, was {value:?}",
    );
}

#[tokio::test]
async fn test_on_demand_dns_request() {
    // first request should trigger on-demand DNS resolution
    // second request should use cached DNS response
    run_requests_test(
        &format!("{TEST_VIP_DNS}:80"),
        "",
        2,
        Some(on_demand_dns_assertions),
        true,
    )
    .await;
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
async fn test_hostname_request_local() {
    run_request_test(&format!("{TEST_SERVICE_HOST}:80"), "local").await;
}

#[tokio::test]
async fn test_stats_exist() {
    testapp::with_app(test_config(), async move |app| {
        let metrics = app.metrics().await.unwrap();
        // Only check metrics that are always populated at startup.
        // prometheus-client 0.24.1+ omits empty metric families from output,
        // so counter families with no samples (traffic, xds, dns) won't appear
        // until they are incremented. Those are covered by dedicated tests
        // (test_tcp_connections_metrics, test_dns_metrics, etc).
        assert!(
            metrics.query("istio_build", &Default::default()).is_some(),
            "expected metric istio_build"
        );
        let metric_info = metrics.metric_info();
        // Note: this is referring to the HELP doc line
        // This does NOT have the _total suffix
        // See https://github.com/OpenObservability/OpenMetrics/blob/main/specification/OpenMetrics.md#counter-1
        let stable_metrics = HashSet::from([
            "istio_build",
            "istio_tcp_connections_opened",
            "istio_tcp_connections_closed",
            "istio_tcp_received_bytes",
            "istio_tcp_sent_bytes",
            "process_max_fds",
            "process_open_fds",
            "tokio_num_workers",
            "tokio_global_queue_depth",
            "tokio_num_alive_tasks",
            "tokio_worker_park_count",
            "tokio_worker_park_unpark_count",
            "tokio_worker_total_busy_duration_seconds",
        ]);
        {
            for (name, doc) in metric_info {
                if stable_metrics.contains(&*name) {
                    assert!(!doc.contains("unstable"), "{name}: {doc}");
                } else {
                    assert!(doc.contains("unstable"), "{name}: {doc}");
                }
            }
        }
    })
    .await;
}

#[tokio::test]
async fn test_dns_metrics() {
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite, 0).await;
    tokio::spawn(echo.run());
    testapp::with_app(test_config(), async move |app| {
        // Make a valid request that will be forwarded to the upstream resolver.
        _ = app.dns_request("www.google.com.", true, false).await;

        let metrics = app.metrics().await.unwrap();
        assert_eq!(
            metrics.query_sum("istio_dns_requests_total", &Default::default()),
            1,
            "metrics: {}",
            metrics.dump()
        );

        // TODO(nmittler): Remaining require adding a workload for this client (127.0.0.1).
        /*assert_eq!(
            metrics.query_sum("istio_dns_upstream_requests_total", &Default::default()),
            1,
            "metrics: {}",
            metrics.dump()
        );
        assert_eq!(
            metrics.query_sum("istio_dns_upstream_failures_total", &Default::default()),
            0,
            "metrics: {}",
            metrics.dump()
        );
        assert!(
            !metrics.query("istio_dns_upstream_request_duration_seconds", &Default::default()).unwrap().is_empty(),
            "metrics: {}",
            metrics.dump()
        );*/
    })
    .await;
}

#[tokio::test]
async fn test_tcp_connections_metrics() {
    // Test a round trip outbound call (via socks5)
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite, 0).await;
    let echo_addr = echo.address();
    tokio::spawn(echo.run());
    testapp::with_app(test_config(), async move |app| {
        let dst = helpers::with_ip(echo_addr, TEST_WORKLOAD_TCP.parse().unwrap());
        let mut stream = app
            .socks5_connect(
                DestinationAddr::Ip(dst),
                TEST_WORKLOAD_SOURCE.parse().unwrap(),
            )
            .await;
        read_write_stream(&mut stream).await;

        // We should have 1 open connection but 0 closed connections
        let metrics = app.metrics().await.unwrap();
        assert_eq!(
            metrics.query_sum("istio_tcp_connections_opened_total", &Default::default()),
            1,
            "metrics: {}",
            metrics.dump()
        );
        assert_eq!(
            metrics.query_sum("istio_tcp_connections_closed_total", &Default::default()),
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
                    .unwrap()
                    .query_sum("istio_tcp_connections_opened_total", &Default::default())
            },
            1,
        )
        .await;
        assert_eventually(
            Duration::from_secs(2),
            || async {
                app.metrics()
                    .await
                    .unwrap()
                    .query_sum("istio_tcp_connections_closed_total", &Default::default())
            },
            1,
        )
        .await;
    })
    .await;
}

#[tokio::test]
async fn test_tcp_bytes_metrics() {
    let echo = tcp::TestServer::new(tcp::Mode::ReadWrite, 0).await;
    let echo_addr = echo.address();
    tokio::spawn(echo.run());
    let cfg = test_config();
    testapp::with_app(cfg, async move |app| {
        let dst = helpers::with_ip(echo_addr, TEST_WORKLOAD_TCP.parse().unwrap());
        let mut stream = app
            .socks5_connect(
                DestinationAddr::Ip(dst),
                TEST_WORKLOAD_SOURCE.parse().unwrap(),
            )
            .await;
        let size = read_write_stream(&mut stream).await as u64;
        drop(stream);

        // Verify the bytes sent and received counters are correct
        assert_eventually(
            Duration::from_secs(2),
            || async {
                app.metrics()
                    .await
                    .unwrap()
                    .query_sum("istio_tcp_received_bytes_total", &Default::default())
            },
            size,
        )
        .await;
        assert_eventually(
            Duration::from_secs(2),
            || async {
                app.metrics()
                    .await
                    .unwrap()
                    .query_sum("istio_tcp_sent_bytes_total", &Default::default())
            },
            size,
        )
        .await;
    })
    .await;
}

async fn read_write_stream(stream: &mut TcpStream) -> usize {
    const BODY: &[u8] = b"hello world";
    stream.write_all(BODY).await.unwrap();
    let mut buf: [u8; BODY.len()] = [0; BODY.len()];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(BODY, buf);
    BODY.len()
}

/// admin_shutdown triggers a shutdown - from the admin server
async fn admin_shutdown(addr: SocketAddr) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:{}/quitquitquit", addr.port()))
        .header("content-type", "application/json")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let client =
        ::hyper_util::client::legacy::Client::builder(::hyper_util::rt::TokioExecutor::new())
            .build_http();
    let resp = client.request(req).await.expect("admin shutdown request");
    assert_eq!(resp.status(), hyper::StatusCode::OK);
}

mod xds_readiness_rearm {
    //! End-to-end tests for the `XDS_UNHEALTHY_THRESHOLD` readiness re-arm
    //! feature. Drives a real ztunnel against the in-process ADS test server
    //! and asserts behavior through the operator-visible surface
    //! (`/healthz/ready` on the readiness port and `/metrics` on the stats
    //! port). Test-only xDS signals gate the protocol phases so the public
    //! assertions do not depend on fixed sleeps.
    //!
    //! `tokio::test` (real time) is used rather than `start_paused = true`:
    //! the in-process gRPC server runs on real I/O, so virtual time would
    //! desynchronize the protocol exchange from the monitor's grace timer.
    //! Threshold is set to 200 ms (matching the in-module wiring test) to
    //! keep the test fast while leaving headroom for loaded CI schedulers.
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use textnonce::TextNonce;
    use ztunnel::identity::mock::new_secret_manager;
    use ztunnel::test_helpers::app::XdsTestSignals;
    use ztunnel::test_helpers::helpers::initialize_telemetry;
    use ztunnel::test_helpers::xds::{AdsConnection, AdsServer};
    use ztunnel::xds::service::discovery::v3::{DeltaDiscoveryRequest, DeltaDiscoveryResponse};
    use ztunnel::xds::{ADDRESS_TYPE, AUTHORIZATION_TYPE};

    const REARM_TEST_THRESHOLD: Duration = Duration::from_millis(200);

    /// Drive each watched type to ACK by replying with an empty resource set
    /// on the first request seen for that type. The xDS client publishes
    /// `Synced` once at least one ACK lands on the current stream and no
    /// watched resource is currently rejected, which is what restores
    /// readiness in both the initial-sync and post-rearm paths.
    async fn ack_each_watched_type(conn: &mut AdsConnection) {
        let mut addr_acked = false;
        let mut auth_acked = false;
        while !(addr_acked && auth_acked) {
            let req = tokio::time::timeout(Duration::from_secs(2), conn.recv_request())
                .await
                .expect("timed out waiting for xDS request")
                .expect("ADS request channel closed");
            if req.type_url == *ADDRESS_TYPE && !addr_acked {
                send_empty_response(conn, &ADDRESS_TYPE).await;
                addr_acked = true;
            } else if req.type_url == *AUTHORIZATION_TYPE && !auth_acked {
                send_empty_response(conn, &AUTHORIZATION_TYPE).await;
                auth_acked = true;
            }
            // Other request shapes (NACKs, ACK-of-ACK, on-demand) are
            // ignored: they don't advance us toward Synced.
        }
    }

    async fn send_empty_response(conn: &mut AdsConnection, type_url: &str) {
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![],
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: type_url.to_string(),
            removed_resources: vec![],
        }))
        .await;
    }

    async fn ack_watched_request(conn: &mut AdsConnection, req: &DeltaDiscoveryRequest) {
        match req.type_url.as_str() {
            t if t == &*ADDRESS_TYPE => send_empty_response(conn, &ADDRESS_TYPE).await,
            t if t == &*AUTHORIZATION_TYPE => send_empty_response(conn, &AUTHORIZATION_TYPE).await,
            other => panic!("unexpected reconnect xDS request type {other}"),
        }
    }

    async fn readiness_status(addr: SocketAddr) -> hyper::StatusCode {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("http://localhost:{}/healthz/ready", addr.port()))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let client =
            ::hyper_util::client::legacy::Client::builder(::hyper_util::rt::TokioExecutor::new())
                .build_http();
        client
            .request(req)
            .await
            .expect("readiness request")
            .status()
    }

    async fn metrics_text(addr: SocketAddr) -> String {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("http://{addr}/metrics"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let client =
            ::hyper_util::client::legacy::Client::builder(::hyper_util::rt::TokioExecutor::new())
                .build_http();
        let body = client
            .request(req)
            .await
            .expect("metrics request")
            .into_body();
        let body = http_body_util::BodyExt::collect(body)
            .await
            .expect("metrics body")
            .to_bytes();
        String::from_utf8(body.to_vec()).expect("metrics body utf-8")
    }

    fn metric_value_u64(metrics: &str, line_prefix: &str) -> Option<u64> {
        metrics
            .lines()
            .find(|l| l.starts_with(line_prefix))
            .and_then(|l| l.strip_prefix(line_prefix))
            .and_then(|rest| rest.trim().parse::<u64>().ok())
    }

    async fn wait_for_readiness(readiness_address: SocketAddr, ready: bool, reason: &str) {
        let mut last_status = None;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let status = readiness_status(readiness_address).await;
                last_status = Some(status);
                if (status == hyper::StatusCode::OK) == ready {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("timed out waiting for {reason}; last readiness status: {last_status:?}")
        });
    }

    async fn assert_readiness_ready_without_rearm(
        readiness_address: SocketAddr,
        metrics_address: SocketAddr,
        reason: &str,
    ) {
        assert_eq!(
            readiness_status(readiness_address).await,
            hyper::StatusCode::OK,
            "readiness became unhealthy while {reason}"
        );

        let metrics = metrics_text(metrics_address).await;
        assert_eq!(
            metric_value_u64(&metrics, "istio_xds_readiness_rearmed_total "),
            Some(0),
            "readiness rearm counter changed while {reason}:\n{metrics}"
        );
    }

    /// Operator scenario: with `XDS_UNHEALTHY_THRESHOLD` configured, a
    /// sustained xDS disconnect must flip `/healthz/ready` to non-OK and
    /// bump `istio_xds_readiness_rearmed_total`, then a fresh ACK on the
    /// reconnected stream must restore it. This is the same scenario the
    /// in-module `test_app_wires_xds_unhealthy_threshold_to_readiness_rearm`
    /// covers, but observed only through the public probe and metrics
    /// endpoints.
    #[tokio::test]
    async fn rearms_after_threshold_and_restores_on_resync() {
        initialize_telemetry();

        let (mut conn_receiver, mut cfg) = AdsServer::spawn_app_server().await;
        cfg.xds_unhealthy_threshold = Some(REARM_TEST_THRESHOLD);

        let cert_manager = new_secret_manager(Duration::from_secs(10));
        let app = ztunnel::app::build_with_cert(Arc::new(cfg), cert_manager)
            .await
            .expect("ztunnel builds");
        let shutdown = app.shutdown.trigger().clone();
        let readiness_address = app.readiness_address;
        let metrics_address = app.metrics_address;
        let mut xds_signals =
            XdsTestSignals::from_bound(&app).expect("remote xDS app exposes test signals");
        let app_task = tokio::spawn(app.wait_termination());

        // 1. Initial sync. ACK each watched type so readiness flips to OK.
        let mut conn = tokio::time::timeout(Duration::from_secs(5), conn_receiver.recv())
            .await
            .expect("timed out waiting for initial xDS connection")
            .expect("ADS connection channel closed");
        ack_each_watched_type(&mut conn).await;
        xds_signals.wait_for_startup_sync().await;
        let synced_epoch = xds_signals.wait_for_synced("initial xDS sync").await;
        wait_for_readiness(readiness_address, true, "initial readiness").await;

        // Sanity: rearm counter is exported and starts at zero.
        let metrics = metrics_text(metrics_address).await;
        assert_eq!(
            metric_value_u64(&metrics, "istio_xds_readiness_rearmed_total "),
            Some(0),
            "rearm counter should be exported and zero before any disconnect:\n{metrics}"
        );

        // 2. Force a disconnect by aborting the stream, then refuse to ACK on
        //    the reconnected stream. Once the threshold elapses the monitor
        //    must register `xds freshness` and readiness must flip non-OK.
        conn.send_response(Err(tonic::Status::aborted("simulated disconnect")))
            .await;
        let mut restore_conn = tokio::time::timeout(Duration::from_secs(5), conn_receiver.recv())
            .await
            .expect("timed out waiting for reconnect")
            .expect("ADS connection channel closed");
        xds_signals
            .wait_for_connected_at_epoch(synced_epoch, "raw reconnect before ACK")
            .await;

        // Drain the reconnected stream's first request so the gRPC layer is
        // settled; we deliberately do NOT respond, leaving the stream raw
        // `Connected` (not `Synced`) and forcing the threshold to elapse.
        let first_req = tokio::time::timeout(Duration::from_secs(5), restore_conn.recv_request())
            .await
            .expect("timed out waiting for reconnect's first request")
            .expect("ADS request channel closed");

        wait_for_readiness(
            readiness_address,
            false,
            "readiness to re-arm after threshold",
        )
        .await;

        let metrics = metrics_text(metrics_address).await;
        let rearms = metric_value_u64(&metrics, "istio_xds_readiness_rearmed_total ")
            .expect("rearm counter must be exported after threshold and reconnect");
        assert!(
            rearms >= 1,
            "rearm counter should be >= 1 after threshold and reconnect (got {rearms}):\n{metrics}"
        );

        // 3. ACK exactly one watched request on the reconnected stream. A
        //    single usable ACK must restore readiness; requiring every watched
        //    type to re-ACK would keep quiet types from ever recovering.
        ack_watched_request(&mut restore_conn, &first_req).await;
        xds_signals
            .wait_for_synced_after(synced_epoch, "post-reconnect xDS ACK")
            .await;
        wait_for_readiness(
            readiness_address,
            true,
            "readiness to restore after first post-reconnect ACK",
        )
        .await;

        shutdown.shutdown_now().await;
        app_task
            .await
            .expect("app task joins")
            .expect("app exits clean");
    }

    /// Default-off behavior: with `XDS_UNHEALTHY_THRESHOLD` unset, an
    /// extended xDS disconnect must NOT re-arm readiness. This guards
    /// against silent regressions that would change the default contract
    /// (the feature is opt-in by design).
    #[tokio::test]
    async fn does_not_rearm_when_threshold_unset() {
        initialize_telemetry();

        let (mut conn_receiver, cfg) = AdsServer::spawn_app_server().await;
        assert_eq!(
            cfg.xds_unhealthy_threshold, None,
            "test_helpers must default xds_unhealthy_threshold to None"
        );

        let cert_manager = new_secret_manager(Duration::from_secs(10));
        let app = ztunnel::app::build_with_cert(Arc::new(cfg), cert_manager)
            .await
            .expect("ztunnel builds");
        let shutdown = app.shutdown.trigger().clone();
        let readiness_address = app.readiness_address;
        let metrics_address = app.metrics_address;
        let mut xds_signals =
            XdsTestSignals::from_bound(&app).expect("remote xDS app exposes test signals");
        let app_task = tokio::spawn(app.wait_termination());

        let mut conn = tokio::time::timeout(Duration::from_secs(5), conn_receiver.recv())
            .await
            .expect("timed out waiting for initial xDS connection")
            .expect("ADS connection channel closed");
        ack_each_watched_type(&mut conn).await;
        xds_signals.wait_for_startup_sync().await;
        xds_signals.wait_for_readiness_monitor_exit().await;
        let synced_epoch = xds_signals.wait_for_synced("initial xDS sync").await;
        wait_for_readiness(readiness_address, true, "initial readiness").await;

        // The monitor has exited in disabled mode, so a later reconnect cannot
        // re-arm readiness. Disconnect, accept a reconnect, refuse to ACK, and
        // assert the public readiness and metric surfaces remain unchanged.
        conn.send_response(Err(tonic::Status::aborted("simulated disconnect")))
            .await;
        let mut reconnect = tokio::time::timeout(Duration::from_secs(5), conn_receiver.recv())
            .await
            .expect("timed out waiting for reconnect")
            .expect("ADS connection channel closed");
        xds_signals
            .wait_for_connected_at_epoch(synced_epoch, "disabled reconnect before ACK")
            .await;
        // Drain at least one request so the reconnect is fully established.
        let _ = tokio::time::timeout(Duration::from_secs(5), reconnect.recv_request())
            .await
            .expect("timed out waiting for reconnect's first request")
            .expect("ADS request channel closed");

        assert_readiness_ready_without_rearm(
            readiness_address,
            metrics_address,
            "XDS_UNHEALTHY_THRESHOLD is unset and reconnect remains unACKed",
        )
        .await;

        shutdown.shutdown_now().await;
        app_task
            .await
            .expect("app task joins")
            .expect("app exits clean");
    }
}
