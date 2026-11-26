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
use std::sync::atomic::{AtomicUsize, Ordering};
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
use ztunnel::signal::Shutdown;
use ztunnel::test_helpers::app::{self as testapp, ParsedMetrics};
use ztunnel::test_helpers::app::{DestinationAddr, TestApp};
use ztunnel::test_helpers::assert_eventually;
use ztunnel::test_helpers::dns::run_dns;
use ztunnel::test_helpers::helpers::initialize_telemetry;
use ztunnel::test_helpers::*;

#[tokio::test]
async fn test_shutdown_lifecycle() {
    helpers::initialize_telemetry();

    let app = ztunnel::app::build(Arc::new(test_config()), Shutdown::new())
        .await
        .unwrap();

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

    assert!(
        ztunnel::app::build(Arc::new(cfg), Shutdown::new())
            .await
            .is_err()
    );
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

    assert!(
        ztunnel::app::build(Arc::new(cfg), Shutdown::new())
            .await
            .is_err()
    );
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
    let app = ztunnel::app::build_with_cert(
        Arc::new(test_config()),
        cert_manager.clone(),
        Shutdown::new(),
    )
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
    let app = ztunnel::app::build_with_cert(Arc::new(cfg), cert_manager.clone(), Shutdown::new())
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

    let app = ztunnel::app::build(Arc::new(test_config()), Shutdown::new())
        .await
        .unwrap();
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

struct CountingHandler(Arc<AtomicUsize>);

impl ztunnel::admin::AdminHandler for CountingHandler {
    fn key(&self) -> &'static str {
        "counting"
    }
    fn handle(&self) -> anyhow::Result<serde_json::Value> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(serde_json::Value::Null)
    }
}

// Runs an admin server on a free localhost port with the given proxy state,
// one certificate per service account and a handler that counts its calls.
// The server stops when the returned trigger is dropped.
async fn admin_server(
    proxy_state: ztunnel::state::DemandProxyState,
    service_accounts: &[&str],
) -> (SocketAddr, Arc<AtomicUsize>, ztunnel::drain::DrainTrigger) {
    let cert_manager = new_secret_manager(Duration::from_secs(60 * 60));
    for sa in service_accounts {
        cert_manager
            .fetch_certificate(&ztunnel::identity::Identity::Spiffe {
                trust_domain: "cluster.local".into(),
                namespace: "default".into(),
                service_account: (*sa).into(),
            })
            .await
            .unwrap();
    }
    let mut cfg = test_config();
    cfg.admin_addr = config::Address::Localhost(false, 0);
    let (drain_tx, drain_rx) = ztunnel::drain::new();
    let mut admin = ztunnel::admin::Service::new(
        Arc::new(cfg),
        proxy_state,
        Shutdown::new().trigger(),
        drain_rx,
        cert_manager,
    )
    .await
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    admin.add_handler(Arc::new(CountingHandler(calls.clone())));
    let addr = admin.address();
    admin.spawn();
    (addr, calls, drain_tx)
}

async fn admin_get(addr: SocketAddr, path: &str) -> (hyper::StatusCode, Option<String>, String) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{addr}{path}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = ztunnel::hyper_util::pooling_client()
        .request(req)
        .await
        .unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(hyper::header::CONTENT_TYPE)
        .map(|v| v.to_str().unwrap().to_string());
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

#[tokio::test]
async fn test_config_dump_certificates() {
    let (addr, calls, _drain) =
        admin_server(new_proxy_state(&[], &[], &[]), &["sa-0", "sa-1"]).await;

    let (status, content_type, certs) = admin_get(addr, "/config_dump?resource=certificates").await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert_eq!(content_type.as_deref(), Some("application/json"));
    for resource in [
        "workloads",
        "Certificates",
        "cert",
        "certs",
        "certificates%20",
    ] {
        let (status, content_type, body) =
            admin_get(addr, &format!("/config_dump?resource={resource}")).await;
        assert_eq!(status, hyper::StatusCode::NOT_FOUND, "{resource}");
        assert_eq!(content_type.as_deref(), Some("text/plain"));
        // A fixed reply, so the request is never echoed back.
        assert_eq!(
            body,
            "unsupported resource; only resource=certificates is supported\n"
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // An empty first value means no filter, as in Envoy.
    let (_, _, empty_first) = admin_get(addr, "/config_dump?resource=&resource=certificates").await;
    let (status, _, full) = admin_get(addr, "/config_dump").await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(empty_first, full);

    // Only the certificates key, holding what the full dump holds, with the
    // same formatting, so the two agree byte for byte.
    let full: serde_json::Value = serde_json::from_str(&full).unwrap();
    let want = serde_json::json!({ "certificates": full["certificates"] });
    assert_eq!(want["certificates"].as_array().unwrap().len(), 2, "{full}");
    assert_eq!(certs, serde_json::to_string_pretty(&want).unwrap());
}

#[tokio::test]
async fn test_config_dump_certificates_skips_rest_of_dump() {
    // Poison the proxy state lock, so serialising the proxy state fails. This
    // relies on std's RwLock poisoning.
    let state = Arc::new(std::sync::RwLock::new(ztunnel::state::ProxyState::new(
        None,
    )));
    let _ = std::panic::catch_unwind(|| {
        let _guard = state.write().unwrap();
        std::panic::resume_unwind(Box::new(()));
    });
    let proxy_state = ztunnel::state::DemandProxyState::new(
        state,
        None,
        Default::default(),
        Default::default(),
        helpers::test_proxy_metrics(),
    );
    let (addr, calls, _drain) = admin_server(proxy_state, &[]).await;

    let (status, _, body) = admin_get(addr, "/config_dump?resource=certificates").await;
    assert_eq!(status, hyper::StatusCode::OK, "{body}");
    assert_eq!(body, "{\n  \"certificates\": []\n}");
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The full dump serialises the proxy state, so it fails.
    let (status, _, body) = admin_get(addr, "/config_dump").await;
    assert_eq!(status, hyper::StatusCode::INTERNAL_SERVER_ERROR, "{body}");
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
