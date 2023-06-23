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

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use pprof::criterion::{Output, PProfProfiler};
use prometheus_client::registry::Registry;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::sync::Mutex;
use tracing::info;

use ztunnel::metrics::traffic::ConnectionOpen;
use ztunnel::metrics::{IncrementRecorder, Metrics};

use ztunnel::rbac::{Authorization, RbacMatch, StringMatch};
use ztunnel::test_helpers::app::TestApp;
use ztunnel::test_helpers::tcp::Mode;
use ztunnel::test_helpers::TEST_WORKLOAD_HBONE;
use ztunnel::test_helpers::TEST_WORKLOAD_SOURCE;
use ztunnel::test_helpers::TEST_WORKLOAD_TCP;
use ztunnel::test_helpers::{helpers, tcp};

use ztunnel::{app, identity, test_helpers};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

struct TestEnv {
    ta: TestApp,
    echo_addr: SocketAddr,
    direct: TcpStream,
    tcp: TcpStream,
    hbone: TcpStream,
}

/// initialize_environment sets up a benchmarking environment. This works around issues in async setup with criterion.
/// Since tests are only sending data on existing connections, we setup a connection for each test type in the setup phase.
/// Tests consume the

const N_RULES: usize = 10;
const N_POLICIES: usize = 10_000;
const DUMMY_NETWORK: &str = "198.51.100.0/24";

fn create_test_policies() -> Vec<Authorization> {
    let mut policies: Vec<Authorization> = vec![];
    let mut rules = vec![];
    for _ in 0..N_RULES {
        rules.push(vec![vec![RbacMatch {
            namespaces: vec![
                StringMatch::Prefix("random-prefix-2b123".to_string()),
                StringMatch::Suffix("random-postix-2b723".to_string()),
                StringMatch::Exact("random-exac-2bc13".to_string()),
            ],
            not_namespaces: vec![],
            principals: vec![
                StringMatch::Prefix("random-prefix-2b123".to_string()),
                StringMatch::Suffix("random-postix-2b723".to_string()),
                StringMatch::Exact("random-exac-2bc13".to_string()),
            ],
            not_principals: vec![],
            source_ips: vec![DUMMY_NETWORK.parse().unwrap()],
            not_source_ips: vec![],
            destination_ips: vec![DUMMY_NETWORK.parse().unwrap()],
            not_destination_ips: vec![],
            destination_ports: vec![0],
            not_destination_ports: vec![],
        }]]);
    }

    for i in 0..N_POLICIES {
        policies.push(Authorization {
            name: format!("policy {i}"),
            action: ztunnel::rbac::RbacAction::Deny,
            scope: ztunnel::rbac::RbacScope::Global,
            namespace: "default".to_string(),
            rules: rules.clone(),
        });
    }

    policies
}

fn initialize_environment(
    mode: Mode,
    policies: Vec<Authorization>,
) -> (Arc<Mutex<TestEnv>>, Runtime) {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "error")
    }
    helpers::initialize_telemetry();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    // Global setup: spin up an echo server and ztunnel instance
    let (env, _) = rt.block_on(async move {
        let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
        let port = 80;
        let config_source = Some(ztunnel::config::ConfigSource::Static(
            test_helpers::local_xds_config(port, None, policies).unwrap(),
        ));
        let config = test_helpers::test_config_with_port_xds_addr_and_root_cert(
            port,
            None,
            None,
            config_source,
        );
        let app = app::build_with_cert(config, cert_manager.clone())
            .await
            .unwrap();

        let ta = TestApp::from((&app, cert_manager));
        ta.ready().await;
        let echo = tcp::TestServer::new(mode, 0).await;
        let echo_addr = helpers::with_ip(echo.address(), TEST_WORKLOAD_SOURCE.parse().unwrap());
        let t = tokio::spawn(async move {
            let _ = tokio::join!(app.wait_termination(), echo.run());
        });
        let mut hbone = ta
            .socks5_connect(helpers::with_ip(
                echo_addr,
                TEST_WORKLOAD_HBONE.parse().unwrap(),
            ))
            .await;
        let mut tcp = ta
            .socks5_connect(helpers::with_ip(
                echo_addr,
                TEST_WORKLOAD_TCP.parse().unwrap(),
            ))
            .await;
        let mut direct = TcpStream::connect(echo_addr).await.unwrap();
        direct.set_nodelay(true).unwrap();
        info!("setup complete");

        let client_mode = match mode {
            Mode::ReadWrite => Mode::ReadWrite,
            Mode::ReadDoubleWrite => Mode::ReadDoubleWrite,
            Mode::Write => Mode::Read,
            Mode::Read => Mode::Write,
        };
        // warmup: send 1 byte so we ensure we have the full connection setup.
        tcp::run_client(&mut hbone, 1, client_mode).await.unwrap();
        tcp::run_client(&mut tcp, 1, client_mode).await.unwrap();
        tcp::run_client(&mut direct, 1, client_mode).await.unwrap();
        info!("warmup complete");

        (
            Arc::new(Mutex::new(TestEnv {
                hbone,
                tcp,
                direct,
                ta,
                echo_addr,
            })),
            t,
        )
    });
    (env, rt)
}

pub fn latency(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::ReadWrite, vec![]);
    let mut c = c.benchmark_group("latency");
    for size in [1usize, KB] {
        c.bench_with_input(BenchmarkId::new("direct", size), &size, |b, size| {
            b.to_async(&rt).iter(|| async {
                tcp::run_client(&mut env.lock().await.direct, *size, Mode::ReadWrite).await
            })
        });
        c.bench_with_input(BenchmarkId::new("tcp", size), &size, |b, size| {
            b.to_async(&rt).iter(|| async {
                tcp::run_client(&mut env.lock().await.tcp, *size, Mode::ReadWrite).await
            })
        });
        c.bench_with_input(BenchmarkId::new("hbone", size), &size, |b, size| {
            b.to_async(&rt).iter(|| async {
                tcp::run_client(&mut env.lock().await.hbone, *size, Mode::ReadWrite).await
            })
        });
    }
}

pub fn rbac_latency(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::ReadWrite, create_test_policies());
    let mut c = c.benchmark_group("rbac_latency");
    for size in [1usize, KB] {
        c.bench_with_input(BenchmarkId::new("direct", size), &size, |b, size| {
            b.to_async(&rt).iter(|| async {
                tcp::run_client(&mut env.lock().await.direct, *size, Mode::ReadWrite).await
            })
        });
        c.bench_with_input(BenchmarkId::new("tcp", size), &size, |b, size| {
            b.to_async(&rt).iter(|| async {
                tcp::run_client(&mut env.lock().await.tcp, *size, Mode::ReadWrite).await
            })
        });
        c.bench_with_input(BenchmarkId::new("hbone", size), &size, |b, size| {
            b.to_async(&rt).iter(|| async {
                tcp::run_client(&mut env.lock().await.hbone, *size, Mode::ReadWrite).await
            })
        });
    }
}

pub fn throughput(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::Read, vec![]);
    let mut c = c.benchmark_group("throughput");

    let size: usize = 10 * MB;
    c.throughput(Throughput::Bytes(size as u64));

    // Test takes a while, so reduce how many iterations we run
    c.sample_size(10);
    c.sampling_mode(SamplingMode::Flat);
    c.measurement_time(Duration::from_secs(5));
    c.bench_with_input("direct", &size, |b, size| {
        b.to_async(&rt).iter(|| async {
            tcp::run_client(&mut env.lock().await.direct, *size, Mode::Write).await
        })
    });
    c.bench_with_input("tcp", &size, |b, size| {
        b.to_async(&rt)
            .iter(|| async { tcp::run_client(&mut env.lock().await.tcp, *size, Mode::Write).await })
    });
    c.bench_with_input("hbone", &size, |b, size| {
        b.to_async(&rt).iter(|| async {
            tcp::run_client(&mut env.lock().await.hbone, *size, Mode::Write).await
        })
    });
}

pub fn rbac_throughput(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::Read, create_test_policies());
    let mut c = c.benchmark_group("rbac_throughput");

    let size: usize = 10 * MB;
    c.throughput(Throughput::Bytes(size as u64));

    // Test takes a while, so reduce how many iterations we run
    c.sample_size(10);
    c.sampling_mode(SamplingMode::Flat);
    c.measurement_time(Duration::from_secs(5));
    c.bench_with_input("direct", &size, |b, size| {
        b.to_async(&rt).iter(|| async {
            tcp::run_client(&mut env.lock().await.direct, *size, Mode::Write).await
        })
    });
    c.bench_with_input("tcp", &size, |b, size| {
        b.to_async(&rt)
            .iter(|| async { tcp::run_client(&mut env.lock().await.tcp, *size, Mode::Write).await })
    });
    c.bench_with_input("hbone", &size, |b, size| {
        b.to_async(&rt).iter(|| async {
            tcp::run_client(&mut env.lock().await.hbone, *size, Mode::Write).await
        })
    });
}

pub fn connections(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::ReadWrite, vec![]);
    let mut c = c.benchmark_group("connections");
    c.bench_function("direct", |b| {
        b.to_async(&rt).iter(|| async {
            let e = env.lock().await;
            let mut s = TcpStream::connect(e.echo_addr).await.unwrap();
            s.set_nodelay(true).unwrap();
            tcp::run_client(&mut s, 1, Mode::ReadWrite).await
        })
    });
    c.bench_function("tcp", |b| {
        b.to_async(&rt).iter(|| async {
            let e = env.lock().await;
            let mut s =
                e.ta.socks5_connect(helpers::with_ip(
                    e.echo_addr,
                    TEST_WORKLOAD_TCP.parse().unwrap(),
                ))
                .await;
            tcp::run_client(&mut s, 1, Mode::ReadWrite).await
        })
    });
    // TODO(https://github.com/istio/ztunnel/issues/15): when we have pooling, split this into "new hbone connection"
    // and "new connection on existing HBONE connection"
    c.bench_function("hbone", |b| {
        b.to_async(&rt).iter(|| async {
            let e = env.lock().await;
            let mut s =
                e.ta.socks5_connect(helpers::with_ip(
                    e.echo_addr,
                    TEST_WORKLOAD_HBONE.parse().unwrap(),
                ))
                .await;
            tcp::run_client(&mut s, 1, Mode::ReadWrite).await
        })
    });
}

pub fn rbac_connections(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::ReadWrite, create_test_policies());
    let mut c = c.benchmark_group("rbac_connections");
    c.bench_function("direct", |b| {
        b.to_async(&rt).iter(|| async {
            let e = env.lock().await;
            let mut s = TcpStream::connect(e.echo_addr).await.unwrap();
            s.set_nodelay(true).unwrap();
            tcp::run_client(&mut s, 1, Mode::ReadWrite).await
        })
    });
    c.bench_function("tcp", |b| {
        b.to_async(&rt).iter(|| async {
            let e = env.lock().await;
            let mut s =
                e.ta.socks5_connect(helpers::with_ip(
                    e.echo_addr,
                    TEST_WORKLOAD_TCP.parse().unwrap(),
                ))
                .await;
            tcp::run_client(&mut s, 1, Mode::ReadWrite).await
        })
    });
    // TODO(https://github.com/istio/ztunnel/issues/15): when we have pooling, split this into "new hbone connection"
    // and "new connection on existing HBONE connection"
    c.bench_function("hbone", |b| {
        b.to_async(&rt).iter(|| async {
            let e = env.lock().await;
            let mut s =
                e.ta.socks5_connect(helpers::with_ip(
                    e.echo_addr,
                    TEST_WORKLOAD_HBONE.parse().unwrap(),
                ))
                .await;
            tcp::run_client(&mut s, 1, Mode::ReadWrite).await
        })
    });
}

pub fn metrics(c: &mut Criterion) {
    let mut registry = Registry::default();
    let metrics = Metrics::from(&mut registry);

    let mut c = c.benchmark_group("metrics");
    c.bench_function("write", |b| {
        b.iter(|| {
            metrics.increment(&ConnectionOpen {
                reporter: Default::default(),
                source: Some(test_helpers::test_default_workload()),
                derived_source: None,
                destination: None,
                destination_service: None,
                destination_service_name: None,
                destination_service_namespace: None,
                connection_security_policy: Default::default(),
            })
        })
    });
    c.bench_function("encode", |b| {
        b.iter(|| {
            let mut buf = String::new();
            prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Protobuf))
        .warm_up_time(Duration::from_millis(1));
    targets = latency, throughput, connections, rbac_latency, rbac_throughput, rbac_connections,
}

criterion_main!(benches);
