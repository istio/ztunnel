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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
use ztunnel::metrics::Metrics;
use ztunnel::metrics::Recorder;
use ztunnel::test_helpers::app::TestApp;
use ztunnel::test_helpers::tcp::Mode;
use ztunnel::test_helpers::{helpers, tcp};
use ztunnel::workload::Workload;
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
fn initialize_environment(mode: Mode) -> (Arc<Mutex<TestEnv>>, Runtime) {
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
        // let mut env = async_global_setup(|| async move {
        let cert_manager = identity::mock::MockCaClient::new(Duration::from_secs(10));
        let app = app::build_with_cert(test_helpers::test_config(), cert_manager)
            .await
            .unwrap();

        let ta = TestApp {
            admin_address: app.admin_address,
            proxy_addresses: app.proxy_addresses,
            readiness_address: app.readiness_address,
        };
        ta.ready().await;
        let echo = tcp::TestServer::new(mode).await;
        let echo_addr = helpers::with_ip(echo.address(), "127.0.0.1".parse().unwrap());
        let t = tokio::spawn(async move {
            let _ = tokio::join!(app.wait_termination(), echo.run());
        });
        let mut hbone = ta
            .socks5_connect(helpers::with_ip(echo_addr, "127.0.0.1".parse().unwrap()))
            .await;
        let mut tcp = ta
            .socks5_connect(helpers::with_ip(echo_addr, "127.0.0.2".parse().unwrap()))
            .await;
        let mut direct = TcpStream::connect(echo_addr).await.unwrap();
        direct.set_nodelay(true).unwrap();
        info!("setup complete");

        let client_mode = match mode {
            Mode::ReadWrite => Mode::ReadWrite,
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
    let (env, rt) = initialize_environment(Mode::ReadWrite);
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

pub fn throughput(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::Read);
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

pub fn connections(c: &mut Criterion) {
    let (env, rt) = initialize_environment(Mode::ReadWrite);
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
                e.ta.socks5_connect(helpers::with_ip(e.echo_addr, "127.0.0.2".parse().unwrap()))
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
                e.ta.socks5_connect(helpers::with_ip(e.echo_addr, "127.0.0.1".parse().unwrap()))
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
            metrics.record(&ConnectionOpen {
                reporter: Default::default(),
                source: Workload {
                    workload_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    waypoint_addresses: Default::default(),
                    gateway_address: Default::default(),
                    protocol: Default::default(),
                    name: Default::default(),
                    namespace: Default::default(),
                    service_account: Default::default(),
                    workload_name: Default::default(),
                    workload_type: Default::default(),
                    canonical_name: Default::default(),
                    canonical_revision: Default::default(),
                    node: Default::default(),
                    native_hbone: Default::default(),
                    authorization_policies: Default::default(),
                },
                destination: None,
                destination_service: None,
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
    targets = latency, throughput, connections, metrics
}
criterion_main!(benches);
