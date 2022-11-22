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

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use std::{env, thread};
use tokio::sync::Mutex;

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use pprof::criterion::{Output, PProfProfiler};
use tokio::net::TcpStream;
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;
use tracing::info;

use ztunnel::test_helpers::app::TestApp;
use ztunnel::test_helpers::{echo, helpers, tcp};
use ztunnel::{app, identity, test_helpers};

const KB: usize = 1024;
const MB: usize = 1024 * KB;

struct TestEnv {
    direct: TcpStream,
    tcp: TcpStream,
    hbone: TcpStream,
}

/// initialize_environment sets up a benchmarking environment. This works around issues in async setup with criterion.
/// Since tests are only sending data on existing connections, we setup a connection for each test type in the setup phase.
/// Tests consume the
fn initialize_environment() -> (Arc<Mutex<TestEnv>>, Runtime) {
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
        };
        ta.ready().await;
        let echo = echo::TestServer::new().await;
        let echo_addr = helpers::with_ip(echo.address(), "127.0.0.1".parse().unwrap());
        let t = tokio::spawn(async move {
            let _ = tokio::join!(app.spawn(), echo.run());
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

        // warmup: send 1 byte so we ensure we have the full connection setup.
        tcp::run_latency(&mut hbone, 1).await.unwrap();
        tcp::run_latency(&mut tcp, 1).await.unwrap();
        tcp::run_latency(&mut direct, 1).await.unwrap();
        info!("warmup complete");

        (Arc::new(Mutex::new(TestEnv { hbone, tcp, direct })), t)
    });
    (env, rt)
}

pub fn latency(c: &mut Criterion) {
    let (env, rt) = initialize_environment();
    let mut c = c.benchmark_group("latency");
    for size in [1usize, KB] {
        c.bench_with_input(BenchmarkId::new("direct", size), &size, |b, size| {
            b.to_async(&rt)
                .iter(|| async { tcp::run_latency(&mut env.lock().await.direct, *size).await })
        });
        c.bench_with_input(BenchmarkId::new("tcp", size), &size, |b, size| {
            b.to_async(&rt)
                .iter(|| async { tcp::run_latency(&mut env.lock().await.tcp, *size).await })
        });
        c.bench_with_input(BenchmarkId::new("hbone", size), &size, |b, size| {
            b.to_async(&rt)
                .iter(|| async { tcp::run_latency(&mut env.lock().await.hbone, *size).await })
        });
    }
}

pub fn throughput(c: &mut Criterion) {
    let (env, rt) = initialize_environment();
    let mut c = c.benchmark_group("throughput");

    let size: usize = 10 * MB;
    c.throughput(Throughput::Bytes(size as u64));

    // Test takes a while, so reduce how many iterations we run
    c.sample_size(10);
    c.sampling_mode(SamplingMode::Flat);
    c.measurement_time(Duration::from_secs(5));
    c.bench_with_input(BenchmarkId::new("direct", size), &size, |b, size| {
        b.to_async(&rt)
            .iter(|| async { tcp::run_throughput(&mut env.lock().await.direct, *size).await })
    });
    c.bench_with_input(BenchmarkId::new("tcp", size), &size, |b, size| {
        b.to_async(&rt)
            .iter(|| async { tcp::run_throughput(&mut env.lock().await.tcp, *size).await })
    });
    c.bench_with_input(BenchmarkId::new("hbone", size), &size, |b, size| {
        b.to_async(&rt)
            .iter(|| async { tcp::run_throughput(&mut env.lock().await.hbone, *size).await })
    });
}

//
// pub fn throughput(c: &mut Criterion) {
//     let size = 100 * MB;
//     let (env, rt) = initialize_environment();
//     let mut c = c.warm_up_time(Duration::from_secs(1)).benchmark_group("latency");
//     for size in [1usize, 100, 1000].iter() {
//         c.bench_with_input(BenchmarkId::new("direct", size), size, |b, size| {
//             b.to_async(&rt).iter(|| async { tcp::run_throughput(&mut env.loc.await.direct, *size).await })
//         });
//         c.bench_with_input(BenchmarkId::new("tcp", size), size, |b, size| {
//             b.to_async(&rt).iter(|| async { tcp::run_throughput(&mut env.loc.await.tcp, *size).await })
//         });
//         c.bench_with_input(BenchmarkId::new("hbone", size), size, |b, size| {
//             b.to_async(&rt).iter(|| async { tcp::run_throughput(&mut env.loc.await.hbone, *size as usize).await })
//         });
//     }
// }

/// throughput tests throughput of TCP
/// Warning: Criterion reports throughput in **Bytes**. Other tools like iperf3 are in **Bits**.
// pub fn throughput(c: &mut Criterion) {
//     if env::var("RUST_LOG").is_err() {
//         env::set_var("RUST_LOG", "error")
//     }
//     helpers::initialize_telemetry();
//     let mut c = c.benchmark_group("throughput");
//
//     // Each test will proxy 100MB. Note: we do this many times for multiple samples
//     let size = 100 * MB;
//     c.throughput(Throughput::Bytes(size));
//     c.sample_size(10);
//     c.warm_up_time(Duration::from_secs(1));
//     // Designed for longer running benchmarks
//     c.sampling_mode(SamplingMode::Flat);
//     // We take longer than default 5s to get appropriate results
//     c.measurement_time(Duration::from_secs(5));
//
//     // Global setup: spin up an echo server and ztunnel instance
//     let (echo_addr, test_app) = async_global_setup(|| async move {
//         let cert_manager = identity::mock::MockCaClient::new(Duration::from_secs(10));
//         let app = app::build_with_cert(test_helpers::test_config(), cert_manager)
//             .await
//             .unwrap();
//
//         let ta = TestApp {
//             admin_address: app.admin_address,
//             proxy_addresses: app.proxy_addresses,
//         };
//         let echo = echo::TestServer::new().await;
//         let echo_addr = echo.address();
//         let t = tokio::spawn(async move {
//             ta.ready().await;
//             let _t = tokio::join!(app.spawn(), echo.run());
//         });
//         ((echo_addr, ta), t)
//     });
//
//     // Direct TCP. This acts as the baseline.
//     // Ztunnel is not exercised at all here, only the test client/server and host machine.
//     c.bench_function("direct", |b| {
//         b.to_async(Runtime::new().unwrap()).iter_batched(
//             async_setup(move || async move { TcpStream::connect(echo_addr).await.unwrap() }),
//             |s| async move { tcp::run_client_throughput(s, size as usize).await },
//             BatchSize::PerIteration,
//         )
//     });
//     // Proxy over HBONE. Flow is client -> ztunnel ----TCP---> ztunnel -> server
//     c.bench_function("tcp", |b| {
//         b.to_async(Runtime::new().unwrap()).iter_batched(
//             async_setup(move || async move {
//                 let dst = helpers::with_ip(echo_addr, "127.0.0.2".parse().unwrap());
//
//                 test_app.socks5_connect(dst).await
//             }),
//             |s| async move { tcp::run_client_throughput(s, size as usize).await },
//             BatchSize::PerIteration,
//         )
//     });
//     // Proxy over HBONE. Flow is client -> ztunnel ----hbone---> ztunnel -> server
//     c.bench_function("hbone", |b| {
//         b.to_async(Runtime::new().unwrap()).iter_batched(
//             async_setup(move || async move {
//                 let dst = helpers::with_ip(echo_addr, "127.0.0.1".parse().unwrap());
//
//                 test_app.socks5_connect(dst).await
//             }),
//             |s| async move { tcp::run_client_throughput(s, size as usize).await },
//             BatchSize::PerIteration,
//         )
//     });
// }

/// async_setup allows handling async tasks in criterion 'iter' functions, which do not allow async.
pub fn async_setup<I, S, F>(setup: S) -> impl FnMut() -> I
where
    S: FnMut() -> F + Send + 'static + Clone,
    F: Future<Output = I> + Send,
    I: Send + 'static,
{
    move || {
        let mut s = setup.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let _s = Handle::current().spawn(async move {
            let sa = s();
            let input = sa.await;
            tx.send(input).unwrap();
        });

        rx.recv().unwrap()
    }
}

/// async_global_setup works around criterion not allowing async setup by spinning up a new runtime
/// to produce some output, and returning that. Essentially this bridges async to sync.
pub fn async_global_setup<I, S, F>(setup: S) -> I
where
    S: Fn() -> F + Send + 'static,
    F: Future<Output = (I, JoinHandle<()>)> + Send,
    I: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let _s = thread::spawn(|| {
        Runtime::new().unwrap().block_on(async move {
            let sa = setup();
            let (input, jh) = sa.await;
            tx.send(input).unwrap();
            jh.await.unwrap()
        });
    });

    rx.recv().unwrap()
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Protobuf))
        .warm_up_time(Duration::from_millis(1));
    targets = latency, throughput
}
criterion_main!(benches);
