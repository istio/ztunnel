use std::future::Future;
use std::time::Duration;
use std::{env, thread};

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use pprof::criterion::{Output, PProfProfiler};
use tokio::net::TcpStream;
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;

use ztunnel::test_helpers::app::TestApp;
use ztunnel::test_helpers::{echo, helpers, tcp};
use ztunnel::{app, identity, test_helpers};

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;

/// tcp tests throughput of TCP
pub fn tcp(c: &mut Criterion) {
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "error")
    }
    helpers::initialize_telemetry();
    let mut c = c.benchmark_group("tcp");

    // Each test will proxy 100MB. Note: we do this many times for multiple samples
    let size = 100 * MB;
    c.throughput(Throughput::Bytes(size));
    c.sample_size(10);
    // We take longer than default 5s to get appropriate results
    c.measurement_time(Duration::from_secs(30));

    // Global setup: spin up an echo server and ztunnel instance
    let (echo_addr, test_app) = async_global_setup(|| async move {
        let cert_manager = identity::mock::MockCaClient::new(Duration::from_secs(10));
        let app = app::build_with_cert(test_helpers::test_config(), cert_manager)
            .await
            .unwrap();

        let ta = TestApp {
            admin_address: app.admin_address,
            proxy_addresses: app.proxy_addresses,
        };
        let echo = echo::TestServer::new().await;
        let echo_addr = echo.address();
        let t = tokio::spawn(async move {
            ta.ready().await;
            let _t = tokio::join!(app.spawn(), echo.run());
        });
        ((echo_addr, ta), t)
    });

    // Direct TCP. This acts as the baseline.
    // Ztunnel is not exercised at all here, only the test client/server and host machine.
    c.bench_function("direct", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            async_setup(move || async move { TcpStream::connect(echo_addr).await.unwrap() }),
            |s| async move { tcp::run(s, size as usize).await },
            BatchSize::PerIteration,
        )
    });
    // Proxy over HBONE. Flow is client -> ztunnel ----hbone---> ztunnel -> server
    c.bench_function("hbone", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            async_setup(move || async move {
                let dst = helpers::with_ip(echo_addr, "127.0.0.1".parse().unwrap());

                test_app.socks5_connect(dst).await
            }),
            |s| async move { tcp::run(s, size as usize).await },
            BatchSize::PerIteration,
        )
    });
    // Proxy over HBONE. Flow is client -> ztunnel ----TCP---> ztunnel -> server
    c.bench_function("tcp", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            async_setup(move || async move {
                let dst = helpers::with_ip(echo_addr, "127.0.0.2".parse().unwrap());

                test_app.socks5_connect(dst).await
            }),
            |s| async move { tcp::run(s, size as usize).await },
            BatchSize::PerIteration,
        )
    });
}

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
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = tcp
}
criterion_main!(benches);
