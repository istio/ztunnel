use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use futures_util::SinkExt;
use pprof::criterion::{Output, PProfProfiler};
use tokio::net::TcpStream;
use tokio::runtime::{Handle, Runtime};
use tokio::task::JoinHandle;

use ztunnel::test_helpers::app::TestApp;
use ztunnel::test_helpers::{echo, helpers, tcp};
use ztunnel::{app, config, identity};

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

async fn do_test(stream: TcpStream, size: usize) {
    tokio::time::sleep(Duration::from_millis(100)).await;
}

pub fn tcp_direct(c: &mut Criterion) {
    helpers::initialize_telemetry();
    let mut c = c.benchmark_group("tcp");
    let size = 100 * MB;
    c.throughput(Throughput::Bytes(size));
    let (echo_addr, test_app) = async_global_setup(|| async move {
        let cert_manager = identity::mock::MockCaClient::new(Duration::from_secs(10));
        let app = app::build_with_cert(test_config(), cert_manager).await.unwrap();
        let shutdown = app.shutdown.trigger().clone();

        let ta = TestApp {
            admin_address: app.admin_address,
            proxy_addresses: app.proxy_addresses,
        };
        let echo = echo::TestServer::new().await;
        let echo_addr = echo.address();
        let t = tokio::spawn(async move {
            ta.ready().await;
            let t = tokio::join!(app.spawn(), echo.run());
                ()
        });
        ((echo_addr, ta), t)
    });
    c.bench_function("direct", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            async_setup(
                move || async move { TcpStream::connect(echo_addr.clone()).await.unwrap() },
            ),
            |s| async move { tcp::run(s, size as usize).await },
            BatchSize::PerIteration,
        )
    });
    c.bench_function("socks5", |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            async_setup(move || async move {
                let dst = helpers::with_ip(echo_addr, "127.0.0.1".parse().unwrap());
                let mut stream = test_app.socks5_connect(dst).await;

                stream
            }),
            |s| async move { tcp::run(s, size as usize).await },
            BatchSize::PerIteration,
        )
    });
}

fn test_config() -> config::Config {
    config::Config {
        xds_address: None,
        local_xds_path: Some("examples/localhost.yaml".to_string()),
        socks5_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        inbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        admin_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        outbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        ..Default::default()
    }
}

/// async_setup allows handling async tasks in criterion 'iter' functions, which do not allow async
pub fn async_setup<I, S, F>(mut setup: S) -> impl FnMut() -> I
where
    S: FnMut() -> F + Send + 'static + Clone,
    F: Future<Output = I> + Send,
    I: Send + 'static,
{
    move || {
        let mut s = setup.clone();
        let (mut tx, rx) = std::sync::mpsc::channel();
        let s = Handle::current().spawn(async move {
            let sa = s();
            let input = sa.await;
            tx.send(input).unwrap();
        });
        let v = rx.recv().unwrap();
        v
    }
}

pub fn async_global_setup<I, S, F>(mut setup: S) -> I
where
    S: Fn() -> F + Send + 'static,
    F: Future<Output = (I, JoinHandle<()>)> + Send,
    I: Send + 'static,
{
    let (mut tx, rx) = std::sync::mpsc::channel();
    let s = thread::spawn(|| {
        Runtime::new().unwrap().block_on(async move {
            let sa = setup();
            let (input, jh) = sa.await;
            tx.send(input).unwrap();
            jh.await.unwrap()
        });
    });
    let v = rx.recv().unwrap();
    v
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = tcp_direct
}
criterion_main!(benches);
