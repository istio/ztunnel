// #[tokio::test]
// async fn test_direct() {
//     helpers::initialize_telemetry();
//     let echo = echo::TestServer::new().await;
//     let echo_addr = echo.address();
//     tokio::spawn(echo.run());
//     let s = TcpStream::connect(echo_addr).await.unwrap();
//     s.set_nodelay(true).unwrap();
//     tcp::run(s, 10 * GB).await.unwrap();
// }

use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main, Throughput};
use futures_util::SinkExt;
use pprof::criterion::{Output, PProfProfiler};
use tokio::runtime::Runtime;

use ztunnel::test_helpers::echo;

const KB: u64 = 1024;
const MB: u64 = 1024 * KB;
const GB: u64 = 1024 * MB;

async fn do_test(addr: SocketAddr) {
    tokio::time::sleep(Duration::from_millis(10)).await;
}

pub fn tcp_direct(c: &mut Criterion) {
    let mut c = c.benchmark_group("tcp");
    c.throughput(Throughput::Bytes(10 * MB));
    let (mut tx, rx) = std::sync::mpsc::channel();
    thread::spawn(|| {
        println!("in thread");
        let server_rt = Runtime::new().unwrap().block_on(async move {
            println!("in rt");
            let echo = echo::TestServer::new().await;
            println!("in echo");
            let echo_addr = echo.address();
            let t=tokio::spawn(echo.run());
            println!("in running");
            tx.send(echo_addr).unwrap();
            tx.send(echo_addr).unwrap();
            tx.send(echo_addr).unwrap();
            println!("sent");
            t.await.unwrap();
            println!("comlpete");

        });
    });

    let a = rx.recv().unwrap();
    c.bench_function(BenchmarkId::new("tcp_direct", ""), |b| {
        b.to_async(Runtime::new().unwrap()).iter_batched(
            || {
                a
            },
            do_test,
            BatchSize::PerIteration,
        )
    });
    // let rt = Runtime::new().unwrap();
    // rt.spawn()
    // let size = 10*MB;
    // c.bench_with_input(
    //     BenchmarkId::new("tcp_direct", size),
    //     &size,
    //     |b, &s| {
    //         b.to_async(rt).iter(|| do_test(s));
    //     }
    // );
    // c.bench_function("direct", |b| b.iter(|| {}));
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = tcp_direct
}
criterion_main!(benches);
