use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BufMut;
use criterion::{
    BatchSize, BenchmarkId, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use futures_util::future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use ztunnel::state::workload::{InboundProtocol, Workload};
use ztunnel::test_helpers::app::{DestinationAddr, TestApp};
use ztunnel::test_helpers::tcp::Mode;
use ztunnel::test_helpers::{helpers, tcp};
use ztunnel::xds::LocalWorkload;
use ztunnel::{app, identity, test_helpers};

#[cfg(target_os = "linux")]
mod profiler;

#[cfg(target_os = "linux")]
use profiler::{Output, PProfProfiler};

const SOURCE_IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const DESTINATION_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 1, 2));
const STREAM_BYTES: usize = 1024 * 1024;

fn criterion_config() -> Criterion {
    let criterion = Criterion::default();
    #[cfg(target_os = "linux")]
    {
        criterion.with_profiler(PProfProfiler::new(100, Output::Protobuf))
    }
    #[cfg(not(target_os = "linux"))]
    {
        criterion
    }
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

struct ProductionPoolFixture {
    app: Arc<TestApp>,
    destination: DestinationAddr,
}

impl ProductionPoolFixture {
    async fn new() -> Self {
        helpers::initialize_telemetry();
        #[cfg(target_os = "linux")]
        helpers::run_command("ip link set dev lo up").unwrap();
        let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(3600));
        let echo = tcp::TestServer::new(Mode::ReadWrite, 0).await;
        let echo_addr = echo.address();
        let config = test_helpers::test_config_with_port_xds_addr_and_root_cert(
            80,
            None,
            None,
            Some(pool_config()),
        );
        let bound = app::build_with_cert(Arc::new(config), cert_manager.clone())
            .await
            .unwrap();
        let app = Arc::new(TestApp::from((&bound, cert_manager)));
        app.ready().await;
        tokio::spawn(async move {
            let _ = tokio::join!(bound.wait_termination(), echo.run());
        });
        Self {
            app,
            destination: DestinationAddr::Ip(helpers::with_ip(echo_addr, DESTINATION_IP)),
        }
    }

    async fn checkout(&self) {
        let mut stream = self
            .app
            .socks5_connect(self.destination.clone(), SOURCE_IP)
            .await;
        stream.write_u8(42).await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 42);
    }

    async fn stream(&self) -> TcpStream {
        self.app
            .socks5_connect(self.destination.clone(), SOURCE_IP)
            .await
    }
}

fn pool_config() -> ztunnel::config::ConfigSource {
    let workloads = vec![
        LocalWorkload {
            workload: Workload {
                workload_ips: vec![],
                protocol: InboundProtocol::HBONE,
                uid: "cluster1//v1/Pod/default/local-source".into(),
                name: "local-source".into(),
                namespace: "default".into(),
                service_account: "default".into(),
                ..test_helpers::test_default_workload()
            },
            services: Default::default(),
        },
        LocalWorkload {
            workload: Workload {
                workload_ips: vec![DESTINATION_IP],
                protocol: InboundProtocol::HBONE,
                uid: "cluster1//v1/Pod/default/pool-benchmark-destination".into(),
                name: "pool-benchmark-destination".into(),
                namespace: "default".into(),
                service_account: "default".into(),
                ..test_helpers::test_default_workload()
            },
            services: Default::default(),
        },
    ];
    let config = ztunnel::xds::LocalConfig {
        workloads,
        policies: vec![],
        services: vec![],
    };
    let mut bytes = bytes::BytesMut::new().writer();
    serde_yaml::to_writer(&mut bytes, &config).unwrap();
    ztunnel::config::ConfigSource::Static(bytes.into_inner().freeze())
}

async fn run_pool(fixture: Arc<ProductionPoolFixture>, callers: usize) {
    let tasks = (0..callers).map(|_| {
        let fixture = fixture.clone();
        tokio::spawn(async move { fixture.checkout().await })
    });
    future::join_all(tasks)
        .await
        .into_iter()
        .for_each(|result| result.unwrap());
}

async fn checkout_latencies(
    fixture: Arc<ProductionPoolFixture>,
    iterations: usize,
    callers: usize,
) -> Vec<Duration> {
    let mut latencies = Vec::with_capacity(iterations * callers);
    for _ in 0..iterations {
        let tasks = (0..callers).map(|_| {
            let fixture = fixture.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                fixture.checkout().await;
                start.elapsed()
            })
        });
        latencies.extend(
            future::join_all(tasks)
                .await
                .into_iter()
                .map(Result::unwrap),
        );
    }
    latencies
}

fn percentile(latencies: &mut [Duration], percentile: usize) -> Duration {
    latencies.sort_unstable();
    latencies[(latencies.len() - 1) * percentile / 100]
}

fn available_connection(c: &mut Criterion) {
    let runtime = runtime();
    let fixture = Arc::new(runtime.block_on(ProductionPoolFixture::new()));
    runtime.block_on(fixture.checkout());
    let mut group = c.benchmark_group("hbone_pool_compare_available");
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("production", |bencher| {
        bencher.to_async(&runtime).iter(|| async {
            fixture.checkout().await;
        });
    });
    group.finish();
}

fn same_destination_storm(c: &mut Criterion) {
    let runtime = runtime();
    let fixture = Arc::new(runtime.block_on(ProductionPoolFixture::new()));
    runtime.block_on(async {
        let mut latencies = checkout_latencies(fixture.clone(), 20, 32).await;
        println!(
            "hbone_pool_compare_latency callers=32 samples={} median_ns={} p99_ns={}",
            latencies.len(),
            percentile(&mut latencies, 50).as_nanos(),
            percentile(&mut latencies, 99).as_nanos(),
        );
    });
    let mut group = c.benchmark_group("hbone_pool_compare_same_destination");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);
    for callers in [1usize, 8, 32, 128, 512] {
        group.bench_with_input(
            BenchmarkId::new("production", callers),
            &callers,
            |bencher, &callers| {
                bencher.to_async(&runtime).iter_batched(
                    || fixture.clone(),
                    |fixture| async move {
                        run_pool(fixture, callers).await;
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn single_flow_throughput(c: &mut Criterion) {
    let runtime = runtime();
    let fixture = runtime.block_on(ProductionPoolFixture::new());
    let stream = runtime.block_on(fixture.stream());
    let (reader, writer) = tokio::io::split(stream);
    let payload = vec![42; STREAM_BYTES];
    let echoed = vec![0; STREAM_BYTES];
    let stream = Arc::new(tokio::sync::Mutex::new((reader, writer, payload, echoed)));
    let mut group = c.benchmark_group("hbone_pool_compare_single_flow");
    group.throughput(Throughput::Bytes(STREAM_BYTES as u64));
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("production", |bencher| {
        bencher.to_async(&runtime).iter(|| {
            let stream = stream.clone();
            async move {
                let mut stream = stream.lock().await;
                let (reader, writer, payload, echoed) = &mut *stream;
                let (write, read) = tokio::join!(
                    writer.write_all(black_box(payload.as_slice())),
                    reader.read_exact(echoed),
                );
                write.unwrap();
                read.unwrap();
                black_box(echoed);
            }
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = available_connection, same_destination_storm, single_flow_throughput
}
criterion_main!(benches);
