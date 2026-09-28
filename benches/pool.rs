use std::hint::black_box;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BatchSize, BenchmarkId, Criterion, SamplingMode, criterion_group, criterion_main};
use futures_util::future;
use tokio::runtime::Runtime;
use ztunnel::proxy::pool::benchmarks::{ProductionPool, ProductionPoolFixture};

#[cfg(target_os = "linux")]
mod profiler;

#[cfg(target_os = "linux")]
use profiler::{Output, PProfProfiler};

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

async fn run_pool(pool: Arc<ProductionPool>, destinations: usize, callers_per_destination: usize) {
    let tasks = (0..destinations)
        .flat_map(|key| (0..callers_per_destination).map(move |_| key))
        .map(|key| {
            let pool = pool.clone();
            tokio::spawn(async move { pool.checkout(key).await })
        });
    future::join_all(tasks)
        .await
        .into_iter()
        .for_each(|result| result.unwrap());
}

async fn checkout_latencies(
    fixture: &ProductionPoolFixture,
    iterations: usize,
    callers: usize,
) -> Vec<Duration> {
    let mut latencies = Vec::with_capacity(iterations * callers);
    for _ in 0..iterations {
        let pool = Arc::new(fixture.pool());
        let tasks = (0..callers).map(|_| {
            let pool = pool.clone();
            tokio::spawn(async move {
                let start = Instant::now();
                pool.checkout(0).await;
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
    let fixture = runtime.block_on(ProductionPoolFixture::new(1));
    let pool = fixture.pool();
    runtime.block_on(pool.checkout(0));

    let mut group = c.benchmark_group("hbone_pool_available_with_idle");
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("production", |bencher| {
        bencher.to_async(&runtime).iter(|| async {
            pool.checkout(black_box(0)).await;
        });
    });
    group.finish();
}

fn same_destination_storm(c: &mut Criterion) {
    let runtime = runtime();
    let fixture = runtime.block_on(ProductionPoolFixture::new(1));
    runtime.block_on(async {
        let mut latencies = checkout_latencies(&fixture, 50, 32).await;
        println!(
            "hbone_pool_latency_probe callers=32 samples={} median_ns={} p99_ns={}",
            latencies.len(),
            percentile(&mut latencies, 50).as_nanos(),
            percentile(&mut latencies, 99).as_nanos(),
        );

        let pool = Arc::new(fixture.pool());
        run_pool(pool.clone(), 1, 100).await;
        assert_eq!(pool.factory_calls(), 1);
        println!(
            "hbone_pool_single_flight_probe callers=100 factory_calls={} \
             destination_wakeups={} unrelated_wakeups={}",
            pool.factory_calls(),
            pool.wakeups(),
            pool.unrelated_wakeups(),
        );
    });

    let mut group = c.benchmark_group("hbone_pool_same_destination_spawned");
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
                    || Arc::new(fixture.pool()),
                    |pool| async move {
                        run_pool(pool.clone(), 1, callers).await;
                        black_box(pool.factory_calls());
                        black_box(pool.wakeups());
                        pool
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn many_destinations(c: &mut Criterion) {
    let runtime = runtime();
    let fixture = runtime.block_on(ProductionPoolFixture::new(1_000));
    runtime.block_on(async {
        let pool = Arc::new(fixture.pool());
        run_pool(pool.clone(), 100, 2).await;
        println!(
            "hbone_pool_wakeup_probe destinations=100 callers_per_destination=2 \
             factory_calls={} destination_wakeups={} unrelated_wakeups={}",
            pool.factory_calls(),
            pool.wakeups(),
            pool.unrelated_wakeups(),
        );
    });

    let mut group = c.benchmark_group("hbone_pool_many_destinations_spawned");
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(2));
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);
    for destinations in [100usize, 1_000] {
        group.bench_with_input(
            BenchmarkId::new("production", destinations),
            &destinations,
            |bencher, &destinations| {
                bencher.to_async(&runtime).iter_batched(
                    || Arc::new(fixture.pool()),
                    |pool| async move {
                        run_pool(pool.clone(), destinations, 2).await;
                        black_box(pool.factory_calls());
                        black_box(pool.wakeups());
                        pool
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

fn repeated_idle_checkin(c: &mut Criterion) {
    let runtime = runtime();
    let fixture = runtime.block_on(ProductionPoolFixture::new(1));
    let pool = fixture.pool();
    runtime.block_on(pool.checkout(0));

    let mut group = c.benchmark_group("hbone_pool_idle");
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("generation_reset", |bencher| {
        bencher
            .to_async(&runtime)
            .iter(|| async { pool.checkout(black_box(0)).await });
    });
    group.finish();
}

fn saturated_capacity_recovery(c: &mut Criterion) {
    let runtime = runtime();
    let fixture = runtime.block_on(ProductionPoolFixture::with_max_streams(1, 2));
    let mut group = c.benchmark_group("hbone_pool_saturated_capacity");
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("stream_drop_recovery", |bencher| {
        bencher.to_async(&runtime).iter_batched(
            || Arc::new(fixture.pool()),
            |pool| async move {
                let first = pool.open_stream(0).await;
                let second = pool.open_stream(0).await;
                let factory_calls = pool.factory_calls();
                drop(second);
                pool.checkout(0).await;
                assert_eq!(pool.factory_calls(), factory_calls);
                black_box(first);
                pool
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets =
        available_connection,
        same_destination_storm,
        many_destinations,
        repeated_idle_checkin,
        saturated_capacity_recovery
}
criterion_main!(benches);
