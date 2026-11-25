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

//! Benchmarks for the traffic metric families.
//!
//! Unlike `throughput.rs`, this file does not set up network namespaces, so it
//! runs anywhere `cargo bench` runs.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group};
use prometheus_client::registry::Registry;
use ztunnel::test_helpers::test_default_workload;
use ztunnel::{metrics, proxy};

/// Label set number `i`. Only the source workload name differs, which is
/// enough to make every label set distinct.
fn labels(i: usize) -> proxy::CommonTrafficLabels {
    let mut w = test_default_workload();
    w.workload_name = format!("workload-{i}").into();
    proxy::CommonTrafficLabels::from(proxy::ConnectionOpen {
        reporter: Default::default(),
        source: Some(Arc::new(w)),
        derived_source: None,
        destination: None,
        destination_service: None,
        connection_security_policy: Default::default(),
    })
}

fn new_metrics() -> (Registry, Arc<proxy::Metrics>) {
    let mut registry = Registry::default();
    let metrics = Arc::new(proxy::Metrics::new(metrics::sub_registry(&mut registry)));
    (registry, metrics)
}

/// About the number of label sets per family seen on busy production nodes.
const ENTRIES: usize = 6_000;

pub fn metrics(c: &mut Criterion) {
    let mut g = c.benchmark_group("metrics");

    // A get_or_create that finds an existing label set, then inc().
    // This is what connection open and close do.
    {
        let (_registry, m) = new_metrics();
        let tl = labels(0);
        m.connection_opens.get_or_create(&tl).inc();
        g.bench_function("write_hit", |b| {
            b.iter(|| m.connection_opens.get_or_create(black_box(&tl)).inc())
        });
    }

    // The byte hot path: increment_send on a connection's held counter.
    // Called on every successful write in copy.rs.
    {
        let (_registry, m) = new_metrics();
        let conn = proxy::ConnectionResultBuilder::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2),
            None,
            Instant::now(),
            proxy::ConnectionOpen {
                reporter: Default::default(),
                source: Some(Arc::new(test_default_workload())),
                derived_source: None,
                destination: None,
                destination_service: None,
                connection_security_policy: Default::default(),
            },
            m.clone(),
        )
        .build();
        g.bench_function("bytes_increment", |b| {
            b.iter(|| conn.increment_send(black_box(1500)))
        });
    }

    // Encoding the whole registry with one family of ENTRIES label sets.
    {
        let (registry, m) = new_metrics();
        for i in 0..ENTRIES {
            m.connection_opens.get_or_create(&labels(i)).inc();
        }
        g.bench_function("encode_6k", |b| {
            b.iter(|| {
                let mut buf = String::new();
                prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
                black_box(buf.len())
            })
        });
    }

    // One expiry sweep over 10k label sets, half of them idle. try_sweep
    // holds the family write lock for the scan, and then drops the 5k removed
    // entries after releasing it. This measures both, so it is an upper bound
    // on how long data-plane get_or_create calls on that family can wait.
    {
        let (_registry, m) = new_metrics();
        let all: Vec<_> = (0..10_000).map(labels).collect();
        let setup = || {
            for tl in &all {
                m.connection_opens.get_or_create(tl).inc();
            }
            // Clear every flag (all are set, nothing is removed), then write
            // to every other label set.
            m.connection_opens.try_sweep().unwrap();
            for tl in all.iter().step_by(2) {
                m.connection_opens.get_or_create(tl).inc();
            }
        };
        setup();
        assert_eq!(
            m.connection_opens.try_sweep().map(|s| s.removed),
            Some(5_000)
        );
        g.bench_function("sweep_10k_half_idle", |b| {
            b.iter_batched(
                setup,
                // Removes the 5k idle ones and clears the flag on the rest.
                |()| black_box(m.connection_opens.try_sweep().unwrap()),
                criterion::BatchSize::PerIteration,
            )
        });
    }

    g.finish();
}

/// Latency of data-plane get_or_create while another thread encodes the same
/// family in a loop, as a scrape does. Criterion reports means only, and this
/// needs percentiles, so it is measured by hand.
///
/// - miss: a new label set (or one that came back after expiry). It takes the
///   write lock, so it waits for the encode of the family to finish.
/// - hit: an existing label set, looked up on a third thread while misses
///   happen. A waiting writer blocks new readers, so hits wait too.
fn contention_report() {
    const ROUNDS: usize = 5;
    const MISSES: usize = 400;
    let mut miss = Vec::new();
    let mut hit = Vec::new();
    let mut idle_miss = Vec::new();
    for round in 0..ROUNDS {
        let (registry, m) = new_metrics();
        for i in 0..ENTRIES {
            m.connection_opens.get_or_create(&labels(i)).inc();
        }
        // Baseline: misses with nobody encoding.
        for i in 0..MISSES {
            let tl = labels(1_000_000 + round * MISSES + i);
            let t = Instant::now();
            m.connection_opens.get_or_create(&tl).inc();
            idle_miss.push(t.elapsed());
        }
        let registry = Arc::new(registry);
        let stop = Arc::new(AtomicBool::new(false));
        let scraper = {
            let (registry, stop) = (registry.clone(), stop.clone());
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let mut buf = String::new();
                    prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
                    black_box(buf.len());
                }
            })
        };
        let hitter = {
            let (m, stop) = (m.clone(), stop.clone());
            thread::spawn(move || {
                let tl = labels(0);
                let mut v = Vec::new();
                while !stop.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    m.connection_opens.get_or_create(&tl).inc();
                    v.push(t.elapsed());
                    thread::sleep(Duration::from_micros(200));
                }
                v
            })
        };
        for i in 0..MISSES {
            let tl = labels(2_000_000 + round * MISSES + i);
            let t = Instant::now();
            m.connection_opens.get_or_create(&tl).inc();
            miss.push(t.elapsed());
            thread::sleep(Duration::from_micros(500));
        }
        stop.store(true, Ordering::Relaxed);
        scraper.join().unwrap();
        hit.extend(hitter.join().unwrap());
    }
    let encode = {
        let (registry, m) = new_metrics();
        for i in 0..ENTRIES {
            m.connection_opens.get_or_create(&labels(i)).inc();
        }
        let t = Instant::now();
        for _ in 0..20 {
            let mut buf = String::new();
            prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
            black_box(buf.len());
        }
        t.elapsed() / 20
    };
    println!(
        "\ncontention report ({ENTRIES} label sets, one family; encode of the registry takes {encode:?})"
    );
    for (name, v) in [
        ("miss, no encode running", &mut idle_miss),
        ("miss, encode running", &mut miss),
        ("hit on another thread, encode and misses running", &mut hit),
    ] {
        v.sort();
        let p = |q: f64| v[((v.len() - 1) as f64 * q) as usize];
        println!(
            "  {name:<50} n={:<6} p50={:>10.1?} p90={:>10.1?} p99={:>10.1?} max={:>10.1?}",
            v.len(),
            p(0.50),
            p(0.90),
            p(0.99),
            v[v.len() - 1]
        );
    }
}

criterion_group!(benches, metrics);

fn main() {
    benches();
    Criterion::default().configure_from_args().final_summary();
    // Only under `cargo bench`, not in the quick run that `cargo test --benches` does.
    if std::env::args().any(|a| a == "--bench") {
        contention_report();
    }
}
