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

//! A counter family that ztunnel owns, so that it can remove idle label sets.
//!
//! `prometheus_client::metrics::family::Family` cannot be iterated or filtered,
//! and its maintainer suggested forking it for this use
//! (<https://github.com/prometheus/client_rust/issues/197>).
//! The encode loop below is adapted from prometheus-client 0.25.0
//! `src/metrics/family.rs` (Apache-2.0 OR MIT).
//!
//! Idle label sets are found the way Envoy finds unused stats (mark and
//! sweep): every write sets a `used` flag, and [`ExpiringFamily::try_sweep`]
//! removes the label sets whose flag was not set since the previous sweep, and
//! clears it on the others. So a label set goes between one and two sweeps
//! after its last write.
//!
//! A counter that is still held outside the family is never removed. Open
//! connections keep a clone of their opened and bytes counters for their
//! whole life, so those series stay while the connection is open and its
//! bytes are never lost.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::RwLock;
use prometheus_client::encoding::{EncodeLabelSet, EncodeMetric, MetricEncoder, NoLabelSet};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::{MetricType, TypedMetric};
use prometheus_client::registry::Registry;
use tracing::debug;

#[derive(Debug, Default)]
struct CounterInner {
    value: AtomicU64,
    /// Set by every write, cleared by a sweep.
    used: AtomicBool,
}

/// A counter that records whether it was written to since the last sweep.
/// Clones share the same value and flag.
#[derive(Debug, Clone, Default)]
pub struct ExpiringCounter(Arc<CounterInner>);

impl ExpiringCounter {
    /// Increase the counter by 1, returning the previous value.
    #[inline]
    pub fn inc(&self) -> u64 {
        self.inc_by(1)
    }

    /// Increase the counter by `v`, returning the previous value.
    #[inline]
    pub fn inc_by(&self, v: u64) -> u64 {
        let prev = self.0.value.fetch_add(v, Ordering::Relaxed);
        // Relaxed is enough. A sweep only reads the flag after Arc::get_mut
        // has shown it holds the only reference, and that check synchronises
        // with the Release decrement made when every other clone was dropped.
        // So every write made through a clone is visible to the sweep.
        self.0.used.store(true, Ordering::Relaxed);
        prev
    }

    /// The current value.
    #[inline]
    pub fn get(&self) -> u64 {
        self.0.value.load(Ordering::Relaxed)
    }
}

impl TypedMetric for ExpiringCounter {
    const TYPE: MetricType = MetricType::Counter;
}

impl EncodeMetric for ExpiringCounter {
    fn encode(&self, mut encoder: MetricEncoder) -> Result<(), std::fmt::Error> {
        // The same call the library Counter makes.
        encoder.encode_counter::<NoLabelSet, _, u64>(&self.get(), None)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }
}

/// A family of counters keyed by label set, like the library `Family`.
#[derive(Debug)]
pub struct ExpiringFamily<S> {
    metrics: Arc<RwLock<HashMap<S, ExpiringCounter>>>,
}

impl<S> Clone for ExpiringFamily<S> {
    fn clone(&self) -> Self {
        Self {
            metrics: self.metrics.clone(),
        }
    }
}

impl<S> Default for ExpiringFamily<S> {
    fn default() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl<S: Clone + Hash + Eq> ExpiringFamily<S> {
    /// Returns the counter for `labels`, creating it at 0 if needed.
    ///
    /// Unlike the library `Family`, this returns an owned handle (an `Arc`
    /// clone) rather than a lock guard, so the lock is released before it
    /// returns.
    pub fn get_or_create(&self, labels: &S) -> ExpiringCounter {
        if let Some(c) = self.metrics.read().get(labels) {
            return c.clone();
        }
        let mut w = self.metrics.write();
        w.entry(labels.clone()).or_default().clone()
    }

    pub fn len(&self) -> usize {
        self.metrics.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.metrics.read().is_empty()
    }

    /// Runs one sweep: removes every label set that was not written to since
    /// the previous sweep and that nothing outside the family holds, and
    /// clears the flag on the others.
    ///
    /// Returns how many label sets were removed and how many are left, or
    /// `None` if the lock was busy. It never waits for the lock: a waiting
    /// writer would block every new reader of this family, which means every
    /// data-plane `get_or_create`, until the lock is free.
    pub fn try_sweep(&self) -> Option<Swept> {
        let (removed, left) = self.try_sweep_entries()?;
        Some(Swept {
            removed: removed.len(),
            left,
        })
        // `removed` is dropped here, after the lock is released, so the
        // label sets' destructors do not run under it.
    }

    fn try_sweep_entries(&self) -> Option<(Vec<(S, ExpiringCounter)>, usize)> {
        let mut w = self.metrics.try_write()?;
        let removed: Vec<(S, ExpiringCounter)> = w
            .extract_if(|_, c| match Arc::get_mut(&mut c.0) {
                // Held outside the family (an open connection, or a caller
                // between get_or_create and inc). Keep it, and leave the flag
                // as it is: it is judged after the last clone is dropped.
                None => false,
                // The family holds the only reference, so nobody can write to
                // it without calling get_or_create, which our write lock
                // blocks. Remove it if it was not written to since the last
                // sweep.
                Some(inner) => !std::mem::replace(inner.used.get_mut(), false),
            })
            .collect();
        // Counted under the lock, so the caller never has to take it again.
        let left = w.len();
        Some((removed, left))
    }
}

/// The result of one sweep of one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Swept {
    /// Label sets removed by this sweep.
    pub removed: usize,
    /// Label sets left after it.
    pub left: usize,
}

/// A family that can be swept. Lets the expiry task hold families with
/// different label types in one list.
pub trait Sweep: Send + Sync {
    fn try_sweep(&self) -> Option<Swept>;
}

impl<S: Clone + Hash + Eq + Send + Sync> Sweep for ExpiringFamily<S> {
    fn try_sweep(&self) -> Option<Swept> {
        ExpiringFamily::try_sweep(self)
    }
}

impl<S> TypedMetric for ExpiringFamily<S> {
    const TYPE: MetricType = MetricType::Counter;
}

impl<S: Clone + Hash + Eq + EncodeLabelSet + std::fmt::Debug> EncodeMetric for ExpiringFamily<S> {
    fn encode(&self, mut encoder: MetricEncoder) -> Result<(), std::fmt::Error> {
        let guard = self.metrics.read();
        for (labels, m) in guard.iter() {
            let encoder = encoder.encode_family(labels)?;
            m.encode(encoder)?;
        }
        Ok(())
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
    }

    /// The registry leaves out families that are empty, header lines
    /// included. The library `Family` does the same.
    fn is_empty(&self) -> bool {
        ExpiringFamily::is_empty(self)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ExpiryLabels {
    metric: &'static str,
}

/// Metrics about expiry itself. Registered only when expiry is on, so that
/// the output does not change when it is off.
#[derive(Debug)]
struct ExpiryMetrics {
    removed: Family<ExpiryLabels, Counter>,
    series: Family<ExpiryLabels, Gauge>,
    skipped: Family<ExpiryLabels, Counter>,
}

impl ExpiryMetrics {
    fn new(registry: &mut Registry) -> Self {
        let m = Self {
            removed: Family::default(),
            series: Family::default(),
            skipped: Family::default(),
        };
        registry.register(
            "metrics_expired_series",
            "The total number of idle label sets removed from a metric (unstable)",
            m.removed.clone(),
        );
        registry.register(
            "metrics_series",
            "The current number of label sets of a metric that can expire (unstable)",
            m.series.clone(),
        );
        registry.register(
            "metrics_expiry_skipped_sweeps",
            "The total number of expiry sweeps skipped because the metric was busy (unstable)",
            m.skipped.clone(),
        );
        m
    }
}

/// The smallest interval [`Expiry`] runs at, whatever it is given. Tests use
/// short intervals; production config has a 5-minute floor.
pub const MIN_INTERVAL: Duration = Duration::from_millis(100);

/// Removes idle label sets from `families` every `interval`.
pub struct Expiry {
    interval: Duration,
    families: Vec<(&'static str, Box<dyn Sweep>)>,
    metrics: ExpiryMetrics,
}

impl Expiry {
    /// `registry` gets the expiry self-metrics. `families` pairs each family
    /// with the name it is registered under. `interval` is raised to at least
    /// [`MIN_INTERVAL`]: start-up config already rejects values under 5
    /// minutes, but a `Config` built in code is not validated, and a tiny
    /// interval would turn the sweep into a busy loop on the main runtime.
    pub fn new(
        interval: Duration,
        registry: &mut Registry,
        families: Vec<(&'static str, Box<dyn Sweep>)>,
    ) -> Self {
        Self {
            interval: interval.max(MIN_INTERVAL),
            families,
            metrics: ExpiryMetrics::new(registry),
        }
    }

    /// Sweeps every family once per interval, forever. A label set goes about
    /// one to two intervals after its last write, or up to three if a sweep of
    /// its family is skipped. "About": a family's sweep can start up to half a
    /// second late when the lock is busy, so the lower bound is approximate.
    pub async fn run(self) {
        let mut tick = tokio::time::interval(self.interval);
        // After a stall longer than the interval (for example SIGSTOP), sweep
        // once, then wait a full interval before the next sweep. Skip would
        // put the next tick back on the old schedule, possibly milliseconds
        // later, and that second sweep would remove label sets written during
        // the stall almost at once.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick completes at once. Do not sweep at start-up.
        tick.tick().await;
        loop {
            tick.tick().await;
            self.sweep_all().await;
        }
    }

    async fn sweep_all(&self) {
        for (name, family) in &self.families {
            let labels = ExpiryLabels { metric: name };
            match sweep_with_retry(family.as_ref()).await {
                Some(Swept { removed, left }) => {
                    self.metrics
                        .removed
                        .get_or_create(&labels)
                        .inc_by(removed as u64);
                    self.metrics.series.get_or_create(&labels).set(left as i64);
                    debug!(
                        metric = name,
                        removed, left, "removed idle metric label sets"
                    );
                }
                None => {
                    self.metrics.skipped.get_or_create(&labels).inc();
                    debug!(metric = name, "metric expiry sweep skipped, metric busy");
                }
            }
            // Let other tasks on this runtime (a scrape) run between families.
            tokio::task::yield_now().await;
        }
    }
}

/// The sweep, or `None` if the lock was busy on every try. `try_write` only
/// succeeds when no thread holds the lock at all. A data-plane `get_or_create`
/// holds it for well under a microsecond, so at normal connection rates a
/// retry almost always succeeds. Under a constant flood of lookups on one
/// family it can fail every time; that family is then skipped and the skip is
/// counted.
async fn sweep_with_retry(family: &dyn Sweep) -> Option<Swept> {
    const TRIES: usize = 10;
    for attempt in 1..=TRIES {
        if let Some(swept) = family.try_sweep() {
            return Some(swept);
        }
        if attempt < TRIES {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::encoding::EncodeLabelSet;
    use prometheus_client::registry::Registry;
    use std::sync::OnceLock;
    use std::time::Duration;

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    struct L {
        name: String,
    }

    fn l(name: &str) -> L {
        L { name: name.into() }
    }

    /// One sweep, returning only how many label sets it removed.
    fn sweep<S: Clone + Hash + Eq>(f: &ExpiringFamily<S>) -> Option<usize> {
        f.try_sweep().map(|s| s.removed)
    }

    fn encode(f: &ExpiringFamily<L>) -> String {
        let mut r = Registry::default();
        r.register("test", "help (unstable)", f.clone());
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &r).unwrap();
        out
    }

    #[test]
    fn removed_at_the_second_sweep_after_last_write() {
        let f = ExpiringFamily::default();
        f.get_or_create(&l("a")).inc();
        assert_eq!(sweep(&f), Some(0), "written since last sweep: kept");
        assert_eq!(f.len(), 1);
        assert_eq!(sweep(&f), Some(1), "idle for a full sweep: removed");
        assert!(f.is_empty());
    }

    #[test]
    fn kept_while_written_between_sweeps() {
        let f = ExpiringFamily::default();
        for _ in 0..5 {
            f.get_or_create(&l("a")).inc();
            assert_eq!(sweep(&f), Some(0));
        }
        assert_eq!(f.get_or_create(&l("a")).get(), 5);
    }

    #[test]
    fn removed_series_leave_the_output() {
        let f = ExpiringFamily::default();
        f.get_or_create(&l("a")).inc_by(7);
        f.get_or_create(&l("b")).inc();
        assert!(encode(&f).contains("test_total{name=\"a\"} 7"));
        sweep(&f);
        f.get_or_create(&l("b")).inc();
        sweep(&f);
        let out = encode(&f);
        assert!(!out.contains("name=\"a\""), "{out}");
        assert!(out.contains("test_total{name=\"b\"} 2"), "{out}");
    }

    #[test]
    fn held_counter_is_never_removed() {
        let f = ExpiringFamily::default();
        let held = f.get_or_create(&l("a"));
        for _ in 0..3 {
            assert_eq!(sweep(&f), Some(0));
        }
        assert_eq!(f.len(), 1);
        drop(held);
    }

    // A sweep leaves the flag alone while a clone is held, so a write
    // made while held still counts after release: the first sweep after
    // release keeps the series, so its last value gets a full interval to be
    // scraped, and the second removes it.
    #[test]
    fn held_counter_is_removed_after_release() {
        let f = ExpiringFamily::default();
        let held = f.get_or_create(&l("a"));
        held.inc();
        sweep(&f);
        sweep(&f);
        drop(held);
        assert_eq!(sweep(&f), Some(0), "written while held: kept once");
        assert_eq!(sweep(&f), Some(1));
        assert!(f.is_empty());
    }

    #[test]
    fn writes_through_a_held_counter_are_not_lost() {
        let f = ExpiringFamily::default();
        let held = f.get_or_create(&l("a"));
        held.inc_by(10);
        for _ in 0..3 {
            sweep(&f);
        }
        held.inc_by(5);
        assert!(encode(&f).contains("test_total{name=\"a\"} 15"));
    }

    #[test]
    fn recreated_after_removal_starts_at_zero() {
        let f = ExpiringFamily::default();
        f.get_or_create(&l("a")).inc_by(100);
        sweep(&f);
        sweep(&f);
        assert!(f.is_empty());
        let c = f.get_or_create(&l("a"));
        assert_eq!(c.get(), 0);
        c.inc();
        assert_eq!(f.get_or_create(&l("a")).get(), 1);
    }

    #[test]
    fn empty_family_has_no_header_lines() {
        let f = ExpiringFamily::default();
        assert_eq!(encode(&f), "# EOF\n");
        f.get_or_create(&l("a")).inc();
        assert!(encode(&f).contains("# HELP test help (unstable)."));
        sweep(&f);
        sweep(&f);
        assert_eq!(encode(&f), "# EOF\n");
    }

    #[test]
    fn sweep_does_not_wait_for_a_reader() {
        let f = ExpiringFamily::<L>::default();
        f.get_or_create(&l("a"));
        let guard = f.metrics.read();
        assert_eq!(sweep(&f), None);
        drop(guard);
        assert_eq!(sweep(&f), Some(1));
    }

    // If removed entries were dropped under the write lock, the len()
    // in this Drop would deadlock.
    static FAMILY: OnceLock<ExpiringFamily<DropProbe>> = OnceLock::new();

    #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
    struct DropProbe {
        name: String,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            if let Some(f) = FAMILY.get() {
                let _ = f.len();
            }
        }
    }

    #[test]
    fn removed_entries_are_dropped_outside_the_lock() {
        let f = FAMILY.get_or_init(ExpiringFamily::default);
        f.get_or_create(&DropProbe { name: "a".into() });
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tx.send(sweep(f)).unwrap();
        });
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)), Ok(Some(1)));
    }

    // Writers hold clones (as open connections do) and write through
    // them, other writers create and drop short-lived handles, and a sweeper
    // runs in a loop. No write is lost: for every label set, what is still
    // exported plus what removed entries held at removal equals what was
    // written. A removed entry's value is final, because removal needs the
    // family to be the only holder.
    #[test]
    fn concurrent_writes_and_sweeps() {
        const WRITERS: usize = 4;
        const ROUNDS: u64 = 200_000;
        let f = ExpiringFamily::default();
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            let sweeper = s.spawn(|| {
                let (mut sweeps, mut removed, mut removed_value) = (0u64, 0usize, 0u64);
                while !stop.load(Ordering::Relaxed) {
                    if let Some((entries, _)) = f.try_sweep_entries() {
                        sweeps += 1;
                        removed += entries.len();
                        removed_value += entries.iter().map(|(_, c)| c.get()).sum::<u64>();
                    }
                    std::thread::yield_now();
                }
                (sweeps, removed, removed_value)
            });
            let churners: Vec<_> = (0..2)
                .map(|i| {
                    let f = &f;
                    let stop = &stop;
                    s.spawn(move || {
                        let mut n = 0u64;
                        while !stop.load(Ordering::Relaxed) {
                            f.get_or_create(&l(&format!("churn-{i}-{}", n % 64))).inc();
                            n += 1;
                        }
                        n
                    })
                })
                .collect();
            let held: Vec<_> = (0..WRITERS)
                .map(|i| {
                    let f = &f;
                    s.spawn(move || {
                        let c = f.get_or_create(&l(&format!("held-{i}")));
                        for _ in 0..ROUNDS {
                            c.inc();
                            std::thread::yield_now();
                        }
                        c
                    })
                })
                .collect();
            let held: Vec<ExpiringCounter> = held.into_iter().map(|h| h.join().unwrap()).collect();
            stop.store(true, Ordering::Relaxed);
            let churn_written: u64 = churners.into_iter().map(|h| h.join().unwrap()).sum();
            let (sweeps, removed, removed_value) = sweeper.join().unwrap();
            // Make sure the test really overlapped sweeps with writes.
            assert!(sweeps > 100, "only {sweeps} sweeps ran");
            assert!(removed > 0, "no churn label set was ever removed");
            let churn_left: u64 = f
                .metrics
                .read()
                .iter()
                .filter(|(k, _)| k.name.starts_with("churn-"))
                .map(|(_, c)| c.get())
                .sum();
            assert_eq!(
                churn_left + removed_value,
                churn_written,
                "churn writes lost: {churn_written} written, {churn_left} left, {removed_value} removed"
            );
            let out = encode(&f);
            for i in 0..WRITERS {
                let want = format!("test_total{{name=\"held-{i}\"}} {ROUNDS}");
                assert!(out.contains(&want), "missing {want}");
            }
            drop(held);
        });
    }

    fn expiry_for(
        f: &ExpiringFamily<L>,
        registry: &mut Registry,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let e = Expiry::new(interval, registry, vec![("test", Box::new(f.clone()))]);
        tokio::spawn(e.run())
    }

    // The "1 to 2 intervals" rule, on the real task with paused time.
    #[tokio::test(start_paused = true)]
    async fn task_removes_after_one_to_two_intervals() {
        const I: Duration = Duration::from_secs(60);
        let f = ExpiringFamily::default();
        let mut registry = Registry::default();
        let task = expiry_for(&f, &mut registry, I);
        // Let the task consume its first, immediate tick.
        tokio::task::yield_now().await;

        // Written just after a sweep: survives the next one, goes at the second.
        tokio::time::sleep(Duration::from_secs(1)).await;
        f.get_or_create(&l("a")).inc();
        tokio::time::sleep(I).await; // past sweep 1
        assert_eq!(f.len(), 1, "kept by the first sweep after the write");
        tokio::time::sleep(I).await; // past sweep 2
        assert!(
            f.is_empty(),
            "removed by the second sweep, under 2 intervals"
        );

        // Written just before a sweep: goes at the following one, after 1 interval.
        tokio::time::sleep(I - Duration::from_secs(2)).await;
        f.get_or_create(&l("b")).inc();
        tokio::time::sleep(Duration::from_secs(2)).await; // past the next sweep
        assert_eq!(f.len(), 1);
        tokio::time::sleep(I).await;
        assert!(f.is_empty(), "removed after just over 1 interval");

        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry).unwrap();
        assert!(
            out.contains("metrics_expired_series_total{metric=\"test\"} 2"),
            "{out}"
        );
        assert!(out.contains("metrics_series{metric=\"test\"} 0"), "{out}");
        assert!(
            !out.contains("metrics_expiry_skipped_sweeps_total"),
            "{out}"
        );
        task.abort();
    }

    // A held counter (an idle open connection) survives many intervals under
    // the real task, and its bytes are all there when it writes again.
    #[tokio::test(start_paused = true)]
    async fn task_keeps_held_counter() {
        const I: Duration = Duration::from_secs(60);
        let f = ExpiringFamily::default();
        let mut registry = Registry::default();
        let task = expiry_for(&f, &mut registry, I);
        let held = f.get_or_create(&l("conn"));
        held.inc_by(100);
        tokio::time::sleep(I * 5).await;
        assert_eq!(f.len(), 1);
        held.inc_by(23);
        assert!(encode(&f).contains("test_total{name=\"conn\"} 123"));
        drop(held);
        tokio::time::sleep(I * 2 + Duration::from_secs(1)).await;
        assert!(f.is_empty());
        task.abort();
    }

    // After a stall longer than the interval, a label set written during the
    // stall must still get about one full interval. The task's runtime stalls
    // here because time jumps ahead while the task cannot run: tokio then sees
    // its tick as overdue, as it would after SIGSTOP.
    #[tokio::test(start_paused = true)]
    async fn stall_does_not_cause_back_to_back_sweeps() {
        const I: Duration = Duration::from_secs(60);
        let f = ExpiringFamily::default();
        let mut registry = Registry::default();
        let task = expiry_for(&f, &mut registry, I);
        tokio::task::yield_now().await; // first tick consumed
        // Stall for 2.9 intervals, ending just before the old grid point at
        // 3 intervals, with a write right at the end of the stall.
        tokio::time::advance(I * 29 / 10).await;
        f.get_or_create(&l("a")).inc();
        // Let the overdue tick run: it sees the write and clears the flag.
        tokio::task::yield_now().await;
        // Just past the old grid point. With Skip, a second sweep would run
        // here and remove the label set 0.1 interval after its write.
        tokio::time::sleep(I / 5).await;
        assert_eq!(f.len(), 1, "removed right after a stall");
        task.abort();
    }

    // A tiny interval from a Config built in code must not turn the task into
    // a busy loop.
    #[tokio::test(start_paused = true)]
    async fn tiny_interval_is_raised() {
        let tries = Arc::new(AtomicU64::new(0));
        let mut registry = Registry::default();
        let e = Expiry::new(
            Duration::from_micros(1),
            &mut registry,
            vec![(
                "count",
                Box::new(Busy {
                    busy: 0,
                    tries: tries.clone(),
                }),
            )],
        );
        let task = tokio::spawn(e.run());
        tokio::time::sleep(MIN_INTERVAL * 10).await;
        let n = tries.load(Ordering::Relaxed);
        assert!(n <= 11, "{n} sweeps in 10 x MIN_INTERVAL");
        task.abort();
    }

    // Several threads write the same label sets through clones and
    // short-lived handles, as data-plane workers do, while a sweeper runs. No
    // increment may be lost.
    #[test]
    fn concurrent_writers_on_one_label_set() {
        const THREADS: u64 = 6;
        const ROUNDS: u64 = 50_000;
        let f = ExpiringFamily::default();
        let stop = AtomicBool::new(false);
        let (removed_value, written) = std::thread::scope(|s| {
            let sweeper = s.spawn(|| {
                let mut removed_value = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    if let Some((entries, _)) = f.try_sweep_entries() {
                        removed_value += entries.iter().map(|(_, c)| c.get()).sum::<u64>();
                    }
                    std::thread::yield_now();
                }
                removed_value
            });
            let writers: Vec<_> = (0..THREADS)
                .map(|t| {
                    let f = &f;
                    s.spawn(move || {
                        // A held clone, shared by name with the other threads.
                        let held = f.get_or_create(&l("shared-held"));
                        for i in 0..ROUNDS {
                            held.inc();
                            // A short-lived handle on a label set others write too.
                            f.get_or_create(&l(&format!("shared-{}", (i + t) % 4)))
                                .inc();
                        }
                        2 * ROUNDS
                    })
                })
                .collect();
            let written: u64 = writers.into_iter().map(|h| h.join().unwrap()).sum();
            stop.store(true, Ordering::Relaxed);
            (sweeper.join().unwrap(), written)
        });
        let left: u64 = f.metrics.read().values().map(|c| c.get()).sum();
        assert_eq!(
            left + removed_value,
            written,
            "{left} left + {removed_value} removed"
        );
    }

    /// A family whose lock is busy for the first `busy` tries.
    struct Busy {
        busy: usize,
        tries: Arc<AtomicU64>,
    }

    impl Sweep for Busy {
        fn try_sweep(&self) -> Option<Swept> {
            let n = self.tries.fetch_add(1, Ordering::Relaxed) as usize;
            (n >= self.busy).then_some(Swept {
                removed: 0,
                left: 0,
            })
        }
    }

    // A busy family is retried, and counted as skipped only when every retry
    // fails.
    #[tokio::test(start_paused = true)]
    async fn busy_family_is_retried_then_skipped() {
        let tries = Arc::new(AtomicU64::new(0));
        let mut registry = Registry::default();
        let e = Expiry::new(
            Duration::from_secs(60),
            &mut registry,
            vec![
                (
                    "always_busy",
                    Box::new(Busy {
                        busy: usize::MAX,
                        tries: tries.clone(),
                    }),
                ),
                (
                    "busy_once",
                    Box::new(Busy {
                        busy: 1,
                        tries: Arc::new(AtomicU64::new(0)),
                    }),
                ),
            ],
        );
        e.sweep_all().await;
        assert_eq!(tries.load(Ordering::Relaxed), 10, "tried 10 times");
        let mut out = String::new();
        prometheus_client::encoding::text::encode(&mut out, &registry).unwrap();
        assert!(
            out.contains("metrics_expiry_skipped_sweeps_total{metric=\"always_busy\"} 1"),
            "{out}"
        );
        assert!(
            !out.contains("metrics_expiry_skipped_sweeps_total{metric=\"busy_once\"}"),
            "{out}"
        );
        assert!(
            out.contains("metrics_expired_series_total{metric=\"busy_once\"} 0"),
            "{out}"
        );
    }

    // The last holder writes and drops just before the sweep: kept now,
    // removed next time. This checks the flag logic. It cannot catch a
    // memory-ordering bug: the scope join already orders the write before the
    // sweep. The ordering argument rests on Arc::get_mut being sound (it
    // hands out &mut only after an Acquire load that pairs with every Release
    // decrement), not on this test.
    #[test]
    fn last_write_before_release_is_seen() {
        for _ in 0..2_000 {
            let f = ExpiringFamily::default();
            let held = f.get_or_create(&l("a"));
            assert_eq!(sweep(&f), Some(0));
            std::thread::scope(|s| {
                s.spawn(move || {
                    held.inc();
                    drop(held);
                });
            });
            assert_eq!(sweep(&f), Some(0), "the write before the drop was missed");
            assert_eq!(sweep(&f), Some(1));
        }
    }
}
