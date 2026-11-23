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

//! Idle-based eviction of connection metric series.
//!
//! The [Evictor] remembers when each connection label set was last active. A series is dropped by
//! the first scrape after it has had no open connections and no new activity for the configured
//! TTL. This bounds metric cardinality for short-lived workloads without tracking workload
//! lifecycle at all.

use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::proxy::metrics::{CommonTrafficLabels, OnDemandDnsLabels};

/// A source of metric series that can be evicted when idle.
pub trait Evictable: Send + Sync {
    /// Evicts series idle for at least `ttl`. Returns the number evicted, or None if eviction is
    /// disabled.
    fn evict_idle(&self, ttl: Duration) -> Option<usize>;
}

/// Number of independently locked shards. Connections open and close on the proxy hot path, so
/// label sets are spread over shards to keep unrelated traffic from contending on a single lock.
const SHARDS: usize = 16;

#[derive(Debug)]
struct SeriesState {
    /// Number of connections currently open with these labels.
    active: usize,
    /// Last time a connection with these labels opened or closed.
    last_active: Instant,
}

type Shard = Mutex<HashMap<CommonTrafficLabels, SeriesState>>;

#[derive(Debug)]
pub struct Evictor {
    ttl: Duration,
    hasher: RandomState,
    shards: [Shard; SHARDS],
    /// Last time each on-demand DNS series was incremented. They are not tied to a connection.
    on_demand_dns: Mutex<HashMap<OnDemandDnsLabels, Instant>>,
}

impl Evictor {
    pub fn new(ttl: Duration) -> Self {
        Evictor {
            ttl,
            hasher: RandomState::new(),
            shards: Default::default(),
            on_demand_dns: Default::default(),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Runs `f` on the state for `labels`, creating it if needed.
    fn with_state<R>(
        &self,
        labels: &CommonTrafficLabels,
        f: impl FnOnce(&mut SeriesState) -> R,
    ) -> R {
        let shard = &self.shards[self.hasher.hash_one(labels) as usize % SHARDS];
        let mut shard = shard.lock().expect("evictor mutex");
        if let Some(s) = shard.get_mut(labels) {
            return f(s);
        }
        f(shard.entry(labels.clone()).or_insert(SeriesState {
            active: 0,
            last_active: Instant::now(),
        }))
    }

    /// Records that a connection has opened with `labels`.
    pub fn connection_opened(&self, labels: &CommonTrafficLabels) {
        self.opened_at(labels, Instant::now());
    }

    fn opened_at(&self, labels: &CommonTrafficLabels, now: Instant) {
        self.with_state(labels, |s| {
            s.active += 1;
            s.last_active = now;
        });
    }

    /// Records that a connection opened with `open` has closed. `closed` are the final labels,
    /// which can differ from the ones at open (for example, response flags); both are marked as
    /// recently active.
    pub fn connection_closed(&self, open: &CommonTrafficLabels, closed: &CommonTrafficLabels) {
        self.closed_at(open, closed, Instant::now());
    }

    fn closed_at(&self, open: &CommonTrafficLabels, closed: &CommonTrafficLabels, now: Instant) {
        self.with_state(open, |s| {
            s.active = s.active.saturating_sub(1);
            s.last_active = now;
        });
        if open != closed {
            self.with_state(closed, |s| s.last_active = now);
        }
    }

    /// Marks `labels` as recently active without affecting its open connection count, for series
    /// written outside a connection's open/close.
    pub fn touch(&self, labels: &CommonTrafficLabels) {
        self.with_state(labels, |s| s.last_active = Instant::now());
    }

    /// Records that the on-demand DNS series `labels` is about to be written. Call before
    /// creating the series, so a concurrent sweep cannot evict it in between.
    pub fn on_demand_dns_used(&self, labels: &OnDemandDnsLabels) {
        let mut m = self.on_demand_dns.lock().expect("evictor mutex");
        match m.get_mut(labels) {
            Some(t) => *t = Instant::now(),
            None => {
                m.insert(labels.clone(), Instant::now());
            }
        }
    }

    /// Calls `evict` for every on-demand DNS series unused for at least `ttl`, and stops tracking
    /// it. Returns the number evicted.
    pub fn sweep_on_demand_dns(
        &self,
        now: Instant,
        ttl: Duration,
        mut evict: impl FnMut(&OnDemandDnsLabels),
    ) -> usize {
        let mut evicted = 0;
        // Evicting under the lock, for the same reason as in [Self::sweep_idle].
        self.on_demand_dns
            .lock()
            .expect("evictor mutex")
            .retain(|labels, last| {
                let due = now.saturating_duration_since(*last) >= ttl;
                if due {
                    evict(labels);
                    evicted += 1;
                }
                !due
            });
        evicted
    }

    /// Number of label sets currently tracked.
    pub fn tracked(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().expect("evictor mutex").len())
            .sum::<usize>()
            + self.on_demand_dns.lock().expect("evictor mutex").len()
    }

    /// Calls `evict` for every connection label set with no open connections
    /// that has been idle for at least one TTL, and stops tracking it. Returns the number of
    /// connection label sets evicted.
    pub fn sweep(&self, now: Instant, evict: impl FnMut(&CommonTrafficLabels)) -> usize {
        self.sweep_idle(now, self.ttl, evict)
    }

    /// Like [Self::sweep], but evicts label sets idle for at least `ttl` instead of the configured
    /// one.
    pub fn sweep_idle(
        &self,
        now: Instant,
        ttl: Duration,
        mut evict: impl FnMut(&CommonTrafficLabels),
    ) -> usize {
        let mut evicted = 0;
        for shard in &self.shards {
            // One shard at a time, so a scrape never blocks the whole hot path.
            shard.lock().expect("evictor mutex").retain(|labels, s| {
                let due = s.active == 0 && now.saturating_duration_since(s.last_active) >= ttl;
                if due {
                    // Evict while still holding the shard lock. A concurrent open with the same
                    // labels then waits for us and recreates its series afterwards, instead of
                    // having a fresh series deleted underneath it. Metric families take their own
                    // locks, but nothing takes those and then calls back into the evictor.
                    evict(labels);
                    evicted += 1;
                }
                !due
            });
        }
        evicted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::metrics::RequestProtocol;

    fn labels(request_protocol: RequestProtocol) -> CommonTrafficLabels {
        let mut l = CommonTrafficLabels::default();
        l.request_protocol = request_protocol;
        l
    }

    fn swept(e: &Evictor, now: Instant) -> Vec<CommonTrafficLabels> {
        let mut out = vec![];
        e.sweep(now, |l| out.push(l.clone()));
        out
    }

    #[test]
    fn evicts_only_after_idle_ttl() {
        let e = Evictor::new(Duration::from_secs(60));
        let l = labels(RequestProtocol::tcp);
        e.connection_opened(&l);
        e.connection_closed(&l, &l);
        let t0 = Instant::now();

        assert!(swept(&e, t0 + Duration::from_secs(30)).is_empty());
        assert_eq!(swept(&e, t0 + Duration::from_secs(61)), vec![l]);
        // Already evicted and no longer tracked.
        assert_eq!(e.tracked(), 0);
        assert!(swept(&e, t0 + Duration::from_secs(600)).is_empty());
    }

    #[test]
    fn activity_resets_the_idle_clock() {
        let e = Evictor::new(Duration::from_secs(60));
        let l = labels(RequestProtocol::tcp);
        let t0 = Instant::now();
        e.opened_at(&l, t0);
        e.closed_at(&l, &l, t0);
        // New traffic arrives just before the first close would have expired.
        let t1 = t0 + Duration::from_secs(50);
        e.opened_at(&l, t1);
        e.closed_at(&l, &l, t1);
        assert!(swept(&e, t0 + Duration::from_secs(70)).is_empty());
        assert_eq!(swept(&e, t1 + Duration::from_secs(60)), vec![l]);
    }

    #[test]
    fn open_connections_are_not_evicted() {
        let e = Evictor::new(Duration::from_secs(60));
        let open = labels(RequestProtocol::tcp);
        let later = Instant::now() + Duration::from_secs(600);
        e.connection_opened(&open);
        assert!(swept(&e, later).is_empty());

        // The connection closes with different final labels: both series are fresh again, and
        // are evicted once idle.
        let closed = labels(RequestProtocol::http);
        e.connection_closed(&open, &closed);
        assert!(swept(&e, Instant::now()).is_empty());
        assert_eq!(swept(&e, Instant::now() + Duration::from_secs(61)).len(), 2);
    }
}
