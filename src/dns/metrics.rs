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

use hickory_server::server::Request;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::metrics::evict::Evictable;
use crate::metrics::{DefaultedUnknown, DeferRecorder, Recorder};

use crate::state::workload::Workload;
use crate::strng;
use crate::strng::RichStrng;

#[derive(Clone)]
pub struct Metrics {
    pub requests: Family<DnsLabels, Counter>,
    pub forwarded_requests: Family<DnsLabels, Counter>,
    pub forwarded_failures: Family<DnsLabels, Counter>,
    pub forwarded_duration: Family<DnsLabels, Histogram>,
    /// Series are evicted once unused for this long. Zero disables eviction.
    ttl: Duration,
    /// Millis since `epoch` of the last write to each label set; the same labels key every family.
    last_used: Arc<RwLock<HashMap<DnsLabels, AtomicU64>>>,
    epoch: Instant,
}

/// Writes closer together than this don't refresh `last_used`, keeping the hot path read-only.
const TOUCH_GRANULARITY_MS: u64 = 1000;

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        Self::with_eviction_ttl(registry, Duration::ZERO)
    }

    /// Creates metrics that evict a label set once it has been unused for `ttl`. A zero `ttl`
    /// disables eviction.
    pub fn with_eviction_ttl(registry: &mut Registry, ttl: Duration) -> Self {
        let requests = Family::default();
        registry.register(
            "dns_requests",
            "Total number of DNS requests (unstable)",
            requests.clone(),
        );

        let forwarded_requests = Family::default();
        registry.register(
            "dns_upstream_requests",
            "Total number of DNS requests forwarded to upstream (unstable)",
            forwarded_requests.clone(),
        );

        let forwarded_failures = Family::default();
        registry.register(
            "dns_upstream_failures",
            "Total number of DNS requests that failed to forward upstream (unstable)",
            forwarded_failures.clone(),
        );

        let forwarded_duration = Family::<DnsLabels, Histogram>::new_with_constructor(|| {
            Histogram::new(vec![0.0005f64, 0.001, 0.01, 0.1, 1.0, 5.0])
        });
        registry.register_with_unit(
            "dns_upstream_request_duration",
            "Total time in seconds Istio takes to get DNS response from upstream (unstable)",
            Unit::Seconds,
            forwarded_duration.clone(),
        );

        Self {
            requests,
            forwarded_requests,
            forwarded_failures,
            forwarded_duration,
            ttl,
            last_used: Default::default(),
            epoch: Instant::now(),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Records that `labels` is about to be written. Call before creating the series, so a
    /// concurrent sweep cannot evict it in between.
    fn touch(&self, labels: &DnsLabels) {
        if self.ttl.is_zero() {
            return;
        }
        let now = self.now_ms();
        {
            let m = self.last_used.read().expect("dns metrics lock");
            if let Some(t) = m.get(labels) {
                if now.saturating_sub(t.load(Ordering::Relaxed)) >= TOUCH_GRANULARITY_MS {
                    t.store(now, Ordering::Relaxed);
                }
                return;
            }
        }
        self.last_used
            .write()
            .expect("dns metrics lock")
            .entry(labels.clone())
            .or_default()
            .store(now, Ordering::Relaxed);
    }

    fn sweep(&self, ttl: Duration) -> usize {
        let now = self.now_ms();
        let ttl = ttl.as_millis() as u64;
        let mut evicted = 0;
        // Removing under the write lock, so a concurrent writer waits and recreates its series after.
        self.last_used
            .write()
            .expect("dns metrics lock")
            .retain(|l, last| {
                let due = now.saturating_sub(last.load(Ordering::Relaxed)) >= ttl;
                if due {
                    self.requests.remove(l);
                    self.forwarded_requests.remove(l);
                    self.forwarded_failures.remove(l);
                    self.forwarded_duration.remove(l);
                    evicted += 1;
                }
                !due
            });
        evicted
    }
}

impl Evictable for Metrics {
    fn evict_idle(&self, ttl: Duration) -> Option<usize> {
        (!self.ttl.is_zero()).then(|| self.sweep(ttl))
    }
}

impl DeferRecorder for Metrics {}

#[derive(Clone, Hash, Debug, PartialEq, Eq, EncodeLabelSet)]
pub struct DnsLabels {
    request_query_type: DefaultedUnknown<RichStrng>,
    request_protocol: RichStrng,

    // Source workload.
    source_canonical_service: DefaultedUnknown<RichStrng>,
    source_canonical_revision: DefaultedUnknown<RichStrng>,
}

impl DnsLabels {
    pub fn new(r: &Request) -> Self {
        Self {
            request_query_type: r
                .request_info()
                .map(|q| q.query.query_type().to_string().to_lowercase())
                .ok()
                .map(|s| RichStrng::from(strng::new(s)))
                .into(),
            request_protocol: r.protocol().to_string().to_lowercase().into(),
            source_canonical_service: Default::default(),
            source_canonical_revision: Default::default(),
        }
    }

    pub fn with_source(mut self, w: &Workload) -> Self {
        self.source_canonical_service = w.canonical_name.clone().into();
        self.source_canonical_revision = w.canonical_revision.clone().into();

        self
    }
}

#[derive(Clone)]
pub struct DnsRequest<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<DnsRequest<'_>, u64> for Metrics {
    fn record(&self, reason: &DnsRequest, count: u64) {
        let labels = DnsLabels::from(reason);
        self.touch(&labels);
        self.requests.get_or_create(&labels).inc_by(count);
    }
}

impl From<&DnsRequest<'_>> for DnsLabels {
    fn from(value: &DnsRequest) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}

#[derive(Clone)]
pub struct ForwardedRequest<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<ForwardedRequest<'_>, u64> for Metrics {
    fn record(&self, reason: &ForwardedRequest, count: u64) {
        let labels = DnsLabels::from(reason);
        self.touch(&labels);
        self.forwarded_requests.get_or_create(&labels).inc_by(count);
    }
}

impl From<&ForwardedRequest<'_>> for DnsLabels {
    fn from(value: &ForwardedRequest) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}

#[derive(Clone)]
pub struct ForwardedFailure<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<ForwardedFailure<'_>, u64> for Metrics {
    fn record(&self, reason: &ForwardedFailure, count: u64) {
        let labels = DnsLabels::from(reason);
        self.touch(&labels);
        self.forwarded_failures.get_or_create(&labels).inc_by(count);
    }
}

impl From<&ForwardedFailure<'_>> for DnsLabels {
    fn from(value: &ForwardedFailure) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}

#[derive(Clone)]
pub struct ForwardedDuration<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<ForwardedDuration<'_>, Duration> for Metrics {
    fn record(&self, reason: &ForwardedDuration, duration: Duration) {
        let labels = DnsLabels::from(reason);
        self.touch(&labels);
        self.forwarded_duration
            .get_or_create(&labels)
            .observe(duration.as_secs_f64());
    }
}

impl From<&ForwardedDuration<'_>> for DnsLabels {
    fn from(value: &ForwardedDuration) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(service: &str) -> DnsLabels {
        DnsLabels {
            request_query_type: Default::default(),
            request_protocol: "udp".into(),
            source_canonical_service: Some(RichStrng::from(strng::new(service))).into(),
            source_canonical_revision: Default::default(),
        }
    }

    #[test]
    fn idle_series_are_evicted_from_every_family() {
        let m = Metrics::with_eviction_ttl(&mut Registry::default(), Duration::from_secs(3600));
        let (a, b) = (labels("a"), labels("b"));
        for l in [&a, &b] {
            m.touch(l);
            m.requests.get_or_create(l).inc();
            m.forwarded_requests.get_or_create(l).inc();
            m.forwarded_failures.get_or_create(l).inc();
            m.forwarded_duration.get_or_create(l).observe(0.1);
        }

        // Nothing has been idle for an hour yet.
        m.evict_idle(Duration::from_secs(3600));
        assert!(m.requests.get(&a).is_some());

        m.touch(&b);
        assert_eq!(m.sweep(Duration::ZERO), 2);
        for l in [&a, &b] {
            assert!(m.requests.get(l).is_none());
            assert!(m.forwarded_requests.get(l).is_none());
            assert!(m.forwarded_failures.get(l).is_none());
            assert!(m.forwarded_duration.get(l).is_none());
        }
    }

    #[test]
    fn disabled_without_ttl() {
        let m = Metrics::new(&mut Registry::default());
        let l = labels("a");
        m.touch(&l);
        m.requests.get_or_create(&l).inc();
        assert_eq!(m.evict_idle(Duration::ZERO), None);
        assert!(m.requests.get(&l).is_some());
    }
}
