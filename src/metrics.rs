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

use std::mem;

use prometheus_client::registry::Registry;

mod meta;
#[allow(non_camel_case_types)]
pub mod traffic;
pub mod xds;

/// Set of Swarm and protocol metrics derived from emitted events.
pub struct Metrics {
    xds: xds::Metrics,
    #[allow(dead_code)]
    meta: meta::Metrics,
    traffic: traffic::Metrics,
}

impl Metrics {
    fn new(registry: &mut Registry) -> Self {
        Self {
            xds: xds::Metrics::new(registry),
            meta: meta::Metrics::new(registry),
            traffic: traffic::Metrics::new(registry),
        }
    }
}

impl From<&mut Registry> for Metrics {
    fn from(registry: &mut Registry) -> Self {
        Metrics::new(registry.sub_registry_with_prefix("istio"))
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        Metrics::new(registry.sub_registry_with_prefix("istio"))
    }
}

impl Metrics {
    #[must_use = "metric will be dropped (and thus recorded) immediately if not assign"]
    /// increment_defer is used to increment a metric now and another metric later once the MetricGuard is dropped
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let connection_open = ConnectionOpen {};
    /// // Record connection opened now
    /// let connection_close = self.metrics.increment_defer::<_, ConnectionClosed>(&connection_open);
    /// // Eventually, report connection closed
    /// drop(connection_close);
    /// ```
    pub fn increment_defer<'a, M1, M2>(&'a self, event: &'a M1) -> MetricGuard<'a, M2>
    where
        M1: Clone + 'a,
        M2: From<&'a M1>,
        Metrics: RecorderIncrement<M1> + RecorderIncrement<M2>,
    {
        self.increment(event);
        let m2: M2 = event.into();
        MetricGuard {
            metrics: self,
            event: Some(m2),
        }
    }
}

pub struct MetricGuard<'a, E>
where
    Metrics: RecorderIncrement<E>,
{
    metrics: &'a Metrics,
    event: Option<E>,
}

impl<E> Drop for MetricGuard<'_, E>
where
    Metrics: RecorderIncrement<E>,
{
    fn drop(&mut self) {
        if let Some(m) = mem::take(&mut self.event) {
            self.metrics.increment(&m)
        }
    }
}

pub trait Recorder<E, T> {
    /// Record the given event
    fn record(&self, event: &E, meta: T);
}

pub trait RecorderIncrement<E>: Recorder<E, u64> {
    /// Record the given event by incrementing the counter by count
    fn increment(&self, event: &E);
}

impl<E, R> RecorderIncrement<E> for R
where
    R: Recorder<E, u64>,
{
    fn increment(&self, event: &E) {
        self.record(event, 1);
    }
}
