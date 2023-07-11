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

use std::fmt::Write;
use std::marker::PhantomData;
use std::mem;
use std::sync::Arc;

use crate::identity::Identity;
use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use prometheus_client::registry::Registry;
use tracing::error;

pub mod dns;
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
    dns: dns::Metrics,
}

impl Metrics {
    fn new(registry: &mut Registry) -> Self {
        Self {
            xds: xds::Metrics::new(registry),
            meta: meta::Metrics::new(registry),
            traffic: traffic::Metrics::new(registry),
            dns: dns::Metrics::new(registry),
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
    #[must_use = "metric will be dropped (and thus recorded) immediately if not assigned"]
    pub fn defer<'a, F>(self: &Arc<Metrics>, record: F) -> Deferred<'a, F>
    where
        F: FnOnce(Arc<Metrics>),
    {
        Deferred::new(self.clone(), record)
    }

    #[must_use = "metric will be dropped (and thus recorded) immediately if not assigned"]
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
    pub fn increment_defer<'a, M1, M2>(
        self: &Arc<Metrics>,
        event: &'a M1,
    ) -> Deferred<'a, impl FnOnce(Arc<Metrics>)>
    where
        M1: Clone + 'a,
        M2: From<&'a M1> + 'a,
        Metrics: IncrementRecorder<M1> + IncrementRecorder<M2>,
    {
        self.increment(event);
        let m2: M2 = event.into();
        self.defer(move |metrics| {
            metrics.increment(&m2);
        })
    }
}

pub struct Deferred<'a, F>
where
    F: FnOnce(Arc<Metrics>),
{
    metrics: Arc<Metrics>,
    record_fn: Option<F>,
    _lifetime: PhantomData<&'a F>,
}

impl<'a, F> Deferred<'a, F>
where
    F: FnOnce(Arc<Metrics>),
{
    pub fn new(metrics: Arc<Metrics>, record_fn: F) -> Self {
        Self {
            metrics,
            record_fn: Some(record_fn),
            _lifetime: PhantomData::default(),
        }
    }
}

impl<'a, F> Drop for Deferred<'a, F>
where
    F: FnOnce(Arc<Metrics>),
{
    fn drop(&mut self) {
        if let Some(record_fn) = mem::take(&mut self.record_fn) {
            (record_fn)(self.metrics.clone());
        } else {
            error!("defer record failed, event is gone");
        }
    }
}

pub trait Recorder<E, T> {
    /// Record the given event
    fn record(&self, event: &E, meta: T);
}

pub trait IncrementRecorder<E>: Recorder<E, u64> {
    /// Record the given event by incrementing the counter by count
    fn increment(&self, event: &E);
}

impl<E, R> IncrementRecorder<E> for R
where
    R: Recorder<E, u64>,
{
    fn increment(&self, event: &E) {
        self.record(event, 1);
    }
}

#[derive(Default, Hash, PartialEq, Eq, Clone, Debug)]
// DefaultedUnknown is a wrapper around an Option that encodes as "unknown" when missing, rather than ""
struct DefaultedUnknown<T>(Option<T>);

impl From<String> for DefaultedUnknown<String> {
    fn from(t: String) -> Self {
        if t.is_empty() {
            DefaultedUnknown(None)
        } else {
            DefaultedUnknown(Some(t))
        }
    }
}

impl<T> From<Option<T>> for DefaultedUnknown<T> {
    fn from(t: Option<T>) -> Self {
        DefaultedUnknown(t)
    }
}

impl From<Identity> for DefaultedUnknown<Identity> {
    fn from(t: Identity) -> Self {
        DefaultedUnknown(Some(t))
    }
}

impl<T: EncodeLabelValue> EncodeLabelValue for DefaultedUnknown<T> {
    fn encode(&self, writer: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        match self {
            DefaultedUnknown(Some(i)) => i.encode(writer),
            DefaultedUnknown(None) => writer.write_str("unknown"),
        }
    }
}
