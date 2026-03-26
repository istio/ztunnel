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

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeLabelSet, EncodeMetric};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::ConstCounter;
use prometheus_client::metrics::gauge::ConstGauge;
use prometheus_client::registry::Registry;

#[derive(Debug)]
pub struct TokioRuntimeCollector {
    metrics: tokio::runtime::RuntimeMetrics,
}

impl TokioRuntimeCollector {
    pub fn new(handle: &tokio::runtime::Handle) -> Self {
        Self {
            metrics: handle.metrics(),
        }
    }

    pub fn register(registry: &mut Registry, handle: &tokio::runtime::Handle) {
        registry
            .sub_registry_with_prefix("tokio")
            .register_collector(Box::new(Self::new(handle)));
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct LabelSet {
    worker: usize,
}

macro_rules! encode_gauge {
    ($self:expr, $encoder:expr, $name:tt, $help:expr) => {{
        let metric = ConstGauge::new($self.metrics.$name() as i64);
        let metric_encoder =
            $encoder.encode_descriptor(stringify!($name), $help, None, metric.metric_type())?;
        metric.encode(metric_encoder)?;
    }};
}

macro_rules! encode_per_worker_duration_seconds {
    ($self:expr, $encoder:expr, $name:tt, $help:expr) => {{
        let mut family_encoder = $encoder.encode_descriptor(
            concat!(stringify!($name), "_seconds"),
            $help,
            None,
            MetricType::Counter,
        )?;
        for worker in 0..$self.metrics.num_workers() {
            let metric = ConstCounter::new($self.metrics.$name(worker).as_secs_f64());
            let labels = LabelSet { worker };
            let metric_encoder = family_encoder.encode_family(&labels)?;
            metric.encode(metric_encoder)?;
        }
    }};
}

macro_rules! encode_per_worker_count {
    ($self:expr, $encoder:expr, $name:tt, $help:expr) => {{
        let mut family_encoder =
            $encoder.encode_descriptor(stringify!($name), $help, None, MetricType::Counter)?;
        for worker in 0..$self.metrics.num_workers() {
            let metric = ConstGauge::new($self.metrics.$name(worker) as i64);
            let labels = LabelSet { worker };
            let metric_encoder = family_encoder.encode_family(&labels)?;
            metric.encode(metric_encoder)?;
        }
    }};
}

impl Collector for TokioRuntimeCollector {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        encode_gauge!(
            self,
            &mut encoder,
            num_workers,
            "the number of worker threads used by the runtime"
        );

        encode_gauge!(
            self,
            &mut encoder,
            global_queue_depth,
            "the number of tasks currently scheduled in the runtime's global queue"
        );

        encode_gauge!(
            self,
            &mut encoder,
            num_alive_tasks,
            "the number of alive tasks in the runtime"
        );

        #[cfg(target_has_atomic = "64")]
        encode_per_worker_duration_seconds!(
            self,
            &mut encoder,
            worker_total_busy_duration,
            "the amount of time worker threads have been busy"
        );

        #[cfg(target_has_atomic = "64")]
        encode_per_worker_count!(
            self,
            &mut encoder,
            worker_park_count,
            "the total number of times the given worker thread has parked"
        );

        #[cfg(target_has_atomic = "64")]
        encode_per_worker_count!(
            self,
            &mut encoder,
            worker_park_unpark_count,
            "the total number of times the given worker thread has parked and unparked"
        );

        Ok(())
    }
}
