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

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};

use crate::metrics::Recorder;

use super::service::discovery::v3::DeltaDiscoveryResponse;

pub struct Metrics {
    pub connection_terminations: Family<ConnectionTermination, Counter>,
    pub message_types: Family<TypeUrl, Counter>,
    pub total_messages_size: Family<TypeUrl, Counter>,
    pub up: Option<Gauge>,
    pub disconnect_duration: Option<Histogram>,
}

#[derive(Clone, Hash, Debug, PartialEq, Eq, EncodeLabelSet)]
pub struct ConnectionTermination {
    pub reason: ConnectionTerminationReason,
}

#[derive(Copy, Clone, Hash, Debug, PartialEq, Eq, EncodeLabelValue)]
pub enum ConnectionTerminationReason {
    ConnectionError,
    Error,
    Reconnect,
    Complete,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TypeUrl {
    pub url: String,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        Self::new_with_remote_xds(registry, true)
    }

    pub fn new_with_remote_xds(registry: &mut Registry, remote_xds_configured: bool) -> Self {
        let connection_terminations = Family::default();
        registry.register(
            "xds_connection_terminations",
            "The total number of completed connections to xds server (unstable)",
            connection_terminations.clone(),
        );

        let message_count = Family::default();

        registry.register(
            "xds_message",
            "Total number of messages received (unstable)",
            message_count.clone(),
        );

        let total_messages_size = Family::default();

        registry.register_with_unit(
            "xds_message",
            "Total number of bytes received (unstable)",
            Unit::Bytes,
            total_messages_size.clone(),
        );

        let up = remote_xds_configured.then(|| {
            let up = Gauge::default();
            registry.register(
                "xds_up",
                "Whether the xDS gRPC stream is currently connected (1) or not (0); this is not Prometheus scrape liveness (unstable)",
                up.clone(),
            );
            up
        });

        let disconnect_duration = remote_xds_configured.then(|| {
            let disconnect_duration = Histogram::new(
                [
                    0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
                    600.0, 1800.0, 3600.0, 7200.0, 14400.0, 43200.0, 86400.0,
                ]
                .into_iter(),
            );
            registry.register_with_unit(
                "xds_disconnect_duration",
                "Duration of completed xDS disconnections, observed when a new xDS stream is established (unstable)",
                Unit::Seconds,
                disconnect_duration.clone(),
            );
            disconnect_duration
        });

        Self {
            connection_terminations,
            message_types: message_count,
            total_messages_size,
            up,
            disconnect_duration,
        }
    }
}

impl Recorder<ConnectionTerminationReason, u64> for Metrics {
    fn record(&self, reason: &ConnectionTerminationReason, count: u64) {
        self.connection_terminations
            .get_or_create(&ConnectionTermination { reason: *reason })
            .inc_by(count);
    }
}

impl Recorder<DeltaDiscoveryResponse, ()> for Metrics {
    fn record(&self, response: &DeltaDiscoveryResponse, _: ()) {
        let type_url = TypeUrl {
            url: response.type_url.clone(),
        };
        self.message_types.get_or_create(&type_url).inc();

        let mut total_message_size: u64 = 0;
        for resource in &response.resources {
            total_message_size += resource
                .resource
                .as_ref()
                .map(|v| v.value.len())
                .unwrap_or_default() as u64;
        }
        self.total_messages_size
            .get_or_create(&type_url)
            .inc_by(total_message_size);
    }
}

#[cfg(test)]
mod tests {
    use prometheus_client::encoding::text::encode;

    use super::*;

    #[test]
    fn disconnect_duration_help_describes_completed_disconnects() {
        let mut registry = Registry::default();
        let _metrics = Metrics::new(&mut registry);

        let mut encoded = String::new();
        encode(&mut encoded, &registry).unwrap();

        assert!(
            encoded.contains(
                "# HELP xds_disconnect_duration_seconds Duration of completed xDS disconnections, observed when a new xDS stream is established (unstable)"
            ),
            "disconnect-duration HELP text should describe completed disconnect semantics:\n{encoded}"
        );
    }

    #[test]
    fn monitor_sender_dropped_help_describes_all_input_senders() {
        let mut registry = Registry::default();
        let _metrics = XdsConnectionMonitorMetrics::new(&mut registry);

        let mut encoded = String::new();
        encode(&mut encoded, &registry).unwrap();

        assert!(
            encoded.contains(
                "# HELP xds_monitor_sender_dropped Total number of times an xDS readiness monitor input sender dropped and the monitor failed closed (unstable)"
            ),
            "sender-drop HELP text should cover startup and connection-state sender drops:\n{encoded}"
        );
    }
}

#[derive(Clone)]
pub(crate) struct XdsConnectionMonitorMetrics {
    pub(crate) readiness_rearmed: Counter,
    pub(crate) sender_dropped: Counter,
}

impl XdsConnectionMonitorMetrics {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let readiness_rearmed = Counter::default();
        registry.register(
            "xds_readiness_rearmed",
            "Total number of times xDS stayed non-fresh past the unhealthy threshold and readiness was blocked (unstable)",
            readiness_rearmed.clone(),
        );
        let sender_dropped = Counter::default();
        registry.register(
            "xds_monitor_sender_dropped",
            "Total number of times an xDS readiness monitor input sender dropped and the monitor failed closed (unstable)",
            sender_dropped.clone(),
        );
        Self {
            readiness_rearmed,
            sender_dropped,
        }
    }
}
