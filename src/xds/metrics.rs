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
    pub config_fresh: Option<Gauge>,
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

        let config_fresh = remote_xds_configured.then(|| {
            let config_fresh = Gauge::default();
            registry.register(
                "xds_config_fresh",
                "Whether the current xDS stream has ACKed usable config and has no watched-resource rejection outstanding (1) or not (0) (unstable)",
                config_fresh.clone(),
            );
            config_fresh
        });

        let disconnect_duration = remote_xds_configured.then(|| {
            let disconnect_duration = Histogram::new(
                [
                    0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0,
                    600.0, 1800.0, 3600.0, 7200.0, 14400.0, 43200.0, 86400.0,
                ],
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
            config_fresh,
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
    fn config_fresh_help_describes_synced_semantics() {
        let mut registry = Registry::default();
        let _metrics = Metrics::new(&mut registry);

        let mut encoded = String::new();
        encode(&mut encoded, &registry).unwrap();

        assert!(
            encoded.contains(
                "# HELP xds_config_fresh Whether the current xDS stream has ACKed usable config and has no watched-resource rejection outstanding (1) or not (0) (unstable)"
            ),
            "config-fresh HELP text should describe Synced semantics:\n{encoded}"
        );
    }

    #[test]
    fn monitor_sender_dropped_help_describes_monitor_senders() {
        let mut registry = Registry::default();
        let _metrics = XdsConnectionMonitorMetrics::new(&mut registry);

        let mut encoded = String::new();
        encode(&mut encoded, &registry).unwrap();

        assert!(
            encoded.contains(
                "# HELP xds_monitor_sender_dropped Total number of times an xDS monitor input sender dropped (unstable)"
            ),
            "sender-drop HELP text should describe the monitor input senders:\n{encoded}"
        );
    }

    #[test]
    fn monitor_events_lagged_help_describes_skipped_events() {
        let mut registry = Registry::default();
        let _metrics = XdsConnectionMonitorMetrics::new(&mut registry);

        let mut encoded = String::new();
        encode(&mut encoded, &registry).unwrap();

        assert!(
            encoded.contains(
                "# HELP xds_monitor_events_lagged Total number of xDS connection-state events skipped because the freshness monitor receiver lagged (unstable)"
            ),
            "lag HELP text should describe skipped monitor events:\n{encoded}"
        );
    }

    #[test]
    fn monitor_metrics_do_not_export_policy_threshold_series() {
        let mut registry = Registry::default();
        let _metrics = XdsConnectionMonitorMetrics::new(&mut registry);

        let mut encoded = String::new();
        encode(&mut encoded, &registry).unwrap();

        assert!(
            !encoded.contains("xds_config_non_fresh_over_threshold"),
            "freshness monitor metrics should expose facts, not policy threshold gauges:\n{encoded}"
        );
        assert!(
            !encoded.contains("xds_config_non_fresh_threshold_exceeded"),
            "freshness monitor metrics should expose facts, not policy threshold counters:\n{encoded}"
        );
        assert!(
            !encoded.contains("XDS_NON_FRESH_THRESHOLD"),
            "freshness monitor metric HELP should not mention removed threshold config:\n{encoded}"
        );
    }
}

#[derive(Clone)]
pub(crate) struct XdsConnectionMonitorMetrics {
    pub(crate) non_fresh_duration: Histogram,
    pub(crate) sender_dropped: Counter,
    pub(crate) events_lagged: Counter,
    #[cfg(any(test, feature = "testing"))]
    non_fresh_observation_tx: tokio::sync::watch::Sender<u64>,
}

impl XdsConnectionMonitorMetrics {
    pub(crate) fn new(registry: &mut Registry) -> Self {
        let non_fresh_duration = Histogram::new([
            0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0,
            3600.0, 7200.0, 14400.0, 43200.0, 86400.0,
        ]);
        registry.register_with_unit(
            "xds_config_non_fresh_duration",
            "Duration of completed periods where xDS was non-fresh (unstable)",
            Unit::Seconds,
            non_fresh_duration.clone(),
        );
        let sender_dropped = Counter::default();
        registry.register(
            "xds_monitor_sender_dropped",
            "Total number of times an xDS monitor input sender dropped (unstable)",
            sender_dropped.clone(),
        );
        let events_lagged = Counter::default();
        registry.register(
            "xds_monitor_events_lagged",
            "Total number of xDS connection-state events skipped because the freshness monitor receiver lagged (unstable)",
            events_lagged.clone(),
        );
        #[cfg(any(test, feature = "testing"))]
        let (non_fresh_observation_tx, _) = tokio::sync::watch::channel(0);
        Self {
            non_fresh_duration,
            sender_dropped,
            events_lagged,
            #[cfg(any(test, feature = "testing"))]
            non_fresh_observation_tx,
        }
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn non_fresh_observation_receiver(&self) -> tokio::sync::watch::Receiver<u64> {
        self.non_fresh_observation_tx.subscribe()
    }

    #[cfg(any(test, feature = "testing"))]
    pub(crate) fn record_non_fresh_observation_for_test(&self) {
        let next = (*self.non_fresh_observation_tx.borrow()).wrapping_add(1);
        self.non_fresh_observation_tx.send_replace(next);
    }
}
