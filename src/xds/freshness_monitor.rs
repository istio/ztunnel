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

use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::readiness;

use super::{XdsConnectionMonitorMetrics, XdsConnectionState, XdsConnectionStateKind};

pub(crate) const XDS_MONITOR_DEAD_TASK: &str = "xds monitor dead";

#[derive(Clone)]
pub(crate) struct XdsStartupReadinessGate {
    inner: Arc<Mutex<XdsStartupReadinessGateInner>>,
}

struct XdsStartupReadinessGateInner {
    task: Option<readiness::BlockReady>,
}

impl XdsStartupReadinessGate {
    pub(crate) fn new(_ready: readiness::Ready, initial_task: readiness::BlockReady) -> Self {
        Self {
            inner: Arc::new(Mutex::new(XdsStartupReadinessGateInner {
                task: Some(initial_task),
            })),
        }
    }

    fn clear(&self) {
        let task = self.inner.lock().unwrap().task.take();
        drop(task);
    }

    fn replace_held_with(&self, name: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(task) = inner.task.take() else {
            return false;
        };
        inner.task = Some(task.replace_with(name));
        true
    }
}

async fn park_monitor_dead(_gate: XdsStartupReadinessGate) -> ! {
    std::future::pending().await
}

async fn fail_startup_for_sender_drop(
    gate: XdsStartupReadinessGate,
    metrics: XdsConnectionMonitorMetrics,
) -> ! {
    error!("xDS startup signal sender dropped before initial sync");
    metrics.sender_dropped.inc();
    gate.replace_held_with(XDS_MONITOR_DEAD_TASK);
    park_monitor_dead(gate).await
}

async fn fail_startup_for_monitor_exit(gate: XdsStartupReadinessGate) -> ! {
    error!("xDS freshness monitor exited before initial sync");
    gate.replace_held_with(XDS_MONITOR_DEAD_TASK);
    park_monitor_dead(gate).await
}

/// Replaces a still-held startup readiness blocker with `xds monitor dead` and
/// parks forever. If startup readiness was already cleared, the panic is logged
/// but readiness is not re-armed.
pub(crate) async fn park_monitor_dead_after_panic(gate: XdsStartupReadinessGate) -> ! {
    error!("xDS freshness monitor task panicked");
    gate.replace_held_with(XDS_MONITOR_DEAD_TASK);
    park_monitor_dead(gate).await
}

fn current_state(
    conn_state_rx: &mut tokio::sync::watch::Receiver<XdsConnectionState>,
) -> XdsConnectionState {
    *conn_state_rx.borrow_and_update()
}

enum FreshnessEvent {
    Fresh(XdsConnectionState),
    NonFresh(XdsConnectionState),
    ResyncedFresh(XdsConnectionState),
    ResyncedNonFresh(XdsConnectionState),
    Closed,
}

enum ConnectionStateEvent {
    State(XdsConnectionState),
    Resynced(XdsConnectionState),
    Closed,
}

struct XdsFreshnessMonitor {
    initial_state: XdsConnectionState,
    conn_state_rx: tokio::sync::watch::Receiver<XdsConnectionState>,
    conn_state_events_rx: broadcast::Receiver<XdsConnectionState>,
    metrics: XdsConnectionMonitorMetrics,
}

impl XdsFreshnessMonitor {
    fn new(
        initial_state: XdsConnectionState,
        conn_state_rx: tokio::sync::watch::Receiver<XdsConnectionState>,
        conn_state_events_rx: broadcast::Receiver<XdsConnectionState>,
        metrics: XdsConnectionMonitorMetrics,
    ) -> Self {
        Self {
            initial_state,
            conn_state_rx,
            conn_state_events_rx,
            metrics,
        }
    }

    fn current_state(&mut self) -> XdsConnectionState {
        current_state(&mut self.conn_state_rx)
    }

    async fn recv_connection_state(&mut self) -> ConnectionStateEvent {
        match self.conn_state_events_rx.recv().await {
            Ok(state) => ConnectionStateEvent::State(state),
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(
                    skipped,
                    "xDS freshness monitor lagged connection-state events"
                );
                self.metrics.events_lagged.inc_by(skipped);
                self.conn_state_events_rx = self.conn_state_events_rx.resubscribe();
                ConnectionStateEvent::Resynced(self.current_state())
            }
            Err(broadcast::error::RecvError::Closed) => ConnectionStateEvent::Closed,
        }
    }

    async fn wait_for_non_synced_state(
        &mut self,
        current_state: &mut XdsConnectionState,
    ) -> Option<XdsConnectionState> {
        loop {
            if current_state.kind() != XdsConnectionStateKind::Synced {
                return Some(*current_state);
            }
            *current_state = match self.recv_connection_state().await {
                ConnectionStateEvent::State(state) | ConnectionStateEvent::Resynced(state) => state,
                ConnectionStateEvent::Closed => return None,
            };
        }
    }

    async fn wait_for_freshness_after(&mut self, freshness_epoch: u64) -> FreshnessEvent {
        loop {
            let (state, resynced) = match self.recv_connection_state().await {
                ConnectionStateEvent::State(state) => (state, false),
                ConnectionStateEvent::Resynced(state) => (state, true),
                ConnectionStateEvent::Closed => return FreshnessEvent::Closed,
            };
            if state.freshness_epoch() == freshness_epoch {
                continue;
            }
            match state.kind() {
                XdsConnectionStateKind::Synced if resynced => {
                    return FreshnessEvent::ResyncedFresh(state);
                }
                XdsConnectionStateKind::Synced => return FreshnessEvent::Fresh(state),
                _ if resynced => return FreshnessEvent::ResyncedNonFresh(state),
                _ => return FreshnessEvent::NonFresh(state),
            }
        }
    }

    fn record_completed_non_fresh(
        &mut self,
        non_fresh_started_at: tokio::time::Instant,
        non_fresh_ended_at: tokio::time::Instant,
    ) -> std::time::Duration {
        let total_non_fresh = non_fresh_ended_at.saturating_duration_since(non_fresh_started_at);
        self.metrics
            .non_fresh_duration
            .observe(total_non_fresh.as_secs_f64());
        #[cfg(any(test, feature = "testing"))]
        self.metrics.record_non_fresh_observation_for_test();
        total_non_fresh
    }

    fn restore_freshness(
        &mut self,
        non_fresh_started_at: tokio::time::Instant,
        non_fresh_ended_at: tokio::time::Instant,
    ) {
        let total_non_fresh =
            self.record_completed_non_fresh(non_fresh_started_at, non_fresh_ended_at);
        info!(
            total_non_fresh_ms = total_non_fresh.as_millis() as u64,
            "xDS freshness restored"
        );
    }

    fn sender_dropped(&mut self) {
        error!("xDS freshness monitor input sender dropped");
        self.metrics.sender_dropped.inc();
    }

    async fn run(mut self) {
        let mut current_state = self.initial_state;
        'monitor: loop {
            let Some(non_fresh_state) = self.wait_for_non_synced_state(&mut current_state).await
            else {
                self.sender_dropped();
                return;
            };
            let mut non_fresh_started_at = non_fresh_state.transitioned_at();
            let mut non_fresh_started_epoch = non_fresh_state.freshness_epoch();

            loop {
                let event = self.wait_for_freshness_after(non_fresh_started_epoch).await;

                match event {
                    FreshnessEvent::Fresh(state) => {
                        self.restore_freshness(non_fresh_started_at, state.transitioned_at());
                        current_state = state;
                        continue 'monitor;
                    }
                    FreshnessEvent::ResyncedFresh(state) => {
                        info!("xDS freshness monitor resynced to fresh state after skipped epochs");
                        current_state = state;
                        continue 'monitor;
                    }
                    FreshnessEvent::NonFresh(state) => {
                        let total_non_fresh = self.record_completed_non_fresh(
                            non_fresh_started_at,
                            state.transitioned_at(),
                        );
                        info!(
                            total_non_fresh_ms = total_non_fresh.as_millis() as u64,
                            "xDS freshness epoch advanced before another non-fresh state"
                        );
                        non_fresh_started_at = state.transitioned_at();
                        non_fresh_started_epoch = state.freshness_epoch();
                    }
                    FreshnessEvent::ResyncedNonFresh(state) => {
                        info!(
                            "xDS freshness monitor resynced to non-fresh state after skipped fresh epoch"
                        );
                        non_fresh_started_at = state.transitioned_at();
                        non_fresh_started_epoch = state.freshness_epoch();
                    }
                    FreshnessEvent::Closed => {
                        self.sender_dropped();
                        return;
                    }
                }
            }
        }
    }
}

/// Updates xDS freshness metrics from the xDS connection state stream.
pub(crate) async fn run_freshness_monitor(
    initial_state: XdsConnectionState,
    conn_state_rx: tokio::sync::watch::Receiver<XdsConnectionState>,
    conn_state_events_rx: broadcast::Receiver<XdsConnectionState>,
    metrics: XdsConnectionMonitorMetrics,
) {
    XdsFreshnessMonitor::new(initial_state, conn_state_rx, conn_state_events_rx, metrics)
        .run()
        .await;
}

/// Starts the freshness metrics monitor and independently waits for startup xDS
/// sync before clearing readiness. The monitor reports xDS freshness facts, but
/// it does not re-arm readiness after startup.
pub(crate) async fn run_xds_monitor_task(
    xds_connection_initial_state: Option<XdsConnectionState>,
    xds_connection_state_rx: Option<tokio::sync::watch::Receiver<XdsConnectionState>>,
    xds_connection_state_events_rx: Option<broadcast::Receiver<XdsConnectionState>>,
    mut xds_rx_for_task: tokio::sync::watch::Receiver<()>,
    readiness_gate: XdsStartupReadinessGate,
    xds_monitor_metrics: Option<XdsConnectionMonitorMetrics>,
) {
    match xds_connection_state_rx {
        Some(conn_state_rx) => {
            let initial_state = xds_connection_initial_state
                .expect("remote xDS freshness monitor requires initial state");
            let xds_monitor_metrics =
                xds_monitor_metrics.expect("remote xDS freshness monitor requires metrics");
            let conn_state_events_rx = xds_connection_state_events_rx
                .expect("remote xDS freshness monitor requires connection-state events");
            let startup_metrics = xds_monitor_metrics.clone();
            let monitor = run_freshness_monitor(
                initial_state,
                conn_state_rx,
                conn_state_events_rx,
                xds_monitor_metrics,
            );
            tokio::pin!(monitor);

            tokio::select! {
                biased;
                changed = xds_rx_for_task.changed() => {
                    if changed.is_err() {
                        fail_startup_for_sender_drop(readiness_gate, startup_metrics).await;
                    }
                    readiness_gate.clear();
                }
                () = &mut monitor => {
                    fail_startup_for_monitor_exit(readiness_gate).await;
                }
            }

            monitor.await;
        }
        None => {
            // No remote xDS client owns this startup signal in local-only
            // mode; sender drop means local config loading already completed
            // or build would have returned an error.
            let _ = xds_rx_for_task.changed().await;
            readiness_gate.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use prometheus_client::registry::Registry;

    use super::*;
    use crate::readiness;
    use crate::xds::XdsConnectionState;

    #[tokio::test]
    async fn test_startup_sender_drop_blocks_readiness_permanently() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsStartupReadinessGate::new(ready.clone(), state_mgr_task);
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (xds_tx, xds_rx) = tokio::sync::watch::channel(());
        let (_state_tx, _state_events_tx, conn_state_rx, conn_state_events_rx) =
            state_channels(XdsConnectionState::initializing());

        drop(xds_tx);
        let initial_state = *conn_state_rx.borrow();
        let monitor = tokio::spawn(run_xds_monitor_task(
            Some(initial_state),
            Some(conn_state_rx),
            Some(conn_state_events_rx),
            xds_rx,
            gate,
            Some(metrics),
        ));

        tokio::task::yield_now().await;
        let pending = ready.pending();
        assert!(
            pending.contains(XDS_MONITOR_DEAD_TASK),
            "xDS monitor dead readiness task was not registered after startup sender drop"
        );
        assert!(
            !pending.contains("state manager"),
            "state manager blocker was not replaced after startup sender drop"
        );
        assert_sender_dropped_total(&registry, 1);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test]
    async fn test_startup_signal_wins_when_monitor_exits_at_same_time() {
        for _ in 0..64 {
            let ready = readiness::Ready::new();
            let state_mgr_task = ready.register_task("state manager");
            let gate = XdsStartupReadinessGate::new(ready.clone(), state_mgr_task);
            let mut registry = Registry::default();
            let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
            let (xds_tx, xds_rx) = tokio::sync::watch::channel(());
            let (state_tx, state_events_tx, state_rx, state_events_rx) =
                state_channels(XdsConnectionState::initializing());

            xds_tx.send_replace(());
            drop(state_tx);
            drop(state_events_tx);

            let initial_state = *state_rx.borrow();
            let monitor = tokio::spawn(run_xds_monitor_task(
                Some(initial_state),
                Some(state_rx),
                Some(state_events_rx),
                xds_rx,
                gate,
                Some(metrics),
            ));

            tokio::task::yield_now().await;
            assert!(
                ready.pending().is_empty(),
                "startup signal must clear readiness when monitor exit is also ready"
            );
            if monitor.is_finished() {
                monitor.await.expect("xDS monitor task panicked");
            } else {
                abort_monitor_for_test(monitor).await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_monitor_records_startup_non_fresh_duration_without_policy_metrics() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsStartupReadinessGate::new(ready.clone(), state_mgr_task);
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (xds_tx, xds_rx) = tokio::sync::watch::channel(());
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels(XdsConnectionState::initializing());

        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_xds_monitor_task(
            Some(initial_state),
            Some(state_rx),
            Some(state_events_rx),
            xds_rx,
            gate,
            Some(metrics),
        ));

        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        assert_pending_tasks(&ready, &["state manager"]);
        assert_metric_absent(&registry, "xds_config_non_fresh_over_threshold");
        assert_metric_absent(&registry, "xds_config_non_fresh_threshold_exceeded");

        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(1));
        xds_tx.send_replace(());
        tokio::task::yield_now().await;

        assert!(ready.pending().is_empty());
        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 1);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test]
    async fn test_panic_path_does_not_rearm_readiness_after_startup() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsStartupReadinessGate::new(ready.clone(), state_mgr_task);

        gate.clear();
        let monitor = tokio::spawn(park_monitor_dead_after_panic(gate));

        tokio::task::yield_now().await;
        assert!(
            ready.pending().is_empty(),
            "post-startup monitor panic must not re-arm readiness"
        );

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test]
    async fn test_panic_path_replaces_startup_blocker_before_startup() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsStartupReadinessGate::new(ready.clone(), state_mgr_task);

        let monitor = tokio::spawn(park_monitor_dead_after_panic(gate));

        tokio::task::yield_now().await;
        assert_pending_tasks(&ready, &[XDS_MONITOR_DEAD_TASK]);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_keeps_readiness_ready_while_non_fresh() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels(XdsConnectionState::synced(1));
        gate_after_startup(&ready);

        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        assert!(
            ready.pending().is_empty(),
            "freshness monitor must not re-arm readiness after startup"
        );
        assert_metric_absent(&registry, "xds_config_non_fresh_over_threshold");
        assert_metric_absent(&registry, "xds_config_non_fresh_threshold_exceeded");

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_records_duration_on_restored_freshness() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels(XdsConnectionState::synced(1));
        gate_after_startup(&ready);

        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(2));
        tokio::task::yield_now().await;

        assert!(ready.pending().is_empty());
        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 1);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_records_coalesced_disconnect_sync() {
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels(XdsConnectionState::synced(1));

        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(2));
        tokio::task::yield_now().await;

        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 1);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_tracks_duration() {
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels(XdsConnectionState::synced(1));

        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        tokio::task::yield_now().await;
        assert_metric_absent(&registry, "xds_config_non_fresh_over_threshold");
        assert_metric_absent(&registry, "xds_config_non_fresh_threshold_exceeded");

        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(2));
        tokio::task::yield_now().await;
        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 1);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test]
    async fn test_freshness_monitor_sender_drop_after_startup_records_sender_drop_only() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels(XdsConnectionState::synced(1));
        gate_after_startup(&ready);

        drop(state_tx);
        drop(state_events_tx);

        let initial_state = *state_rx.borrow();
        run_freshness_monitor(initial_state, state_rx, state_events_rx, metrics).await;

        assert!(
            ready.pending().is_empty(),
            "freshness monitor input closure after startup must not re-arm readiness"
        );
        assert_metric_line(&registry, "xds_monitor_sender_dropped_total", 1);
        assert_metric_line(&registry, "xds_monitor_events_lagged_total", 0);
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_lag_uses_lag_metric_and_resyncs_snapshot() {
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels_with_capacity(XdsConnectionState::synced(1), 1);
        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(2));
        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(2),
        );
        tokio::task::yield_now().await;

        assert_metric_line(&registry, "xds_monitor_events_lagged_total", 1);
        assert_metric_line(&registry, "xds_monitor_sender_dropped_total", 0);
        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 0);

        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(3));
        tokio::task::yield_now().await;
        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 1);
        let sum = metric_value_f64(&registry, "xds_config_non_fresh_duration_seconds_sum")
            .expect("duration histogram sum must be exported");
        assert!(
            sum.abs() < f64::EPSILON,
            "lag recovery must not record skipped fresh time as non-fresh duration, got {sum}"
        );

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_lag_resynced_fresh_drops_ambiguous_duration() {
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels_with_capacity(XdsConnectionState::synced(1), 1);
        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(10)).await;

        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(2));
        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(2),
        );
        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(3));
        tokio::task::yield_now().await;

        assert_metric_line(&registry, "xds_monitor_events_lagged_total", 2);
        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 0);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_lag_does_not_replay_stale_retained_events() {
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels_with_capacity(XdsConnectionState::synced(1), 2);

        let initial_state = *state_rx.borrow();
        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(2));
        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(2),
        );
        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(3));
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }

        assert_metric_line(&registry, "xds_monitor_events_lagged_total", 2);
        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 0);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_starts_from_ordered_initial_state() {
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let initial_state =
            XdsConnectionState::initializing().with_transitioned_at(tokio::time::Instant::now());
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels_with_capacity(initial_state, 16);

        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::connected(0),
        );
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(1));
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );

        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }

        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 1);
        let sum = metric_value_f64(&registry, "xds_config_non_fresh_duration_seconds_sum")
            .expect("duration histogram sum must be exported");
        assert!(
            (sum - 15.0).abs() < f64::EPSILON,
            "duration histogram should process retained states in publish order, got {sum}"
        );

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_freshness_monitor_uses_publish_time_for_queued_duration() {
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let initial_state = XdsConnectionState::synced(1);
        let (state_tx, state_events_tx, state_rx, state_events_rx) =
            state_channels_with_capacity(initial_state, 16);

        send_state(
            &state_tx,
            &state_events_tx,
            XdsConnectionState::disconnected(1),
        );
        tokio::time::advance(std::time::Duration::from_secs(10)).await;
        send_state(&state_tx, &state_events_tx, XdsConnectionState::synced(2));
        tokio::time::advance(std::time::Duration::from_secs(60)).await;

        let monitor = tokio::spawn(run_freshness_monitor(
            initial_state,
            state_rx,
            state_events_rx,
            metrics,
        ));
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }

        assert_metric_line(&registry, "xds_config_non_fresh_duration_seconds_count", 1);
        let sum = metric_value_f64(&registry, "xds_config_non_fresh_duration_seconds_sum")
            .expect("duration histogram sum must be exported");
        assert!(
            (sum - 10.0).abs() < f64::EPSILON,
            "duration histogram should use xDS publish time, got {sum}"
        );

        abort_monitor_for_test(monitor).await;
    }

    fn state_channels(
        initial_state: XdsConnectionState,
    ) -> (
        tokio::sync::watch::Sender<XdsConnectionState>,
        broadcast::Sender<XdsConnectionState>,
        tokio::sync::watch::Receiver<XdsConnectionState>,
        broadcast::Receiver<XdsConnectionState>,
    ) {
        state_channels_with_capacity(initial_state, 16)
    }

    fn state_channels_with_capacity(
        initial_state: XdsConnectionState,
        event_capacity: usize,
    ) -> (
        tokio::sync::watch::Sender<XdsConnectionState>,
        broadcast::Sender<XdsConnectionState>,
        tokio::sync::watch::Receiver<XdsConnectionState>,
        broadcast::Receiver<XdsConnectionState>,
    ) {
        let (state_tx, state_rx) = tokio::sync::watch::channel(initial_state);
        let (state_events_tx, state_events_rx) = broadcast::channel(event_capacity);
        (state_tx, state_events_tx, state_rx, state_events_rx)
    }

    fn send_state(
        state_tx: &tokio::sync::watch::Sender<XdsConnectionState>,
        state_events_tx: &broadcast::Sender<XdsConnectionState>,
        state: XdsConnectionState,
    ) {
        let state = state.with_transitioned_at(tokio::time::Instant::now());
        state_tx.send_replace(state);
        state_events_tx
            .send(state)
            .expect("test connection-state event receiver should be alive");
    }

    async fn abort_monitor_for_test<T>(monitor: tokio::task::JoinHandle<T>) {
        assert!(
            !monitor.is_finished(),
            "xDS monitor task exited before test cleanup"
        );
        monitor.abort();
        match monitor.await {
            Err(err) if err.is_cancelled() => {}
            Ok(_) => panic!("xDS monitor task exited before cancellation"),
            Err(err) if err.is_panic() => {
                panic!("xDS monitor task panicked before cancellation: {err:?}")
            }
            Err(err) => panic!("xDS monitor task failed before cancellation: {err:?}"),
        }
    }

    fn gate_after_startup(ready: &readiness::Ready) -> XdsStartupReadinessGate {
        let startup_task = ready.register_task("state manager");
        let gate = XdsStartupReadinessGate::new(ready.clone(), startup_task);
        gate.clear();
        gate
    }

    fn assert_sender_dropped_total(registry: &Registry, expected: u64) {
        assert_metric_line(registry, "xds_monitor_sender_dropped_total", expected);
    }

    fn assert_metric_line(registry: &Registry, metric: &str, expected: u64) {
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, registry).unwrap();
        let expected_line = format!("{metric} {expected}");
        assert!(
            encoded.lines().any(|line| line == expected_line),
            "expected metric line `{expected_line}`, got:\n{encoded}"
        );
    }

    fn assert_metric_absent(registry: &Registry, metric: &str) {
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, registry).unwrap();
        assert!(
            !encoded.contains(metric),
            "did not expect metric `{metric}`, got:\n{encoded}"
        );
    }

    fn metric_value_f64(registry: &Registry, metric: &str) -> Option<f64> {
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, registry).unwrap();
        let prefix = format!("{metric} ");
        encoded
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .and_then(|value| value.parse().ok())
    }

    fn assert_pending_tasks(ready: &readiness::Ready, expected: &[&str]) {
        let pending = ready.pending();
        let expected: std::collections::HashSet<String> =
            expected.iter().map(|task| task.to_string()).collect();
        assert_eq!(
            pending, expected,
            "readiness pending tasks did not match expected set"
        );
    }
}
