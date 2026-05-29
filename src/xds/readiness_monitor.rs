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

use tracing::{error, info, warn};

use crate::readiness;

use super::{XdsConnectionMonitorMetrics, XdsConnectionState, XdsConnectionStateKind};

pub(crate) const XDS_FRESHNESS_TASK: &str = "xds freshness";
pub(crate) const XDS_MONITOR_DEAD_TASK: &str = "xds monitor dead";

#[derive(Clone)]
pub(crate) struct XdsReadinessGate {
    inner: Arc<Mutex<XdsReadinessGateInner>>,
}

struct XdsReadinessGateInner {
    ready: readiness::Ready,
    task: Option<readiness::BlockReady>,
}

impl XdsReadinessGate {
    pub(crate) fn new(ready: readiness::Ready, initial_task: readiness::BlockReady) -> Self {
        Self {
            inner: Arc::new(Mutex::new(XdsReadinessGateInner {
                ready,
                task: Some(initial_task),
            })),
        }
    }

    fn block(&self, name: &str) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if inner.task.is_some() {
            return false;
        }
        let task = inner.ready.register_task(name);
        inner.task = Some(task);
        true
    }

    fn clear(&self) {
        let task = self.inner.lock().unwrap().task.take();
        drop(task);
    }

    fn replace_with(&self, name: &str) {
        let mut inner = self.inner.lock().unwrap();
        let replacement = match inner.task.take() {
            Some(task) => task.replace_with(name),
            None => inner.ready.register_task(name),
        };
        inner.task = Some(replacement);
    }
}

async fn park_monitor_dead(_gate: XdsReadinessGate) -> ! {
    std::future::pending().await
}

async fn fail_monitor_for_sender_drop(
    gate: XdsReadinessGate,
    metrics: XdsConnectionMonitorMetrics,
) -> ! {
    error!("xDS readiness monitor input sender dropped; readiness rearm monitor exiting");
    metrics.sender_dropped.inc();
    gate.replace_with(XDS_MONITOR_DEAD_TASK);
    park_monitor_dead(gate).await
}

/// Registers a permanent `xds monitor dead` blocker and parks forever.
///
/// Intended for use as a panic-recovery supervisor wrapping the spawned
/// `run_readiness_task` future. The readiness gate is owned outside the
/// unwinding future, so an existing startup/freshness blocker can be replaced
/// without first dropping readiness open.
pub(crate) async fn park_monitor_dead_after_panic(gate: XdsReadinessGate) -> ! {
    error!("xDS readiness monitor task panicked; readiness rearm monitor exiting");
    gate.replace_with(XDS_MONITOR_DEAD_TASK);
    park_monitor_dead(gate).await
}

fn current_state(
    conn_state_rx: &mut tokio::sync::watch::Receiver<XdsConnectionState>,
) -> XdsConnectionState {
    *conn_state_rx.borrow_and_update()
}

enum FreshnessEvent {
    Fresh,
    NonFresh(XdsConnectionState),
    Closed,
}

fn classify_observed_freshness(
    state: XdsConnectionState,
    freshness_epoch: u64,
    has_changed: Result<bool, tokio::sync::watch::error::RecvError>,
) -> Option<FreshnessEvent> {
    if state.freshness_epoch() == freshness_epoch {
        return None;
    }
    match has_changed {
        Err(_) => Some(FreshnessEvent::Closed),
        Ok(true) => None,
        Ok(false) => Some(match state.kind() {
            XdsConnectionStateKind::Synced => FreshnessEvent::Fresh,
            _ => FreshnessEvent::NonFresh(state),
        }),
    }
}

struct XdsReadinessReconciler {
    threshold: std::time::Duration,
    conn_state_rx: tokio::sync::watch::Receiver<XdsConnectionState>,
    gate: XdsReadinessGate,
    metrics: XdsConnectionMonitorMetrics,
}

impl XdsReadinessReconciler {
    fn new(
        threshold: std::time::Duration,
        conn_state_rx: tokio::sync::watch::Receiver<XdsConnectionState>,
        gate: XdsReadinessGate,
        metrics: XdsConnectionMonitorMetrics,
    ) -> Self {
        Self {
            threshold,
            conn_state_rx,
            gate,
            metrics,
        }
    }

    async fn wait_for_non_synced_state(&mut self) -> Option<XdsConnectionState> {
        loop {
            let state = current_state(&mut self.conn_state_rx);
            if state.kind() != XdsConnectionStateKind::Synced {
                return Some(state);
            }
            self.conn_state_rx.changed().await.ok()?;
        }
    }

    async fn wait_for_freshness_after(&mut self, freshness_epoch: u64) -> FreshnessEvent {
        loop {
            let state = current_state(&mut self.conn_state_rx);
            if let Some(event) = classify_observed_freshness(
                state,
                freshness_epoch,
                self.conn_state_rx.has_changed(),
            ) {
                return event;
            }
            if self.conn_state_rx.changed().await.is_err() {
                return FreshnessEvent::Closed;
            }
        }
    }

    fn block_readiness(&mut self, non_fresh_started_at: tokio::time::Instant) {
        if !self.gate.block(XDS_FRESHNESS_TASK) {
            return;
        }

        warn!(
            non_fresh_duration_ms = non_fresh_started_at.elapsed().as_millis() as u64,
            threshold_ms = self.threshold.as_millis() as u64,
            "xDS freshness threshold exceeded; marking not ready"
        );
        self.metrics.readiness_rearmed.inc();
    }

    fn restore_readiness(&mut self, non_fresh_started_at: tokio::time::Instant) {
        let total_non_fresh_ms = non_fresh_started_at.elapsed().as_millis() as u64;
        self.gate.clear();
        info!(total_non_fresh_ms, "xDS resynced; marking ready");
    }

    async fn fail_closed(self) -> ! {
        fail_monitor_for_sender_drop(self.gate, self.metrics).await
    }

    async fn run(mut self) {
        'monitor: loop {
            let Some(mut non_fresh_state) = self.wait_for_non_synced_state().await else {
                self.fail_closed().await;
            };

            loop {
                let non_fresh_started_at = tokio::time::Instant::now();
                let non_fresh_started_epoch = non_fresh_state.freshness_epoch();

                let reconnected_in_time = tokio::time::timeout(
                    self.threshold,
                    self.wait_for_freshness_after(non_fresh_started_epoch),
                )
                .await;
                match reconnected_in_time {
                    Ok(FreshnessEvent::Fresh) => continue 'monitor,
                    Ok(FreshnessEvent::NonFresh(state)) => {
                        non_fresh_state = state;
                        continue;
                    }
                    Ok(FreshnessEvent::Closed) => {
                        self.fail_closed().await;
                    }
                    Err(_elapsed) => { /* threshold exceeded; fall through to rearm */ }
                }

                self.block_readiness(non_fresh_started_at);

                let mut blocked_epoch = non_fresh_started_epoch;
                loop {
                    match self.wait_for_freshness_after(blocked_epoch).await {
                        FreshnessEvent::Fresh => {
                            self.restore_readiness(non_fresh_started_at);
                            continue 'monitor;
                        }
                        FreshnessEvent::NonFresh(state) => {
                            blocked_epoch = state.freshness_epoch();
                        }
                        FreshnessEvent::Closed => self.fail_closed().await,
                    }
                }
            }
        }
    }
}

/// Re-blocks readiness if xDS stays non-fresh for longer than `threshold`,
/// and unblocks once the current stream has ACKed at least one xDS response.
pub(crate) async fn run_unhealthy_monitor(
    threshold: std::time::Duration,
    conn_state_rx: tokio::sync::watch::Receiver<XdsConnectionState>,
    gate: XdsReadinessGate,
    metrics: XdsConnectionMonitorMetrics,
) {
    XdsReadinessReconciler::new(threshold, conn_state_rx, gate, metrics)
        .run()
        .await;
}

/// Waits for startup xDS sync, then starts the steady-state readiness monitor.
pub(crate) async fn run_readiness_task(
    xds_connection_state_rx: Option<tokio::sync::watch::Receiver<XdsConnectionState>>,
    mut xds_rx_for_task: tokio::sync::watch::Receiver<()>,
    readiness_gate: XdsReadinessGate,
    xds_unhealthy_threshold: Option<std::time::Duration>,
    xds_monitor_metrics: XdsConnectionMonitorMetrics,
) {
    match xds_connection_state_rx {
        Some(conn_state_rx) => {
            if xds_rx_for_task.changed().await.is_err() {
                fail_monitor_for_sender_drop(readiness_gate, xds_monitor_metrics).await;
            }
            readiness_gate.clear();

            let Some(threshold) = xds_unhealthy_threshold else {
                return;
            };
            run_unhealthy_monitor(
                threshold,
                conn_state_rx,
                readiness_gate,
                xds_monitor_metrics,
            )
            .await;
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

    #[test]
    fn test_freshness_event_defers_stale_synced_snapshot() {
        let event = classify_observed_freshness(XdsConnectionState::synced(2), 1, Ok(true));

        assert!(
            event.is_none(),
            "a Synced snapshot with a pending newer watch value must be reread before restoring readiness"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_xds_readiness_monitor_sender_drop_replaces_held_freshness_task() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_rx) = tokio::sync::watch::channel(XdsConnectionState::synced(1));
        let threshold = std::time::Duration::from_secs(10);
        let gate = gate_after_startup(&ready);

        let monitor = tokio::spawn(run_unhealthy_monitor(threshold, state_rx, gate, metrics));

        state_tx.send_replace(XdsConnectionState::disconnected(1));
        tokio::task::yield_now().await;
        tokio::time::advance(threshold).await;
        tokio::task::yield_now().await;
        assert!(
            ready.pending().contains(XDS_FRESHNESS_TASK),
            "freshness task did not fire after threshold"
        );

        drop(state_tx);
        tokio::task::yield_now().await;
        let pending = ready.pending();
        assert!(
            pending.contains(XDS_MONITOR_DEAD_TASK),
            "xDS monitor dead readiness task was not registered after sender drop"
        );
        assert!(
            !pending.contains(XDS_FRESHNESS_TASK),
            "freshness task was not replaced after sender drop"
        );
        assert_sender_dropped_total(&registry, 1);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test]
    async fn test_xds_readiness_monitor_sender_drop_blocks_readiness_permanently() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let gate = gate_after_startup(&ready);

        let monitor = tokio::spawn(fail_monitor_for_sender_drop(gate, metrics));

        tokio::task::yield_now().await;
        assert!(
            ready.pending().contains(XDS_MONITOR_DEAD_TASK),
            "xDS monitor dead readiness task was not registered"
        );

        assert_sender_dropped_total(&registry, 1);

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test]
    async fn test_xds_readiness_monitor_panic_path_does_not_count_sender_drop() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsReadinessGate::new(ready.clone(), state_mgr_task);
        let mut registry = Registry::default();
        let _metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);

        let monitor = tokio::spawn(park_monitor_dead_after_panic(gate));

        tokio::task::yield_now().await;
        assert_pending_tasks(&ready, &[XDS_MONITOR_DEAD_TASK]);
        assert_sender_dropped_total(&registry, 0);

        abort_monitor_for_test(monitor).await;
    }

    #[test]
    fn test_xds_readiness_gate_replaces_existing_blocker_with_monitor_dead() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsReadinessGate::new(ready.clone(), state_mgr_task);

        assert_pending_tasks(&ready, &["state manager"]);

        gate.replace_with(XDS_MONITOR_DEAD_TASK);

        assert_pending_tasks(&ready, &[XDS_MONITOR_DEAD_TASK]);
    }

    #[tokio::test]
    async fn test_xds_readiness_monitor_startup_sender_drop_blocks_readiness_permanently() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsReadinessGate::new(ready.clone(), state_mgr_task);
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (xds_tx, xds_rx) = tokio::sync::watch::channel(());
        let (_conn_state_tx, conn_state_rx) =
            tokio::sync::watch::channel(XdsConnectionState::initializing());

        drop(xds_tx);
        let monitor = tokio::spawn(run_readiness_task(
            Some(conn_state_rx),
            xds_rx,
            gate,
            None,
            metrics,
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
    async fn test_run_readiness_task_exits_after_startup_when_threshold_unset() {
        let ready = readiness::Ready::new();
        let state_mgr_task = ready.register_task("state manager");
        let gate = XdsReadinessGate::new(ready.clone(), state_mgr_task);
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (xds_tx, xds_rx) = tokio::sync::watch::channel(());
        let (conn_state_tx, conn_state_rx) =
            tokio::sync::watch::channel(XdsConnectionState::initializing());

        let monitor = tokio::spawn(run_readiness_task(
            Some(conn_state_rx),
            xds_rx,
            gate,
            None,
            metrics,
        ));

        xds_tx.send_replace(());
        tokio::time::timeout(std::time::Duration::from_secs(1), monitor)
            .await
            .expect("readiness task should exit after startup sync when threshold is unset")
            .expect("readiness task should join cleanly");

        conn_state_tx.send_replace(XdsConnectionState::disconnected(1));
        tokio::task::yield_now().await;
        assert!(
            ready.pending().is_empty(),
            "no steady-state xDS freshness task should remain when threshold is unset"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_xds_readiness_monitor_restores_readiness_from_watch_state() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_rx) = tokio::sync::watch::channel(XdsConnectionState::synced(1));
        let threshold = std::time::Duration::from_secs(10);
        let gate = gate_after_startup(&ready);

        let monitor = tokio::spawn(run_unhealthy_monitor(threshold, state_rx, gate, metrics));

        state_tx.send_replace(XdsConnectionState::disconnected(1));
        tokio::task::yield_now().await;
        tokio::time::advance(threshold).await;
        tokio::task::yield_now().await;

        assert!(
            ready.pending().contains(XDS_FRESHNESS_TASK),
            "xDS freshness readiness task was not registered after threshold"
        );

        state_tx.send_replace(XdsConnectionState::synced(2));
        tokio::task::yield_now().await;

        assert!(
            ready.pending().is_empty(),
            "xDS freshness readiness task was not cleared after Synced"
        );

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_xds_readiness_monitor_restores_readiness_after_epoch_wrap() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_rx) =
            tokio::sync::watch::channel(XdsConnectionState::disconnected(u64::MAX));
        let threshold = std::time::Duration::from_secs(10);
        let gate = gate_after_startup(&ready);

        let monitor = tokio::spawn(run_unhealthy_monitor(threshold, state_rx, gate, metrics));

        tokio::task::yield_now().await;
        tokio::time::advance(threshold).await;
        tokio::task::yield_now().await;
        assert!(
            ready.pending().contains(XDS_FRESHNESS_TASK),
            "xDS freshness readiness task was not registered after threshold"
        );

        state_tx.send_replace(XdsConnectionState::synced(0));
        tokio::task::yield_now().await;

        assert!(
            ready.pending().is_empty(),
            "wrapped freshness epoch did not clear xDS freshness readiness task"
        );

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_xds_monitor_rearms_on_coalesced_disconnect_to_connected() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_rx) = tokio::sync::watch::channel(XdsConnectionState::synced(1));
        let threshold = std::time::Duration::from_secs(10);
        let gate = gate_after_startup(&ready);

        let monitor = tokio::spawn(run_unhealthy_monitor(threshold, state_rx, gate, metrics));

        state_tx.send_replace(XdsConnectionState::disconnected(1));
        state_tx.send_replace(XdsConnectionState::connected(1));
        tokio::task::yield_now().await;
        tokio::time::advance(threshold).await;
        tokio::task::yield_now().await;

        assert!(
            ready.pending().contains(XDS_FRESHNESS_TASK),
            "xDS freshness readiness task was not registered after coalesced reconnect"
        );

        state_tx.send_replace(XdsConnectionState::synced(2));
        tokio::task::yield_now().await;

        assert!(
            ready.pending().is_empty(),
            "xDS freshness readiness task was not cleared after coalesced reconnect"
        );

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_xds_monitor_resets_threshold_on_coalesced_sync_disconnect() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_rx) = tokio::sync::watch::channel(XdsConnectionState::synced(1));
        let threshold = std::time::Duration::from_secs(10);
        let gate = gate_after_startup(&ready);

        let monitor = tokio::spawn(run_unhealthy_monitor(threshold, state_rx, gate, metrics));

        state_tx.send_replace(XdsConnectionState::disconnected(1));
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(9)).await;
        tokio::task::yield_now().await;
        assert!(
            !ready.pending().contains(XDS_FRESHNESS_TASK),
            "freshness task fired before the configured threshold"
        );

        state_tx.send_replace(XdsConnectionState::synced(2));
        state_tx.send_replace(XdsConnectionState::disconnected(2));
        tokio::task::yield_now().await;

        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(
            !ready.pending().contains(XDS_FRESHNESS_TASK),
            "freshness task fired from the stale pre-ACK timer"
        );

        tokio::time::advance(std::time::Duration::from_secs(8)).await;
        tokio::task::yield_now().await;
        assert!(
            ready.pending().contains(XDS_FRESHNESS_TASK),
            "freshness task did not fire after the reset threshold elapsed"
        );

        abort_monitor_for_test(monitor).await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_xds_monitor_stays_rearmed_on_coalesced_post_rearm_sync_disconnect() {
        let ready = readiness::Ready::new();
        let mut registry = Registry::default();
        let metrics = crate::xds::XdsConnectionMonitorMetrics::new(&mut registry);
        let (state_tx, state_rx) = tokio::sync::watch::channel(XdsConnectionState::synced(1));
        let threshold = std::time::Duration::from_secs(10);
        let gate = gate_after_startup(&ready);

        let monitor = tokio::spawn(run_unhealthy_monitor(threshold, state_rx, gate, metrics));

        state_tx.send_replace(XdsConnectionState::disconnected(1));
        tokio::task::yield_now().await;
        tokio::time::advance(threshold).await;
        tokio::task::yield_now().await;
        assert!(
            ready.pending().contains(XDS_FRESHNESS_TASK),
            "freshness task did not fire after threshold"
        );

        state_tx.send_replace(XdsConnectionState::synced(2));
        state_tx.send_replace(XdsConnectionState::disconnected(2));
        tokio::task::yield_now().await;
        assert!(
            ready.pending().contains(XDS_FRESHNESS_TASK),
            "coalesced non-synced state must not clear freshness task after rearm"
        );

        state_tx.send_replace(XdsConnectionState::synced(3));
        tokio::task::yield_now().await;
        assert!(
            ready.pending().is_empty(),
            "freshness task should clear after a later visible Synced state"
        );

        abort_monitor_for_test(monitor).await;
    }

    async fn abort_monitor_for_test<T>(monitor: tokio::task::JoinHandle<T>) {
        assert!(
            !monitor.is_finished(),
            "xDS readiness monitor task exited before test cleanup"
        );
        monitor.abort();
        match monitor.await {
            Err(err) if err.is_cancelled() => {}
            Ok(_) => panic!("xDS readiness monitor task exited before cancellation"),
            Err(err) if err.is_panic() => {
                panic!("xDS readiness monitor task panicked before cancellation: {err:?}")
            }
            Err(err) => panic!("xDS readiness monitor task failed before cancellation: {err:?}"),
        }
    }

    fn gate_after_startup(ready: &readiness::Ready) -> XdsReadinessGate {
        let startup_task = ready.register_task("state manager");
        let gate = XdsReadinessGate::new(ready.clone(), startup_task);
        gate.clear();
        gate
    }

    fn assert_sender_dropped_total(registry: &Registry, expected: u64) {
        let mut encoded = String::new();
        prometheus_client::encoding::text::encode(&mut encoded, registry).unwrap();
        let expected_line = format!("xds_monitor_sender_dropped_total {expected}");
        assert!(
            encoded.lines().any(|line| line == expected_line),
            "expected sender drop metric line `{expected_line}`, got:\n{encoded}"
        );
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
