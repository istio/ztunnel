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

use crate::drain;
use crate::drain::DrainTrigger;
use std::sync::Arc;
use tracing::{Instrument, debug, info};

use super::{Error, WorkloadMessage, metrics::Metrics};

use crate::proxyfactory::ProxyFactory;
use crate::state::WorkloadInfo;

use super::config::InPodConfig;

use super::WorkloadUid;
use super::netns::{InpodNetns, NetnsID};

// Note: we can't drain on drop, as drain is async (it waits for the drain to finish).
pub(super) struct WorkloadState {
    drain: DrainTrigger,
    netns_id: NetnsID,
}

#[derive(Default)]
struct DrainingTasks {
    draining: Vec<tokio::task::JoinHandle<()>>,
}

impl DrainingTasks {
    fn shutdown_workload(&mut self, workload_state: WorkloadState) {
        // Workload is gone, so no need to gracefully clean it up
        let handle = tokio::spawn(
            workload_state
                .drain
                .start_drain_and_wait(drain::DrainMode::Immediate),
        );
        // before we push to draining, try to clear done entries, so the vector doesn't grow too much
        self.draining.retain(|x| !x.is_finished());
        // add deleted pod to draining. we do this so we make sure to wait for it incase we
        // get the global drain signal.
        self.draining.push(handle);
    }

    async fn join(self) {
        futures::future::join_all(self.draining).await;
    }
}

pub struct WorkloadProxyManagerState {
    proxy_gen: ProxyFactory,
    metrics: Arc<Metrics>,
    admin_handler: Arc<super::admin::WorkloadManagerAdminHandler>,
    // use hashbrown for extract_if
    workload_states: hashbrown::HashMap<WorkloadUid, WorkloadState>,

    // workloads we wanted to start but couldn't because we had an error starting them.
    // This happened to use mainly in testing when we redeploy ztunnel, and the old pod was
    // not completely drained yet.
    pending_workloads: hashbrown::HashMap<WorkloadUid, (WorkloadInfo, InpodNetns)>,
    draining: DrainingTasks,

    // new connection stuff
    snapshot_received: bool,
    snapshot_names: std::collections::HashSet<WorkloadUid>,

    inpod_config: InPodConfig,
}

impl WorkloadProxyManagerState {
    pub fn new(
        proxy_gen: ProxyFactory,
        inpod_config: InPodConfig,
        metrics: Arc<Metrics>,
        admin_handler: Arc<super::admin::WorkloadManagerAdminHandler>,
    ) -> Self {
        WorkloadProxyManagerState {
            proxy_gen,
            metrics,
            admin_handler,
            workload_states: Default::default(),
            pending_workloads: Default::default(),
            draining: Default::default(),

            snapshot_received: false,
            snapshot_names: Default::default(),
            inpod_config,
        }
    }

    #[cfg(test)] // only used in tests, so added this to avoid warning
    pub(super) fn workload_states(&self) -> &hashbrown::HashMap<WorkloadUid, WorkloadState> {
        &self.workload_states
    }

    // Call this on new connection
    pub fn reset_snapshot(&mut self) {
        self.snapshot_names.clear();
        self.pending_workloads.clear();
        self.snapshot_received = false;
    }

    pub async fn process_msg(&mut self, msg: WorkloadMessage) -> Result<(), Error> {
        match msg {
            WorkloadMessage::AddWorkload(poddata) => {
                info!(
                    uid = poddata.workload_uid.0,
                    name = poddata
                        .workload_info
                        .as_ref()
                        .map(|w| w.name.as_str())
                        .unwrap_or_default(),
                    namespace = poddata
                        .workload_info
                        .as_ref()
                        .map(|w| w.namespace.as_str())
                        .unwrap_or_default(),
                    "pod received, starting proxy",
                );
                let Some(wli) = poddata.workload_info else {
                    return Err(Error::ProtocolError(
                        "workload_info is required but not present".into(),
                    ));
                };
                if !self.snapshot_received {
                    debug!("got workload add before snapshot");
                    self.snapshot_names.insert(poddata.workload_uid.clone());
                }
                let netns =
                    InpodNetns::new(self.inpod_config.cur_netns(), poddata.netns).map_err(|e| {
                        Error::ProxyError(
                            poddata.workload_uid.0.clone(),
                            crate::proxy::Error::Io(e),
                        )
                    })?;
                let info = WorkloadInfo {
                    name: wli.name,
                    namespace: wli.namespace,
                    service_account: wli.service_account,
                };
                self.add_workload(&poddata.workload_uid, info, netns)
                    .await
                    .map_err(|e| Error::ProxyError(poddata.workload_uid.0, e))
            }
            WorkloadMessage::KeepWorkload(workload_uid) => {
                info!(
                    uid = workload_uid.0,
                    "pod keep received. will not delete it when snapshot is sent"
                );
                if self.snapshot_received {
                    // this can only happen before snapshot is received.
                    return Err(Error::ProtocolError(
                        "pod keep received after snapshot".into(),
                    ));
                }
                self.snapshot_names.insert(workload_uid);
                Ok(())
            }
            WorkloadMessage::DelWorkload(workload_uid) => {
                info!(
                    uid = workload_uid.0,
                    "pod delete request, shutting down proxy"
                );
                if !self.snapshot_received {
                    debug!("got workload delete before snapshot");
                    // Since we insert here on AddWorkload before we get a snapshot,
                    // make sure we also opportunistically remove here before we
                    // get a snapshot
                    //
                    // Note that even though AddWorkload starts the workload, we do *not* need
                    // to stop it here, as it should be auto-dropped subsequently during snapshot
                    // reconcile(), when we actually get the `SnapshotSent` notification.
                    self.snapshot_names.remove(&workload_uid);
                    // `reconcile()` will drop this workload later, but if the workload never successfully
                    // starts it will stay in the pending queue (which `reconcile()` can't remove it from),
                    // so clear the pending queue here.
                    self.pending_workloads.remove(&workload_uid);
                    return Ok(());
                }
                self.del_workload(&workload_uid);
                Ok(())
            }
            WorkloadMessage::WorkloadSnapshotSent => {
                info!("received snapshot sent");
                if self.snapshot_received {
                    return Err(Error::ProtocolError("pod snapshot received already".into()));
                }
                self.reconcile();
                // mark ready
                self.snapshot_received = true;
                Ok(())
            }
        }
    }

    // reconcile existing state to snaphsot. drains any workloads not in the snapshot
    // this can happen if workloads were removed while we were disconnected.
    fn reconcile(&mut self) {
        for (_, workload_state) in self
            .workload_states
            .extract_if(|uid, _| !self.snapshot_names.contains(uid))
        {
            self.draining.shutdown_workload(workload_state);
        }
        self.snapshot_names.clear();
        self.update_proxy_count_metrics();
    }

    pub async fn drain(self) {
        let drain_futures =
            self.workload_states.into_iter().map(|(_, v)| {
                v.drain.start_drain_and_wait(drain::DrainMode::Graceful)
            } /* do not .await here!!! */);
        // join these first, as we need to drive these to completion
        futures::future::join_all(drain_futures).await;
        // these are join handles that are driven by tokio, we just need to wait for them, so join these
        // last
        self.draining.join().await;
    }

    async fn add_workload(
        &mut self,
        workload_uid: &WorkloadUid,
        workload_info: WorkloadInfo,
        netns: InpodNetns,
    ) -> Result<(), crate::proxy::Error> {
        match self
            .add_workload_inner(workload_uid, &workload_info, netns.clone())
            .await
        {
            Ok(()) => {
                // If the workload is already pending, make sure we drop it, so we don't retry.
                self.pending_workloads.remove(workload_uid);
                self.update_proxy_count_metrics();
                Ok(())
            }
            Err(e) => {
                self.pending_workloads
                    .insert(workload_uid.clone(), (workload_info, netns));
                self.update_proxy_count_metrics();
                Err(e)
            }
        }
    }
    async fn add_workload_inner(
        &mut self,
        workload_uid: &WorkloadUid,
        workload_info: &WorkloadInfo,
        netns: InpodNetns,
    ) -> Result<(), crate::proxy::Error> {
        // check if we have a proxy already
        let maybe_existing = self.workload_states.get(workload_uid);
        if let Some(existing) = maybe_existing {
            if existing.netns_id != netns.workload_netns_id() {
                // inodes are different, we have a new netns.
                // this can happen when there's a CNI failure (that's unrelated to us) which triggers
                // pod sandobx to be re-created with a fresh new netns.
                // drain the old proxy and add this one.
                self.del_workload(workload_uid);
            } else {
                // idempotency - no error if we already have a proxy for the workload
                // check if the inodes match. if they don't, we have a new netns
                // we need to drain the previous proxy and add this one.
                return Ok(());
            }
        }
        self.admin_handler
            .proxy_pending(workload_uid, workload_info);

        let workload_netns_id = netns.workload_netns_id();

        debug!(
            workload=?workload_uid,
            workload_info=?workload_info,
            netns_id=?workload_netns_id,
            "starting proxy",
        );

        // We create a per workload drain here. If the main loop in WorkloadProxyManager::run drains,
        // we drain all these per-workload drains before exiting the loop
        let (drain_tx, drain_rx) = drain::new();

        let proxies = self
            .proxy_gen
            .new_proxies_from_factory(
                Some(drain_rx),
                workload_info.clone(),
                Arc::from(self.inpod_config.socket_factory(netns)),
            )
            .await?;

        let uid = workload_uid.clone();

        self.admin_handler
            .proxy_up(&uid, workload_info, proxies.connection_manager);

        let metrics = self.metrics.clone();
        let admin_handler = self.admin_handler.clone();

        metrics.proxies_started.inc();
        if let Some(proxy) = proxies.proxy {
            tokio::spawn(
                async move {
                    proxy.run().await;
                    debug!("proxy for workload {:?} exited", uid);
                    metrics.proxies_stopped.inc();
                    admin_handler.proxy_down(&uid);
                }
                .instrument(tracing::info_span!("proxy", wl=%format!("{}/{}", workload_info.namespace, workload_info.name))),
            );
        }
        if let Some(proxy) = proxies.dns_proxy {
            tokio::spawn(proxy.run().instrument(tracing::info_span!("dns_proxy", wl=%format!("{}/{}", workload_info.namespace, workload_info.name))));
        }

        self.workload_states.insert(
            workload_uid.clone(),
            WorkloadState {
                drain: drain_tx,
                netns_id: workload_netns_id,
            },
        );

        Ok(())
    }

    pub fn have_pending(&self) -> bool {
        !self.pending_workloads.is_empty()
    }

    pub fn pending_uids(&self) -> Vec<String> {
        self.pending_workloads.keys().map(|k| k.0.clone()).collect()
    }

    pub fn ready(&self) -> bool {
        // We are ready after we received our first snapshot and don't have any proxies that failed to start.
        self.snapshot_received && !self.have_pending()
    }

    pub async fn retry_pending(&mut self) {
        let current_pending_workloads = std::mem::take(&mut self.pending_workloads);

        for (uid, (info, netns)) in current_pending_workloads {
            info!(uid = uid.0, "retrying workload");
            match self.add_workload(&uid, info, netns).await {
                Ok(()) => {}
                Err(e) => {
                    info!(uid = uid.0, "retrying workload failed: {}", e);
                }
            }
        }
    }

    fn del_workload(&mut self, workload_uid: &WorkloadUid) {
        // for idempotency, we ignore errors here (maybe just log / metric them)
        self.pending_workloads.remove(workload_uid);
        let Some(workload_state) = self.workload_states.remove(workload_uid) else {
            // TODO: add metrics
            return;
        };

        self.update_proxy_count_metrics();

        self.draining.shutdown_workload(workload_state);
    }

    fn update_proxy_count_metrics(&self) {
        self.metrics
            .active_proxy_count
            .set(self.workload_states.len().try_into().unwrap_or(-1));
        self.metrics
            .pending_proxy_count
            .set(self.pending_workloads.len().try_into().unwrap_or(-1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inpod::WorkloadData;
    use crate::inpod::test_helpers::{self, create_proxy_conflict, new_netns, uid};

    use crate::inpod::istio::zds;
    use matches::assert_matches;
    use std::sync::Arc;
    use std::time::Duration;

    struct Fixture {
        state: WorkloadProxyManagerState,
        metrics: Arc<crate::inpod::Metrics>,
    }

    fn workload_info() -> Option<zds::WorkloadInfo> {
        Some(zds::WorkloadInfo {
            name: "name".to_string(),
            namespace: "ns".to_string(),
            service_account: "sa".to_string(),
        })
    }

    macro_rules! fixture {
        () => {{
            if !crate::test_helpers::can_run_privilged_test() {
                eprintln!("This test requires root; skipping");
                return;
            }
            let f = test_helpers::Fixture::default();
            let state = WorkloadProxyManagerState::new(
                f.proxy_factory,
                f.ipc,
                f.inpod_metrics.clone(),
                Default::default(),
            );
            Fixture {
                state,
                metrics: f.inpod_metrics,
            }
        }};
    }

    #[tokio::test]
    async fn add_workload_starts_a_proxy() {
        let fixture = fixture!();
        let mut state = fixture.state;
        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn idemepotency_add_workload_starts_only_one_proxy() {
        let fixture = fixture!();
        let mut state = fixture.state;
        let ns = new_netns();
        let data = WorkloadData {
            netns: ns.try_clone().unwrap(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn idemepotency_add_workload_fails() {
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;
        let ns = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let sock = create_proxy_conflict(&ns);

        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;
        assert!(ret.is_err());
        assert!(state.have_pending());

        std::mem::drop(sock);
        // Unfortunate but necessary. When we close a socket in listener, the port is not synchronously freed.
        // This can lead to our retry failing due to a conflict. There doesn't seem to be a great way to reliably detect this.
        // Sleeping 10ms, however, is quite small and seems very reliable.
        tokio::time::sleep(Duration::from_millis(10)).await;

        state.retry_pending().await;
        assert!(!state.have_pending());
        state.drain().await;
        assert_eq!(m.proxies_started.get(), 1);
    }

    #[tokio::test]
    async fn workload_added_while_pending() {
        // Regression test for https://github.com/istio/istio/issues/52858
        // Workload is added and fails, so put on the pending queue. Then it is added and succeeds.
        // The bug is that when we retry with the failed netns, we (1) never succeed and (2) drop the running proxy.
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;
        let ns1 = new_netns();
        let ns2 = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let _sock = create_proxy_conflict(&ns1);

        // Add the pod in netns1
        let ret = state
            .process_msg(WorkloadMessage::AddWorkload(WorkloadData {
                netns: ns1,
                workload_uid: uid(0),
                workload_info: workload_info(),
            }))
            .await;
        assert!(ret.is_err());
        assert!(state.have_pending());

        // Add it again with another netns. The original pod should still be present in the retry queue with ns1
        state
            .process_msg(WorkloadMessage::AddWorkload(WorkloadData {
                netns: ns2,
                workload_uid: uid(0),
                workload_info: workload_info(),
            }))
            .await
            .expect("should start");

        state.retry_pending().await;
        assert!(!state.have_pending());
        state.drain().await;
        assert_eq!(m.proxies_started.get(), 1);
    }

    #[tokio::test]
    async fn idempotency_add_workload_fails_and_then_deleted() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let ns = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let _sock = create_proxy_conflict(&ns);

        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();

        let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;
        assert!(ret.is_err());
        assert!(state.have_pending());

        state
            .process_msg(WorkloadMessage::DelWorkload(uid(0)))
            .await
            .unwrap();

        assert!(!state.have_pending());
        state.drain().await;
    }

    #[tokio::test]
    async fn del_workload_before_snapshot_removes_from_snapshot_and_pending() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let ns = new_netns();

        // to make the proxy fail, bind to its ports in its netns
        let _sock = create_proxy_conflict(&ns);

        let data = WorkloadData {
            netns: ns,
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;

        assert!(state.snapshot_names.len() == 1);
        assert!(ret.is_err());
        assert!(state.have_pending());

        state
            .process_msg(WorkloadMessage::DelWorkload(uid(0)))
            .await
            .unwrap();

        assert!(state.snapshot_names.is_empty());

        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();

        assert!(state.snapshot_names.is_empty());
        assert!(!state.have_pending());
        state.drain().await;
    }

    #[tokio::test]
    async fn add_delete_add_workload_starts_only_one_proxy() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let ns = new_netns();
        let data = WorkloadData {
            netns: ns.try_clone().unwrap(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let workload_uid = data.workload_uid.clone();

        let msg1 = WorkloadMessage::AddWorkload(data);
        let msg2 = WorkloadMessage::DelWorkload(workload_uid.clone());
        let msg3 = WorkloadMessage::AddWorkload(WorkloadData {
            netns: ns,
            workload_uid,
            workload_info: workload_info(),
        });

        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();
        state.process_msg(msg1).await.unwrap();
        state.process_msg(msg2).await.unwrap();
        // give a bit of time for the proxy to drain
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        state.process_msg(msg3).await.unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn proxy_added_then_kept_with_new_snapshot() {
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };

        let workload_uid = data.workload_uid.clone();

        let msg1 = WorkloadMessage::AddWorkload(data);
        let msg2 = WorkloadMessage::KeepWorkload(workload_uid.clone());

        state.process_msg(msg1).await.unwrap();
        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();
        state.reset_snapshot();
        state.process_msg(msg2).await.unwrap();
        state
            .process_msg(WorkloadMessage::WorkloadSnapshotSent)
            .await
            .unwrap();

        assert_eq!(m.proxies_started.get(), 1);

        state.drain().await;
    }

    #[tokio::test]
    async fn add_with_different_netns_keeps_latest_proxy() {
        let fixture = fixture!();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: workload_info(),
        };
        let workload_uid = data.workload_uid.clone();

        let add1 = WorkloadMessage::AddWorkload(data);
        let add2 = WorkloadMessage::AddWorkload(WorkloadData {
            netns: new_netns(),
            workload_uid,
            workload_info: workload_info(),
        });

        state.process_msg(add1).await.unwrap();
        state.process_msg(add2).await.unwrap();
        state.drain().await;

        assert_eq!(m.proxies_started.get(), 2);
        assert_eq!(m.active_proxy_count.get(), 1);
    }

    #[tokio::test]
    async fn no_workload_info_rejected() {
        let fixture = fixture!();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            workload_uid: uid(0),
            workload_info: None,
        };

        let add = WorkloadMessage::AddWorkload(data);

        assert_matches!(state.process_msg(add).await, Err(_));
    }
}
