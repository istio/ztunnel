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

use drain::Signal;
use std::sync::Arc;
use tracing::{debug, info, Instrument};

use super::{metrics::Metrics, Error, WorkloadInfo, WorkloadMessage};

use crate::proxyfactory::ProxyFactory;

use super::config::InPodConfig;

use super::netns::InpodNetns;

// Note: we can't drain on drop, as drain is async (it waits for the drain to finish).
pub(super) struct WorkloadState {
    drain: Signal,
    workload_netns_inode: libc::ino_t,
}

#[derive(Default)]
struct DrainingTasks {
    draining: Vec<tokio::task::JoinHandle<()>>,
}

impl DrainingTasks {
    fn drain_workload(&mut self, workload_state: WorkloadState) {
        let handle = tokio::spawn(workload_state.drain.drain());
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
    // use hashbrown for extract_if
    workload_states: hashbrown::HashMap<String, WorkloadState>,

    // workloads we wanted to start but couldn't because we had an error starting them.
    // This happened to use mainly in testing when we redeploy ztunnel, and the old pod was
    // not completely drained yet.
    pending_workloads: hashbrown::HashMap<String, (WorkloadInfo, InpodNetns)>,
    draining: DrainingTasks,

    // new connection stuff
    snapshot_received: bool,
    snapshot_names: std::collections::HashSet<String>,

    inpod_config: InPodConfig,
}

impl WorkloadProxyManagerState {
    pub fn new(proxy_gen: ProxyFactory, inpod_config: InPodConfig, metrics: Arc<Metrics>) -> Self {
        WorkloadProxyManagerState {
            proxy_gen,
            metrics,
            workload_states: Default::default(),
            pending_workloads: Default::default(),
            draining: Default::default(),

            snapshot_received: false,
            snapshot_names: Default::default(),
            inpod_config,
        }
    }

    #[cfg(test)] // only used in tests, so added this to avoid warning
    pub(super) fn workload_states(&self) -> &hashbrown::HashMap<String, WorkloadState> {
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
                    "pod {} received netns, starting proxy",
                    poddata.info.workload_uid
                );
                if !self.snapshot_received {
                    self.snapshot_names
                        .insert(poddata.info.workload_uid.clone());
                }
                let netns = InpodNetns::new(self.inpod_config.cur_netns(), poddata.netns)
                    .map_err(|e| Error::ProxyError(crate::proxy::Error::Io(e)))?;

                self.add_workload(poddata.info, netns)
                    .await
                    .map_err(Error::ProxyError)
            }
            WorkloadMessage::KeepWorkload(workload_uid) => {
                debug!("pod keep recieved. will not delete it when snapshot is sent");
                if self.snapshot_received {
                    // this can only happen before snapshot is received.
                    return Err(Error::ProtocolError);
                }
                self.snapshot_names.insert(workload_uid);
                Ok(())
            }
            WorkloadMessage::DelWorkload(workload_uid) => {
                info!("pod delete request, draining proxy");
                if !self.snapshot_received {
                    // TODO: consider if this is an error. if not, do this instead:
                    // self.snapshot_names.remove(&workload_uid)
                    // self.pending_workloads.remove(&workload_uid)
                    return Err(Error::ProtocolError);
                }
                self.del_workload(&workload_uid);
                Ok(())
            }
            WorkloadMessage::WorkloadSnapshotSent => {
                info!("pod received snapshot sent");
                if self.snapshot_received {
                    return Err(Error::ProtocolError);
                }
                self.reconcile();
                // mark ready
                self.snapshot_received = true;
                Ok(())
            }
        }
        // TODO: add metrics, about how many pods we have currently, how many we added, how many we removed
    }

    // reconcile existing state to snaphsot. drains any workloads not in the snapshot
    // this can happen if workloads were removed while we were disconnected.
    fn reconcile(&mut self) {
        for (_, workload_state) in self
            .workload_states
            .extract_if(|uid, _| !self.snapshot_names.contains(uid))
        {
            self.draining.drain_workload(workload_state);
        }
        self.snapshot_names.clear();
        self.update_proxy_count_metrics();
    }

    pub async fn drain(self) {
        let drain_futures = self
            .workload_states
            .into_iter()
            .map(|(_, v)| v.drain.drain() /* do not .await here!!! */);
        // join these first, as we need to drive these to completion
        futures::future::join_all(drain_futures).await;
        // these are join handles that are driven by tokio, we just need to wait for them, so join these
        // last
        self.draining.join().await;
    }

    async fn add_workload(
        &mut self,
        workload_info: WorkloadInfo,
        netns: InpodNetns,
    ) -> Result<(), crate::proxy::Error> {
        match self.add_workload_inner(&workload_info, netns.clone()).await {
            Ok(()) => {
                self.update_proxy_count_metrics();
                Ok(())
            }
            Err(e) => {
                self.pending_workloads
                    .insert(workload_info.workload_uid.clone(), (workload_info, netns));
                self.update_proxy_count_metrics();
                Err(e)
            }
        }
    }
    async fn add_workload_inner(
        &mut self,
        workload_info: &WorkloadInfo,
        netns: InpodNetns,
    ) -> Result<(), crate::proxy::Error> {
        // check if we have a proxy already
        let maybe_existing = self.workload_states.get(&workload_info.workload_uid);
        if let Some(existing) = maybe_existing {
            if existing.workload_netns_inode != netns.workload_inode() {
                // inodes are different, we have a new netns.
                // this can happen when there's a CNI failure (that's unrelated to us) which triggers
                // pod sandobx to be re-created with a fresh new netns.
                // drain the old proxy and add this one.
                self.del_workload(&workload_info.workload_uid);
            } else {
                // idempotency - no error if we already have a proxy for the workload
                // check if the inodes match. if they don't, we have a new netns
                // we need to drain the previous proxy and add this one.
                return Ok(());
            }
        }
        self.metrics
            .admin_handler()
            .proxy_pending(&workload_info.workload_uid);

        debug!(
            workload=?workload_info,
            inode=?netns.workload_inode(),
            "starting proxy",
        );

        // We create a per workload drain here. If the main loop in WorkloadProxyManager::run drains,
        // we drain all these per-workload drains before exiting the loop
        let workload_netns_inode = netns.workload_inode();
        let (drain_tx, drain_rx) = drain::channel();

        let proxies = self
            .proxy_gen
            .new_proxies_from_factory(
                Some(drain_rx),
                Arc::from(self.inpod_config.socket_factory(netns)),
            )
            .await?;

        let uid = workload_info.workload_uid.clone();

        self.metrics.admin_handler().proxy_up(&uid);

        let metrics = self.metrics.clone();
        metrics.proxies_started.get_or_create(&()).inc();
        if let Some(proxy) = proxies.proxy {
            tokio::spawn(
                async move {
                    proxy.run().await;
                    debug!("proxy for workload {} exited", uid);
                    metrics.proxies_stopped.get_or_create(&()).inc();
                    metrics.admin_handler().proxy_down(&uid);
                }
                .instrument(tracing::info_span!("proxy", uid=%workload_info.workload_uid)),
            );
        }
        if let Some(proxy) = proxies.dns_proxy {
            tokio::spawn(
                proxy
                    .run()
                    .instrument(tracing::info_span!("dns_proxy", uid=%workload_info.workload_uid)),
            );
        }

        self.workload_states.insert(
            workload_info.workload_uid.clone(),
            WorkloadState {
                drain: drain_tx,
                workload_netns_inode,
            },
        );

        Ok(())
    }

    pub fn have_pending(&self) -> bool {
        !self.pending_workloads.is_empty()
    }

    pub fn ready(&self) -> bool {
        // We are ready after we received our first snapshot and don't have any proxies that failed to start.
        self.snapshot_received && !self.have_pending()
    }

    pub async fn retry_pending(&mut self) {
        let current_pending_workloads = std::mem::take(&mut self.pending_workloads);

        for (uid, (info, netns)) in current_pending_workloads {
            info!("retrying workload {}", uid);
            match self.add_workload(info, netns).await {
                Ok(()) => {}
                Err(e) => {
                    info!("retrying workload {} failed: {}", uid, e);
                }
            }
        }
    }

    fn del_workload(&mut self, workload_uid: &str) {
        // for idempotency, we ignore errors here (maybe just log / metric them)
        self.pending_workloads.remove(workload_uid);
        let Some(workload_state) = self.workload_states.remove(workload_uid) else {
            // TODO: add metrics
            return;
        };

        self.update_proxy_count_metrics();

        self.draining.drain_workload(workload_state);
    }

    fn update_proxy_count_metrics(&self) {
        self.metrics
            .active_proxy_count
            .get_or_create(&())
            .set(self.workload_states.len().try_into().unwrap_or(-1));
        self.metrics
            .pending_proxy_count
            .get_or_create(&())
            .set(self.pending_workloads.len().try_into().unwrap_or(-1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inpod::test_helpers::{self, create_proxy_confilct, new_netns, uid};
    use crate::inpod::WorkloadData;
    use std::sync::Arc;

    struct Fixture {
        state: WorkloadProxyManagerState,
        metrics: Arc<crate::inpod::Metrics>,
    }
    fn fixture() -> Fixture {
        let f = test_helpers::fixture();
        let state = WorkloadProxyManagerState::new(f.proxy_factory, f.ipc, f.inpod_metrics.clone());
        Fixture {
            state,
            metrics: f.inpod_metrics,
        }
    }
    #[tokio::test]
    async fn add_workload_starts_a_proxy() {
        let fixture = fixture();
        let mut state = fixture.state;
        let data = WorkloadData {
            netns: new_netns(),
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn idemepotency_add_workload_starts_only_one_proxy() {
        let fixture = fixture();
        let mut state = fixture.state;
        let ns = new_netns();
        let data = WorkloadData {
            netns: ns.try_clone().unwrap(),
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        let data = WorkloadData {
            netns: ns,
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
        };
        state
            .process_msg(WorkloadMessage::AddWorkload(data))
            .await
            .unwrap();
        state.drain().await;
    }

    #[tokio::test]
    async fn idemepotency_add_workload_fails() {
        let fixture = fixture();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;
        let ns = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let sock = create_proxy_confilct(&ns);

        let data = WorkloadData {
            netns: ns,
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
        };

        let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;
        assert!(ret.is_err());
        assert!(state.have_pending());

        std::mem::drop(sock);

        state.retry_pending().await;
        assert!(!state.have_pending());
        state.drain().await;
        assert_eq!(m.proxies_started.get_or_create(&()).get(), 1);
    }

    #[tokio::test]
    async fn idemepotency_add_workload_fails_and_then_deleted() {
        let fixture = fixture();
        let mut state = fixture.state;

        let ns = new_netns();
        // to make the proxy fail, bind to its ports in its netns
        let _sock = create_proxy_confilct(&ns);

        let data = WorkloadData {
            netns: ns,
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
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
    async fn add_delete_add_workload_starts_only_one_proxy() {
        let fixture = fixture();
        let mut state = fixture.state;

        let ns = new_netns();
        let data = WorkloadData {
            netns: ns.try_clone().unwrap(),
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
        };

        let info = data.info.clone();

        let msg1 = WorkloadMessage::AddWorkload(data);
        let msg2 = WorkloadMessage::DelWorkload(info.workload_uid.clone());
        let msg3 = WorkloadMessage::AddWorkload(WorkloadData { netns: ns, info });

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
        let fixture = fixture();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
        };

        let info = data.info.clone();

        let msg1 = WorkloadMessage::AddWorkload(data);
        let msg2 = WorkloadMessage::KeepWorkload(info.workload_uid.clone());

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

        assert_eq!(m.proxies_started.get_or_create(&()).get(), 1);

        state.drain().await;
    }

    #[tokio::test]
    async fn add_with_different_netns_keeps_latest_proxy() {
        let fixture = fixture();
        let m = fixture.metrics.clone();
        let mut state = fixture.state;

        let data = WorkloadData {
            netns: new_netns(),
            info: WorkloadInfo {
                workload_uid: uid(0),
            },
        };
        let info = data.info.clone();

        let add1 = WorkloadMessage::AddWorkload(data);
        let add2 = WorkloadMessage::AddWorkload(WorkloadData {
            netns: new_netns(),
            info,
        });

        state.process_msg(add1).await.unwrap();
        state.process_msg(add2).await.unwrap();
        state.drain().await;

        assert_eq!(m.proxies_started.get_or_create(&()).get(), 2);
        assert_eq!(m.active_proxy_count.get_or_create(&()).get(), 1);
    }
}
