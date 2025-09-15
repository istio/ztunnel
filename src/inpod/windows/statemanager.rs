use crate::drain;
use crate::drain::DrainTrigger;
use crate::inpod::Error;
use crate::inpod::metrics::Metrics;
use crate::inpod::windows::WorkloadData;
use crate::inpod::windows::admin::State;
use std::sync::Arc;

use crate::proxyfactory::ProxyFactory;
use crate::state::WorkloadInfo;

use super::config::InPodConfig;
use tracing::{Instrument, debug, info};
use windows::core::GUID;

use super::WorkloadMessage;
use super::WorkloadUid;
use super::namespace::InpodNamespace;

// Note: we can't drain on drop, as drain is async (it waits for the drain to finish).
pub(super) struct WorkloadState {
    drain: DrainTrigger,
    netns_guid: String,
}

pub enum ProxyState {
    Up,
    PendingCompartment,
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
    pending_workloads: hashbrown::HashMap<WorkloadUid, (WorkloadInfo, InpodNamespace)>,
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

    pub async fn process_msg(&mut self, msg: &WorkloadMessage) -> Result<ProxyState, Error> {
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
                let Some(wli) = &poddata.workload_info else {
                    return Err(Error::ProtocolError(
                        "workload_info is required but not present".into(),
                    ));
                };
                if !self.snapshot_received {
                    self.snapshot_names.insert(poddata.workload_uid.clone());
                }
                let ns = wli
                    .windows_namespace
                    .as_ref()
                    .expect("pod should have windows namespace");
                let netns = InpodNamespace::new(ns.guid.clone()).map_err(|e| {
                    Error::ProxyError(poddata.workload_uid.0.clone(), crate::proxy::Error::Io(e))
                })?;
                let info = WorkloadInfo {
                    name: wli.name.clone(),
                    namespace: wli.namespace.clone(),
                    service_account: wli.service_account.clone(),
                };
                if ns.id == 0 {
                    info!(
                        "network compartment not yet available for workload {:?}, waiting for compartment...",
                        poddata.workload_uid
                    );
                    self.admin_handler.proxy_pending(
                        State::WaitingCompartment,
                        &poddata.workload_uid,
                        &info,
                    );
                    return Ok(ProxyState::PendingCompartment);
                }
                let res = self.add_workload(&poddata.workload_uid, info, netns).await;

                match res {
                    Ok(()) => Ok(ProxyState::Up),
                    Err(e) => Err(Error::ProxyError(poddata.workload_uid.0.clone(), e)),
                }
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
                self.snapshot_names.insert(workload_uid.clone());
                Ok(ProxyState::Up)
            }
            WorkloadMessage::DelWorkload(workload_uid) => {
                info!(
                    uid = workload_uid.0,
                    "pod delete request, shutting down proxy"
                );
                if !self.snapshot_received {
                    // TODO: consider if this is an error. if not, do this instead:
                    // self.snapshot_names.remove(&workload_uid)
                    // self.pending_workloads.remove(&workload_uid)
                    return Err(Error::ProtocolError(
                        "pod delete received before snapshot".into(),
                    ));
                }
                self.del_workload(&workload_uid);
                Ok(ProxyState::Up)
            }
            WorkloadMessage::WorkloadSnapshotSent => {
                info!("pod received snapshot sent");
                if self.snapshot_received {
                    return Err(Error::ProtocolError("pod snapshot received already".into()));
                }
                self.reconcile();
                // mark ready
                self.snapshot_received = true;
                Ok(ProxyState::Up)
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
        netns: InpodNamespace,
    ) -> Result<(), crate::proxy::Error> {
        match self
            .add_workload_inner(workload_uid, &workload_info, netns.clone())
            .await
        {
            Ok(()) => {
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
        netns: InpodNamespace,
    ) -> Result<(), crate::proxy::Error> {
        // check if we have a proxy already
        let maybe_existing = self.workload_states.get(workload_uid);
        if let Some(existing) = maybe_existing {
            if existing.netns_guid != netns.namespace_guid {
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
            .proxy_pending(State::Pending, workload_uid, workload_info);

        debug!(
            workload=?workload_uid,
            workload_info=?workload_info,
            netns_id=?netns.namespace_guid,
            compartment_id=?netns.compartment_id,
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
                Arc::from(self.inpod_config.socket_factory(netns.clone())),
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
                netns_guid: netns.namespace_guid,
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
            info!("retrying workload {:?}", uid);
            match self.add_workload(&uid, info, netns).await {
                Ok(()) => {}
                Err(e) => {
                    info!("retrying workload {:?} failed: {}", uid, e);
                }
            }
        }
    }

    pub async fn retry_compartmentless(&mut self, poddata: &WorkloadData) -> Result<(), Error> {
        let uid = &poddata.workload_uid;
        let info = poddata.workload_info.as_ref().unwrap();
        let netns = InpodNamespace::new(
            info.windows_namespace
                .as_ref()
                .expect("unable to retry invalid namespace")
                .guid
                .clone(),
        )
        .expect("unableto create network namespace");
        let netns_guid = GUID::try_from(netns.namespace_guid.as_str()).map_err(|e| {
            Error::NamespaceError(format!(
                "invalid network namespace GUID {}: {}",
                netns.namespace_guid, e
            ))
        })?;
        let ns = hcn::api::open_namespace(&netns_guid).map_err(|e| {
            Error::NamespaceError(format!(
                "unable to open network namespace {}: {}",
                netns.namespace_guid, e
            ))
        })?;
        debug!(
            "checking for compartments in network namespace {}",
            netns.namespace_guid
        );
        let ns_details = hcn::api::query_namespace_properties(ns, "").map_err(|e| {
            Error::NamespaceError(format!(
                "unable to query properties for namespace {}: {}",
                netns.namespace_guid, e
            ))
        })?;
        let ns_details: serde_json::Value = serde_json::from_str(&ns_details).map_err(|e| {
            Error::NamespaceError(format!(
                "unable to parse properties from namespace {}: {}",
                netns.namespace_guid, e
            ))
        })?;
        let compartment_id = match &ns_details.as_object() {
            Some(object) => object["CompartmentId"]
                .as_u64()
                .ok_or(Error::NamespaceError(format!(
                    "invalid compartment ID: {:?}",
                    &object
                )))
                .and_then(|id| {
                    u32::try_from(id).map_err(|e| {
                        Error::NamespaceError(format!("invalid compartment ID: {}, {}", id, e))
                    })
                }),
            None => Err(Error::NamespaceError(format!(
                "invalid details for compartment {}",
                netns.namespace_guid
            ))),
        }?;

        let info = WorkloadInfo {
            name: info.name.clone(),
            namespace: info.namespace.clone(),
            service_account: info.service_account.clone(),
        };

        if compartment_id == 0 {
            return Err(Error::NamespaceError(format!(
                "network compartment ID not yet available for namespace {}",
                netns.namespace_guid
            )));
        }

        debug!(
            "compartment id {} found for network namespace {}",
            compartment_id, netns.namespace_guid
        );

        let new_netns = InpodNamespace::new(netns.namespace_guid.clone()).map_err(|e| {
            Error::NamespaceError(format!("unable to create new network namespace: {}", e))
        })?;
        self.add_workload(&uid, info.clone(), new_netns)
            .await
            .map_err(|e| {
                Error::NamespaceError(format!(
                    "unable to add workload from namespace {}: {}",
                    netns.namespace_guid, e
                ))
            })?;
        return Ok(());
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

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::inpod::linux::test_helpers::{self, create_proxy_confilct, new_netns, uid};
//     use crate::inpod::linux::WorkloadData;

//     use std::sync::Arc;
//     use std::time::Duration;

//     struct Fixture {
//         state: WorkloadProxyManagerState,
//         metrics: Arc<crate::inpod::metrics::Metrics>,
//     }

//     macro_rules! fixture {
//         () => {{
//             if !crate::test_helpers::can_run_privilged_test() {
//                 eprintln!("This test requires root; skipping");
//                 return;
//             }
//             let f = test_helpers::Fixture::default();
//             let state = WorkloadProxyManagerState::new(
//                 f.proxy_factory,
//                 f.ipc,
//                 f.inpod_metrics.clone(),
//                 Default::default(),
//             );
//             Fixture {
//                 state,
//                 metrics: f.inpod_metrics,
//             }
//         }};
//     }

//     #[tokio::test]
//     async fn add_workload_starts_a_proxy() {
//         let fixture = fixture!();
//         let mut state = fixture.state;
//         let data = WorkloadData {
//             netns: new_netns(),
//             workload_uid: uid(0),
//             workload_info: None,
//         };
//         state
//             .process_msg(WorkloadMessage::AddWorkload(data))
//             .await
//             .unwrap();
//         state.drain().await;
//     }

//     #[tokio::test]
//     async fn idemepotency_add_workload_starts_only_one_proxy() {
//         let fixture = fixture!();
//         let mut state = fixture.state;
//         let ns = new_netns();
//         let data = WorkloadData {
//             netns: ns.try_clone().unwrap(),
//             workload_uid: uid(0),
//             workload_info: None,
//         };
//         state
//             .process_msg(WorkloadMessage::AddWorkload(data))
//             .await
//             .unwrap();
//         let data = WorkloadData {
//             netns: ns,
//             workload_uid: uid(0),
//             workload_info: None,
//         };
//         state
//             .process_msg(WorkloadMessage::AddWorkload(data))
//             .await
//             .unwrap();
//         state.drain().await;
//     }

//     #[tokio::test]
//     async fn idemepotency_add_workload_fails() {
//         let fixture = fixture!();
//         let m = fixture.metrics.clone();
//         let mut state = fixture.state;
//         let ns = new_netns();
//         // to make the proxy fail, bind to its ports in its netns
//         let sock = create_proxy_confilct(&ns);

//         let data = WorkloadData {
//             netns: ns,
//             workload_uid: uid(0),
//             workload_info: None,
//         };

//         let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;
//         assert!(ret.is_err());
//         assert!(state.have_pending());

//         std::mem::drop(sock);
//         // Unfortunate but necessary. When we close a socket in listener, the port is not synchronously freed.
//         // This can lead to our retry failing due to a conflict. There doesn't seem to be a great way to reliably detect this.
//         // Sleeping 10ms, however, is quite small and seems very reliable.
//         tokio::time::sleep(Duration::from_millis(10)).await;

//         state.retry_pending().await;
//         assert!(!state.have_pending());
//         state.drain().await;
//         assert_eq!(m.proxies_started.get_or_create(&()).get(), 1);
//     }

//     #[tokio::test]
//     async fn idemepotency_add_workload_fails_and_then_deleted() {
//         let fixture = fixture!();
//         let mut state = fixture.state;

//         let ns = new_netns();
//         // to make the proxy fail, bind to its ports in its netns
//         let _sock = create_proxy_confilct(&ns);

//         let data = WorkloadData {
//             netns: ns,
//             workload_uid: uid(0),
//             workload_info: None,
//         };
//         state
//             .process_msg(WorkloadMessage::WorkloadSnapshotSent)
//             .await
//             .unwrap();

//         let ret = state.process_msg(WorkloadMessage::AddWorkload(data)).await;
//         assert!(ret.is_err());
//         assert!(state.have_pending());

//         state
//             .process_msg(WorkloadMessage::DelWorkload(uid(0)))
//             .await
//             .unwrap();

//         assert!(!state.have_pending());
//         state.drain().await;
//     }

//     #[tokio::test]
//     async fn add_delete_add_workload_starts_only_one_proxy() {
//         let fixture = fixture!();
//         let mut state = fixture.state;

//         let ns = new_netns();
//         let data = WorkloadData {
//             netns: ns.try_clone().unwrap(),
//             workload_uid: uid(0),
//             workload_info: None,
//         };

//         let workload_uid = data.workload_uid.clone();

//         let msg1 = WorkloadMessage::AddWorkload(data);
//         let msg2 = WorkloadMessage::DelWorkload(workload_uid.clone());
//         let msg3 = WorkloadMessage::AddWorkload(WorkloadData {
//             netns: ns,
//             workload_uid,
//             workload_info: None,
//         });

//         state
//             .process_msg(WorkloadMessage::WorkloadSnapshotSent)
//             .await
//             .unwrap();
//         state.process_msg(msg1).await.unwrap();
//         state.process_msg(msg2).await.unwrap();
//         // give a bit of time for the proxy to drain
//         tokio::time::sleep(std::time::Duration::from_millis(100)).await;
//         state.process_msg(msg3).await.unwrap();
//         state.drain().await;
//     }

//     #[tokio::test]
//     async fn proxy_added_then_kept_with_new_snapshot() {
//         let fixture = fixture!();
//         let m = fixture.metrics.clone();
//         let mut state = fixture.state;

//         let data = WorkloadData {
//             netns: new_netns(),
//             workload_uid: uid(0),
//             workload_info: None,
//         };

//         let workload_uid = data.workload_uid.clone();

//         let msg1 = WorkloadMessage::AddWorkload(data);
//         let msg2 = WorkloadMessage::KeepWorkload(workload_uid.clone());

//         state.process_msg(msg1).await.unwrap();
//         state
//             .process_msg(WorkloadMessage::WorkloadSnapshotSent)
//             .await
//             .unwrap();
//         state.reset_snapshot();
//         state.process_msg(msg2).await.unwrap();
//         state
//             .process_msg(WorkloadMessage::WorkloadSnapshotSent)
//             .await
//             .unwrap();

//         assert_eq!(m.proxies_started.get_or_create(&()).get(), 1);

//         state.drain().await;
//     }

//     #[tokio::test]
//     async fn add_with_different_netns_keeps_latest_proxy() {
//         let fixture = fixture!();
//         let m = fixture.metrics.clone();
//         let mut state = fixture.state;

//         let data = WorkloadData {
//             netns: new_netns(),
//             workload_uid: uid(0),
//             workload_info: None,
//         };
//         let workload_uid = data.workload_uid.clone();

//         let add1 = WorkloadMessage::AddWorkload(data);
//         let add2 = WorkloadMessage::AddWorkload(WorkloadData {
//             netns: new_netns(),
//             workload_uid,
//             workload_info: None,
//         });

//         state.process_msg(add1).await.unwrap();
//         state.process_msg(add2).await.unwrap();
//         state.drain().await;

//         assert_eq!(m.proxies_started.get_or_create(&()).get(), 2);
//         assert_eq!(m.active_proxy_count.get_or_create(&()).get(), 1);
//     }
// }
