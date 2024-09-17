use crate::drain;
use crate::drain::DrainTrigger;
use crate::inpod::metrics::Metrics;
use std::sync::Arc;

use crate::proxyfactory::ProxyFactory;
use crate::state::WorkloadInfo;

use super::config::InPodConfig;
use tracing::{debug, info, Instrument};

use super::WorkloadUid;
use crate::inpod::windows::namespace::InpodNetns;
use crate::inpod::windows::WorkloadMessage;
use crate::inpod::Error;

// Note: we can't drain on drop, as drain is async (it waits for the drain to finish).
pub(super) struct WorkloadState {
    drain: DrainTrigger,
    netns_id: u32,
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
    pending_workloads: hashbrown::HashMap<WorkloadUid, (Option<WorkloadInfo>, InpodNetns)>,
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

    // Call this on new connection
    pub fn reset_snapshot(&mut self) {
        self.snapshot_names.clear();
        self.pending_workloads.clear();
        self.snapshot_received = false;
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
        workload_info: Option<WorkloadInfo>,
        netns: InpodNetns,
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
        workload_info: &Option<WorkloadInfo>,
        netns: InpodNetns,
    ) -> Result<(), crate::proxy::Error> {
        // check if we have a proxy already
        let maybe_existing = self.workload_states.get(workload_uid);
        if let Some(existing) = maybe_existing {
            if existing.netns_id != netns.workload_namespace() {
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

        let workload_netns_id = netns.workload_namespace();

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
        let admin_handler: Arc<crate::inpod::windows::admin::WorkloadManagerAdminHandler> =
            self.admin_handler.clone();

        metrics.proxies_started.get_or_create(&()).inc();
        if let Some(proxy) = proxies.proxy {
            let span = if let Some(wl) = workload_info {
                tracing::info_span!("proxy", wl=%format!("{}/{}", wl.namespace, wl.name))
            } else {
                tracing::info_span!("proxy", uid=%workload_uid.clone().into_string())
            };
            tokio::spawn(
                async move {
                    proxy.run().await;
                    debug!("proxy for workload {:?} exited", uid);
                    metrics.proxies_stopped.get_or_create(&()).inc();
                    admin_handler.proxy_down(&uid);
                }
                .instrument(span),
            );
        }
        if let Some(proxy) = proxies.dns_proxy {
            let span = if let Some(wl) = workload_info {
                tracing::info_span!("dns_proxy", wl=%format!("{}/{}", wl.namespace, wl.name))
            } else {
                tracing::info_span!("dns_proxy", uid=%workload_uid.clone().into_string())
            };
            tokio::spawn(proxy.run().instrument(span));
        }

        self.workload_states.insert(
            workload_uid.clone(),
            WorkloadState {
                drain: drain_tx,
                // TODO: implement this with the correct value
                // netns_id: workload_netns_id,
                netns_id: 0,
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
                if !self.snapshot_received {
                    self.snapshot_names.insert(poddata.workload_uid.clone());
                }
                let netns = InpodNetns::new(self.inpod_config.cur_netns(), poddata.namespace_id)
                    .map_err(|e| Error::ProxyError(crate::proxy::Error::Io(e)))?;
                let info = poddata.workload_info.map(|w| WorkloadInfo {
                    name: w.name,
                    namespace: w.namespace,
                    service_account: w.service_account,
                });
                self.add_workload(&poddata.workload_uid, info, netns)
                    .await
                    .map_err(Error::ProxyError)
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
                    // TODO: consider if this is an error. if not, do this instead:
                    // self.snapshot_names.remove(&workload_uid)
                    // self.pending_workloads.remove(&workload_uid)
                    return Err(Error::ProtocolError(
                        "pod delete received before snapshot".into(),
                    ));
                }
                self.del_workload(&workload_uid);
                Ok(())
            }
            WorkloadMessage::WorkloadSnapshotSent => {
                info!("pod received snapshot sent");
                if self.snapshot_received {
                    return Err(crate::inpod::Error::ProtocolError(
                        "pod snapshot received already".into(),
                    ));
                }
                self.reconcile();
                // mark ready
                self.snapshot_received = true;
                Ok(())
            }
        }
    }

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
            .get_or_create(&())
            .set(self.workload_states.len().try_into().unwrap_or(-1));
        self.metrics
            .pending_proxy_count
            .get_or_create(&())
            .set(self.pending_workloads.len().try_into().unwrap_or(-1));
    }
}
