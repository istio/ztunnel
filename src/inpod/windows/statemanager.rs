use crate::drain;
use crate::drain::DrainTrigger;
use crate::inpod::metrics::Metrics;
use std::sync::Arc;

use crate::proxyfactory::ProxyFactory;
use crate::state::WorkloadInfo;

use super::config::InPodConfig;

use super::WorkloadUid;
use crate::inpod::windows::namespace::InpodNetns;

// Note: we can't drain on drop, as drain is async (it waits for the drain to finish).
pub(super) struct WorkloadState {
  drain: DrainTrigger,
  netns_id: String,
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
