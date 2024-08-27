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

// use crate::config as zconfig;
// use crate::readiness;
// use crate::inpod::metrics::Metrics;
// use std::sync::Arc;
// use workloadmanager::WorkloadProxyManager;

// use crate::proxyfactory::ProxyFactory;

// use self::config::InPodConfig;

pub mod istio {
  pub mod zds {
      tonic::include_proto!("istio.workload.zds");
  }
}

pub fn init_and_new(
  metrics: Arc<Metrics>,
  admin_server: &mut crate::admin::Service,
  cfg: &zconfig::Config,
  proxy_gen: ProxyFactory,
  ready: readiness::Ready,
) -> anyhow::Result<WorkloadProxyManager> {
  // verify that we have the permissions for the syscalls we need
  WorkloadProxyManager::verify_syscalls()?;
  let admin_handler: Arc<admin::WorkloadManagerAdminHandler> = Default::default();
  admin_server.add_handler(admin_handler.clone());
  let inpod_config = crate::inpod_linux::InPodConfig::new(cfg)?;

  let state_mgr = statemanager::WorkloadProxyManagerState::new(
      proxy_gen,
      inpod_config,
      metrics,
      admin_handler,
  );

  Ok(WorkloadProxyManager::new(
      cfg.inpod_uds.clone(),
      state_mgr,
      ready,
  )?)
}
