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

use crate::config as zconfig;
use crate::readiness;
use metrics::Metrics;
use std::sync::Arc;
use workloadmanager::WorkloadProxyManager;

use crate::proxyfactory::ProxyFactory;

use self::config::InPodConfig;

pub mod admin;
mod config;
pub mod metrics;
pub mod netns;
pub mod packet;
mod protocol;
mod statemanager;
mod workloadmanager;

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers;

pub mod istio {
    pub mod zds {
        tonic::include_proto!("istio.workload.zds");
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error creating proxy: {0}")]
    ProxyError(crate::proxy::Error),
    #[error("error receiving message: {0}")]
    ReceiveMessageError(String),
    #[error("error sending ack: {0}")]
    SendAckError(String),
    #[error("error sending nack: {0}")]
    SendNackError(String),
    #[error("protocol error: {0}")]
    ProtocolError(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct WorkloadUid(String);

impl WorkloadUid {
    pub fn new(uid: String) -> Self {
        Self(uid)
    }
    pub fn into_string(self) -> String {
        self.0
    }
}

#[derive(Debug)]
pub struct WorkloadData {
    netns: std::os::fd::OwnedFd,
    workload_uid: WorkloadUid,
    workload_info: Option<istio::zds::WorkloadInfo>,
}

#[derive(Debug)]
pub enum WorkloadMessage {
    AddWorkload(WorkloadData),
    KeepWorkload(WorkloadUid),
    WorkloadSnapshotSent,
    DelWorkload(WorkloadUid),
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
    let inpod_config = crate::inpod::InPodConfig::new(cfg)?;

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
