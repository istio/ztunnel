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
use prometheus_client::registry::Registry;
use std::sync::Arc;
use workloadmanager::WorkloadProxyManager;

use crate::proxyfactory::ProxyFactory;

use self::config::InPodConfig;

pub use self::config::InPodSocketFactory;

pub mod admin;
mod config;
mod metrics;
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
    #[error("protocol error")]
    ProtocolError,
}

#[derive(Debug, Clone)]
struct WorkloadInfo {
    workload_uid: String,
}
#[derive(Debug)]
pub struct WorkloadData {
    netns: std::os::fd::OwnedFd,
    info: WorkloadInfo,
}

#[derive(Debug)]
pub enum WorkloadMessage {
    AddWorkload(WorkloadData),
    KeepWorkload(String),
    WorkloadSnapshotSent,
    DelWorkload(String),
}

pub fn init_and_new(
    registry: &mut Registry,
    admin_server: &mut crate::admin::Service,
    cfg: &zconfig::Config,
    proxy_gen: ProxyFactory,
    ready: readiness::Ready,
) -> anyhow::Result<WorkloadProxyManager> {
    // verify that we have the permissions for the syscalls we need
    WorkloadProxyManager::verify_syscalls()?;
    let metrics = Arc::new(Metrics::new(registry));
    admin_server.add_handler(metrics.admin_handler());
    let inpod_config = crate::inpod::InPodConfig::new(cfg)?;

    let state_mgr = statemanager::WorkloadProxyManagerState::new(proxy_gen, inpod_config, metrics);

    Ok(WorkloadProxyManager::new(
        cfg.inpod_uds.clone(),
        state_mgr,
        ready,
    )?)
}
