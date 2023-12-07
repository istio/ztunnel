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

#[mockall_double::double]
use crate::proxyfactory::ProxyFactory;

#[mockall_double::double]
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
    NoWorkloadSnapshot,
    WorkloadSnapshotSent,
    DelWorkload(String),
}

//#[mockall_double::double]
//type Config = InPodConfig;

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

#[cfg(test)]
pub(crate) mod tests {
    use super::config::MockInPodConfig;
    use super::*;
    use crate::proxyfactory::MockProxyFactory;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    use std::sync::Arc;
    static FD2UID: once_cell::sync::Lazy<
        std::sync::Mutex<
            std::collections::HashMap<(std::thread::ThreadId, usize), std::os::unix::io::RawFd>,
        >,
    > = once_cell::sync::Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

    pub(crate) fn uid(i: usize) -> String {
        format!("uid{i}")
    }

    pub(crate) fn fd_for_uid(i: usize) -> std::os::unix::io::RawFd {
        {
            let id = std::thread::current().id();
            let map = FD2UID.lock().unwrap();
            if let Some(fd) = map.get(&(id, i)) {
                return *fd;
            }
        }
        new_fd(i)
    }

    pub fn expect_new_proxy(
        mock_proxy_gen: &mut MockProxyFactory,
        mock_ipc: &mut MockInPodConfig,
        i: usize,
    ) {
        expect_new_proxy_with_fd(mock_proxy_gen, mock_ipc, i, None)
    }

    pub fn expect_new_proxy_with_fd(
        mock_proxy_gen: &mut MockProxyFactory,
        mock_ipc: &mut MockInPodConfig,
        i: usize,
        fd: Option<std::os::unix::io::RawFd>,
    ) {
        mock_ipc
            .expect_socket_factory()
            .times(1)
            .returning(move |netns| {
                let fd = fd.unwrap_or_else(|| fd_for_uid(i));
                assert_eq!(netns.as_raw_fd(), fd);
                Box::new(InPodSocketFactory::new(netns, None))
            });

        mock_proxy_gen
            .expect_new_proxies_from_factory()
            .times(1)
            .returning(move |drain, _factory| {
                //assert_eq!(ipc.uid, uid(i));
                assert!(drain.is_some());

                let mut mock_proxy = crate::proxy::MockProxy::default();
                mock_proxy.expect_run().once().return_once(move || {
                    // keep drain alive until run is called, otherwise the assertion might not work -
                    // the test might be over before the tokio routine will call run
                    // (as each proxy is spawned to its own routing).
                    std::mem::drop(drain);
                });

                Ok(crate::proxyfactory::ProxyResult {
                    proxy: Some(mock_proxy),
                    dns_proxy: None,
                })
            });
    }
    pub fn expect_error_proxy(
        mock_proxy_gen: &mut MockProxyFactory,
        mock_ipc: &mut MockInPodConfig,
        i: usize,
    ) {
        mock_ipc
            .expect_socket_factory()
            .times(1)
            .returning(move |netns| {
                assert_eq!(netns.as_raw_fd(), fd_for_uid(i));
                Box::new(InPodSocketFactory::new(netns, None))
            });

        mock_proxy_gen
            .expect_new_proxies_from_factory()
            .times(1)
            .returning(move |drain, _factory| {
                //assert_eq!(ipc.uid, uid(i));
                assert!(drain.is_some());

                Err(crate::proxy::Error::UnsupportedFeature(
                    "test error".to_string(),
                ))
            });
    }

    pub(crate) fn metrics() -> Arc<metrics::Metrics> {
        let mut registry = Registry::default();
        Arc::new(Metrics::new(&mut registry))
    }

    fn new_fd(i: usize) -> std::os::unix::io::RawFd {
        // the FDs here may be closed by the test, so we need to dup them.
        // if the test doesn't close them, they might leak, but that's ok for tests.
        let f = std::fs::File::open("/dev/null").unwrap();
        let raw_fd: std::os::unix::io::RawFd =
            nix::unistd::dup(f.as_raw_fd()).expect("failed to dup fd");

        let id = std::thread::current().id();
        let mut map = FD2UID.lock().unwrap();
        map.insert((id, i), raw_fd);
        raw_fd
    }

    pub(crate) fn workload_netns(i: usize) -> std::os::fd::OwnedFd {
        unsafe { std::os::fd::OwnedFd::from_raw_fd(new_fd(i)) }
    }
    pub(crate) fn workload_data(i: usize) -> WorkloadData {
        WorkloadData {
            netns: workload_netns(i),
            info: WorkloadInfo {
                workload_uid: uid(i),
            },
        }
    }
}
