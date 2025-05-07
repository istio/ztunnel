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

use super::config::InPodConfig;
use super::netns::InpodNetns;

use crate::proxyfactory::ProxyFactory;
use crate::state::{DemandProxyState, ProxyState};
use nix::sched::{CloneFlags, unshare};
use prometheus_client::registry::Registry;

use std::sync::{Arc, RwLock};
use tokio::net::UnixStream;

use hickory_resolver::config::{ResolverConfig, ResolverOpts};

use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::istio::zds::{WorkloadInfo, WorkloadRequest, WorkloadResponse, ZdsHello};

use crate::drain::{DrainTrigger, DrainWatcher};
use crate::{dns, drain};
use once_cell::sync::Lazy;
use std::os::fd::{AsRawFd, OwnedFd};
use tracing::debug;

pub fn uid(i: usize) -> crate::inpod::WorkloadUid {
    crate::inpod::WorkloadUid::new(format!("uid{}", i))
}

pub struct Fixture {
    pub proxy_factory: ProxyFactory,
    pub ipc: InPodConfig,
    pub inpod_metrics: Arc<crate::inpod::Metrics>,
    pub drain_tx: DrainTrigger,
    pub drain_rx: DrainWatcher,
}
// Ensure that the `tracing` stack is only initialised once using `once_cell`
static UNSHARE: Lazy<()> = Lazy::new(|| {
    unshare(CloneFlags::CLONE_NEWNET).unwrap();
    let lo_set = std::process::Command::new("ip")
        .args(["link", "set", "lo", "up"])
        .status()
        .unwrap()
        .success();
    assert!(lo_set);
});

impl Default for Fixture {
    fn default() -> Fixture {
        crate::test_helpers::helpers::initialize_telemetry();
        Lazy::force(&UNSHARE);
        let mut registry = Registry::default();

        let cfg = crate::config::Config {
            packet_mark: Some(1),
            ..crate::config::construct_config(Default::default()).unwrap()
        };
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let cert_manager: Arc<crate::identity::SecretManager> =
            crate::identity::mock::new_secret_manager(std::time::Duration::from_secs(10));
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let (drain_tx, drain_rx) = drain::new();
        let dns_metrics = Some(dns::Metrics::new(&mut registry));

        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics.clone(),
        );

        let ipc = InPodConfig::new(&cfg).unwrap();
        let proxy_gen = ProxyFactory::new(
            Arc::new(cfg),
            dstate,
            cert_manager,
            metrics,
            dns_metrics,
            drain_rx.clone(),
        )
        .unwrap();
        Fixture {
            proxy_factory: proxy_gen,
            ipc,
            inpod_metrics: Arc::new(crate::inpod::Metrics::new(&mut registry)),
            drain_tx,
            drain_rx,
        }
    }
}

pub fn new_netns() -> OwnedFd {
    let mut lo_up = false;
    let mut new_netns: Option<OwnedFd> = None;
    std::thread::scope(|s| {
        s.spawn(|| {
            let res = nix::sched::unshare(CloneFlags::CLONE_NEWNET);
            if res.is_err() {
                return;
            }
            // bring lo up
            lo_up = std::process::Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success();

            if let Ok(newns) =
                std::fs::File::open(format!("/proc/self/task/{}/ns/net", nix::unistd::gettid()))
            {
                new_netns = Some(newns.into());
            }
        });
    });

    assert!(lo_up);
    new_netns.expect("failed to create netns")
}

pub async fn read_msg(s: &mut UnixStream) -> WorkloadResponse {
    let mut buf: [u8; 1000] = [0u8; 1000];
    let read_amount = s.read(&mut buf).await.expect("failed to read");

    debug!("read {} bytes", read_amount);

    let ret = WorkloadResponse::decode(&buf[..read_amount])
        .unwrap_or_else(|_| panic!("failed to decode. read amount: {}", read_amount));

    debug!("decoded {:?}", ret);
    ret
}

pub async fn read_hello(s: &mut UnixStream) -> ZdsHello {
    let mut buf: [u8; 100] = [0u8; 100];
    let read_amount = s.read(&mut buf).await.unwrap();
    ZdsHello::decode(&buf[..read_amount]).unwrap()
}

pub async fn send_snap_sent(s: &mut UnixStream) {
    let r = WorkloadRequest {
        payload: Some(
            crate::inpod::istio::zds::workload_request::Payload::SnapshotSent(Default::default()),
        ),
    };
    let data = r.encode_to_vec();
    let written = s.write(&data).await.expect("send failed");
    assert_eq!(written, data.len());
}

pub async fn send_workload_added(
    s: &mut UnixStream,
    uid: super::WorkloadUid,
    info: Option<WorkloadInfo>,
    fd: impl std::os::fd::AsRawFd,
) {
    let fds = [fd.as_raw_fd()];
    let mut cmsgs = vec![];
    let cmsg = nix::sys::socket::ControlMessage::ScmRights(&fds);
    cmsgs.push(cmsg);
    let r = WorkloadRequest {
        payload: Some(crate::inpod::istio::zds::workload_request::Payload::Add(
            crate::inpod::istio::zds::AddWorkload {
                uid: uid.into_string(),
                workload_info: info,
            },
        )),
    };

    let data: Vec<u8> = r.encode_to_vec();

    let iov = [std::io::IoSlice::new(&data[..])];
    // Wait for the socket to be writable

    s.async_io(tokio::io::Interest::WRITABLE, || {
        nix::sys::socket::sendmsg::<()>(
            s.as_raw_fd(),
            &iov,
            &cmsgs[..],
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    })
    .await
    .expect("failed to sendmsg");
}

pub async fn send_workload_del(s: &mut UnixStream, uid: super::WorkloadUid) {
    let r = WorkloadRequest {
        payload: Some(crate::inpod::istio::zds::workload_request::Payload::Del(
            crate::inpod::istio::zds::DelWorkload {
                uid: uid.into_string(),
            },
        )),
    };
    let data: Vec<u8> = r.encode_to_vec();

    let iov = [std::io::IoSlice::new(&data[..])];
    // Wait for the socket to be writable

    s.async_io(tokio::io::Interest::WRITABLE, || {
        nix::sys::socket::sendmsg::<()>(
            s.as_raw_fd(),
            &iov,
            &[],
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    })
    .await
    .expect("failed to sendmsg");
}

pub fn create_proxy_conflict(ns: &std::os::fd::OwnedFd) -> std::os::fd::OwnedFd {
    let inpodns = InpodNetns::new(
        Arc::new(crate::inpod::netns::InpodNetns::current().unwrap()),
        ns.try_clone().unwrap(),
    )
    .unwrap();
    let tl = inpodns
        .run(|| std::net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], 15008))))
        .unwrap()
        .unwrap();

    tl.into()
}
