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

use std::os::fd::AsRawFd;

use ztunnel::test_helpers::inpod::StartZtunnelMessage;
use ztunnel::{
    inpod::istio::zds::WorkloadInfo,
    test_helpers::inpod::{Message, start_ztunnel_server},
};

const PROXY_WORKLOAD_INFO: &str = "PROXY_WORKLOAD_INFO";

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let uds = std::env::var("INPOD_UDS").unwrap();
    let pwi = match parse_proxy_workload_info() {
        Ok(pwi) => pwi,
        Err(e) => {
            eprintln!("Failed to parse proxy workload info: {:?}", e);
            return;
        }
    };
    let netns = std::env::args().nth(1).unwrap();
    let mut netns_base_dir = std::path::PathBuf::from("/var/run/netns");
    netns_base_dir.push(netns);
    let netns_file = std::fs::File::open(netns_base_dir).unwrap();

    let fd = netns_file.as_raw_fd();

    let mut sender = start_ztunnel_server(uds.into()).await;
    sender
        .send(Message::Start(StartZtunnelMessage {
            uid: "uid-0".to_string(),
            workload_info: Some(pwi),
            fd,
        }))
        .await
        .unwrap();
    sender.wait_forever().await.unwrap();
}

fn parse_proxy_workload_info() -> Result<WorkloadInfo, Error> {
    let pwi = match std::env::var(PROXY_WORKLOAD_INFO) {
        Ok(val) => val,
        Err(_) => {
            // Provide a default WorkloadInfo value if the environment variable is not set.
            return Ok(WorkloadInfo {
                name: "local".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
            });
        }
    };

    let s: Vec<&str> = pwi.splitn(3, "/").collect();
    let &[ns, name, sa] = &s[..] else {
        return Err(Error::InvalidArgument(format!(
            "{PROXY_WORKLOAD_INFO} must match the format 'namespace/name/service-account' (got {s:?})"
        )));
    };

    Ok(WorkloadInfo {
        name: name.to_string(),
        namespace: ns.to_string(),
        service_account: sa.to_string(),
    })
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}

#[cfg(not(target_os = "linux"))]
fn main() {}
