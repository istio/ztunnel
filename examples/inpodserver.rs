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
use ztunnel::test_helpers::inpod::{start_ztunnel_server, Message};

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    let uds = std::env::var("INPOD_UDS").unwrap();
    let netns = std::env::args().nth(1).unwrap();
    let mut netns_base_dir = std::path::PathBuf::from("/var/run/netns");
    netns_base_dir.push(netns);
    let netns_file = std::fs::File::open(netns_base_dir).unwrap();

    let fd = netns_file.as_raw_fd();

    let mut sender = start_ztunnel_server(uds.into()).await;
    sender
        .send(Message::Start(StartZtunnelMessage {
            uid: "uid-0".to_string(),
            workload_info: None,
            fd,
        }))
        .await
        .unwrap();
    sender.wait_forever().await.unwrap();
}

#[cfg(not(target_os = "linux"))]
fn main() {}
