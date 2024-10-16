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

use crate::inpod::test_helpers::{
    read_hello, read_msg, send_snap_sent, send_workload_added, send_workload_del,
};

use crate::inpod::istio::zds::WorkloadInfo;
use crate::test_helpers;
use crate::test_helpers::MpscAckSender;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;
use tracing::{debug, info, instrument};

#[derive(Debug)]
pub struct StartZtunnelMessage {
    pub uid: String,
    pub workload_info: Option<WorkloadInfo>,
    pub fd: i32,
}

#[derive(Debug)]
pub enum Message {
    Start(StartZtunnelMessage),
    Stop(String),
}

#[instrument]
pub async fn start_ztunnel_server(bind_path: PathBuf) -> MpscAckSender<Message> {
    info!("starting server");

    // remove file if exists
    if bind_path.exists() {
        info!("removing existing server socket file",);
        std::fs::remove_file(&bind_path).expect("remove file failed");
    }
    let (tx, mut rx) = test_helpers::mpsc_ack::<Message>(1);

    info!("spawning server");
    tokio::task::spawn(async move {
        let listener = crate::inpod::packet::bind(&bind_path).expect("bind failed");
        info!("waiting for connection from ztunnel server");
        let (mut ztun_sock, _) = listener.accept().await.expect("accept failed");
        info!("accepted connection from ztunnel server");

        // read the hello message:
        let hello = read_hello(&mut ztun_sock).await;
        info!(?hello, "hello received");

        // send snapshot done msg:
        send_snap_sent(&mut ztun_sock).await;
        info!("sent initial snapshot",);

        // receive ack from ztunnel
        let mut buf: [u8; 100] = [0u8; 100];
        let read_amount = ztun_sock.read(&mut buf).await.unwrap();
        info!("ack received, len {}", read_amount);
        // Now await for FDs
        while let Some(msg) = rx.recv().await {
            let uid = match msg {
                Message::Start(StartZtunnelMessage {
                    uid,
                    workload_info,
                    fd,
                }) => {
                    let orig_uid = uid.clone();
                    debug!(uid, %fd, "sending start message");
                    let uid = crate::inpod::WorkloadUid::new(uid);
                    send_workload_added(&mut ztun_sock, uid, workload_info, fd).await;
                    orig_uid
                }
                Message::Stop(uid) => {
                    let orig_uid = uid.clone();
                    debug!(uid, "sending delete message");
                    let uid = crate::inpod::WorkloadUid::new(uid);
                    send_workload_del(&mut ztun_sock, uid).await;
                    orig_uid
                }
            };
            // receive ack from ztunnel
            let _ = read_msg(&mut ztun_sock).await;
            info!(uid, "ack received");
            if rx.ack().await.is_err() {
                // Server shut down
                break;
            }
        }
    });
    tx
}
