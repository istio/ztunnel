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

use crate::test_helpers;
use crate::test_helpers::MpscAckSender;
use std::path::Path;
use tokio::io::AsyncReadExt;
use tracing::info;

pub fn start_ztunnel_server<P: AsRef<Path> + Send + 'static>(
    bind_path: P,
) -> MpscAckSender<(String, i32)> {
    info!("starting server {}", bind_path.as_ref().display());

    // remove file if exists
    if bind_path.as_ref().exists() {
        info!(
            "removing existing server socket file {}",
            bind_path.as_ref().display()
        );
        std::fs::remove_file(&bind_path).expect("remove file failed");
    }
    let (tx, mut rx) = test_helpers::mpsc_ack::<(String, i32)>(1);

    // these tests are structured in an unusual way - async operations are done in a different thread,
    // that is joined. This blocks asyncs done here. thus the need run the servers in a different thread
    info!("spawning server {}", bind_path.as_ref().display());
    std::thread::spawn(move || {
        info!("starting server thread {}", bind_path.as_ref().display());
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = crate::inpod::packet::bind(bind_path.as_ref()).expect("bind failed");
            info!(
                "waiting for connection from ztunnel server {}",
                bind_path.as_ref().display()
            );
            let (mut ztun_sock, _) = listener.accept().await.expect("accept failed");
            info!(
                "accepted connection from ztunnel server {}",
                bind_path.as_ref().display()
            );

            // read the hello message:
            let hello = read_hello(&mut ztun_sock).await;
            info!("hello received, {:?}", hello);

            // send snapshot done msg:
            send_snap_sent(&mut ztun_sock).await;
            info!(
                "initial snapshot sent from ztun server {}",
                bind_path.as_ref().display()
            );

            // receive ack from ztunnel
            let mut buf: [u8; 100] = [0u8; 100];
            let read_amount = ztun_sock.read(&mut buf).await.unwrap();
            info!("ack received, len {}", read_amount);
            // Now await for FDs
            while let Some((uid, fd)) = rx.recv().await {
                let orig_uid = uid.clone();
                let uid = crate::inpod::WorkloadUid::new(uid);
                if fd >= 0 {
                    send_workload_added(&mut ztun_sock, uid, fd).await;
                } else {
                    send_workload_del(&mut ztun_sock, uid).await;
                };

                // receive ack from ztunnel
                let _ = read_msg(&mut ztun_sock).await;
                info!(uid=orig_uid, %fd, "ack received");
                rx.ack().await.expect("ack failed");
            }
        });
    });
    tx
}
