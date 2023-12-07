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
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

pub fn start_ztunnel_server<P: AsRef<Path> + Send + 'static>(
    bind_path: P,
) -> (
    tokio::sync::mpsc::Sender<i32>,
    tokio::sync::mpsc::Receiver<()>,
) {
    info!("starting server {}", bind_path.as_ref().display());
    use prost::Message;

    // remove file if exists
    if bind_path.as_ref().exists() {
        info!(
            "removing existing server socket file {}",
            bind_path.as_ref().display()
        );
        std::fs::remove_file(&bind_path).expect("remove file failed");
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<i32>(1);
    let (ack_tx, ack_rx) = tokio::sync::mpsc::channel::<()>(1);

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

            // send snapshot done msg:
            let r = crate::inpod::istio::zds::WorkloadRequest {
                payload: Some(
                    crate::inpod::istio::zds::workload_request::Payload::SnapshotSent(
                        Default::default(),
                    ),
                ),
            };
            let data = r.encode_to_vec();
            let written = ztun_sock.write(&data).await.expect("send failed");
            info!(
                "initial snapshot sent from ztun server {}",
                bind_path.as_ref().display()
            );
            assert_eq!(written, data.len());

            // receive ack from ztunnel
            let mut buf: [u8; 100] = [0u8; 100];
            let read_amount = ztun_sock.read(&mut buf).await.unwrap();
            info!("ack received, len {}", read_amount);
            // Now await for FDs
            while let Some(fd) = rx.recv().await {
                let fds = [fd];
                let mut cmsgs = vec![];    
                let r = if fd >= 0 {
                    let cmsg = nix::sys::socket::ControlMessage::ScmRights(&fds);
                    cmsgs.push(cmsg);
                    crate::inpod::istio::zds::WorkloadRequest {
                        payload: Some(crate::inpod::istio::zds::workload_request::Payload::Add(
                            crate::inpod::istio::zds::AddWorkload {
                                uid: "uid-0".into(),
                            },
                        )),
                    }
                } else {
                    crate::inpod::istio::zds::WorkloadRequest {
                        payload: Some(crate::inpod::istio::zds::workload_request::Payload::Del(
                            crate::inpod::istio::zds::DelWorkload {
                                uid: "uid-0".into(),
                            },
                        )),
                    }
                };
                let data: Vec<u8> = r.encode_to_vec();

                let iov = [std::io::IoSlice::new(&data[..])];
                // Wait for the socket to be writable
                ztun_sock
                    .async_io(tokio::io::Interest::WRITABLE, || {
                        nix::sys::socket::sendmsg::<()>(
                            ztun_sock.as_raw_fd(),
                            &iov,
                            &cmsgs[..],
                            nix::sys::socket::MsgFlags::empty(),
                            None,
                        )
                        .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                    })
                    .await
                    .expect("failed to sendmsg");

                // receive ack from ztunnel
                let mut buf: [u8; 100] = [0u8; 100];
                let read_amount = ztun_sock.read(&mut buf).await.unwrap();
                info!("ack received, len {}", read_amount);
                ack_tx.send(()).await.expect("send failed");
            }
        });
    });
    (tx, ack_rx)
}
