use crate::inpod::windows::protocol::istio::zds::WorkloadInfo;
use crate::inpod::windows::{WorkloadData, WorkloadMessage, WorkloadUid};
use istio::zds::{
    workload_request::Payload, Ack, Version, WorkloadRequest, WorkloadResponse, ZdsHello,
};
use prost::Message;
use std::io::{IoSlice, IoSliceMut};
use std::process::exit;
use tokio::net::windows::named_pipe::*;

pub mod istio {
    pub mod zds {
        tonic::include_proto!("istio.workload.zds");
    }
}

const PIPE_NAME: &str = r"\\.\pipe\istio-zds";

pub fn get_zds_pipe_name() -> &'static str {
    PIPE_NAME
}

// pub fn get_zcs_name_piped_client() -> NamedPipeClient {
//     ClientOptions::new()
//         .pipe_mode(PipeMode::Message)
//         .open(PIPE_NAME)
//         .expect("Failed to connect to pipe")
// }

pub struct WorkloadStreamProcessor {
    client: NamedPipeClient,
}

impl WorkloadStreamProcessor {
    pub fn new(client: NamedPipeClient) -> Self {
        WorkloadStreamProcessor { client }
    }

    pub async fn send_hello(&mut self) -> std::io::Result<()> {
        let r = ZdsHello {
            version: Version::V1 as i32,
        };
        self.send_msg(r).await
    }

    pub async fn send_ack(&mut self) -> std::io::Result<()> {
        let r = WorkloadResponse {
            payload: Some(istio::zds::workload_response::Payload::Ack(Ack {
                error: String::new(),
            })),
        };
        self.send_msg(r).await
    }

    pub async fn send_nack(&mut self, e: anyhow::Error) -> std::io::Result<()> {
        let r = WorkloadResponse {
            payload: Some(istio::zds::workload_response::Payload::Ack(Ack {
                error: e.to_string(),
            })),
        };
        self.send_msg(r).await
    }

    async fn send_msg<T: prost::Message + 'static>(&mut self, r: T) -> std::io::Result<()> {
        let mut buf = Vec::new();
        r.encode(&mut buf).unwrap();

        let iov = [IoSlice::new(&buf)];
        loop {
            self.client.writable().await?;
            match self.client.try_write_vectored(&iov) {
                Ok(n) => {
                    println!("Wrote {:?} bytes to pipe", n);
                    return Ok(());
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    println!("Received WouldBlock error, retrying");
                    continue;
                }
                Err(e) => return Err(e),
            };
        }
    }

    pub async fn read_message(&self) -> anyhow::Result<Option<WorkloadMessage>> {
        // TODO: support messages for removing workload
        let mut buffer: Vec<u8> = vec![0u8; 1024];
        let mut iov = [IoSliceMut::new(&mut buffer)];

        let len = {
            loop {
                println!("Waiting for pipe to be readable");
                self.client.readable().await?;
                // let read = Overlapped::new(cb)
                let res = self.client.try_read_vectored(&mut iov);
                let ok_res = match res {
                    Ok(res) => {
                        if res == 0 {
                            println!("No data read from pipe. Probably a bug");
                            return Ok(None);
                        }
                        res
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        println!("Received WouldBlock error, retrying");
                        continue;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                };
                break ok_res;
            }
        };
        get_workload_data(&buffer[..len]).map(Some)
    }
}

fn get_workload_data(data: &[u8]) -> anyhow::Result<WorkloadMessage> {
    let req = get_info_from_data(data)?;
    let payload = req.payload.ok_or(anyhow::anyhow!("no payload"))?;
    match payload {
        Payload::Add(a) => {
            let uid = a.uid;
            let workload_info: Option<WorkloadInfo> = a.workload_info;
            let windows_namespace_id: u32 = a
                .windows_namespace_id
                .parse()
                .map_err(|e| anyhow::anyhow!("Failed to parse windows_namespace_id: {}", e))?;
            Ok(WorkloadMessage::AddWorkload(WorkloadData {
                windows_namespace_id,
                workload_uid: WorkloadUid::new(uid),
                workload_info,
            }))
        }
        Payload::Keep(k) => Ok(WorkloadMessage::KeepWorkload(WorkloadUid::new(k.uid))),
        Payload::Del(d) => Ok(WorkloadMessage::DelWorkload(WorkloadUid::new(d.uid))),
        Payload::SnapshotSent(_) => Ok(WorkloadMessage::WorkloadSnapshotSent),
    }
}

fn get_info_from_data<'a>(data: impl bytes::Buf + 'a) -> anyhow::Result<WorkloadRequest> {
    Ok(WorkloadRequest::decode(data)?)
}

#[tokio::main]
async fn main() {
    let client = loop {
        match ClientOptions::new()
            .pipe_mode(PipeMode::Message)
            .open(PIPE_NAME)
        {
            Ok(client) => break client,
            Err(e) => {
                println!("Failed to connect to pipe: {}", e);
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    };

    let mut processor = WorkloadStreamProcessor::new(client);
    processor
        .send_hello()
        .await
        .expect("Failed to send hello message");

    println!("Sent hello message");
    let resp = process(&mut processor)
        .await
        .expect("Failed to read message after sending hello");
    match resp {
        Some(msg) => {
            println!("Received WorkloadMessage: {:?}", msg);
            // Send Ack
            processor
                .send_ack()
                .await
                .expect("Failed to send ack message");
        }
        None => {
            println!("No message received");
            exit(1);
        }
    }
}

async fn process(
    processor: &mut WorkloadStreamProcessor,
) -> anyhow::Result<Option<WorkloadMessage>> {
    let readmsg = processor.read_message();
    // Note: readmsg future is NOT cancel safe, so we want to make sure this function doesn't exit
    // return without completing it.
    futures::pin_mut!(readmsg);
    readmsg.await
}
