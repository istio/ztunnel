use crate::drain::DrainWatcher;
use crate::inpod::windows::{WorkloadData, WorkloadMessage, WorkloadUid};
use crate::inpod::istio::zds::{
    self, workload_request::Payload, Ack, Version, WorkloadRequest, WorkloadResponse, ZdsHello,
};
use prost::Message;
use tracing::info;
use std::io::{IoSlice, IoSliceMut};
use tokio::net::windows::named_pipe::*;


pub struct WorkloadStreamProcessor {
    client: NamedPipeClient,
    drain: DrainWatcher,
}

impl WorkloadStreamProcessor {
    pub fn new(client: NamedPipeClient, drain: DrainWatcher) -> Self {
        WorkloadStreamProcessor { client, drain }
    }

    pub async fn send_hello(&mut self) -> std::io::Result<()> {
        let r = ZdsHello {
            version: Version::V1 as i32,
        };
        self.send_msg(r).await
    }

    pub async fn send_ack(&mut self) -> std::io::Result<()> {
        let r = WorkloadResponse {
            payload: Some(zds::workload_response::Payload::Ack(Ack {
                error: String::new(),
            })),
        };
        self.send_msg(r).await
    }

    pub async fn send_nack(&mut self, e: anyhow::Error) -> std::io::Result<()> {
        let r = WorkloadResponse {
            payload: Some(zds::workload_response::Payload::Ack(Ack {
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
                tokio::select! {
                    biased; // check drain first, so we don't read from the pipe if we are draining.
                    _ = self.drain.clone().wait_for_drain() => {
                        info!("workload proxy manager: drain requested");
                        return Ok(None);
                    }
                    res = self.client.readable() => res,
                }?;
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
        info!("Successfully read {:?} bytes from pipe", len);
        get_workload_data(&buffer[..len]).map(Some)
    }
}

fn get_workload_data(data: &[u8]) -> anyhow::Result<WorkloadMessage> {
    let req = get_info_from_data(data)?;
    let payload = req.payload.ok_or(anyhow::anyhow!("no payload"))?;
    match payload {
        Payload::Add(a) => {
            let uid = a.uid;
            Ok(WorkloadMessage::AddWorkload(WorkloadData {
                workload_uid: WorkloadUid::new(uid),
                workload_info: a.workload_info,
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
