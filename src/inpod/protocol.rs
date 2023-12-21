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

use super::istio::zds::{self, Ack, WorkloadRequest, WorkloadResponse};
use super::{WorkloadData, WorkloadInfo, WorkloadMessage};
use nix::sys::socket::{recvmsg, sendmsg, MsgFlags};
use prost::Message;
use std::io::{IoSlice, IoSliceMut};

use drain::Watch;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use tokio::net::UnixStream;
use tracing::{debug, info};

#[cfg(test)]
use mockall::automock;

// Not dead code, but automock confuses Rust otherwise when built with certain targets
#[allow(dead_code)]
pub struct WorkloadStreamProcessor {
    stream: UnixStream,
    drain: Watch,
}

#[cfg_attr(test, automock)]
#[allow(dead_code)]
impl WorkloadStreamProcessor {
    pub fn new(stream: UnixStream, drain: Watch) -> Self {
        WorkloadStreamProcessor { stream, drain }
    }
    pub async fn send_ack(&mut self) -> std::io::Result<()> {
        let r = WorkloadResponse {
            payload: Some(zds::workload_response::Payload::Ack(Ack {
                error: String::new(),
            })),
        };
        self.send_response(r).await
    }
    pub async fn send_nack(&mut self, e: anyhow::Error) -> std::io::Result<()> {
        let r = WorkloadResponse {
            payload: Some(zds::workload_response::Payload::Ack(Ack {
                error: e.to_string(),
            })),
        };
        self.send_response(r).await
    }

    async fn send_response(&mut self, r: WorkloadResponse) -> std::io::Result<()> {
        let mut buf = Vec::new();
        r.encode(&mut buf).unwrap();

        let iov = [IoSlice::new(&buf)];
        let raw_fd = self.stream.as_raw_fd();

        // async_io takes care of WouldBlock error, so no need for loop here
        self.stream
            .async_io(tokio::io::Interest::WRITABLE, || {
                sendmsg::<()>(raw_fd, &iov[..], &[], MsgFlags::empty(), None)
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            })
            .await
            .map(|_| ())
    }
    pub async fn read_message(&self) -> anyhow::Result<Option<WorkloadMessage>> {
        // TODO: support messages for removing workload
        let mut cmsgspace = nix::cmsg_space!(RawFd);
        let mut buffer = vec![0u8; 1024];
        let raw_fd = self.stream.as_raw_fd();

        // can't use async_io here as the borrow checker doesn't like it. i get it..
        loop {
            let msgspace_ref = cmsgspace.as_mut();
            let mut iov = [IoSliceMut::new(&mut buffer)];

            tokio::select! {
                biased; // check drain first, so we don't read from the socket if we are draining.
                _ =   self.drain.clone().signaled() => {
                    info!("workload proxy manager: drain requested");
                    return Ok(None);
                }
                res =  self.stream.readable() => res,
            }?;

            let res: Result<nix::sys::socket::RecvMsg<'_, '_, ()>, std::io::Error> =
                self.stream.try_io(tokio::io::Interest::READABLE, || {
                    recvmsg::<()>(
                        raw_fd,
                        &mut iov,
                        Some(msgspace_ref),
                        MsgFlags::MSG_CMSG_CLOEXEC,
                    )
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                });
            match res {
                Ok(res) => {
                    if res.bytes == 0 {
                        return Ok(None);
                    }
                    return workload_processor_helpers::get_workload_data(res, &iov[..]).map(Some);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Err(e) => {
                    return Err(e.into());
                }
            };
        }
    }
}

// Helper functions for WorkloadStreamProcessor. separated to their on mod for easier mocking of WorkloadStreamProcessor.
mod workload_processor_helpers {
    use super::*;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags};
    use tracing::warn;
    use zds::workload_request::Payload;

    pub(super) fn get_workload_data(
        res: nix::sys::socket::RecvMsg<'_, '_, ()>,
        iov: &[IoSliceMut],
    ) -> anyhow::Result<WorkloadMessage> {
        get_workload_data_from_parts(iovs_buf(iov, res.bytes), res.cmsgs(), res.flags)
    }
    // This is separated from get_workload_data so we can test it without needing a real RecvMsg.
    pub(super) fn get_workload_data_from_parts<'a>(
        data: impl bytes::Buf + 'a,
        cmsgs: impl Iterator<Item = ControlMessageOwned>,
        flags: MsgFlags,
    ) -> anyhow::Result<WorkloadMessage> {
        // call maybe_get_fd first (and not get_info_from_data), so that if it fails we will close the FDs.
        let maybe_our_fd = maybe_get_fd(cmsgs)?;

        // do all other checks after we parsed fds, so no leaks happen.
        if flags.contains(MsgFlags::MSG_TRUNC) {
            // TODO: add metrics
            anyhow::bail!("received truncated message");
        }

        if flags.contains(MsgFlags::MSG_CTRUNC) {
            // TODO: add metrics
            anyhow::bail!("received truncated message");
        }

        let req = get_info_from_data(data)?;
        let payload = req.payload.ok_or(anyhow::anyhow!("no payload"))?;
        match (payload, maybe_our_fd) {
            (Payload::Add(a), Some(our_netns)) => {
                let uid: String = a.uid;
                Ok(WorkloadMessage::AddWorkload(WorkloadData {
                    netns: our_netns,
                    info: WorkloadInfo { workload_uid: uid },
                }))
            }
            (Payload::Add(_), None) => Err(anyhow::anyhow!("No control message")),
            // anything other than Add shouldn't have FDs
            (_, Some(_)) => Err(anyhow::anyhow!("Unexpected control message")),
            (Payload::Keep(k), None) => Ok(WorkloadMessage::KeepWorkload(k.uid)),
            (Payload::Del(d), None) => Ok(WorkloadMessage::DelWorkload(d.uid)),
            (Payload::SnapshotSent(_), None) => Ok(WorkloadMessage::WorkloadSnapshotSent),
        }
    }

    fn get_info_from_data<'a>(data: impl bytes::Buf + 'a) -> anyhow::Result<WorkloadRequest> {
        Ok(WorkloadRequest::decode(data)?)
    }

    fn maybe_get_fd(
        cmsgs: impl Iterator<Item = ControlMessageOwned>,
    ) -> anyhow::Result<Option<std::os::fd::OwnedFd>> {
        let mut our_netns = None;
        let mut total_fds = 0;
        for cmsg in cmsgs {
            match cmsg {
                ControlMessageOwned::ScmRights(fds) => {
                    let len = fds.len();
                    total_fds += len;
                    if total_fds != 1 {
                        for fd in fds {
                            // fds in the vector are ours, so own them and drop them so they are closed (prevent resource leak).
                            // Safety: ScmRights returns a list of FDs that we own, so we can safely drop them.
                            std::mem::drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) });
                        }
                    } else {
                        // Safety: ScmRights returns FDs opened by the kernel for us, so we can
                        // safely own it.
                        our_netns = Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) })
                    }
                }
                u => {
                    warn!("Unexpected control message {:?}", u);
                    continue;
                }
            }
        }
        // only check for errors once we are done parsing all FDs
        if total_fds > 1 {
            anyhow::bail!("Expected 1 FD, got {}", total_fds);
        }

        // make sure that we got a netns FD.
        if let Some(our_netns) = &our_netns {
            // validate that the fd we got is a netns. This should never happen, and is here
            // to catch potential bugs in the node agent during development.
            debug!(
                "Validating netns FD: {:?}",
                validate_ns(our_netns.as_raw_fd())
            );
        }

        Ok(our_netns)
    }
}

fn validate_ns(fd: std::os::fd::RawFd) -> anyhow::Result<()> {
    // on newer kernels we can get the ns type! note that this doesn't work on older kernels.
    // so an error doesn't mean its not a netns.
    // #define NSIO	0xb7
    const NSIO: u8 = 0xb7;
    // #define NS_GET_NSTYPE		_IO(NSIO, 0x3)
    const NS_GET_NSTYPE: u8 = 0x3;
    nix::ioctl_none!(get_ns_type, NSIO, NS_GET_NSTYPE);
    let nstype = unsafe { get_ns_type(fd) };
    if let Ok(nstype) = nstype {
        // ignore errors in case we are in an old kernel
        if nstype != nix::libc::CLONE_NEWNET {
            anyhow::bail!("Unexpected ns type: {:?}", nstype);
        } else {
            debug!("FD {} type is netns", fd);
        }
    } else {
        // can get ns type, do a different check - that the fd came from the nsfs.
        let data = nix::sys::statfs::fstatfs(&fd)?;
        let f_type = data.filesystem_type();
        if f_type != nix::sys::statfs::PROC_SUPER_MAGIC && f_type != nix::sys::statfs::NSFS_MAGIC {
            anyhow::bail!("Unexpected FD type for netns: {:?}", f_type);
        }
    }

    debug!("FD {} looks like a netns", fd);
    Ok(())
}

fn iovs_buf<'a>(slices: &'a [IoSliceMut<'a>], remaining: usize) -> IoSliceBuf<'a> {
    IoSliceBuf {
        index: 0,
        offset: 0,
        remaining,
        slices,
    }
}

#[derive(Debug)]
struct IoSliceBuf<'a> {
    index: usize,
    offset: usize,
    remaining: usize,
    slices: &'a [IoSliceMut<'a>],
}

impl<'a> bytes::Buf for IoSliceBuf<'a> {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        let slice = &self.slices[self.index][self.offset..];
        let len = self.remaining.min(slice.len());
        &slice[..len]
    }

    fn advance(&mut self, cnt: usize) {
        if cnt == 0 {
            return;
        }
        if cnt > self.remaining {
            panic!("advancing beyond end of buffer");
        }
        self.offset += cnt;
        self.remaining -= cnt;
        while self.offset >= self.slices[self.index].len() {
            self.offset -= self.slices[self.index].len();
            self.index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::istio;
    use super::super::tests::{fd_for_uid, uid};
    use super::*;
    use bytes::Buf;
    use nix::sys::socket::{ControlMessageOwned, MsgFlags};
    // Helpers to test get_workload_data_from_parts

    fn prep_request(p: zds::workload_request::Payload) -> Vec<u8> {
        let r = WorkloadRequest { payload: Some(p) };
        r.encode_to_vec()
    }

    #[test]
    fn test_parse_add_workload() {
        let cmsgs = [ControlMessageOwned::ScmRights(vec![fd_for_uid(0)])];
        let flags = MsgFlags::empty();
        let data = prep_request(zds::workload_request::Payload::Add(
            istio::zds::AddWorkload { uid: uid(0) },
        ));

        let m = workload_processor_helpers::get_workload_data_from_parts(
            &data[..],
            cmsgs.into_iter(),
            flags,
        )
        .unwrap();

        assert!(matches!(m, WorkloadMessage::AddWorkload(_)));
    }

    #[test]
    fn test_parse_del_workload_with_fds_fails() {
        let cmsgs = [ControlMessageOwned::ScmRights(vec![fd_for_uid(0)])];
        let flags = MsgFlags::empty();
        let data = prep_request(zds::workload_request::Payload::Del(
            istio::zds::DelWorkload { uid: uid(0) },
        ));

        let res = workload_processor_helpers::get_workload_data_from_parts(
            &data[..],
            cmsgs.into_iter(),
            flags,
        );
        assert!(res.is_err());
    }

    #[test]
    fn test_parse_del_workload() {
        let flags = MsgFlags::empty();
        let data = prep_request(zds::workload_request::Payload::Del(
            istio::zds::DelWorkload { uid: uid(0) },
        ));

        let res = workload_processor_helpers::get_workload_data_from_parts(
            &data[..],
            [].into_iter(),
            flags,
        )
        .unwrap();
        assert!(matches!(res, WorkloadMessage::DelWorkload(_)));
    }

    #[test]
    fn test_iovec_buf() {
        let mut buffer = vec![b'a'; 10];
        let iov = [IoSliceMut::new(&mut buffer)];

        let buf = iovs_buf(&iov[..], 2);
        assert_eq!(buf.chunk(), &[b'a'; 2]);
    }

    #[test]
    fn test_iovec_multi_buf() {
        let mut buffer: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        let mut buffer2: Vec<u8> = vec![21, 22, 23, 24, 25, 26, 27, 28, 29, 30];
        let iov = [IoSliceMut::new(&mut buffer), IoSliceMut::new(&mut buffer2)];

        let mut buf = iovs_buf(&iov[..], 15);
        assert_eq!(buf.remaining(), 15);
        assert_eq!(buf.chunk(), &[1u8, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
        buf.advance(6);
        assert_eq!(buf.remaining(), 9);
        assert_eq!(buf.chunk(), &[7u8, 8, 9, 0]);
        buf.advance(6);
        assert_eq!(buf.remaining(), 3);
        assert_eq!(buf.chunk(), &[23u8, 24, 25]);
        // shouldn't panic
        buf.advance(0);
        assert_eq!(buf.chunk(), &[23u8, 24, 25]);
    }

    #[test]
    #[should_panic]
    fn test_iovec_buf_outof_bounds() {
        let mut buffer = vec![b'a'; 10];
        let iov = [IoSliceMut::new(&mut buffer)];

        let mut buf = iovs_buf(&iov[..], 2);
        buf.advance(3);
    }
}
