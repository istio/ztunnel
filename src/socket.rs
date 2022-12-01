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

use std::io::Error;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;

use realm_io;
use tokio::io;
use tokio::net::TcpListener;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn set_transparent(l: &TcpListener) -> io::Result<()> {
    let fd = l.as_raw_fd();

    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_TRANSPARENT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        );
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

pub fn orig_dst_addr_or_default(sock: &tokio::net::TcpStream) -> SocketAddr {
    orig_dst_addr(sock).unwrap_or_else(|_| sock.local_addr().expect("must get local address"))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn orig_dst_addr(sock: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
    let fd = sock.as_raw_fd();

    unsafe { linux::so_original_dst(fd) }
}

#[cfg(not(target_os = "linux"))]
pub fn orig_dst_addr(_: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "SO_ORIGINAL_DST not supported on this operating system",
    ))
}

#[cfg(not(target_os = "linux"))]
#[allow(unsafe_code)]
pub fn set_transparent(_: &TcpListener) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "IP_TRANSPARENT not supported on this operating system",
    ))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::os::unix::io::RawFd;
    use std::{io, mem};

    use log::warn;

    pub unsafe fn so_original_dst(fd: RawFd) -> io::Result<SocketAddr> {
        let mut sockaddr: libc::sockaddr_storage = mem::zeroed();
        let mut socklen: libc::socklen_t = mem::size_of::<libc::sockaddr_storage>() as u32;

        let ret = libc::getsockopt(
            fd,
            libc::SOL_IP,
            libc::SO_ORIGINAL_DST,
            &mut sockaddr as *mut _ as *mut _,
            &mut socklen as *mut _ as *mut _,
        );
        if ret != 0 {
            let e = io::Error::last_os_error();
            warn!("failed to read SO_ORIGINAL_DST: {:?}", e);
            return Err(e);
        }

        mk_addr(&sockaddr, socklen)
    }

    // Borrowed with love from net2-rs
    // https://github.com/rust-lang-nursery/net2-rs/blob/1b4cb4fb05fbad750b271f38221eab583b666e5e/src/socket.rs#L103
    //
    // Copyright (c) 2014 The Rust Project Developers
    fn mk_addr(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> io::Result<SocketAddr> {
        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                assert!(len as usize >= mem::size_of::<libc::sockaddr_in>());

                let sa = {
                    let sa = storage as *const _ as *const libc::sockaddr_in;
                    unsafe { *sa }
                };

                let bits = ntoh32(sa.sin_addr.s_addr);
                let ip = Ipv4Addr::new(
                    (bits >> 24) as u8,
                    (bits >> 16) as u8,
                    (bits >> 8) as u8,
                    bits as u8,
                );
                let port = sa.sin_port;
                Ok(SocketAddr::V4(SocketAddrV4::new(ip, ntoh16(port))))
            }
            libc::AF_INET6 => {
                assert!(len as usize >= mem::size_of::<libc::sockaddr_in6>());

                let sa = {
                    let sa = storage as *const _ as *const libc::sockaddr_in6;
                    unsafe { *sa }
                };

                let arr = sa.sin6_addr.s6_addr;
                let ip = Ipv6Addr::new(
                    (arr[0] as u16) << 8 | (arr[1] as u16),
                    (arr[2] as u16) << 8 | (arr[3] as u16),
                    (arr[4] as u16) << 8 | (arr[5] as u16),
                    (arr[6] as u16) << 8 | (arr[7] as u16),
                    (arr[8] as u16) << 8 | (arr[9] as u16),
                    (arr[10] as u16) << 8 | (arr[11] as u16),
                    (arr[12] as u16) << 8 | (arr[13] as u16),
                    (arr[14] as u16) << 8 | (arr[15] as u16),
                );

                let port = sa.sin6_port;
                let flowinfo = sa.sin6_flowinfo;
                let scope_id = sa.sin6_scope_id;
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    ntoh16(port),
                    flowinfo,
                    scope_id,
                )))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid argument",
            )),
        }
    }

    fn ntoh16(i: u16) -> u16 {
        <u16>::from_be(i)
    }

    fn ntoh32(i: u32) -> u32 {
        <u32>::from_be(i)
    }
}

const EINVAL: i32 = 22;
pub async fn relay(
    downstream: &mut tokio::net::TcpStream,
    upstream: &mut tokio::net::TcpStream,
) -> Result<(), Error> {
    #[cfg(all(target_os = "linux"))]
    {
        match realm_io::bidi_zero_copy(downstream, upstream).await {
            Ok(()) => Ok(()),
            Err(ref e) if e.raw_os_error().map_or(false, |ec| ec == EINVAL) => {
                tokio::io::copy_bidirectional(downstream, upstream)
                    .await
                    .map(|_| ())
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        tokio::io::copy_bidirectional(downstream, upstream)
            .await
            .map(|_| ())
    }
}
