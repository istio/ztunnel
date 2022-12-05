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

use realm_io;
use socket2::SockRef;
use tokio::io;
use tokio::net::TcpListener;
use tracing::warn;

#[cfg(target_os = "linux")]
pub fn set_transparent(l: &TcpListener) -> io::Result<()> {
    SockRef::from(l).set_ip_transparent(true)
}

pub fn orig_dst_addr_or_default(stream: &tokio::net::TcpStream) -> SocketAddr {
    match orig_dst_addr(stream) {
        Ok(addr) => addr,
        _ => stream.local_addr().expect("must get local address"),
    }
}

#[cfg(target_os = "linux")]
pub fn orig_dst_addr(stream: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
    let sock = SockRef::from(stream);
    // Dual-stack IPv4/IPv6 sockets require us to check both options.
    match linux::original_dst(&sock) {
        Ok(addr) => Ok(addr.as_socket().expect("failed to convert to SocketAddr")),
        _ => match linux::original_dst_ipv6(&sock) {
            Ok(addr) => Ok(addr.as_socket().expect("failed to convert to SocketAddr")),
            Err(e) => {
                warn!("failed to read SO_ORIGINAL_DST: {:?}", e);
                Err(e)
            }
        },
    }
}

#[cfg(not(target_os = "linux"))]
pub fn orig_dst_addr(_: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "SO_ORIGINAL_DST not supported on this operating system",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn set_transparent(_: &TcpListener) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "IP_TRANSPARENT not supported on this operating system",
    ))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use std::os::unix::io::AsRawFd;

    use socket2::{SockAddr, SockRef};
    use tokio::io;

    // Replace with socket2's version once there is a release that contains
    // https://github.com/rust-lang/socket2/pull/360
    pub fn original_dst(sock: &SockRef) -> io::Result<SockAddr> {
        // Safety: `getsockopt` initialises the `SockAddr` for us.
        unsafe {
            SockAddr::init(|storage, len| {
                match libc::getsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IP,
                    libc::SO_ORIGINAL_DST,
                    storage.cast(),
                    len,
                ) {
                    -1 => Err(std::io::Error::last_os_error()),
                    retval => Ok(retval),
                }
            })
        }
        .map(|(_, addr)| addr)
    }

    // Replace with socket2's version once there is a release that contains
    // https://github.com/rust-lang/socket2/pull/360
    pub fn original_dst_ipv6(sock: &SockRef) -> io::Result<SockAddr> {
        // Safety: `getsockopt` initialises the `SockAddr` for us.
        unsafe {
            SockAddr::init(|storage, len| {
                match libc::getsockopt(
                    sock.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IP6T_SO_ORIGINAL_DST,
                    storage.cast(),
                    len,
                ) {
                    -1 => Err(std::io::Error::last_os_error()),
                    retval => Ok(retval),
                }
            })
        }
        .map(|(_, addr)| addr)
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
