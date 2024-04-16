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

use realm_io::AsyncRawIO;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::AddAssign;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::TcpSocket;
use tracing::trace;

use crate::proxy::ConnectionResult;
#[cfg(target_os = "linux")]
use {
    realm_io,
    socket2::{Domain, SockRef},
    std::io::ErrorKind,
    tracing::warn,
};

#[cfg(target_os = "linux")]
pub fn set_transparent(l: &TcpListener) -> io::Result<()> {
    SockRef::from(l).set_ip_transparent(true)
}

#[cfg(target_os = "linux")]
pub fn set_freebind_and_transparent(socket: &TcpSocket) -> io::Result<()> {
    let socket = SockRef::from(socket);
    match socket.domain()? {
        Domain::IPV4 => {
            socket.set_ip_transparent(true)?;
            socket.set_freebind(true)?;
        }
        Domain::IPV6 => {
            linux::set_ipv6_transparent(&socket)?;
            socket.set_freebind_ipv6(true)?
        }
        _ => return Err(Error::new(ErrorKind::Unsupported, "unsupported domain")),
    };
    Ok(())
}

pub fn to_canonical(addr: SocketAddr) -> SocketAddr {
    // another match has to be used for IPv4 and IPv6 support
    // @zhlsunshine TODO: to_canonical() should be used when it becomes stable a function in Rust
    let ip = match addr.ip() {
        IpAddr::V4(_) => return addr,
        IpAddr::V6(i) => match i.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            }
            _ => return addr,
        },
    };
    SocketAddr::from((ip, addr.port()))
}

pub fn orig_dst_addr_or_default(stream: &tokio::net::TcpStream) -> SocketAddr {
    to_canonical(match orig_dst_addr(stream) {
        Ok(addr) => addr,
        _ => stream.local_addr().expect("must get local address"),
    })
}

#[cfg(target_os = "linux")]
fn orig_dst_addr(stream: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
    let sock = SockRef::from(stream);
    // Dual-stack IPv4/IPv6 sockets require us to check both options.
    match linux::original_dst(&sock) {
        Ok(addr) => Ok(addr.as_socket().expect("failed to convert to SocketAddr")),
        Err(e4) => match linux::original_dst_ipv6(&sock) {
            Ok(addr) => Ok(addr.as_socket().expect("failed to convert to SocketAddr")),
            Err(e6) => {
                if !sock.ip_transparent().unwrap_or(false) {
                    // In TPROXY mode, this is normal, so don't bother logging
                    warn!(
                        peer=?stream.peer_addr().unwrap(),
                        local=?stream.local_addr().unwrap(),
                        "failed to read SO_ORIGINAL_DST: {e4:?}, {e6:?}"
                    );
                }
                Err(e6)
            }
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn orig_dst_addr(_: &tokio::net::TcpStream) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "SO_ORIGINAL_DST not supported on this operating system",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn set_freebind_and_transparent(_: &TcpSocket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "IP_TRANSPARENT and IP_FREEBIND are not supported on this operating system",
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
pub fn set_mark<S: std::os::unix::io::AsFd>(socket: &S, mark: u32) -> io::Result<()> {
    let socket = SockRef::from(socket);
    socket.set_mark(mark)
}

#[cfg(not(target_os = "linux"))]
pub fn set_mark(_socket: &TcpSocket, _mark: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Other,
        "SO_MARK not supported on this operating system",
    ))
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use std::os::unix::io::AsRawFd;

    use socket2::{SockAddr, SockRef};
    use tokio::io;

    pub fn set_ipv6_transparent(sock: &SockRef) -> io::Result<()> {
        unsafe {
            let optval: libc::c_int = 1;
            let ret = libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_TRANSPARENT,
                &optval as *const _ as *const libc::c_void,
                std::mem::size_of_val(&optval) as libc::socklen_t,
            );
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn original_dst(sock: &SockRef) -> io::Result<SockAddr> {
        sock.original_dst()
    }

    pub fn original_dst_ipv6(sock: &SockRef) -> io::Result<SockAddr> {
        sock.original_dst_ipv6()
    }
}

pub async fn relay<A, B>(
    upgraded: &mut A,
    stream: &mut B,
    x: &ConnectionResult,
) -> Result<(u64, u64), crate::proxy::Error>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let (mut ri, mut wi) = tokio::io::split(upgraded);
    let (mut ro, mut wo) = tokio::io::split(stream);

    let (mut sent, mut received): (u64, u64) = (0, 0);

    let client_to_server = async {
        let mut ri = tokio::io::BufReader::with_capacity(crate::proxy::HBONE_BUFFER_SIZE, &mut ri);
        let res = crate::proxy::copy_buf(&mut ri, &mut wo, &x, false).await;
        trace!(?res, "hbone -> tcp");
        received = res?;
        wo.shutdown().await
    };

    let server_to_client = async {
        let mut ro = tokio::io::BufReader::with_capacity(crate::proxy::HBONE_BUFFER_SIZE, &mut ro);
        let res = crate::proxy::copy_buf(&mut ro, &mut wi, x, true).await;
        trace!(?res, "tcp -> hbone");
        sent = res?;
        wi.shutdown().await
    };

    tokio::try_join!(client_to_server, server_to_client)?;

    trace!(sent, recv = received, "copy hbone complete");
    Ok((sent, received))
}

struct StreamWrapper<'a> {
    inner: realm_io::statistic::StatStream<&'a TcpStream, Wrapper<'a>>,
}
struct Wrapper<'a> {
    data: &'a ConnectionResult,
}

impl<'a> AsRef<realm_io::statistic::StatStream<&'a TcpStream, Wrapper<'a>>> for StreamWrapper<'a, > {
    fn as_ref(&self) -> &realm_io::statistic::StatStream<&'a TcpStream, Wrapper<'a>> {
        &self.inner
    }
}

impl<'a> AsyncRawIO for StreamWrapper<'a>
where
{
    fn x_poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_read_ready(cx)
    }

    fn x_poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.inner.poll_write_ready(cx)
    }

    fn x_try_io<R>(
        &self,
        interest: Interest,
        f: impl FnOnce() -> std::io::Result<R>,
    ) -> std::io::Result<R> {
        self.inner.try_io(interest, f)
    }
}
impl<'a> AddAssign<usize> for Wrapper<'a> {
    fn add_assign(&mut self, rhs: usize) {
        self.data.increment_recv(rhs as u64)
    }
}

#[cfg(target_os = "linux")]
pub async fn relay_zero_copy(
    downstream: &mut tokio::net::TcpStream,
    upstream: &mut tokio::net::TcpStream,
    x: &ConnectionResult,
) -> Result<(u64, u64), Error> {
    const EINVAL: i32 = 22;

    let wrapper = StreamWrapper {
        inner: realm_io::statistic::StatStream::new(downstream, Wrapper { data: x }),
    };
    match realm_io::bidi_zero_copy(&mut wrapper, upstream).await {
        Ok(d) => Ok(d),
        Err(ref e) if e.raw_os_error().map_or(false, |ec| ec == EINVAL) => {
            tokio::io::copy_bidirectional(downstream, upstream).await
        }
        Err(e) => Err(e),
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn relay(
    downstream: &mut tokio::net::TcpStream,
    upstream: &mut tokio::net::TcpStream,
) -> Result<(u64, u64), Error> {
    tokio::io::copy_bidirectional(downstream, upstream).await
}
