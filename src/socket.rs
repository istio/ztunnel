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

use tokio::io;

use tokio::net::TcpSocket;
use tokio::net::{TcpListener, TcpStream};

use crate::config::SocketConfig;
use socket2::{SockRef, TcpKeepalive};

#[cfg(target_os = "linux")]
use {socket2::Domain, std::io::ErrorKind, tracing::warn};

#[cfg(target_os = "linux")]
pub fn set_freebind_and_transparent(socket: &TcpSocket) -> io::Result<()> {
    let socket = SockRef::from(socket);
    match socket.domain()? {
        Domain::IPV4 => {
            socket.set_ip_transparent_v4(true)?;
            socket.set_freebind_v4(true)?;
        }
        Domain::IPV6 => {
            linux::set_ipv6_transparent(&socket)?;
            socket.set_freebind_v6(true)?
        }
        _ => return Err(Error::new(ErrorKind::Unsupported, "unsupported domain")),
    };
    Ok(())
}

pub fn to_canonical(addr: SocketAddr) -> SocketAddr {
    // another match has to be used for IPv4 and IPv6 support
    let ip = addr.ip().to_canonical();
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
                if !sock.ip_transparent_v4().unwrap_or(false) {
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
    Err(Error::new(
        io::ErrorKind::Other,
        "SO_ORIGINAL_DST not supported on this operating system",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn set_freebind_and_transparent(_: &TcpSocket) -> io::Result<()> {
    Err(Error::new(
        io::ErrorKind::Other,
        "IP_TRANSPARENT and IP_FREEBIND are not supported on this operating system",
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
        sock.original_dst_v4()
    }

    pub fn original_dst_ipv6(sock: &SockRef) -> io::Result<SockAddr> {
        sock.original_dst_v6()
    }
}

/// Listener is a wrapper For TCPListener with sane defaults. Notably, setting NODELAY
/// You can also pass it additional socket options to set on accepted connections.
pub struct Listener {
    listener: TcpListener,
    cfg: Option<SocketConfig>,
}

impl Listener {
    pub fn new(l: TcpListener) -> Self {
        Listener {
            listener: l,
            cfg: None,
        }
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().expect("local_addr is available")
    }
    pub fn inner(self) -> TcpListener {
        self.listener
    }
    pub fn set_socket_options(&mut self, cfg: Option<SocketConfig>) {
        self.cfg = cfg;
    }
    pub async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, remote) = self.listener.accept().await?;
        stream.set_nodelay(true)?;
        if let Some(cfg) = self.cfg {
            if cfg.keepalive_enabled {
                let ka = TcpKeepalive::new()
                    .with_time(cfg.keepalive_time)
                    .with_retries(cfg.keepalive_retries)
                    .with_interval(cfg.keepalive_interval);
                let res = SockRef::from(&stream).set_tcp_keepalive(&ka);
                tracing::trace!("set keepalive: {:?}", res);
            }
            if cfg.user_timeout_enabled {
                let ut = cfg.keepalive_time + cfg.keepalive_retries * cfg.keepalive_interval;
                let res = SockRef::from(&stream).set_tcp_user_timeout(Some(ut));
                tracing::trace!("set user timeout: {:?}", res);
            }
        }
        Ok((stream, remote))
    }
}

#[cfg(target_os = "linux")]
impl Listener {
    pub fn set_transparent(&self) -> io::Result<()> {
        SockRef::from(&self.listener).set_ip_transparent_v4(true)
    }
}

#[cfg(not(target_os = "linux"))]
impl Listener {
    pub fn set_transparent(&self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "IP_TRANSPARENT not supported on this operating system",
        ))
    }
}
