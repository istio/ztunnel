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

use crate::config;
use std::{os::fd::FromRawFd, sync::Arc};

use super::netns::InpodNetns;

pub struct InPodConfig {
    cur_netns: Arc<std::os::fd::OwnedFd>,
    mark: Option<std::num::NonZeroU32>,
    reuse_port: bool,
}

impl InPodConfig {
    pub fn new(cfg: &config::Config) -> std::io::Result<Self> {
        Ok(InPodConfig {
            cur_netns: Arc::new(InpodNetns::current()?),
            mark: std::num::NonZeroU32::new(cfg.inpod_mark),
            reuse_port: cfg.inpod_port_reuse,
        })
    }
    pub fn socket_factory(
        &self,
        netns: InpodNetns,
    ) -> Box<dyn crate::proxy::SocketFactory + Send + Sync> {
        let sf = InPodSocketFactory::from_cfg(self, netns);
        if self.reuse_port {
            Box::new(InPodSocketPortReuseFactory::new(sf))
        } else {
            Box::new(sf)
        }
    }

    pub fn cur_netns(&self) -> Arc<std::os::fd::OwnedFd> {
        self.cur_netns.clone()
    }
    fn mark(&self) -> Option<std::num::NonZeroU32> {
        self.mark
    }
}

struct InPodSocketFactory {
    netns: InpodNetns,
    mark: Option<std::num::NonZeroU32>,
}

impl InPodSocketFactory {
    fn from_cfg(inpod_config: &InPodConfig, netns: InpodNetns) -> Self {
        Self::new(netns, inpod_config.mark())
    }
    fn new(netns: InpodNetns, mark: Option<std::num::NonZeroU32>) -> Self {
        Self { netns, mark }
    }

    fn configure<S: std::os::unix::io::AsFd, F: FnOnce() -> std::io::Result<S>>(
        &self,
        f: F,
    ) -> std::io::Result<S> {
        let socket = self.netns.run(f)??;

        if let Some(mark) = self.mark {
            crate::socket::set_mark(&socket, mark.into())?;
        }
        Ok(socket)
    }
}

impl crate::proxy::SocketFactory for InPodSocketFactory {
    fn new_tcp_v4(&self) -> std::io::Result<tokio::net::TcpSocket> {
        self.configure(tokio::net::TcpSocket::new_v4)
    }

    fn new_tcp_v6(&self) -> std::io::Result<tokio::net::TcpSocket> {
        self.configure(tokio::net::TcpSocket::new_v6)
    }

    fn tcp_bind(&self, addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
        let std_sock = self.configure(|| std::net::TcpListener::bind(addr))?;
        std_sock.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(std_sock)
    }

    fn udp_bind(&self, addr: std::net::SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        let std_sock = self.configure(|| std::net::UdpSocket::bind(addr))?;
        std_sock.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std_sock)
    }
}

// Same as socket factory, but sets SO_REUSEPORT
struct InPodSocketPortReuseFactory {
    sf: InPodSocketFactory,
}

impl InPodSocketPortReuseFactory {
    fn new(sf: InPodSocketFactory) -> Self {
        Self { sf }
    }
}

impl crate::proxy::SocketFactory for InPodSocketPortReuseFactory {
    fn new_tcp_v4(&self) -> std::io::Result<tokio::net::TcpSocket> {
        self.sf.new_tcp_v4()
    }

    fn new_tcp_v6(&self) -> std::io::Result<tokio::net::TcpSocket> {
        self.sf.new_tcp_v6()
    }

    fn tcp_bind(&self, addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
        let sock = self.sf.configure(|| match addr {
            std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        })?;

        if let Err(e) = sock.set_reuseport(true) {
            tracing::warn!("setting set_reuseport failed: {} addr: {}", e, addr);
        }

        sock.bind(addr)?;
        sock.listen(128)
    }

    fn udp_bind(&self, addr: std::net::SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        let sock = self.sf.configure(|| {
            let sock = match addr {
                std::net::SocketAddr::V4(_) => nix::sys::socket::socket(
                    nix::sys::socket::AddressFamily::Inet,
                    nix::sys::socket::SockType::Datagram,
                    nix::sys::socket::SockFlag::empty(),
                    None,
                )
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32)),
                std::net::SocketAddr::V6(_) => nix::sys::socket::socket(
                    nix::sys::socket::AddressFamily::Inet6,
                    nix::sys::socket::SockType::Datagram,
                    nix::sys::socket::SockFlag::empty(),
                    None,
                )
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32)),
            }?;
            // safety: we just created this socket
            Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(sock) })
        })?;

        let socket_ref = socket2::SockRef::from(&sock);

        // important to set SO_REUSEPORT before binding!
        socket_ref.set_reuse_port(true)?;
        let addr = socket2::SockAddr::from(addr);
        socket_ref.bind(&addr)?;

        let std_sock: std::net::UdpSocket = sock.into();

        std_sock.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std_sock)
    }
}
