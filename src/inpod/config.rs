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

use crate::proxy::DefaultSocketFactory;
use crate::{config, socket};
use std::sync::Arc;

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
            mark: std::num::NonZeroU32::new(cfg.packet_mark.expect("in pod requires packet mark")),
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

    fn run_in_ns<S, F: FnOnce() -> std::io::Result<S>>(&self, f: F) -> std::io::Result<S> {
        self.netns.run(f)?
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
        self.configure(|| DefaultSocketFactory.new_tcp_v4())
    }

    fn new_tcp_v6(&self) -> std::io::Result<tokio::net::TcpSocket> {
        self.configure(|| DefaultSocketFactory.new_tcp_v6())
    }

    fn tcp_bind(&self, addr: std::net::SocketAddr) -> std::io::Result<socket::Listener> {
        let std_sock = self.configure(|| std::net::TcpListener::bind(addr))?;
        std_sock.set_nonblocking(true)?;
        tokio::net::TcpListener::from_std(std_sock).map(socket::Listener::new)
    }

    fn udp_bind(&self, addr: std::net::SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        let std_sock = self.configure(|| std::net::UdpSocket::bind(addr))?;
        std_sock.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std_sock)
    }

    fn ipv6_enabled_localhost(&self) -> std::io::Result<bool> {
        self.run_in_ns(|| DefaultSocketFactory.ipv6_enabled_localhost())
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

    fn tcp_bind(&self, addr: std::net::SocketAddr) -> std::io::Result<socket::Listener> {
        let sock = self.sf.configure(|| match addr {
            std::net::SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            std::net::SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        })?;

        if let Err(e) = sock.set_reuseport(true) {
            tracing::warn!("setting set_reuseport failed: {} addr: {}", e, addr);
        }

        sock.bind(addr)?;
        sock.listen(128).map(socket::Listener::new)
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
            Ok(sock)
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

    fn ipv6_enabled_localhost(&self) -> std::io::Result<bool> {
        self.sf.ipv6_enabled_localhost()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::inpod::test_helpers::new_netns;

    macro_rules! fixture {
        () => {{
            if !crate::test_helpers::can_run_privilged_test() {
                eprintln!("This test requires root; skipping");
                return;
            }

            crate::config::Config {
                packet_mark: Some(123),
                ..crate::config::parse_config().unwrap()
            }
        }};
    }

    #[tokio::test]
    async fn test_inpod_config_no_port_reuse() {
        let mut cfg = fixture!();
        cfg.inpod_port_reuse = false;

        let inpod_cfg = InPodConfig::new(&cfg).unwrap();
        assert_eq!(
            inpod_cfg.mark(),
            Some(std::num::NonZeroU32::new(123).unwrap())
        );
        assert!(!inpod_cfg.reuse_port);

        let sf = inpod_cfg.socket_factory(
            InpodNetns::new(
                Arc::new(crate::inpod::netns::InpodNetns::current().unwrap()),
                new_netns(),
            )
            .unwrap(),
        );

        let sock_addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        {
            let s = sf.tcp_bind(sock_addr).unwrap().inner();

            // make sure mark nad port re-use are set
            let sock_ref = socket2::SockRef::from(&s);
            assert_eq!(
                sock_ref.local_addr().unwrap(),
                socket2::SockAddr::from(sock_addr)
            );
            assert!(!sock_ref.reuse_port().unwrap());
            assert_eq!(sock_ref.mark().unwrap(), 123);
        }

        {
            let s = sf.udp_bind(sock_addr).unwrap();

            // make sure mark nad port re-use are set
            let sock_ref = socket2::SockRef::from(&s);
            assert_eq!(
                sock_ref.local_addr().unwrap(),
                socket2::SockAddr::from(sock_addr)
            );
            assert!(!sock_ref.reuse_port().unwrap());
            assert_eq!(sock_ref.mark().unwrap(), 123);
        }
    }

    #[tokio::test]
    async fn test_inpod_config_port_reuse() {
        let cfg = fixture!();

        let inpod_cfg = InPodConfig::new(&cfg).unwrap();
        assert_eq!(
            inpod_cfg.mark(),
            Some(std::num::NonZeroU32::new(123).unwrap())
        );
        assert!(inpod_cfg.reuse_port);

        let sf = inpod_cfg.socket_factory(
            InpodNetns::new(
                Arc::new(crate::inpod::netns::InpodNetns::current().unwrap()),
                new_netns(),
            )
            .unwrap(),
        );

        let sock_addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
        {
            let s = sf.tcp_bind(sock_addr).unwrap().inner();

            // make sure mark nad port re-use are set
            let sock_ref = socket2::SockRef::from(&s);
            assert_eq!(
                sock_ref.local_addr().unwrap(),
                socket2::SockAddr::from(sock_addr)
            );
            assert!(sock_ref.reuse_port().unwrap());
            assert_eq!(sock_ref.mark().unwrap(), 123);
        }

        {
            let s = sf.udp_bind(sock_addr).unwrap();

            // make sure mark nad port re-use are set
            let sock_ref = socket2::SockRef::from(&s);
            assert_eq!(
                sock_ref.local_addr().unwrap(),
                socket2::SockAddr::from(sock_addr)
            );
            assert!(sock_ref.reuse_port().unwrap());
            assert_eq!(sock_ref.mark().unwrap(), 123);
        }
    }

    #[tokio::test]
    async fn test_inpod_config_outbound_sockets() {
        let cfg = fixture!();

        let inpod_cfg = InPodConfig::new(&cfg).unwrap();

        let sf = inpod_cfg.socket_factory(
            InpodNetns::new(
                Arc::new(crate::inpod::netns::InpodNetns::current().unwrap()),
                new_netns(),
            )
            .unwrap(),
        );

        {
            let s = sf.new_tcp_v4().unwrap();
            let sock_ref = socket2::SockRef::from(&s);
            assert!(!sock_ref.reuse_port().unwrap());
            assert_eq!(sock_ref.mark().unwrap(), 123);
        }

        {
            let s = sf.new_tcp_v6().unwrap();
            let sock_ref = socket2::SockRef::from(&s);
            assert!(!sock_ref.reuse_port().unwrap());
            assert_eq!(sock_ref.mark().unwrap(), 123);
        }
    }
}
