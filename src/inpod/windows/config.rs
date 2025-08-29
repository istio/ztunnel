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

use crate::inpod::windows::namespace::InpodNamespace;
use crate::proxy::DefaultSocketFactory;
use crate::{config, socket};

pub struct InPodConfig {
    cur_namespace: u32,
    reuse_port: bool, // TODO: Not supported in windows so always must be false
    socket_config: config::SocketConfig,
}

impl InPodConfig {
    pub fn new(cfg: &config::Config) -> std::io::Result<Self> {
        if cfg.inpod_port_reuse {
            return Err(std::io::Error::other(
                "SO_REUSEPORT is not supported in windows",
            ));
        }
        let socket_config = config::SocketConfig {
            user_timeout_enabled: false, // Not supported on windows
            ..cfg.socket_config
        };
        Ok(InPodConfig {
            cur_namespace: InpodNamespace::current()?,
            reuse_port: cfg.inpod_port_reuse,
            socket_config,
        })
    }
    pub fn socket_factory(
        &self,
        netns: InpodNamespace,
    ) -> Box<dyn crate::proxy::SocketFactory + Send + Sync> {
        let base = crate::proxy::DefaultSocketFactory(self.socket_config);
        let sf = InPodSocketFactory::from_cfg(base, self, netns);
        if self.reuse_port {
            // We should never get here
            unreachable!("SO_REUSEPORT is not supported in windows");
        } else {
            Box::new(sf)
        }
    }

    pub fn cur_netns(&self) -> u32 {
        self.cur_namespace
    }
}

struct InPodSocketFactory {
    inner: DefaultSocketFactory,
    netns: InpodNamespace,
}
impl InPodSocketFactory {
    fn from_cfg(inner: DefaultSocketFactory, _: &InPodConfig, netns: InpodNamespace) -> Self {
        Self::new(inner, netns)
    }
    fn new(inner: DefaultSocketFactory, netns: InpodNamespace) -> Self {
        Self { inner, netns }
    }

    fn run_in_ns<S, F: FnOnce() -> std::io::Result<S>>(&self, f: F) -> std::io::Result<S> {
        self.netns.run(f)?
    }

    fn configure<S: std::os::windows::io::AsRawSocket, F: FnOnce() -> std::io::Result<S>>(
        &self,
        f: F,
    ) -> std::io::Result<S> {
        let socket = self.netns.run(f)??;

        Ok(socket)
    }
}

impl crate::proxy::SocketFactory for InPodSocketFactory {
    fn new_tcp_v4(&self) -> std::io::Result<tokio::net::TcpSocket> {
        self.configure(|| self.inner.new_tcp_v4())
    }

    fn new_tcp_v6(&self) -> std::io::Result<tokio::net::TcpSocket> {
        self.configure(|| self.inner.new_tcp_v6())
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
        self.run_in_ns(|| self.inner.ipv6_enabled_localhost())
    }
}

// Same as socket factory, but sets SO_REUSEPORT
// struct InPodSocketPortReuseFactory {
//     sf: InPodSocketFactory,
// }

// impl InPodSocketPortReuseFactory {
//     fn new(_: InPodSocketFactory) -> Self {
//         panic!("SO_REUSEPORT is not supported in windows");
//     }
// }

// #[cfg(test)]
// mod test {
//     use super::*;

//     use crate::inpod::linux::test_helpers::new_netns;

//     macro_rules! fixture {
//         () => {{
//             if !crate::test_helpers::can_run_privilged_test() {
//                 eprintln!("This test requires root; skipping");
//                 return;
//             }

//             crate::config::Config {
//                 packet_mark: Some(123),
//                 ..crate::config::parse_config().unwrap()
//             }
//         }};
//     }

//     #[tokio::test]
//     async fn test_inpod_config_no_port_reuse() {
//         let mut cfg = fixture!();
//         cfg.inpod_port_reuse = false;

//         let inpod_cfg = InPodConfig::new(&cfg).unwrap();
//         assert_eq!(
//             inpod_cfg.mark(),
//             Some(std::num::NonZeroU32::new(123).unwrap())
//         );
//         assert!(!inpod_cfg.reuse_port);

//         let sf = inpod_cfg.socket_factory(
//             InpodNamespace::new(
//                 Arc::new(InpodNamespace::current().unwrap()),
//                 new_netns(),
//             )
//             .unwrap(),
//         );

//         let sock_addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
//         {
//             let s = sf.tcp_bind(sock_addr).unwrap().inner();

//             // make sure mark nad port re-use are set
//             let sock_ref = socket2::SockRef::from(&s);
//             assert_eq!(
//                 sock_ref.local_addr().unwrap(),
//                 socket2::SockAddr::from(sock_addr)
//             );
//             assert!(!sock_ref.reuse_port().unwrap());
//             assert_eq!(sock_ref.mark().unwrap(), 123);
//         }

//         {
//             let s = sf.udp_bind(sock_addr).unwrap();

//             // make sure mark nad port re-use are set
//             let sock_ref = socket2::SockRef::from(&s);
//             assert_eq!(
//                 sock_ref.local_addr().unwrap(),
//                 socket2::SockAddr::from(sock_addr)
//             );
//             assert!(!sock_ref.reuse_port().unwrap());
//             assert_eq!(sock_ref.mark().unwrap(), 123);
//         }
//     }

//     #[tokio::test]
//     async fn test_inpod_config_port_reuse() {
//         let cfg = fixture!();

//         let inpod_cfg = InPodConfig::new(&cfg).unwrap();
//         assert_eq!(
//             inpod_cfg.mark(),
//             Some(std::num::NonZeroU32::new(123).unwrap())
//         );
//         assert!(inpod_cfg.reuse_port);

//         let sf = inpod_cfg.socket_factory(
//             InpodNamespace::new(
//                 Arc::new(crate::inpod::linux::netns::InpodNetns::current().unwrap()),
//                 new_netns(),
//             )
//             .unwrap(),
//         );

//         let sock_addr: std::net::SocketAddr = "127.0.0.1:8080".parse().unwrap();
//         {
//             let s = sf.tcp_bind(sock_addr).unwrap().inner();

//             // make sure mark nad port re-use are set
//             let sock_ref = socket2::SockRef::from(&s);
//             assert_eq!(
//                 sock_ref.local_addr().unwrap(),
//                 socket2::SockAddr::from(sock_addr)
//             );
//             assert!(sock_ref.reuse_port().unwrap());
//             assert_eq!(sock_ref.mark().unwrap(), 123);
//         }

//         {
//             let s = sf.udp_bind(sock_addr).unwrap();

//             // make sure mark nad port re-use are set
//             let sock_ref = socket2::SockRef::from(&s);
//             assert_eq!(
//                 sock_ref.local_addr().unwrap(),
//                 socket2::SockAddr::from(sock_addr)
//             );
//             assert!(sock_ref.reuse_port().unwrap());
//             assert_eq!(sock_ref.mark().unwrap(), 123);
//         }
//     }

//     #[tokio::test]
//     async fn test_inpod_config_outbound_sockets() {
//         let cfg = fixture!();

//         let inpod_cfg = InPodConfig::new(&cfg).unwrap();

//         let sf = inpod_cfg.socket_factory(
//             InpodNamespace::new(
//                 Arc::new(crate::inpod::linux::netns::InpodNetns::current().unwrap()),
//                 new_netns(),
//             )
//             .unwrap(),
//         );

//         {
//             let s = sf.new_tcp_v4().unwrap();
//             let sock_ref = socket2::SockRef::from(&s);
//             assert!(!sock_ref.reuse_port().unwrap());
//             assert_eq!(sock_ref.mark().unwrap(), 123);
//         }

//         {
//             let s = sf.new_tcp_v6().unwrap();
//             let sock_ref = socket2::SockRef::from(&s);
//             assert!(!sock_ref.reuse_port().unwrap());
//             assert_eq!(sock_ref.mark().unwrap(), 123);
//         }
//     }
// }
