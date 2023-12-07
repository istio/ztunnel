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
use std::sync::Arc;

use super::netns::InpodNetns;

#[cfg(test)]
use mockall::automock;

pub struct InPodConfig {
    cur_netns: Arc<std::os::fd::OwnedFd>,
    mark: Option<std::num::NonZeroU32>,
}

#[cfg_attr(test, automock)]
impl InPodConfig {
    pub fn new(cfg: &config::Config) -> std::io::Result<Self> {
        Ok(InPodConfig {
            cur_netns: Arc::new(InpodNetns::current()?),
            mark: std::num::NonZeroU32::new(cfg.inpod_mark),
        })
    }
    pub fn socket_factory(
        &self,
        netns: InpodNetns,
    ) -> Box<dyn crate::proxy::SocketFactory + Send + Sync> {
        Box::new(InPodSocketFactory::from_cfg(self, netns))
    }

    pub fn cur_netns(&self) -> Arc<std::os::fd::OwnedFd> {
        self.cur_netns.clone()
    }
    fn mark(&self) -> Option<std::num::NonZeroU32> {
        self.mark
    }
}

#[derive(Clone)]
pub struct InPodSocketFactory {
    netns: InpodNetns,
    mark: Option<std::num::NonZeroU32>,
}

impl InPodSocketFactory {
    pub fn from_cfg(inpod_config: &InPodConfig, netns: InpodNetns) -> Self {
        Self::new(netns, inpod_config.mark())
    }
    pub fn new(netns: InpodNetns, mark: Option<std::num::NonZeroU32>) -> Self {
        Self { netns, mark }
    }

    pub fn netns(&self) -> &InpodNetns {
        &self.netns
    }

    pub fn configure<S: std::os::unix::io::AsFd, F: FnOnce() -> std::io::Result<S>>(
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
