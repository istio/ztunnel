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

use crate::dns::resolver::{Resolver, Response};
use crate::proxy::SocketFactory;
use hickory_net::NetError;
use hickory_net::runtime::RuntimeProvider;
use hickory_net::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_server::server::Request;
use hickory_server::zone_handler::LookupError;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// A forwarding [Resolver] that delegates requests to an upstream [TokioAsyncResolver].
pub struct Forwarder(hickory_resolver::Resolver<RuntimeProviderAdaptor>);

impl Forwarder {
    /// Creates a new [Forwarder] from the provided resolver configuration.
    pub fn new(
        cfg: ResolverConfig,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        opts: ResolverOpts,
    ) -> Result<Self, NetError> {
        let provider = RuntimeProviderAdaptor {
            socket_factory,
            handle: Default::default(),
        };
        let mut resolver = hickory_resolver::Resolver::builder_with_config(cfg, provider);
        *resolver.options_mut() = opts;
        Ok(Self(resolver.build()?))
    }
}

#[derive(Clone)]
struct RuntimeProviderAdaptor {
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    handle: hickory_net::runtime::TokioHandle,
}
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
impl RuntimeProvider for RuntimeProviderAdaptor {
    type Handle = hickory_net::runtime::TokioHandle;
    type Timer = hickory_net::runtime::TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let sf = self.socket_factory.clone();
        Box::pin(async move {
            let socket = if server_addr.is_ipv4() {
                sf.new_tcp_v4()
            } else {
                sf.new_tcp_v6()
            }?;

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }
            let future = socket.connect(server_addr);
            let wait_for = wait_for.unwrap_or(CONNECT_TIMEOUT);
            match tokio::time::timeout(wait_for, future).await {
                Ok(Ok(socket)) => Ok(AsyncIoTokioAsStd(socket)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
        let sf = self.socket_factory.clone();
        Box::pin(async move { sf.udp_bind(local_addr) })
    }
}

#[async_trait::async_trait]
impl Resolver for Forwarder {
    async fn lookup(&self, request: &Request) -> Result<Response, LookupError> {
        // TODO(nmittler): Should we allow requests to the upstream resolver to be authoritative?
        let query = request.request_info()?.query;
        let name = query.name();
        let rr_type = query.query_type();
        self.0
            .lookup(name, rr_type)
            .await
            .map(Response::from)
            .map_err(LookupError::from)
    }
}

#[cfg(test)]
#[cfg(any(unix, target_os = "windows"))]
mod tests {
    use crate::dns::resolver::Resolver;
    use crate::test_helpers::dns::{a_request, ip, n, run_dns, socket_addr};
    use crate::test_helpers::helpers::initialize_telemetry;
    use hickory_net::xfer::Protocol;
    use hickory_net::{DnsError, NetError, NoRecords};
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::RecordType;
    use hickory_server::zone_handler::LookupError;
    use std::collections::HashMap;

    #[tokio::test]
    async fn found() {
        initialize_telemetry();

        let f = run_dns(HashMap::from([(
            n("test.example.com."),
            vec![ip("1.1.1.1")],
        )]))
        .await
        .unwrap();

        // Lookup a host.
        let req = a_request(
            n("test.example.com"),
            socket_addr("1.1.1.1:80"),
            Protocol::Udp,
        );
        let response = f.lookup(&req).await.unwrap();
        assert!(!response.is_authoritative());

        let record = response.answers().next().unwrap();
        assert_eq!(n("test.example.com."), record.name);
        assert_eq!(RecordType::A, record.record_type());
    }

    #[tokio::test]
    async fn not_found() {
        initialize_telemetry();

        let f = run_dns(HashMap::new()).await.unwrap();

        // Lookup a host.
        let req = a_request(
            n("fake-blahblahblah.com"),
            socket_addr("1.1.1.1:80"),
            Protocol::Udp,
        );

        match f.lookup(&req).await.expect_err("expected error") {
            LookupError::NetError(NetError::Dns(DnsError::NoRecordsFound(NoRecords {
                response_code,
                ..
            }))) => {
                assert_eq!(ResponseCode::NXDomain, response_code);
                return;
            }
            err => panic!("unexpected error kind {err:?}"),
        }
    }
}
