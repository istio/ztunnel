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

use crate::dns::resolver::{Answer, Resolver};
use crate::proxy::SocketFactory;
use hickory_proto::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveError;
use hickory_resolver::name_server;
use hickory_resolver::name_server::{GenericConnector, RuntimeProvider};
use hickory_server::authority::LookupError;
use hickory_server::server::Request;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::{TcpStream, UdpSocket};

/// A forwarding [Resolver] that delegates requests to an upstream [TokioAsyncResolver].
pub struct Forwarder(hickory_resolver::AsyncResolver<GenericConnector<RuntimeProviderAdaptor>>);

impl Forwarder {
    /// Creates a new [Forwarder] from the provided resolver configuration.
    pub fn new(
        cfg: ResolverConfig,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        opts: ResolverOpts,
    ) -> Result<Self, ResolveError> {
        let provider = GenericConnector::new(RuntimeProviderAdaptor {
            socket_factory,
            handle: Default::default(),
        });
        let resolver = hickory_resolver::AsyncResolver::new(cfg, opts, provider);
        Ok(Self(resolver))
    }
}

#[derive(Clone)]
struct RuntimeProviderAdaptor {
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    handle: name_server::TokioHandle,
}

impl RuntimeProvider for RuntimeProviderAdaptor {
    type Handle = name_server::TokioHandle;
    type Timer = hickory_proto::TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.handle.clone()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
        let sf = self.socket_factory.clone();
        Box::pin(async move {
            let socket = if server_addr.is_ipv4() {
                sf.new_tcp_v4()
            } else {
                sf.new_tcp_v6()
            }?;
            socket.connect(server_addr).await.map(AsyncIoTokioAsStd)
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
    async fn lookup(&self, request: &Request) -> Result<Answer, LookupError> {
        // TODO(nmittler): Should we allow requests to the upstream resolver to be authoritative?
        let name = request.query().name();
        let rr_type = request.query().query_type();
        self.0
            .lookup(name, rr_type)
            .await
            .map(Answer::from)
            .map_err(LookupError::from)
    }
}

#[cfg(test)]
#[cfg(any(unix, target_os = "windows"))]
mod tests {
    use crate::dns::resolver::Resolver;
    use crate::test_helpers::dns::{a_request, ip, n, run_dns, socket_addr};
    use crate::test_helpers::helpers::initialize_telemetry;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::RecordType;
    use hickory_resolver::error::ResolveErrorKind;
    use hickory_server::server::Protocol;
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
        let answer = f.lookup(&req).await.unwrap();
        assert!(!answer.is_authoritative());

        let record = answer.record_iter().next().unwrap();
        assert_eq!(n("test.example.com."), *record.name());
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

        // Expect a ResolveError.
        let err = f
            .lookup(&req)
            .await
            .expect_err("expected error")
            .into_resolve_error()
            .expect("expected resolve error");

        // Expect NoRecordsFound with a NXDomain response code.
        let kind = err.kind();
        match kind {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                assert_eq!(&ResponseCode::NXDomain, response_code);
            }
            _ => panic!("unexpected error kind {kind}"),
        }
    }
}
