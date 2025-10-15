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
use hickory_proto::runtime::RuntimeProvider;
use hickory_proto::runtime::iocompat::AsyncIoTokioAsStd;
use hickory_resolver::ResolveError;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::GenericConnector;
use hickory_server::authority::LookupError;
use hickory_server::server::Request;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpStream, UdpSocket};

/// A forwarding [Resolver] that delegates requests to an upstream [TokioAsyncResolver].
pub struct Forwarder(hickory_resolver::Resolver<GenericConnector<RuntimeProviderAdaptor>>);

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
        let mut resolver = hickory_resolver::Resolver::builder_with_config(cfg, provider);
        *resolver.options_mut() = opts;
        Ok(Self(resolver.build()))
    }
}

#[derive(Clone)]
struct RuntimeProviderAdaptor {
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    handle: hickory_proto::runtime::TokioHandle,
}
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
impl RuntimeProvider for RuntimeProviderAdaptor {
    type Handle = hickory_proto::runtime::TokioHandle;
    type Timer = hickory_proto::runtime::TokioTime;
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
    async fn lookup(&self, request: &Request) -> Result<Answer, LookupError> {
        // TODO(nmittler): Should we allow requests to the upstream resolver to be authoritative?
        let query = request.request_info()?.query;
        let name = query.name();
        let rr_type = query.query_type();
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
    use hickory_proto::ProtoErrorKind;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::RecordType;
    use hickory_proto::xfer::Protocol;
    use hickory_resolver::ResolveErrorKind;
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
        if let ResolveErrorKind::Proto(proto) = err.kind()
            && let ProtoErrorKind::NoRecordsFound { response_code, .. } = proto.kind() {
                // Respond with the error code.
                assert_eq!(&ResponseCode::NXDomain, response_code);
                return;
            }
        panic!("unexpected error kind {}", err.kind())
    }
}
