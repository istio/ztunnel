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

use crate::proxy::dns::resolver::{Answer, Resolver};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveError;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};
use trust_dns_server::authority::LookupError;
use trust_dns_server::server::Request;

/// A forwarding [Resolver] that delegates requests to an upstream [TokioAsyncResolver].
pub struct Forwarder(TokioAsyncResolver);

impl Forwarder {
    /// Creates a new [Forwarder] from the provided resolver configuration.
    pub fn new(cfg: ResolverConfig, opts: ResolverOpts) -> Result<Self, ResolveError> {
        let resolver = TokioAsyncResolver::new(cfg, opts, TokioHandle)?;
        Ok(Self(resolver))
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
    use crate::proxy::dns::resolver::Resolver;
    use crate::test_helpers::dns::{a_request, n, socket_addr, system_forwarder};
    use crate::test_helpers::helpers::subscribe;
    use trust_dns_proto::rr::RecordType;
    use trust_dns_server::server::Protocol;

    #[tokio::test]
    async fn forward_google_com() {
        let _guard = subscribe();

        let f = system_forwarder();

        // Lookup a host.
        let req = a_request(
            n("www.google.com"),
            socket_addr("1.1.1.1:80"),
            Protocol::Udp,
        );
        let answer = f.lookup(&req).await.unwrap();
        assert!(!answer.is_authoritative());

        let record = answer.record_iter().next().unwrap();
        assert_eq!(n("www.google.com."), *record.name());
        assert_eq!(RecordType::A, record.rr_type());
    }
}
