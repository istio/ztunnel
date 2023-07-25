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

use std::collections::BTreeMap;

use async_trait::async_trait;
use prost_types::value::Kind;
use prost_types::Struct;
use tonic::codegen::InterceptedService;

use tracing::{instrument, warn};

use crate::config::RootCert;
use crate::identity::auth::AuthSource;
use crate::identity::manager::Identity;
use crate::identity::Error;
use crate::tls::{self, SanChecker, TlsGrpcChannel};
use crate::xds::istio::ca::istio_certificate_service_client::IstioCertificateServiceClient;
use crate::xds::istio::ca::IstioCertificateRequest;

pub struct CaClient {
    pub client: IstioCertificateServiceClient<InterceptedService<TlsGrpcChannel, AuthSource>>,
    pub enable_impersonated_identity: bool,
}

impl CaClient {
    pub fn new(
        address: String,
        root_cert: RootCert,
        auth: AuthSource,
        enable_impersonated_identity: bool,
    ) -> Result<CaClient, Error> {
        let svc = tls::grpc_tls_connector(address, root_cert)?;
        // let client = IstioCertificateServiceClient::new(svc);
        // let svc =
        //     tower_hyper_http_body_compat::Hyper1HttpServiceAsTowerService03HttpService::new(svc);
        let client = IstioCertificateServiceClient::with_interceptor(svc, auth);
        Ok(CaClient {
            client,
            enable_impersonated_identity,
        })
    }
}

impl CaClient {
    #[instrument(skip_all)]
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
        let cs = tls::CsrOptions {
            san: id.to_string(),
        }
        .generate()?;
        let csr: Vec<u8> = cs.csr;
        let pkey = cs.pkey;

        let csr = std::str::from_utf8(&csr).map_err(Error::Utf8)?.to_string();
        let req = IstioCertificateRequest {
            csr,
            validity_duration: 60 * 60 * 24, // 24 hours
            metadata: {
                if self.enable_impersonated_identity {
                    Some(Struct {
                        fields: BTreeMap::from([(
                            "ImpersonatedIdentity".into(),
                            prost_types::Value {
                                kind: Some(Kind::StringValue(id.to_string())),
                            },
                        )]),
                    })
                } else {
                    None
                }
            },
        };
        let resp = self
            .client
            .clone()
            .create_certificate(req)
            .await?
            .into_inner();
        let leaf = resp
            .cert_chain
            .first()
            .ok_or_else(|| Error::EmptyResponse(id.to_owned()))?
            .as_bytes();
        let chain = if resp.cert_chain.len() > 1 {
            resp.cert_chain[1..].iter().map(|s| s.as_bytes()).collect()
        } else {
            warn!("no chain certs for: {}", id);
            vec![]
        };
        let certs = tls::cert_from(&pkey, leaf, chain);
        if self.enable_impersonated_identity {
            certs
                .verify_san(&[id.clone()])
                .map_err(|_| Error::SanError(id.to_owned()))?;
        }
        Ok(certs)
    }
}

#[async_trait]
impl crate::identity::CaClientTrait for CaClient {
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
        self.fetch_certificate(id).await
    }
}

pub mod mock {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::RwLock;
    use tokio::time::Instant;

    use crate::identity::Identity;
    use crate::tls::mock::CertGenerator;
    use crate::tls::Certs;

    use super::*;

    #[derive(Default)]
    struct ClientState {
        fetches: Vec<Identity>,
        gen: CertGenerator,
    }

    #[derive(Clone)]
    pub struct ClientConfig {
        pub cert_lifetime: Duration,
        pub time_conv: crate::time::Converter,
        // If non-zero, causes fetch_certificate calls to sleep for the specified duration before
        // returning. This is helpful to let tests that pause tokio time get more control over code
        // execution.
        pub fetch_latency: Duration,
    }

    impl Default for ClientConfig {
        fn default() -> Self {
            Self {
                fetch_latency: Duration::ZERO,
                cert_lifetime: Duration::from_secs(10),
                time_conv: crate::time::Converter::new(),
            }
        }
    }

    #[derive(Clone)]
    pub struct CaClient {
        cfg: ClientConfig,
        state: Arc<RwLock<ClientState>>,
    }

    impl CaClient {
        pub fn new(cfg: ClientConfig) -> CaClient {
            CaClient {
                cfg,
                state: Default::default(),
            }
        }

        pub fn cert_lifetime(&self) -> Duration {
            self.cfg.cert_lifetime
        }

        // Returns a list of fetch_certificate calls, in the order they happened. Calls are added
        // just before the function returns (ie. after the potential sleep controlled by the
        // fetch_latency config option).
        pub async fn fetches(&self) -> Vec<Identity> {
            self.state.read().await.fetches.clone()
        }

        pub async fn clear_fetches(&self) {
            self.state.write().await.fetches.clear();
        }

        async fn fetch_certificate(&self, id: &Identity) -> Result<Certs, Error> {
            let Identity::Spiffe {
                trust_domain: td,
                namespace: ns,
                ..
            } = id;
            if td == "error" {
                return Err(match ns.as_str() {
                    "forgotten" => Error::Forgotten,
                    _ => panic!("cannot parse injected error: {ns}"),
                });
            }

            if self.cfg.fetch_latency != Duration::ZERO {
                tokio::time::sleep(self.cfg.fetch_latency).await;
            }

            // Get SystemTime::now() via Instant::now() to allow mocking in tests.
            let not_before = self
                .cfg
                .time_conv
                .instant_to_system_time(Instant::now().into())
                .expect("SystemTime cannot represent current time. Was the process started in extreme future?");
            let not_after = not_before + self.cfg.cert_lifetime;

            let mut state = self.state.write().await;
            let certs = state
                .gen
                .new_certs(&id.to_owned().into(), not_before, not_after);
            state.fetches.push(id.to_owned());
            Ok(certs)
        }
    }

    #[async_trait]
    impl crate::identity::CaClientTrait for CaClient {
        async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
            self.fetch_certificate(id).await
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use matches::assert_matches;

    use crate::{
        identity::{Error, Identity},
        test_helpers, tls,
        xds::istio::ca::IstioCertificateResponse,
    };

    async fn test_ca_client_with_response(
        res: IstioCertificateResponse,
    ) -> Result<tls::Certs, Error> {
        let (mock, ca_client) = test_helpers::ca::CaServer::spawn().await;
        mock.send(Ok(res)).unwrap();
        ca_client.fetch_certificate(&Identity::default()).await
    }

    #[tokio::test]
    async fn empty_chain() {
        let res =
            test_ca_client_with_response(IstioCertificateResponse { cert_chain: vec![] }).await;
        assert_matches!(res, Err(Error::EmptyResponse(_)));
    }

    #[tokio::test]
    async fn wrong_identity() {
        let id = Identity::Spiffe {
            service_account: "wrong-sa".to_string(),
            namespace: "foo".to_string(),
            trust_domain: "cluster.local".to_string(),
        };
        let certs =
            tls::generate_test_certs(&id.into(), Duration::from_secs(0), Duration::from_secs(0));

        let res = test_ca_client_with_response(IstioCertificateResponse {
            cert_chain: vec![String::from_utf8(certs.x509().to_pem().unwrap()).unwrap()],
        })
        .await;
        assert_matches!(res, Err(Error::SanError(_)));
    }

    #[tokio::test]
    async fn fetch_certificate() {
        let certs = tls::generate_test_certs(
            &Identity::default().into(),
            Duration::from_secs(0),
            Duration::from_secs(0),
        );
        let res = test_ca_client_with_response(IstioCertificateResponse {
            cert_chain: vec![String::from_utf8(certs.x509().to_pem().unwrap()).unwrap()],
        })
        .await;
        assert_matches!(res, Ok(_));
    }
}
