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
use prost_types::Struct;
use prost_types::value::Kind;
use tonic::IntoRequest;
use tonic::metadata::{AsciiMetadataKey, AsciiMetadataValue};
use tracing::{debug, error, instrument, warn};

use crate::identity::auth::AuthSource;
use crate::identity::{CompositeId, Error, Identity};
use crate::tls::{self, TlsGrpcChannel};
use crate::xds::istio::ca::IstioCertificateRequest;
use crate::xds::istio::ca::istio_certificate_service_client::IstioCertificateServiceClient;

pub struct CaClient {
    pub client: IstioCertificateServiceClient<TlsGrpcChannel>,
    pub enable_impersonated_identity: bool,
    pub secret_ttl: i64,
    ca_headers: Vec<(AsciiMetadataKey, AsciiMetadataValue)>,
}

impl CaClient {
    pub async fn new(
        address: String,
        alt_hostname: Option<String>,
        cert_provider: Box<dyn tls::ControlPlaneClientCertProvider>,
        auth: AuthSource,
        enable_impersonated_identity: bool,
        secret_ttl: i64,
        ca_headers: Vec<(AsciiMetadataKey, AsciiMetadataValue)>,
    ) -> Result<CaClient, Error> {
        let svc =
            tls::grpc_connector(address, auth, cert_provider.fetch_cert(alt_hostname).await?)?;
        let client = IstioCertificateServiceClient::new(svc);
        Ok(CaClient {
            client,
            enable_impersonated_identity,
            secret_ttl,
            ca_headers,
        })
    }
}

impl CaClient {
    #[instrument(skip_all)]
    async fn fetch_certificate(
        &self,
        id: &CompositeId<Identity>,
    ) -> Result<tls::WorkloadCertificate, Error> {
        let cs = tls::csr::CsrOptions {
            san: id.to_string(),
        }
        .generate()?;
        let csr = cs.csr;
        let private_key = cs.private_key;

        let mut req = tonic::Request::new(IstioCertificateRequest {
            csr,
            validity_duration: self.secret_ttl,
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
        });
        self.ca_headers.iter().for_each(|(k, v)| {
            req.metadata_mut().insert(k.clone(), v.clone());

            if let Ok(v_str) = v.to_str() {
                debug!("CA header added: {}={}", k, v_str);
            }
        });

        let resp = self
            .client
            .clone()
            .create_certificate(req.into_request())
            .await
            .map_err(Box::new)?
            .into_inner();

        let leaf = resp
            .cert_chain
            .first()
            .ok_or_else(|| Error::EmptyResponse(id.id().to_owned()))?
            .as_bytes();
        let chain = if resp.cert_chain.len() > 1 {
            resp.cert_chain[1..].iter().map(|s| s.as_bytes()).collect()
        } else {
            warn!("no chain certs for: {}", id);
            vec![]
        };
        let certs = tls::WorkloadCertificate::new(&private_key, leaf, chain)?;
        // Make the certificate actually matches the identity we requested.
        if self.enable_impersonated_identity && certs.identity().as_ref() != Some(id.id()) {
            error!("expected identity {:?}, got {:?}", id, certs.identity());
            return Err(Error::SanError(id.id().to_owned()));
        }
        Ok(certs)
    }
}

#[async_trait]
impl crate::identity::CaClientTrait for CaClient {
    type Key = Identity;
    async fn fetch_certificate(
        &self,
        id: &CompositeId<Identity>,
    ) -> Result<tls::WorkloadCertificate, Error> {
        self.fetch_certificate(id).await
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod mock {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::RwLock;
    use tokio::time::Instant;

    use crate::identity::Identity;

    use super::*;

    #[derive(Default)]
    struct ClientState {
        fetches: Vec<Identity>,
        error: bool,
        cert_gen: tls::mock::CertGenerator,
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

        async fn fetch_certificate(
            &self,
            id: &CompositeId<Identity>,
        ) -> Result<tls::WorkloadCertificate, Error> {
            let Identity::Spiffe {
                trust_domain: td,
                namespace: ns,
                ..
            } = id.id();
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
            state.fetches.push(id.id().to_owned());
            if state.error {
                return Err(Error::Spiffe("injected test error".into()));
            }
            let certs = state
                .cert_gen
                .new_certs(&id.id().to_owned().into(), not_before, not_after);
            Ok(certs)
        }

        pub async fn set_error(&mut self, error: bool) {
            let mut state = self.state.write().await;
            state.error = error;
        }
    }

    #[async_trait]
    impl crate::identity::CaClientTrait for CaClient {
        type Key = Identity;
        async fn fetch_certificate(
            &self,
            id: &CompositeId<Identity>,
        ) -> Result<tls::WorkloadCertificate, Error> {
            self.fetch_certificate(id).await
        }
    }
}

#[cfg(test)]
mod tests {

    use std::time::Duration;

    use matches::assert_matches;

    use crate::{
        identity::{CompositeId, Error, Identity},
        test_helpers, tls,
        xds::istio::ca::IstioCertificateResponse,
    };

    async fn test_ca_client_with_response(
        res: IstioCertificateResponse,
    ) -> Result<tls::WorkloadCertificate, Error> {
        let (mock, ca_client) = test_helpers::ca::CaServer::spawn().await;
        mock.send(Ok(res)).unwrap();
        ca_client
            .fetch_certificate(&CompositeId::with_key(
                Identity::default(),
                Identity::default(),
            ))
            .await
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
            service_account: "wrong-sa".into(),
            namespace: "foo".into(),
            trust_domain: "cluster.local".into(),
        };
        let certs = tls::mock::generate_test_certs(
            &id.into(),
            Duration::from_secs(0),
            Duration::from_secs(0),
        );

        let res = test_ca_client_with_response(IstioCertificateResponse {
            cert_chain: certs.full_chain_and_roots(),
        })
        .await;
        assert_matches!(res, Err(Error::SanError(_)));
    }

    #[tokio::test]
    async fn fetch_certificate() {
        let certs = tls::mock::generate_test_certs(
            &Identity::default().into(),
            Duration::from_secs(0),
            Duration::from_secs(0),
        );

        let res = test_ca_client_with_response(IstioCertificateResponse {
            cert_chain: certs.full_chain_and_roots(),
        })
        .await;
        assert_matches!(res, Ok(_));
    }
}
