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

use async_trait::*;
use prost_types::value::Kind;
use prost_types::Struct;

use dyn_clone::DynClone;
use tracing::{instrument, warn};

use crate::identity::auth::AuthSource;
use crate::identity::manager::Identity;
use crate::identity::Error;
use crate::tls::{self, SanChecker};
use crate::xds::istio::ca::istio_certificate_service_client::IstioCertificateServiceClient;
use crate::xds::istio::ca::{IstioCertificateRequest, IstioCertificateResponse};

#[async_trait]
pub trait IstioCertificateService: DynClone + Send + Sync + 'static {
    async fn create_certificate(
        &mut self,
        request: IstioCertificateRequest,
    ) -> Result<tonic::Response<IstioCertificateResponse>, tonic::Status>;
}

dyn_clone::clone_trait_object!(IstioCertificateService);

#[async_trait]
impl<T> IstioCertificateService for IstioCertificateServiceClient<T>
where
    T: Sync + Send + Clone + 'static,
{
    async fn create_certificate(
        &mut self,
        request: IstioCertificateRequest,
    ) -> Result<tonic::Response<IstioCertificateResponse>, tonic::Status> {
        self.create_certificate(request).await
    }
}

#[derive(Clone)]
pub struct CaClient {
    pub client: Box<dyn IstioCertificateService>,
}

#[async_trait]
pub trait CertificateProvider: DynClone + Send + Sync + 'static {
    async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error>;
}

dyn_clone::clone_trait_object!(CertificateProvider);

impl CaClient {
    pub fn new(auth: AuthSource) -> CaClient {
        let address = if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            "https://istiod.istio-system:15012"
        } else {
            "https://localhost:15012"
        };
        let svc = tls::grpc_connector(address.to_string()).unwrap();
        let client = IstioCertificateServiceClient::with_interceptor(svc, auth);
        CaClient {
            client: Box::new(client),
        }
    }

    pub fn with_client(client: Box<dyn IstioCertificateService>) -> CaClient {
        CaClient { client }
    }
}

#[async_trait]
impl CertificateProvider for CaClient {
    #[instrument(skip_all)]
    async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error> {
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
            metadata: Some(Struct {
                fields: BTreeMap::from([(
                    "ImpersonatedIdentity".into(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue(id.to_string())),
                    },
                )]),
            }),
        };
        let resp = self.client.create_certificate(req).await?.into_inner();
        let leaf = resp
            .cert_chain
            .first()
            .ok_or_else(|| Error::EmptyResponse(id.clone()))?
            .as_bytes();
        let chain = if resp.cert_chain.len() > 1 {
            resp.cert_chain[1..].iter().map(|s| s.as_bytes()).collect()
        } else {
            warn!("no chain certs for: {}", id);
            vec![]
        };
        let certs = tls::cert_from(&pkey, leaf, chain);
        certs
            .verify_san(id)
            .map_err(|_| Error::SanError(id.clone()))?;
        Ok(certs)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CaClient, CertificateProvider, IstioCertificateService};
    use crate::{
        identity::{Error, Identity},
        tls,
        xds::istio::ca::{IstioCertificateRequest, IstioCertificateResponse},
    };
    use async_trait::async_trait;

    #[derive(Clone, Default)]
    struct MockCertService {
        response: Option<IstioCertificateResponse>,
        error: Option<tonic::Status>,
    }

    impl MockCertService {
        fn set_response(&mut self, res: IstioCertificateResponse) {
            self.error = None;
            self.response = Some(res);
        }

        #[allow(dead_code)]
        fn set_error(&mut self, err: tonic::Status) {
            self.response = None;
            self.error = Some(err);
        }
    }

    #[async_trait]
    impl IstioCertificateService for MockCertService {
        async fn create_certificate(
            &mut self,
            _request: IstioCertificateRequest,
        ) -> Result<tonic::Response<IstioCertificateResponse>, tonic::Status> {
            if let Some(res) = &self.response {
                Ok(tonic::Response::new(res.clone()))
            } else if let Some(err) = &self.error {
                Err(err.clone())
            } else {
                Err(tonic::Status::not_found("response not setup yet"))
            }
        }
    }

    async fn test_ca_client_with_response(
        res: IstioCertificateResponse,
    ) -> Result<crate::tls::Certs, crate::identity::Error> {
        let mut mock_service = Box::new(MockCertService::default());
        mock_service.set_response(res);
        let mut ca_client = CaClient::with_client(mock_service);
        ca_client.fetch_certificate(&Identity::default()).await
    }

    #[tokio::test]
    async fn empty_chain() {
        let res =
            test_ca_client_with_response(IstioCertificateResponse { cert_chain: vec![] }).await;
        assert!(matches!(res, Err(Error::EmptyResponse(_))));
    }

    #[tokio::test]
    async fn wrong_identity() {
        let id = &Identity::Spiffe {
            service_account: "wrong-sa".to_string(),
            namespace: "foo".to_string(),
            trust_domain: "cluster.local".to_string(),
        };
        let certs = tls::generate_test_certs(id, Duration::from_secs(0), Duration::from_secs(0));

        let res = test_ca_client_with_response(IstioCertificateResponse {
            cert_chain: vec![String::from_utf8(certs.x509().to_pem().unwrap()).unwrap()],
        })
        .await;
        assert!(matches!(res, Err(Error::SanError(_))));
    }

    #[tokio::test]
    async fn fetch_certificate() {
        let certs = tls::generate_test_certs(
            &Identity::default(),
            Duration::from_secs(0),
            Duration::from_secs(0),
        );
        let res = test_ca_client_with_response(IstioCertificateResponse {
            cert_chain: vec![String::from_utf8(certs.x509().to_pem().unwrap()).unwrap()],
        })
        .await;
        assert!(matches!(res, Ok(_)));
    }
}
