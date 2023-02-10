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

use crate::config::RootCert;
use async_trait::*;
use dyn_clone::DynClone;
use prost_types::value::Kind;
use prost_types::Struct;
use tonic::codegen::InterceptedService;
use tracing::{instrument, warn};

use crate::identity::auth::AuthSource;
use crate::identity::manager::Identity;
use crate::identity::Error;
use crate::tls::{self, SanChecker, TlsGrpcChannel};
use crate::xds::istio::ca::istio_certificate_service_client::IstioCertificateServiceClient;
use crate::xds::istio::ca::IstioCertificateRequest;

#[derive(Clone)]
pub struct CaClient {
    pub client: IstioCertificateServiceClient<InterceptedService<TlsGrpcChannel, AuthSource>>,
}

#[async_trait]
pub trait CertificateProvider: DynClone + Send + Sync + 'static {
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error>;
}

dyn_clone::clone_trait_object!(CertificateProvider);

impl CaClient {
    pub fn new(address: String, root_cert: RootCert, auth: AuthSource) -> Result<CaClient, Error> {
        let svc = tls::grpc_connector(address, root_cert)?;
        let client = IstioCertificateServiceClient::with_interceptor(svc, auth);
        Ok(CaClient { client })
    }
}

#[async_trait]
impl CertificateProvider for CaClient {
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
            metadata: Some(Struct {
                fields: BTreeMap::from([(
                    "ImpersonatedIdentity".into(),
                    prost_types::Value {
                        kind: Some(Kind::StringValue(id.to_string())),
                    },
                )]),
            }),
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

pub mod mock {
    use std::time::Duration;

    use async_trait::async_trait;

    use crate::identity::{CertificateProvider, Identity};
    use crate::tls::{generate_test_certs, Certs};

    use super::*;

    #[derive(Clone, Debug)]
    pub struct CaClient {
        pub cert_lifetime: Duration,
    }

    #[async_trait]
    impl CertificateProvider for CaClient {
        async fn fetch_certificate(&self, id: &Identity) -> Result<Certs, Error> {
            let certs = generate_test_certs(
                &id.clone().into(),
                Duration::from_secs(0),
                self.cert_lifetime,
            );
            return Ok(certs);
        }
    }

    impl CaClient {
        pub fn new(cert_lifetime: Duration) -> CaClient {
            CaClient { cert_lifetime }
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

    use super::CertificateProvider;

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
