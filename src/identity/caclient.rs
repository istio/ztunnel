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

use prost_types::value::Kind;
use prost_types::Struct;
use tonic::codegen::InterceptedService;
use tracing::instrument;

use crate::identity::auth::AuthSource;
use crate::identity::manager::Identity;
use crate::identity::Error;
use crate::tls;
use crate::tls::TlsGrpcChannel;
use crate::xds::istio::ca::istio_certificate_service_client::IstioCertificateServiceClient;
use crate::xds::istio::ca::IstioCertificateRequest;

#[derive(Clone, Debug)]
pub struct CaClient {
    pub client: IstioCertificateServiceClient<InterceptedService<TlsGrpcChannel, AuthSource>>,
}

impl CaClient {
    pub fn new(auth: AuthSource) -> CaClient {
        let address = if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            "https://istiod.istio-system:15012"
        } else {
            "https://localhost:15012"
        };
        let svc = tls::grpc_connector(address).unwrap();
        let client = IstioCertificateServiceClient::with_interceptor(svc, auth);
        CaClient { client }
    }

    #[instrument(skip_all)]
    pub async fn fetch_certificate(&mut self, id: &Identity) -> Result<tls::Certs, Error> {
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

        let leaf = resp.cert_chain.first().unwrap().as_bytes();
        let chain = if resp.cert_chain.len() > 1 {
            resp.cert_chain[1..].iter().map(|s| s.as_bytes()).collect()
        } else {
            vec![]
        };
        Ok(tls::cert_from(&pkey, leaf, chain))
    }
}
