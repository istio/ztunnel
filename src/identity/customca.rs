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

use super::CertificateProvider;
use crate::identity::Error;
use crate::tls;
use crate::{identity::manager::Identity, tls::SanChecker};
use async_trait::async_trait;
use futures::{StreamExt, TryStreamExt};
use k8s_openapi::api::certificates::v1::{
    CertificateSigningRequest, CertificateSigningRequestSpec,
};
use kube::{
    api::{Api, ListParams, PostParams, WatchEvent},
    client::Client,
};
use std::str;
use tracing::{info, instrument, warn};

const TTL: i32 = 86400;

#[derive(Clone)]
pub struct CustomSigner {
    pub signer: String,
    pub client: Client,
}

impl CustomSigner {
    pub fn new(signer: String, client: Client) -> Result<CustomSigner, Error> {
        Ok(CustomSigner { signer, client })
    }
}

#[async_trait]
impl CertificateProvider for CustomSigner {
    #[instrument(skip_all)]
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
        let client = self.client.clone();
        let csr: Api<CertificateSigningRequest> = Api::all(client);
        let pp = PostParams::default();
        let cs = tls::CsrOptions {
            san: id.to_string(),
        }
        .generate()?;
        let cert: Vec<u8> = cs.csr;
        let pkey = cs.pkey;
        let signer_name = &self.signer;
        let usage = vec!["client auth".to_string()];

        let obj_metadata = k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            generate_name: Some("csr-ztunnel-".to_string()),
            ..Default::default()
        };
        let csr_spec = CertificateSigningRequestSpec {
            expiration_seconds: Some(TTL),
            request: k8s_openapi::ByteString(cert),
            signer_name: signer_name.to_string(),
            usages: Some(usage),
            ..Default::default()
        };

        let csr_req = CertificateSigningRequest {
            metadata: obj_metadata,
            spec: csr_spec,
            ..Default::default()
        };

        // creating CSR
        match csr.create(&pp, &csr_req).await {
            Ok(o) => {
                let csr_name = o.metadata.name.unwrap_or_default();
                let final_certs = check_signed_cert(&csr, &csr_name).await;
                match final_certs {
                    Ok(cert_chain) => {
                        let cert_chain_vec = cert_chain.0;
                        let final_cert_chain = vec![str::from_utf8(&cert_chain_vec).unwrap()];
                        let leaf = final_cert_chain[0].as_bytes();
                        let ca_cert_bundle = if final_cert_chain.len() > 1 {
                            final_cert_chain[1..]
                                .iter()
                                .map(|final_cert_chain| final_cert_chain.as_bytes())
                                .collect()
                        } else {
                            warn!("no chain certs for: {}", id);
                            vec![]
                        };
                        let res_certs = tls::cert_from(&pkey, leaf, ca_cert_bundle);
                        res_certs
                            .verify_san(id)
                            .map_err(|_| Error::SanError(id.clone()))?;
                        return Ok(res_certs);
                    }
                    Err(_) => return Err(Error::EmptyResponse(id.clone()))?,
                }
            }
            Err(kube::Error::Api(ae)) => warn!("CSR creation failed with an error {}", ae.message),
            Err(_) => return Err(Error::EmptyResponse(id.clone()))?,
        };
        Err(Error::EmptyResponse(id.clone()))
    }
}
async fn check_signed_cert(
    csr: &Api<CertificateSigningRequest>,
    csr_name: &String,
) -> Result<k8s_openapi::ByteString, anyhow::Error> {
    let lp = ListParams::default()
        .fields(&format!("{}{}", "metadata.name=", csr_name))
        .timeout(60);
    let l = csr.list(&lp).await?;
    if !l.items.is_empty() {
        let req_signed = l.items[0].clone();
        match req_signed.status {
            Some(status) => {
                if let Some(cert) = status.certificate {
                    return Ok(cert);
                }
            }
            None => info!("No status field in the CSR: {} yet", csr_name),
        };
    }
    if let Some(rv) = l.metadata.resource_version {
        let mut stream = csr.watch(&lp, &rv).await?.boxed();
        while let Some(status) = stream.try_next().await? {
            match status {
                WatchEvent::Added(o) => {
                    info!("Added {}", o.metadata.name.unwrap_or_default());
                }
                WatchEvent::Modified(o) => match o.status {
                    Some(status) => {
                        if let Some(cert) = status.certificate {
                            return Ok(cert);
                        }
                    }
                    None => warn!("CSR is not yet signed by the signer"),
                },
                _ => {}
            }
        }
    }
    Err(anyhow::Error::msg(
        "Signer is unable to sign the certificate",
    ))
}
