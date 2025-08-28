use spire_api::DelegatedIdentityClient;
use tonic::async_trait;
use crate::{identity::manager::Identity, inpod::WorkloadPid, tls::{self}};
use super::Error;

pub struct SpireClient {
    client: DelegatedIdentityClient,
}

impl SpireClient {
    pub fn new(client: DelegatedIdentityClient) -> Result<SpireClient, Error> {
        Ok(SpireClient { client })
    }

    pub async fn get_cert(&self, pid: WorkloadPid) -> Result<tls::WorkloadCertificate, Error> {

        let req = self.client.clone().fetch_x509_svid(spire_api::DelegateAttestationRequest::Pid(pid.into_u32())).await.unwrap();
        let private_key = req.private_key();
        let leaf = req.leaf();
        let chain = req.cert_chain()[1..].iter().map(|s| s.content()).collect();
        let certs = tls::WorkloadCertificate::new(&private_key.content(), leaf.content(), chain)?;
        Ok(certs)
    }
}

#[async_trait]
impl crate::identity::CaClientTrait for SpireClient {
    async fn fetch_certificate(&self, id: &Identity, pid: Option<WorkloadPid>) -> Result<tls::WorkloadCertificate, Error> {
        match pid {
            Some(pid) => self.get_cert(pid).await,
            None => Err(Error::MissingPidForSpireIdentity(id.to_owned())),
        }
    }
}

