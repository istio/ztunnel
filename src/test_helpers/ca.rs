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

use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use hyper_util::rt::TokioIo;
use itertools::Itertools;

use tokio::sync::watch;

use tracing::error;

use crate::config::RootCert;

use crate::identity::{AuthSource, CaClient};
use crate::test_helpers::hyper_tower;
use crate::xds::istio::ca::istio_certificate_service_server::{
    IstioCertificateService, IstioCertificateServiceServer,
};
use crate::{
    tls,
    xds::istio::ca::{IstioCertificateRequest, IstioCertificateResponse},
};

/// CaServer provides a fake CA server implementation. Mocked responses can be assigned to it.
#[derive(Clone)]
pub struct CaServer {
    response: watch::Receiver<Result<IstioCertificateResponse, tonic::Status>>,
}

impl CaServer {
    pub async fn spawn() -> (
        watch::Sender<Result<IstioCertificateResponse, tonic::Status>>,
        CaClient,
    ) {
        let default = Err(tonic::Status::not_found("mock not set"));
        let (tx, rx) = watch::channel(default);

        let server = CaServer { response: rx };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let certs = tls::mock::generate_test_certs(
            &server_addr.ip().into(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let root_cert = RootCert::Static(certs.chain.iter().map(|c| c.as_pem()).join("\n").into());
        let acceptor = tls::mock::MockServerCertProvider::new(certs);
        let mut tls_stream = crate::hyper_util::tls_server(acceptor, listener);
        let srv = IstioCertificateServiceServer::new(server);
        tokio::spawn(async move {
            while let Some(socket) = tls_stream.next().await {
                let srv = srv.clone();
                if let Err(err) = crate::hyper_util::http2_server()
                    .serve_connection(
                        TokioIo::new(socket),
                        hyper_tower::TowerToHyperService::new(srv),
                    )
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            }
        });
        let client = CaClient::new(
            "https://".to_string() + &server_addr.to_string(),
            None,
            Box::new(tls::ControlPlaneAuthentication::RootCert(root_cert)),
            AuthSource::Token(
                PathBuf::from(r"src/test_helpers/fake-jwt"),
                "Kubernetes".to_string(),
            ),
            true,
            60 * 60 * 24,
            None,
        )
        .await
        .unwrap();
        (tx, client)
    }
}
#[async_trait]
impl IstioCertificateService for CaServer {
    async fn create_certificate(
        &self,
        _request: tonic::Request<IstioCertificateRequest>,
    ) -> Result<tonic::Response<IstioCertificateResponse>, tonic::Status> {
        let b = self.response.borrow();
        match &*b {
            Ok(res) => Ok(tonic::Response::new(res.clone())),
            Err(e) => Err(e.clone()),
        }
    }
}
