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

use std::convert::Infallible;
use std::path::PathBuf;
use std::time::Duration;

use async_trait::async_trait;
use futures::future;
use hyper::service::make_service_fn;
use tokio::sync::watch;
use tonic::codegen::Service;

use crate::identity::{AuthSource, CaClient};
use crate::xds::istio::ca::istio_certificate_service_server::{
    IstioCertificateService, IstioCertificateServiceServer,
};
use crate::{
    identity::Identity,
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
        let certs = tls::generate_test_certs(
            &Identity::default(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let acceptor = tls::ControlPlaneCertProvider(certs);
        let tls_stream = crate::hyper_util::tls_server(acceptor, listener);
        let incoming = hyper::server::accept::from_stream(tls_stream);

        let srv = IstioCertificateServiceServer::new(server);
        tokio::spawn(async move {
            hyper::Server::builder(incoming)
                .serve(make_service_fn(move |_| {
                    let mut srv = srv.clone();
                    future::ok::<_, Infallible>(tower::service_fn(
                        move |req: hyper::Request<hyper::Body>| srv.call(req),
                    ))
                }))
                .await
                .unwrap()
        });
        let client = CaClient::new(
            "https://".to_string() + &server_addr.to_string(),
            AuthSource::Token(PathBuf::from(r"src/test_helpers/fake-jwt")),
        );
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
