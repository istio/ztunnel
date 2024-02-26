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

use crate::config::RootCert;
use crate::tls::lib::provider;
use crate::tls::{ClientCertProvider, Error, WorkloadCertificate};
use bytes::Bytes;
use http_body_1::{Body, Frame};
use hyper::body::Incoming;
use hyper::Uri;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use rustls::ClientConfig;
use std::future::Future;
use std::io::Cursor;
use std::pin::Pin;

use std::task::{Context, Poll};
use std::time::Duration;

use tonic::body::BoxBody;
use tower_hyper_http_body_compat::{
    http02_request_to_http1, http1_response_to_http02, HttpBody04ToHttpBody1, HttpBody1ToHttpBody04,
};

async fn root_to_store(root_cert: &RootCert) -> Result<rustls::RootCertStore, Error> {
    let mut roots = rustls::RootCertStore::empty();
    match root_cert {
        RootCert::File(f) => {
            let certfile = tokio::fs::read(f)
                .await
                .map_err(|e| Error::InvalidRootCert(e.to_string()))?;
            let mut reader = std::io::BufReader::new(Cursor::new(certfile));
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidRootCert(e.to_string()))?;
            roots.add_parsable_certificates(certs);
        }
        RootCert::Static(b) => {
            let mut reader = std::io::BufReader::new(Cursor::new(b));
            let certs = rustls_pemfile::certs(&mut reader)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::InvalidRootCert(e.to_string()))?;
            roots.add_parsable_certificates(certs);
        }
        RootCert::Default => {
            let certs = rustls_native_certs::load_native_certs()
                .map_err(|e| Error::InvalidRootCert(e.to_string()))?;
            roots.add_parsable_certificates(certs);
        }
    };
    Ok(roots)
}

#[derive(Debug)]
pub enum ControlPlaneAuthentication {
    RootCert(RootCert),
    ClientBundle(WorkloadCertificate),
}

#[async_trait::async_trait]
impl ClientCertProvider for ControlPlaneAuthentication {
    async fn fetch_cert(&self) -> Result<ClientConfig, Error> {
        match self {
            ControlPlaneAuthentication::RootCert(root_cert) => {
                control_plane_client_config(root_cert).await
            }
            ControlPlaneAuthentication::ClientBundle(_bundle) => {
                // TODO: implement this. Its is not currently used so no need.
                unimplemented!();
            }
        }
    }
}

async fn control_plane_client_config(root_cert: &RootCert) -> Result<ClientConfig, Error> {
    let roots = root_to_store(root_cert).await?;
    Ok(ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(crate::tls::TLS_VERSIONS)?
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[derive(Clone, Debug)]
pub struct TlsGrpcChannel {
    uri: Uri,
    client: hyper_util::client::legacy::Client<HttpsConnector<HttpConnector>, BoxBody1>,
}

/// grpc_connector provides a client TLS channel for gRPC requests.
pub async fn grpc_tls_connector(uri: String, root_cert: RootCert) -> Result<TlsGrpcChannel, Error> {
    grpc_connector(uri, control_plane_client_config(&root_cert).await?)
}

/// grpc_connector provides a client TLS channel for gRPC requests.
pub fn grpc_connector(uri: String, cc: ClientConfig) -> Result<TlsGrpcChannel, Error> {
    let uri = Uri::try_from(uri)?;
    let _is_localhost_call = uri.host() == Some("localhost");
    let mut http: HttpConnector = HttpConnector::new();
    // Set keepalives to match istio's Envoy bootstrap configuration:
    // https://github.com/istio/istio/blob/a29d5c9c27d80bff31f218936f5a96759d8911c8/tools/packaging/common/envoy_bootstrap.json#L322C14-L322C28
    //
    // keepalive_interval and keepalive_retries match the linux default per Envoy docs:
    // https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/core/v3/address.proto#config-core-v3-tcpkeepalive
    http.set_keepalive(Some(Duration::from_secs(300)));
    http.set_keepalive_interval(Some(Duration::from_secs(75)));
    http.set_keepalive_retries(Some(9));
    http.set_connect_timeout(Some(Duration::from_secs(5)));
    http.enforce_http(false);
    let https: HttpsConnector<HttpConnector> = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(cc)
        .https_only()
        .enable_http2()
        .wrap_connector(http);

    // Configure hyper's client to be h2 only and build with the
    // correct https connector.
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .http2_only(true)
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .timer(crate::hyper_util::TokioTimer)
        .build(https);

    Ok(TlsGrpcChannel { uri, client })
}

// Everything here is to hack hyper 1.0 onto tonic.
// TODO(https://github.com/hyperium/tonic/issues/1307) remove all of this and use tonic 'transport'

type BoxBody1 = HttpBody04ToHttpBody1<BoxBody>;

#[derive(Default)]
pub enum DefaultIncoming {
    Some(Incoming),
    #[default]
    Empty,
}

impl Body for DefaultIncoming {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            DefaultIncoming::Some(ref mut i) => Pin::new(i).poll_frame(cx),
            DefaultIncoming::Empty => Pin::new(&mut http_body_util::Empty::<Bytes>::new())
                .poll_frame(cx)
                .map_err(|_| unreachable!()),
        }
    }
}

impl tower::Service<http_02::Request<BoxBody>> for TlsGrpcChannel {
    type Response = http_02::Response<HttpBody1ToHttpBody04<DefaultIncoming>>;
    type Error = hyper_util::client::legacy::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Ok(()).into()
    }

    fn call(&mut self, req: http_02::Request<BoxBody>) -> Self::Future {
        let mut req = http02_request_to_http1(req.map(HttpBody04ToHttpBody1::new));
        let uri = Uri::builder()
            .scheme(self.uri.scheme().unwrap().to_owned())
            .authority(self.uri.authority().unwrap().to_owned())
            .path_and_query(req.uri().path_and_query().unwrap().to_owned())
            .build()
            .unwrap();
        *req.uri_mut() = uri;
        let future = self.client.request(req);
        Box::pin(async move {
            let res = future.await?;
            Ok(http1_response_to_http02(
                res.map(DefaultIncoming::Some)
                    .map(HttpBody1ToHttpBody04::new),
            ))
        })
    }
}
