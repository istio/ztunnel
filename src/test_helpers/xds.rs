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

use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::xds::istio::security::Authorization as XdsAuthorization;
use crate::xds::istio::workload::Address as XdsAddress;
use async_trait::async_trait;
use futures::Stream;
use futures::StreamExt;
use hyper::server::conn::http2;
use hyper_util::rt::TokioIo;
use prometheus_client::registry::Registry;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status, Streaming};
use tracing::{error, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

use super::test_config_with_port_xds_addr_and_root_cert;
use crate::config::RootCert;
use crate::hyper_util::TokioExecutor;
use crate::metrics::sub_registry;
use crate::readiness::Ready;
use crate::state::{DemandProxyState, ProxyState};
use crate::tls;
use crate::xds::service::discovery::v3::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use crate::xds::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use crate::xds::{self, AdsClient, ProxyStateUpdater};

pub struct AdsServer {
    tx: mpsc::Sender<AdsConnection>,
}

pub struct AdsConnection {
    pub tx: mpsc::Sender<Result<DeltaDiscoveryResponse, tonic::Status>>,
    pub rx: mpsc::Receiver<DeltaDiscoveryRequest>,
}

impl AdsServer {
    pub async fn spawn(
        xds_on_demand: bool,
    ) -> (mpsc::Receiver<AdsConnection>, AdsClient, DemandProxyState) {
        let (tx, rx) = mpsc::channel(100);

        let server = AdsServer { tx: tx };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let certs = tls::generate_test_certs(
            &server_addr.ip().into(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let root_cert = RootCert::Static(certs.chain().unwrap());
        let acceptor = tls::ControlPlaneCertProvider(certs);
        let listener_addr_string = "https://".to_string() + &server_addr.to_string();
        let mut tls_stream = crate::hyper_util::tls_server(acceptor, listener);
        let srv = AggregatedDiscoveryServiceServer::new(server);
        tokio::spawn(async move {
            while let Some(socket) = tls_stream.next().await {
                let srv = srv.clone();
                if let Err(err) = http2::Builder::new(TokioExecutor)
                    .serve_connection(
                        TokioIo::new(socket),
                        tower_hyper_http_body_compat::TowerService03HttpServiceAsHyper1HttpService::new(srv)
                    )
                    .await
                {
                    error!("Error serving connection: {:?}", err);
                }
            }
        });

        let mut registry = Registry::default();
        let istio_registry = sub_registry(&mut registry);
        let metrics = xds::metrics::Metrics::new(istio_registry);

        let ready = Ready::new();
        let mut cfg = test_config_with_port_xds_addr_and_root_cert(
            80,
            Some(listener_addr_string),
            Some(root_cert),
            None,
        );
        cfg.xds_on_demand = xds_on_demand;

        let state: Arc<RwLock<ProxyState>> = Arc::new(RwLock::new(ProxyState::default()));
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        let store_updater = ProxyStateUpdater::new_no_fetch(state);
        let tls_client_fetcher = Box::new(tls::FileClientCertProviderImpl::RootCert(
            cfg.xds_root_cert.clone(),
        ));
        let xds_client = xds::Config::new(cfg, tls_client_fetcher)
            .with_watched_handler::<XdsAddress>(xds::ADDRESS_TYPE, store_updater.clone())
            .with_watched_handler::<XdsAuthorization>(xds::AUTHORIZATION_TYPE, store_updater)
            .build(metrics, ready.register_task("ads client"));

        (rx, xds_client, dstate)
    }
}

#[async_trait]
impl AggregatedDiscoveryService for AdsServer {
    type StreamAggregatedResourcesStream =
        Pin<Box<dyn Stream<Item = Result<DiscoveryResponse, Status>> + Send>>;
    async fn stream_aggregated_resources(
        &self,
        _request: tonic::Request<Streaming<DiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::StreamAggregatedResourcesStream>, tonic::Status> {
        unimplemented!("We only use Delta in zTunnel");
    }

    type DeltaAggregatedResourcesStream =
        Pin<Box<dyn Stream<Item = Result<DeltaDiscoveryResponse, Status>> + Send>>;
    async fn delta_aggregated_resources(
        &self,
        request: tonic::Request<tonic::Streaming<DeltaDiscoveryRequest>>,
    ) -> Result<tonic::Response<Self::DeltaAggregatedResourcesStream>, tonic::Status> {
        let mut in_stream = request.into_inner();
        let (resp_tx, mut resp_rx) = mpsc::channel(128);
        let (req_tx, req_rx) = mpsc::channel(128);

        let (tx, rx) = mpsc::channel(128);

        let conn = AdsConnection {
            rx: req_rx,
            tx: resp_tx,
        };

        self.tx.send(conn).await.unwrap();

        tokio::spawn(async move {
            while let Ok(result) = in_stream.message().await {
                match result {
                    Some(req) => {
                        req_tx.send(req).await.unwrap();
                        match resp_rx.recv().await {
                            Some(response) => {
                                info!("sending response...");
                                match tx.send(response).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        warn!("ads_server: send failed - {:?} ", e);
                                        break;
                                    }
                                }
                            }
                            None => {
                                warn!("ads_server: config update failed");
                                break;
                            }
                        };
                    }
                    None => {
                        warn!("ads_server: stream failed");
                        break;
                    }
                }
            }
            info!("stream ended");
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::DeltaAggregatedResourcesStream
        ))
    }
}
