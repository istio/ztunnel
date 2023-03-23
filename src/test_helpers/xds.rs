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
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::RootCert;
use crate::readiness::Ready;
use crate::workload::{WorkloadInformation, WorkloadStore};
use async_trait::async_trait;
use futures::{future, Stream};
use hyper::service::make_service_fn;
use log::info;
use prometheus_client::registry::Registry;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::client::GrpcService;
use tonic::{Response, Status, Streaming};
use tracing::warn;

use crate::metrics::Metrics;
use crate::tls;
use crate::xds::service::discovery::v3::aggregated_discovery_service_server::{
    AggregatedDiscoveryService, AggregatedDiscoveryServiceServer,
};
use crate::xds::service::discovery::v3::{
    DeltaDiscoveryRequest, DeltaDiscoveryResponse, DiscoveryRequest, DiscoveryResponse,
};
use crate::xds::{self, AdsClient};

use super::test_config_with_port_xds_addr_and_root_cert;

pub struct AdsServer {
    rx: watch::Receiver<Result<DeltaDiscoveryResponse, tonic::Status>>,
}

impl AdsServer {
    pub async fn spawn() -> (
        watch::Sender<Result<DeltaDiscoveryResponse, tonic::Status>>,
        AdsClient,
        WorkloadInformation,
    ) {
        let (tx, rx) = watch::channel(Err(tonic::Status::unavailable("No response set yet.")));

        let server = AdsServer { rx };
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
        let tls_stream = crate::hyper_util::tls_server(acceptor, listener);
        let incoming = hyper::server::accept::from_stream(tls_stream);

        let srv = AggregatedDiscoveryServiceServer::new(server);
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

        let ready = Ready::new();
        let mut registry = Registry::default();
        let metrics = Arc::new(Metrics::from(&mut registry));
        let cfg = test_config_with_port_xds_addr_and_root_cert(
            80,
            Some(listener_addr_string),
            Some(root_cert),
        );

        let workloads: Arc<Mutex<WorkloadStore>> = Arc::new(Mutex::new(WorkloadStore::default()));
        let xds_workloads = workloads.clone();
        let xds_rbac = workloads.clone();

        let xds_client = xds::Config::new(cfg)
            .with_address_handler(xds_workloads)
            .with_authorization_handler(xds_rbac)
            .watch(xds::WORKLOAD_TYPE.into())
            .watch(xds::AUTHORIZATION_TYPE.into())
            .build(metrics, ready.register_task("ads client"));

        let wi = WorkloadInformation {
            info: workloads,
            demand: None,
        };

        (tx, xds_client, wi)
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
        let (tx, rx) = mpsc::channel(128);
        let mut stream_rx = self.rx.clone();
        tokio::spawn(async move {
            while let Ok(result) = in_stream.message().await {
                match result {
                    Some(_) => {
                        match stream_rx.changed().await {
                            Ok(_) => {
                                let response = stream_rx.borrow().clone();
                                info!("sending response...");
                                match tx.send(response).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        warn!("ads_server: send failed - {:?} ", e);
                                        break;
                                    }
                                }
                            }
                            Err(_) => {
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
