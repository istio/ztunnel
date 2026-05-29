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

use std::error::Error as StdError;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use crate::xds::istio::security::Authorization as XdsAuthorization;
use crate::xds::istio::workload::Address as XdsAddress;
use async_trait::async_trait;
use futures::Stream;
use futures::StreamExt;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hyper::server::conn::http2;
use hyper_util::rt::TokioIo;
use itertools::Itertools;
use prometheus_client::registry::Registry;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status, Streaming};
use tracing::{debug, error, info};

use super::{hyper_tower, test_config_with_port_xds_addr_and_root_cert};
use crate::config::{self, RootCert};
use crate::hyper_util::TokioExecutor;
use crate::metrics::sub_registry;
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
    server_failure_tx: watch::Sender<Option<String>>,
}

pub struct AdsConnection {
    tx: mpsc::Sender<Result<DeltaDiscoveryResponse, tonic::Status>>,
    rx: mpsc::Receiver<DeltaDiscoveryRequest>,
    forwarding_failure: watch::Receiver<Option<String>>,
    server_failure: watch::Receiver<Option<String>>,
}

impl AdsConnection {
    pub async fn recv_request(&mut self) -> Option<DeltaDiscoveryRequest> {
        self.assert_forwarding_healthy();
        tokio::select! {
            req = self.rx.recv() => {
                self.assert_forwarding_healthy();
                req
            }
            changed = self.forwarding_failure.changed() => {
                if changed.is_err() {
                    panic!("ADS forwarding task exited while waiting for request");
                }
                self.assert_forwarding_healthy();
                unreachable!("assert_forwarding_healthy panics when failure is present")
            }
            changed = self.server_failure.changed() => {
                if changed.is_err() {
                    panic!("ADS server task exited while waiting for request");
                }
                self.assert_forwarding_healthy();
                unreachable!("assert_forwarding_healthy panics when failure is present")
            }
        }
    }

    pub async fn send_response(&mut self, response: Result<DeltaDiscoveryResponse, tonic::Status>) {
        self.assert_forwarding_healthy();
        self.tx
            .send(response)
            .await
            .expect("failed to send server response");
        tokio::task::yield_now().await;
        self.assert_forwarding_healthy();
    }

    pub fn assert_forwarding_healthy(&self) {
        if let Some(err) = self.forwarding_failure.borrow().as_ref() {
            panic!("ADS forwarding task failed: {err}");
        }
        if let Some(err) = self.server_failure.borrow().as_ref() {
            panic!("ADS server task failed: {err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn panic_message(err: tokio::task::JoinError) -> String {
        let panic = err.into_panic();
        panic
            .downcast_ref::<String>()
            .map(String::to_string)
            .or_else(|| panic.downcast_ref::<&str>().map(|msg| (*msg).to_string()))
            .expect("panic should include a string message")
    }

    #[test]
    #[should_panic(expected = "ADS server task failed: boom")]
    fn ads_connection_reports_serve_connection_failure() {
        let (resp_tx, _resp_rx) = mpsc::channel(1);
        let (_req_tx, req_rx) = mpsc::channel(1);
        let (_forwarding_tx, forwarding_failure) = watch::channel(None);
        let (server_failure_tx, server_failure) = watch::channel(None);

        let conn = AdsConnection {
            tx: resp_tx,
            rx: req_rx,
            forwarding_failure,
            server_failure,
        };

        server_failure_tx.send_replace(Some("boom".to_string()));
        conn.assert_forwarding_healthy();
    }

    #[tokio::test]
    async fn ads_connection_recv_request_reports_server_failure_while_waiting() {
        let (resp_tx, _resp_rx) = mpsc::channel(1);
        let (_req_tx, req_rx) = mpsc::channel(1);
        let (_forwarding_tx, forwarding_failure) = watch::channel(None);
        let (server_failure_tx, server_failure) = watch::channel(None);

        let mut conn = AdsConnection {
            tx: resp_tx,
            rx: req_rx,
            forwarding_failure,
            server_failure,
        };

        let recv = tokio::spawn(async move {
            conn.recv_request().await;
        });

        tokio::task::yield_now().await;
        server_failure_tx.send_replace(Some("boom".to_string()));

        let err = tokio::time::timeout(Duration::from_millis(100), recv)
            .await
            .expect("recv_request did not report server failure")
            .expect_err("recv_request returned instead of panicking");
        assert!(err.is_panic());

        let panic = err.into_panic();
        let message = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .expect("recv_request panic should include a string message");
        assert!(message.contains("ADS server task failed: boom"));
    }

    #[tokio::test]
    async fn ads_connection_recv_request_reports_preexisting_server_failure() {
        let (resp_tx, _resp_rx) = mpsc::channel(1);
        let (_req_tx, req_rx) = mpsc::channel(1);
        let (_forwarding_tx, forwarding_failure) = watch::channel(None);
        let (_server_failure_tx, server_failure) = watch::channel(Some("boom".to_string()));

        let mut conn = AdsConnection {
            tx: resp_tx,
            rx: req_rx,
            forwarding_failure,
            server_failure,
        };

        let recv = tokio::spawn(async move {
            conn.recv_request().await;
        });

        let err = tokio::time::timeout(Duration::from_millis(100), recv)
            .await
            .expect("recv_request did not report preexisting server failure")
            .expect_err("recv_request returned instead of panicking");
        assert!(err.is_panic());

        let message = panic_message(err);
        assert!(message.contains("ADS server task failed: boom"));
    }
}

impl AdsServer {
    pub async fn spawn_app_server() -> (mpsc::Receiver<AdsConnection>, config::Config) {
        let (tx, rx) = mpsc::channel(100);
        let (server_failure_tx, _server_failure_rx) = watch::channel(None);

        let server = AdsServer {
            tx,
            server_failure_tx: server_failure_tx.clone(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();
        let certs = tls::mock::generate_test_certs(
            &server_addr.ip().into(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let root_cert = RootCert::Static(certs.roots.iter().map(|c| c.as_pem()).join("\n").into());
        let acceptor = tls::mock::MockServerCertProvider::new(certs);
        let listener_addr_string = "https://".to_string() + &server_addr.to_string();
        let mut tls_stream = crate::hyper_util::tls_server(acceptor, listener);
        let srv = AggregatedDiscoveryServiceServer::new(server);
        tokio::spawn(async move {
            while let Some(socket) = tls_stream.next().await {
                let srv = srv.clone();
                let server_failure_tx = server_failure_tx.clone();
                tokio::spawn(async move {
                    if let Err(err) = http2::Builder::new(TokioExecutor)
                        .serve_connection(
                            TokioIo::new(socket),
                            hyper_tower::TowerToHyperService::new(srv),
                        )
                        .await
                    {
                        if is_expected_serve_connection_close(&err) {
                            debug!("ads_server: serve_connection closed: {:?}", err);
                        } else {
                            let failure = format!("serve_connection failed: {err:?}");
                            error!("ads_server: {failure}");
                            server_failure_tx.send_replace(Some(failure));
                        }
                    }
                });
            }
        });

        let cfg = test_config_with_port_xds_addr_and_root_cert(
            80,
            Some(listener_addr_string),
            Some(root_cert),
            None,
        );

        (rx, cfg)
    }

    pub async fn spawn(
        xds_on_demand: bool,
    ) -> (
        mpsc::Receiver<AdsConnection>,
        AdsClient,
        DemandProxyState,
        tokio::sync::watch::Receiver<()>,
    ) {
        let (rx, mut cfg) = Self::spawn_app_server().await;

        let mut registry = Registry::default();
        let istio_registry = sub_registry(&mut registry);
        let metrics = xds::metrics::Metrics::new(istio_registry);

        let (block_tx, block_rx) = tokio::sync::watch::channel(());

        cfg.xds_on_demand = xds_on_demand;

        let proxy_metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let state: Arc<RwLock<ProxyState>> = Arc::new(RwLock::new(ProxyState::new(None)));
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            proxy_metrics,
        );
        let store_updater = ProxyStateUpdater::new_no_fetch(state);
        let tls_client_fetcher = Box::new(tls::ControlPlaneAuthentication::RootCert(
            cfg.xds_root_cert.clone(),
        ));
        let xds_client = xds::Config::new(Arc::new(cfg), tls_client_fetcher)
            .with_watched_handler::<XdsAddress>(xds::ADDRESS_TYPE, store_updater.clone())
            .with_watched_handler::<XdsAuthorization>(xds::AUTHORIZATION_TYPE, store_updater)
            .build(metrics, block_tx);

        (rx, xds_client, dstate, block_rx)
    }
}

fn is_expected_serve_connection_close(err: &(dyn StdError + 'static)) -> bool {
    matches!(
        find_io_error_kind(err),
        Some(
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::NotConnected
        )
    )
}

fn find_io_error_kind(mut err: &(dyn StdError + 'static)) -> Option<io::ErrorKind> {
    loop {
        if let Some(io_err) = err.downcast_ref::<io::Error>() {
            return Some(io_err.kind());
        }
        err = err.source()?;
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
        let (failure_tx, failure_rx) = watch::channel(None);

        let conn = AdsConnection {
            rx: req_rx,
            tx: resp_tx,
            forwarding_failure: failure_rx,
            server_failure: self.server_failure_tx.subscribe(),
        };

        self.tx.send(conn).await.unwrap();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    req = in_stream.next() => {
                        match req {
                            Some(Ok(req)) => {
                                info!("received request...",);
                                debug!(" request {:?}...", req);
                                if let Err(e) = req_tx.send(req).await {
                                    debug!("ads_server: request channel closed - {:?}", e);
                                    return;
                                }
                            }
                            Some(Err(e)) => {
                                debug!("ads_server: stream over - {:?}", e);
                                return;
                            }
                            None => {
                                debug!("ads_server: stream over");
                                return;
                            }
                        }
                    }
                    response = resp_rx.recv() => {
                        match response{
                            Some(response) => {
                                info!("sending response... ");
                                debug!(" response... {:?}", response);
                                match tx.send(response).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        let failure = format!(
                                            "response stream closed while forwarding server response: {e:?}"
                                        );
                                        error!("ads_server: {failure}");
                                        failure_tx.send_replace(Some(failure));
                                        return;
                                    }
                                }
                            }
                            None => {
                                debug!("ads_server: response channel closed");
                                return;
                            }
                        }
                    }
                }
            }
        });

        let output_stream = ReceiverStream::new(rx);
        Ok(Response::new(
            Box::pin(output_stream) as Self::DeltaAggregatedResourcesStream
        ))
    }
}
