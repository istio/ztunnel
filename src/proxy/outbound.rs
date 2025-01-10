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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures_util::TryFutureExt;
use hyper::header::FORWARDED;
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::sync::watch;

use tracing::{debug, error, info, info_span, trace_span, Instrument};

use crate::identity::Identity;

use crate::proxy::metrics::Reporter;
use crate::proxy::{metrics, pool, ConnectionOpen, ConnectionResult, DerivedWorkload};
use crate::proxy::{util, Error, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};

use crate::drain::run_with_drain;
use crate::drain::DrainWatcher;
use crate::proxy::h2::H2Stream;
use crate::state::service::ServiceDescription;
use crate::state::workload::{address::Address, NetworkAddress, Protocol, Workload};
use crate::state::ServiceResolutionMode;
use crate::{assertions, copy, proxy, socket};

use super::inbound::HboneAddress;

pub struct Outbound {
    pi: Arc<ProxyInputs>,
    drain: DrainWatcher,
    listener: socket::Listener,
}

impl Outbound {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: DrainWatcher) -> Result<Outbound, Error> {
        let listener = pi
            .socket_factory
            .tcp_bind(pi.cfg.outbound_addr)
            .map_err(|e| Error::Bind(pi.cfg.outbound_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, &listener)?;

        info!(
            address=%listener.local_addr(),
            component="outbound",
            transparent,
            "listener established",
        );
        Ok(Outbound {
            pi,
            listener,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub(super) async fn run(self) {
        let pool = proxy::pool::WorkloadHBONEPool::new(
            self.pi.cfg.clone(),
            self.pi.socket_factory.clone(),
            self.pi.local_workload_information.clone(),
        );
        let pi = self.pi.clone();
        let accept = |drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
            async move {
                loop {
                    // Asynchronously wait for an inbound socket.
                    let socket = self.listener.accept().await;
                    let start = Instant::now();
                    let drain = drain.clone();
                    let mut force_shutdown = force_shutdown.clone();
                    match socket {
                        Ok((stream, _remote)) => {
                            let mut oc = OutboundConnection {
                                pi: self.pi.clone(),
                                id: TraceParent::new(),
                                pool: pool.clone(),
                                hbone_port: self.pi.cfg.inbound_addr.port(),
                            };
                            let span = info_span!("outbound", id=%oc.id);
                            let serve_outbound_connection = (async move {
                                debug!(component="outbound", "connection started");
                                // Since this task is spawned, make sure we are guaranteed to terminate
                                tokio::select! {
                                    _ = force_shutdown.changed() => {
                                        debug!(component="outbound", "connection forcefully terminated");
                                    }
                                    _ = oc.proxy(stream) => {}
                                }
                                // Mark we are done with the connection, so drain can complete
                                drop(drain);
                                debug!(component="outbound", dur=?start.elapsed(), "connection completed");
                            }).instrument(span);

                            assertions::size_between_ref(1000, 1750, &serve_outbound_connection);
                            tokio::spawn(serve_outbound_connection);
                        }
                        Err(e) => {
                            if util::is_runtime_shutdown(&e) {
                                return;
                            }
                            error!("Failed TCP handshake {}", e);
                        }
                    }
                }
            }
            .in_current_span()
        };

        run_with_drain(
            "outbound".to_string(),
            self.drain,
            pi.cfg.self_termination_deadline,
            accept,
        )
        .await
    }
}

pub(super) struct OutboundConnection {
    pub(super) pi: Arc<ProxyInputs>,
    pub(super) id: TraceParent,
    pub(super) pool: proxy::pool::WorkloadHBONEPool,
    pub(super) hbone_port: u16,
}

impl OutboundConnection {
    async fn proxy(&mut self, source_stream: TcpStream) {
        let source_addr =
            socket::to_canonical(source_stream.peer_addr().expect("must receive peer addr"));
        let dst_addr = socket::orig_dst_addr_or_default(&source_stream);
        self.proxy_to(source_stream, source_addr, dst_addr).await;
    }

    pub async fn proxy_to(
        &mut self,
        source_stream: TcpStream,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
    ) {
        let start = Instant::now();

        let illegal_call =
            dest_addr.ip().is_loopback() && self.pi.cfg.illegal_ports.contains(&dest_addr.port());
        if illegal_call {
            metrics::log_early_deny(source_addr, dest_addr, Reporter::source, Error::SelfCall);
            return;
        }
        // First find the source workload of this traffic. If we don't know where the request is from
        // we will reject it.
        let build = self
            .pi
            .local_workload_information
            .get_workload()
            .and_then(|source| self.build_request(source, source_addr.ip(), dest_addr));
        let req = match Box::pin(build).await {
            Ok(req) => Box::new(req),
            Err(err) => {
                metrics::log_early_deny(source_addr, dest_addr, Reporter::source, err);
                return;
            }
        };
        // TODO: should we use the original address or the actual address? Both seems nice!
        let _conn_guard = self.pi.connection_manager.track_outbound(
            source_addr,
            dest_addr,
            req.actual_destination,
        );

        let metrics = self.pi.metrics.clone();
        let hbone_target = req.hbone_target_destination.map(HboneAddress::SocketAddr);
        let result_tracker = Box::new(ConnectionResult::new(
            source_addr,
            req.actual_destination,
            hbone_target,
            start,
            Self::conn_metrics_from_request(&req),
            metrics,
        ));

        let res = match req.protocol {
            Protocol::HBONE => {
                self.proxy_to_hbone(source_stream, source_addr, &req, &result_tracker)
                    .await
            }
            Protocol::TCP => {
                self.proxy_to_tcp(source_stream, &req, &result_tracker)
                    .await
            }
        };
        result_tracker.record(res)
    }

    async fn proxy_to_hbone(
        &mut self,
        stream: TcpStream,
        remote_addr: SocketAddr,
        req: &Request,
        connection_stats: &ConnectionResult,
    ) -> Result<(), Error> {
        let upgraded = Box::pin(self.send_hbone_request(remote_addr, req)).await?;
        copy::copy_bidirectional(copy::TcpStreamSplitter(stream), upgraded, connection_stats).await
    }

    async fn send_hbone_request(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
    ) -> Result<H2Stream, Error> {
        let mut f = http_types::proxies::Forwarded::new();
        f.add_for(remote_addr.to_string());
        if let Some(svc) = &req.intended_destination_service {
            f.set_host(svc.hostname.as_str());
        }

        let request = http::Request::builder()
            .uri(
                &req.hbone_target_destination
                    .expect("HBONE must have target")
                    .to_string(),
            )
            .method(hyper::Method::CONNECT)
            .version(hyper::Version::HTTP_2)
            .header(BAGGAGE_HEADER, baggage(req, self.pi.cfg.cluster_id.clone()))
            .header(FORWARDED, f.value().expect("Forwarded value is infallible"))
            .header(TRACEPARENT_HEADER, self.id.header())
            .body(())
            .expect("builder with known status code should not fail");

        let pool_key = Box::new(pool::WorkloadKey {
            src_id: req.source.identity(),
            // Clone here shouldn't be needed ideally, we could just take ownership of Request.
            // But that
            dst_id: req.upstream_sans.clone(),
            src: remote_addr.ip(),
            dst: req.actual_destination,
        });
        let upgraded = Box::pin(self.pool.send_request_pooled(&pool_key, request))
            .instrument(trace_span!("outbound connect"))
            .await?;
        Ok(upgraded)
    }

    async fn proxy_to_tcp(
        &mut self,
        stream: TcpStream,
        req: &Request,
        connection_stats: &ConnectionResult,
    ) -> Result<(), Error> {
        let outbound = super::freebind_connect(
            None, // No need to spoof source IP on outbound
            req.actual_destination,
            self.pi.socket_factory.as_ref(),
        )
        .await?;

        // Proxying data between downstream and upstream
        copy::copy_bidirectional(
            copy::TcpStreamSplitter(stream),
            copy::TcpStreamSplitter(outbound),
            connection_stats,
        )
        .await
    }

    fn conn_metrics_from_request(req: &Request) -> ConnectionOpen {
        let derived_source = if req.protocol == Protocol::HBONE {
            Some(DerivedWorkload {
                // We are going to do mTLS, so report our identity
                identity: Some(req.source.as_ref().identity()),
                ..Default::default()
            })
        } else {
            None
        };
        ConnectionOpen {
            reporter: Reporter::source,
            derived_source,
            source: Some(req.source.clone()),
            destination: req.actual_destination_workload.clone(),
            connection_security_policy: if req.protocol == Protocol::HBONE {
                metrics::SecurityPolicy::mutual_tls
            } else {
                metrics::SecurityPolicy::unknown
            },
            destination_service: req.intended_destination_service.clone(),
        }
    }

    // build_request computes all information about the request we should send
    // TODO: Do we want a single lock for source and upstream...?
    async fn build_request(
        &self,
        source_workload: Arc<Workload>,
        downstream: IpAddr,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        let state = &self.pi.state;

        // If this is to-service traffic check for a service waypoint
        // Capture result of whether this is svc addressed
        let svc_addressed = if let Some(Address::Service(target_service)) = state
            .fetch_address(&NetworkAddress {
                network: self.pi.cfg.network.clone(),
                address: target.ip(),
            })
            .await
        {
            // if we have a waypoint for this svc, use it; otherwise route traffic normally
            if let Some(waypoint) = state
                .fetch_service_waypoint(&target_service, &source_workload, target)
                .await?
            {
                let upstream_sans = waypoint.workload_and_services_san();
                let actual_destination = waypoint.workload_socket_addr();
                debug!("built request to service waypoint proxy");
                return Ok(Request {
                    protocol: Protocol::HBONE,
                    source: source_workload,
                    hbone_target_destination: Some(target),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: Some(ServiceDescription::from(&*target_service)),
                    actual_destination,
                    upstream_sans,
                });
            }
            // this was service addressed but we did not find a waypoint
            true
        } else {
            // this wasn't service addressed
            false
        };

        let Some(us) = state
            .fetch_upstream(
                source_workload.network.clone(),
                &source_workload,
                target,
                ServiceResolutionMode::Standard,
            )
            .await?
        else {
            if svc_addressed {
                return Err(Error::NoHealthyUpstream(target));
            }
            debug!("built request as passthrough; no upstream found");
            return Ok(Request {
                protocol: Protocol::TCP,
                source: source_workload,
                hbone_target_destination: None,
                actual_destination_workload: None,
                intended_destination_service: None,
                actual_destination: target,
                upstream_sans: vec![],
            });
        };

        let from_waypoint = proxy::check_from_waypoint(
            state,
            &us.workload,
            Some(&source_workload.identity()),
            &downstream,
        )
        .await;

        // Check if we need to go through a workload addressed waypoint.
        // Don't traverse waypoint twice if the source is sandwich-outbound.
        // Don't traverse waypoint if traffic was addressed to a service (handled before)
        if !from_waypoint && !svc_addressed {
            // For case upstream server has enabled waypoint
            let waypoint = state
                .fetch_workload_waypoint(&us.workload, &source_workload, target)
                .await?;
            if let Some(waypoint) = waypoint {
                let actual_destination = waypoint.workload_socket_addr();
                let upstream_sans = waypoint.workload_and_services_san();
                debug!("built request to workload waypoint proxy");
                return Ok(Request {
                    // Always use HBONE here
                    protocol: Protocol::HBONE,
                    source: source_workload,
                    // Use the original VIP, not translated
                    hbone_target_destination: Some(target),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: us.destination_service.clone(),
                    actual_destination,
                    upstream_sans,
                });
            }
            // Workload doesn't have a waypoint; send directly
        }

        // only change the port if we're sending HBONE
        let actual_destination = match us.workload.protocol {
            Protocol::HBONE => SocketAddr::from((us.selected_workload_ip, self.hbone_port)),
            Protocol::TCP => us.workload_socket_addr(),
        };
        let hbone_target_destination = match us.workload.protocol {
            Protocol::HBONE => Some(us.workload_socket_addr()),
            Protocol::TCP => None,
        };

        // For case no waypoint for both side and direct to remote node proxy
        let upstream_sans = us.workload_and_services_san();
        debug!("built request to workload");
        Ok(Request {
            protocol: us.workload.protocol,
            source: source_workload,
            hbone_target_destination,
            actual_destination_workload: Some(us.workload.clone()),
            intended_destination_service: us.destination_service.clone(),
            actual_destination,
            upstream_sans,
        })
    }
}

fn baggage(r: &Request, cluster: String) -> String {
    format!("k8s.cluster.name={cluster},k8s.namespace.name={namespace},k8s.{workload_type}.name={workload_name},service.name={name},service.version={version}",
            namespace = r.source.namespace,
            workload_type = r.source.workload_type,
            workload_name = r.source.workload_name,
            name = r.source.canonical_name,
            version = r.source.canonical_revision,
    )
}

#[derive(Debug)]
struct Request {
    protocol: Protocol,
    // Source workload sending the request
    source: Arc<Workload>,
    // The actual destination workload we are targeting. When proxying through a waypoint, this is the waypoint,
    // not the original.
    // May be unset in case of passthrough.
    actual_destination_workload: Option<Arc<Workload>>,
    // The intended destination service for the request. When proxying through a waypoint, this is *not* the waypoint
    // service, but rather the original intended service.
    // May be unset in case of non-service traffic
    intended_destination_service: Option<ServiceDescription>,
    // The address we should actually request to. This is the "next hop" address; could be a waypoint, network gateway,
    // etc.
    // When using HBONE, the `hbone_target_destination` is the inner :authority and `actual_destination` is the TCP destination.
    actual_destination: SocketAddr,
    // If using HBONE, the inner (:authority) of the HBONE request.
    hbone_target_destination: Option<SocketAddr>,

    // The identity we will assert for the next hop; this may not be the same as actual_destination_workload
    // in the case of proxies along the path.
    upstream_sans: Vec<Identity>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::config::Config;
    use crate::proxy::connection_manager::ConnectionManager;
    use crate::proxy::LocalWorkloadInformation;
    use crate::state::WorkloadInfo;
    use crate::test_helpers::helpers::{initialize_telemetry, test_proxy_metrics};
    use crate::test_helpers::new_proxy_state;
    use crate::xds::istio::workload::address::Type as XdsAddressType;
    use crate::xds::istio::workload::TunnelProtocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::{IpFamilies, Port};
    use crate::xds::istio::workload::{NetworkAddress as XdsNetworkAddress, PortList};
    use crate::xds::istio::workload::{NetworkMode, Service as XdsService};
    use crate::{identity, xds};

    async fn run_build_request(
        from: &str,
        to: &str,
        xds: XdsAddressType,
        expect: Option<ExpectedRequest<'_>>,
    ) {
        run_build_request_multi(from, to, vec![xds], expect).await;
    }

    async fn run_build_request_multi(
        from: &str,
        to: &str,
        xds: Vec<XdsAddressType>,
        expect: Option<ExpectedRequest<'_>>,
    ) -> Option<Request> {
        let cfg = Arc::new(Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        });
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 1]),
                Bytes::copy_from_slice("::1".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            node: "local-node".to_string(),
            ..Default::default()
        };
        let waypoint = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/waypoint-workload".to_string(),
            name: "waypoint-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 10])],
            node: "local-node".to_string(),
            service_account: "waypoint-sa".to_string(),
            ..Default::default()
        };
        let waypoint_dual = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/waypoint-workload-dual".to_string(),
            name: "waypoint-workload-dual".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 11]),
                Bytes::copy_from_slice("ff06::c5".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            node: "local-node".to_string(),
            service_account: "waypoint-sa".to_string(),
            ..Default::default()
        };
        let mut workloads = vec![source, waypoint, waypoint_dual];
        let mut services = vec![];
        for x in xds {
            match x {
                XdsAddressType::Workload(wl) => workloads.push(wl),
                XdsAddressType::Service(svc) => services.push(svc),
            };
        }
        let state = new_proxy_state(&workloads, &services, &[]);

        let sock_fact = std::sync::Arc::new(crate::proxy::DefaultSocketFactory::default());

        let wi = WorkloadInfo {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            service_account: "default".to_string(),
        };
        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(wi.clone()),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));
        let outbound = OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state: state.clone(),
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sock_fact.clone(),
                local_workload_information: local_workload_information.clone(),
                connection_manager: ConnectionManager::default(),
                resolver: None,
            }),
            id: TraceParent::new(),
            pool: pool::WorkloadHBONEPool::new(
                cfg.clone(),
                sock_fact,
                local_workload_information.clone(),
            ),
            hbone_port: cfg.inbound_addr.port(),
        };

        let local = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();
        let req = outbound
            .build_request(local, from.parse().unwrap(), to.parse().unwrap())
            .await
            .ok();
        if let Some(ref r) = req {
            assert_eq!(
                expect,
                Some(ExpectedRequest {
                    protocol: r.protocol,
                    hbone_destination: &r
                        .hbone_target_destination
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    destination: &r.actual_destination.to_string(),
                })
            );
        } else {
            assert_eq!(expect, None);
        }
        req
    }

    #[tokio::test]
    async fn build_request_unknown_dest() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                hbone_destination: "",
                destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_source_waypoint() {
        run_build_request(
            "127.0.0.2",
            "127.0.0.1:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Even though source has a waypoint, we don't use it
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.1:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.10:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_waypoint_mismatch_ip() {
        run_build_request(
            "127.0.0.1",
            "[ff06::c3]:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![
                    Bytes::copy_from_slice(&[127, 0, 0, 2]),
                    Bytes::copy_from_slice(
                        "ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice(),
                    ),
                ],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 11].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "127.0.0.11:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_svc_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.3:80",
            XdsAddressType::Service(XdsService {
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                }],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "127.0.0.3:80",
                destination: "127.0.0.10:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_empty_service() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.3:80",
            XdsAddressType::Service(XdsService {
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                }],
                ..Default::default()
            }),
            // Should use the waypoint
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_target_port() {
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    }],
                    ports: vec![
                        Port {
                            service_port: 80,
                            target_port: 0, // named port
                        },
                        Port {
                            service_port: 8080,
                            target_port: 0, // named port
                        },
                    ],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/matching-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 1234,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                // This pod does not have a port 80 defined at all
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/unmatching-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 4])],
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 8080,
                                target_port: 9999,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:1234",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_host_network() {
        let xds = vec![
            // Normal service
            XdsAddressType::Service(XdsService {
                hostname: "example.com".to_string(),
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                }],
                ..Default::default()
            }),
            // Workload is host network, so it's going to have the same IP as another workload
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/pod1".to_string(),
                name: "pod1".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                services: std::collections::HashMap::from([(
                    "/example.com".to_string(),
                    PortList {
                        ports: vec![Port {
                            service_port: 80,
                            target_port: 80,
                        }],
                    },
                )]),
                network_mode: NetworkMode::HostNetwork as i32,
                ..Default::default()
            }),
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/pod2".to_string(),
                name: "pod2".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                network_mode: NetworkMode::HostNetwork as i32,
                ..Default::default()
            }),
        ];
        let res = run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            xds.clone(),
            // Traffic to the service should go to the pod in the service
            Some(ExpectedRequest {
                destination: "127.0.0.2:80",
                protocol: Protocol::TCP,
                hbone_destination: "",
            }),
        )
        .await
        .expect("must resolve");
        // Ensure it actually went to pod1, not the other pod with the same IP
        assert_eq!(
            res.actual_destination_workload.expect("found a dest").name,
            "pod1"
        );

        // Traffic to the node directly. We should forward the request, but as passthrough, rather than
        // associating it with a random pod.
        let res = run_build_request_multi(
            "127.0.0.1",
            "127.0.0.2:80",
            xds.clone(),
            // Traffic to the service should go to the pod in the service
            Some(ExpectedRequest {
                destination: "127.0.0.2:80",
                protocol: Protocol::TCP,
                hbone_destination: "",
            }),
        )
        .await
        .expect("must resolve");
        // Ensure it actually went to pod1, not the other pod with the same IP
        assert_eq!(res.actual_destination_workload, None);
    }

    #[tokio::test]
    async fn multiple_address_workload() {
        let workload = XdsAddressType::Workload(XdsWorkload {
            uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
            name: "test-tcp".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 2]),
                Bytes::copy_from_slice("ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            tunnel_protocol: XdsProtocol::None as i32,
            node: "remote-node".to_string(),
            ..Default::default()
        });
        // v4 goes go v4
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            workload.clone(),
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
        // v6 goes go v6
        run_build_request(
            "127.0.0.1",
            "[ff06::c3]:80",
            workload.clone(),
            Some(ExpectedRequest {
                protocol: Protocol::TCP,
                hbone_destination: "",
                destination: "[ff06::c3]:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn service_ip_families() {
        initialize_telemetry();
        let workload = XdsAddressType::Workload(XdsWorkload {
            uid: "cluster1//v1/Pod/default/dual".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 2]),
                Bytes::copy_from_slice("ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            tunnel_protocol: 1,
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList { ports: vec![] },
            )]),
            ..Default::default()
        });
        let svc = |f: IpFamilies| {
            let mut s = XdsService {
                hostname: "example.com".to_string(),
                addresses: vec![
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                    },
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: "::3".parse::<Ipv6Addr>().unwrap().octets().into(),
                    },
                ],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                }],
                ..Default::default()
            };
            s.set_ip_families(f);
            XdsAddressType::Service(s)
        };
        // V6 only should always use V6 IP
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Ipv6Only), workload.clone()],
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "[ff06::c3]:15008",
            }),
        )
        .await;
        // V4 only should always use V4 IP
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Ipv4Only), workload.clone()],
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
        // Dual stack should always prefer the original family (here ipv4)
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Dual), workload.clone()],
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
        // Dual stack should always prefer the original family (here ipv6)
        run_build_request_multi(
            "::1",
            "[::3]:80",
            vec![svc(IpFamilies::Dual), workload.clone()],
            Some(ExpectedRequest {
                protocol: Protocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "[ff06::c3]:15008",
            }),
        )
        .await;
    }

    #[derive(PartialEq, Debug)]
    struct ExpectedRequest<'a> {
        protocol: Protocol,
        hbone_destination: &'a str,
        destination: &'a str,
    }
}
