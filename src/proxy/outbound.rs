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

use tracing::{Instrument, debug, error, info, info_span, trace_span};

use crate::identity::Identity;

use crate::proxy::metrics::Reporter;
use crate::proxy::{
    BAGGAGE_HEADER, Error, HboneAddress, ProxyInputs, TRACEPARENT_HEADER, TraceParent, util,
};
use crate::proxy::{ConnectionOpen, ConnectionResult, DerivedWorkload, metrics};

use crate::drain::DrainWatcher;
use crate::drain::run_with_drain;
use crate::proxy::h2::{H2Stream, client::WorkloadKey};
use crate::state::service::{LoadBalancerMode, Service, ServiceDescription};
use crate::state::workload::OutboundProtocol;
use crate::state::workload::{InboundProtocol, NetworkAddress, Workload, address::Address};
use crate::state::{ServiceResolutionMode, Upstream};
use crate::{assertions, copy, proxy, socket};

use super::h2::TokioH2Stream;

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
        let accept = async move |drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
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
                        let serve_outbound_connection = async move {
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
                        }.instrument(span);

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
            req.protocol,
        );

        let metrics = self.pi.metrics.clone();
        let hbone_target = req.hbone_target_destination.clone();
        let result_tracker = Box::new(ConnectionResult::new(
            source_addr,
            req.actual_destination,
            hbone_target,
            start,
            Self::conn_metrics_from_request(&req),
            metrics,
        ));

        let res = match req.protocol {
            OutboundProtocol::DOUBLEHBONE => {
                // We box this since its not a common path and it would make the future really big.
                Box::pin(self.proxy_to_double_hbone(
                    source_stream,
                    source_addr,
                    &req,
                    &result_tracker,
                ))
                .await
            }
            OutboundProtocol::HBONE => {
                self.proxy_to_hbone(source_stream, source_addr, &req, &result_tracker)
                    .await
            }
            OutboundProtocol::TCP => {
                self.proxy_to_tcp(source_stream, &req, &result_tracker)
                    .await
            }
        };
        result_tracker.record(res)
    }

    async fn proxy_to_double_hbone(
        &mut self,
        stream: TcpStream,
        remote_addr: SocketAddr,
        req: &Request,
        connection_stats: &ConnectionResult,
    ) -> Result<(), Error> {
        // Create the outer HBONE stream
        let upgraded = Box::pin(self.send_hbone_request(remote_addr, req)).await?;
        // Wrap upgraded to implement tokio's Async{Write,Read}
        let upgraded = TokioH2Stream::new(upgraded);

        // For the inner one, we do it manually to avoid connection pooling.
        // Otherwise, we would only ever reach one workload in the remote cluster.
        // We also need to abort tasks the right way to get graceful terminations.
        let wl_key = WorkloadKey {
            src_id: req.source.identity(),
            dst_id: req.final_sans.clone(),
            src: remote_addr.ip(),
            dst: req.actual_destination,
        };

        // Fetch certs and establish inner TLS connection.
        let cert = self
            .pi
            .local_workload_information
            .fetch_certificate()
            .await?;
        let connector = cert.outbound_connector(wl_key.dst_id.clone())?;
        let tls_stream = connector.connect(upgraded).await?;

        // Spawn inner CONNECT tunnel
        let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
        let mut sender =
            super::h2::client::spawn_connection(self.pi.cfg.clone(), tls_stream, drain_rx, wl_key)
                .await?;
        let http_request = self.create_hbone_request(remote_addr, req);
        let inner_upgraded = sender.send_request(http_request).await?;

        // Proxy
        let res = copy::copy_bidirectional(
            copy::TcpStreamSplitter(stream),
            inner_upgraded,
            connection_stats,
        )
        .await;

        let _ = drain_tx.send(true);

        res
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

    fn create_hbone_request(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
    ) -> http::Request<()> {
        http::Request::builder()
            .uri(
                req.hbone_target_destination
                    .as_ref()
                    .expect("HBONE must have target")
                    .to_string(),
            )
            .method(hyper::Method::CONNECT)
            .version(hyper::Version::HTTP_2)
            .header(BAGGAGE_HEADER, baggage(req, self.pi.cfg.cluster_id.clone()))
            .header(
                FORWARDED,
                build_forwarded(remote_addr, &req.intended_destination_service),
            )
            .header(TRACEPARENT_HEADER, self.id.header())
            .body(())
            .expect("builder with known status code should not fail")
    }

    async fn send_hbone_request(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
    ) -> Result<H2Stream, Error> {
        let request = self.create_hbone_request(remote_addr, req);
        let pool_key = Box::new(WorkloadKey {
            src_id: req.source.identity(),
            // Clone here shouldn't be needed ideally, we could just take ownership of Request.
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
        let (derived_source, security_policy) = match req.protocol {
            OutboundProtocol::HBONE | OutboundProtocol::DOUBLEHBONE => (
                Some(DerivedWorkload {
                    // We are going to do mTLS, so report our identity
                    identity: Some(req.source.as_ref().identity()),
                    ..Default::default()
                }),
                metrics::SecurityPolicy::mutual_tls,
            ),
            OutboundProtocol::TCP => (None, metrics::SecurityPolicy::unknown),
        };
        ConnectionOpen {
            reporter: Reporter::source,
            derived_source,
            source: Some(req.source.clone()),
            destination: req.actual_destination_workload.clone(),
            connection_security_policy: security_policy,
            destination_service: req.intended_destination_service.clone(),
        }
    }

    // This function is called when the select next hop is on a different network,
    // so we expect the upstream workload to have a network gatewy configured.
    //
    // When we use a gateway to reach to a workload on a remote network we have to
    // use double HBONE (HBONE incapsulated inside HBONE). The gateway will
    // terminate the outer HBONE tunnel and forward the inner HBONE to the actual
    // destination as a opaque stream of bytes and the actual destination will
    // interpret it as an HBONE connection.
    //
    // If the upstream workload does not have an E/W gateway this function returns
    // an error indicating that it could not find a valid destination.
    //
    // A note about double HBONE, in double HBONE both inner and outer HBONE use
    // destination service name as HBONE target URI.
    //
    // Having target URI in the outer HBONE tunnel allows E/W gateway to figure out
    // where to route the data next witout the need to terminate inner HBONE tunnel.
    // In other words, it could forward inner HBONE as if it's an opaque stream of
    // bytes without trying to interpret it.
    //
    // NOTE: when connecting through an E/W gateway, regardless of whether there is
    // a waypoint or not, we always use service hostname and the service port. It's
    // somewhat different from how regular HBONE works, so I'm calling it out here.
    async fn build_request_through_gateway(
        &self,
        source: Arc<Workload>,
        // next hop on the remote network that we picked as our destination.
        // It may be a local view of a Waypoint workload on remote network or
        // a local view of the service workload (when waypoint is not
        // configured).
        upstream: Upstream,
        // This is a target service we wanted to reach in the first place.
        //
        // NOTE: Crossing network boundaries is only supported for services
        // at the moment, so we should always have a service we could use.
        service: &Service,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        if let Some(gateway) = &upstream.workload.network_gateway {
            let gateway_upstream = self
                .pi
                .state
                .fetch_network_gateway(gateway, &source, target)
                .await?;
            let hbone_target_destination = Some(HboneAddress::SvcHostname(
                service.hostname.clone(),
                target.port(),
            ));

            debug!("built request to a destination on another network through an E/W gateway");
            Ok(Request {
                protocol: OutboundProtocol::DOUBLEHBONE,
                source,
                hbone_target_destination,
                actual_destination_workload: Some(gateway_upstream.workload.clone()),
                intended_destination_service: Some(ServiceDescription::from(service)),
                actual_destination: gateway_upstream.workload_socket_addr().ok_or(
                    Error::NoValidDestination(Box::new((*gateway_upstream.workload).clone())),
                )?,
                // The outer tunnel of double HBONE is terminated by the E/W
                // gateway and so for the credentials of the next hop
                // (upstream_sans) we use gateway credentials.
                upstream_sans: gateway_upstream.workload_and_services_san(),
                // The inner HBONE tunnel is terminated by either the server
                // we want to reach or a Waypoint in front of it, depending on
                // the configuration. So for the final destination credentials
                // (final_sans) we use the upstream workload credentials.
                final_sans: upstream.service_sans(),
            })
        } else {
            // Do not try to send cross-network traffic without network gateway.
            Err(Error::NoValidDestination(Box::new(
                (*upstream.workload).clone(),
            )))
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
        let service = if let Some(Address::Service(target_service)) = state
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
                if waypoint.workload.network != source_workload.network {
                    debug!("picked a waypoint on remote network");
                    return self
                        .build_request_through_gateway(
                            source_workload.clone(),
                            waypoint,
                            &target_service,
                            target,
                        )
                        .await;
                }

                let upstream_sans = waypoint.workload_and_services_san();
                let actual_destination =
                    waypoint
                        .workload_socket_addr()
                        .ok_or(Error::NoValidDestination(Box::new(
                            (*waypoint.workload).clone(),
                        )))?;
                debug!("built request to service waypoint proxy");
                return Ok(Request {
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload,
                    hbone_target_destination: Some(HboneAddress::SocketAddr(target)),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: Some(ServiceDescription::from(&*target_service)),
                    actual_destination,
                    upstream_sans,
                    final_sans: vec![],
                });
            }
            // this was service addressed but we did not find a waypoint
            Some(target_service)
        } else {
            // this wasn't service addressed
            None
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
            if let Some(service) = service {
                if service.
                load_balancer.
                as_ref().
                // If we are not a passthrough service, we should have an upstream
                map(|lb| lb.mode != LoadBalancerMode::Passthrough).
                // If the service had no lb, we should have an upstream
                unwrap_or(true) {
                    return Err(Error::NoHealthyUpstream(target));
                }
            }
            debug!("built request as passthrough; no upstream found");
            return Ok(Request {
                protocol: OutboundProtocol::TCP,
                source: source_workload,
                hbone_target_destination: None,
                actual_destination_workload: None,
                intended_destination_service: None,
                actual_destination: target,
                upstream_sans: vec![],
                final_sans: vec![],
            });
        };

        // Check whether we are using an E/W gateway and sending cross network traffic
        if us.workload.network != source_workload.network {
            // Workloads on remote network must be service addressed, so if we got here
            // and we don't have a service for the original target address then it's a
            // bug either in ztunnel itself or in istiod.
            //
            // For a double HBONE protocol implementation we have to know the
            // destination service and if there is no service for the target it's a bug.
            //
            // This situation "should never happen" because for workloads fetch_upstream
            // above only checks the workloads on the same network as this ztunnel
            // instance and therefore it should not be able to find a workload on a
            // different network.
            debug_assert!(
                service.is_some(),
                "workload on remote network is not service addressed"
            );
            debug!("picked a workload on remote network");
            let service = service.as_ref().ok_or(Error::NoService(target))?;
            return self
                .build_request_through_gateway(source_workload.clone(), us, service, target)
                .await;
        }

        // We are not using a network gateway and there is no workload address.
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
        if !from_waypoint && service.is_none() {
            // For case upstream server has enabled waypoint
            let waypoint = state
                .fetch_workload_waypoint(&us.workload, &source_workload, target)
                .await?;
            if let Some(waypoint) = waypoint {
                let actual_destination =
                    waypoint
                        .workload_socket_addr()
                        .ok_or(Error::NoValidDestination(Box::new(
                            (*waypoint.workload).clone(),
                        )))?;
                let upstream_sans = waypoint.workload_and_services_san();
                debug!("built request to workload waypoint proxy");
                return Ok(Request {
                    // Always use HBONE here
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload,
                    // Use the original VIP, not translated
                    hbone_target_destination: Some(HboneAddress::SocketAddr(target)),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: us.destination_service.clone(),
                    actual_destination,
                    upstream_sans,
                    final_sans: vec![],
                });
            }
            // Workload doesn't have a waypoint; send directly
        }

        let selected_workload_ip = us
            .selected_workload_ip
            .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?;

        // only change the port if we're sending HBONE
        let actual_destination = match us.workload.protocol {
            InboundProtocol::HBONE => SocketAddr::from((selected_workload_ip, self.hbone_port)),
            InboundProtocol::TCP => us
                .workload_socket_addr()
                .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?,
        };
        let hbone_target_destination = match us.workload.protocol {
            InboundProtocol::HBONE => Some(HboneAddress::SocketAddr(
                us.workload_socket_addr()
                    .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?,
            )),
            InboundProtocol::TCP => None,
        };

        // For case no waypoint for both side and direct to remote node proxy
        let (upstream_sans, final_sans) = (us.workload_and_services_san(), vec![]);
        debug!("built request to workload");
        Ok(Request {
            protocol: OutboundProtocol::from(us.workload.protocol),
            source: source_workload,
            hbone_target_destination,
            actual_destination_workload: Some(us.workload.clone()),
            intended_destination_service: us.destination_service.clone(),
            actual_destination,
            upstream_sans,
            final_sans,
        })
    }
}

fn build_forwarded(remote_addr: SocketAddr, server: &Option<ServiceDescription>) -> String {
    match server {
        None => {
            format!("for=\"{remote_addr}\"")
        }
        Some(svc) => {
            format!("for=\"{remote_addr}\";host={}", svc.hostname)
        }
    }
}

fn baggage(r: &Request, cluster: String) -> String {
    format!(
        "k8s.cluster.name={cluster},k8s.namespace.name={namespace},k8s.{workload_type}.name={workload_name},service.name={name},service.version={version},cloud.region={region},cloud.availability_zone={zone}",
        namespace = r.source.namespace,
        workload_type = r.source.workload_type,
        workload_name = r.source.workload_name,
        name = r.source.canonical_name,
        version = r.source.canonical_revision,
        region = r.source.locality.region,
        zone = r.source.locality.zone,
    )
}

#[derive(Debug)]
struct Request {
    protocol: OutboundProtocol,
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
    hbone_target_destination: Option<HboneAddress>,

    // The identity we will assert for the next hop; this may not be the same as actual_destination_workload
    // in the case of proxies along the path.
    upstream_sans: Vec<Identity>,

    // The identity of workload that will ultimately process this request.
    // This field only matters if we need to know both the identity of the next hop, as well as the
    // final hop (currently, this is only double HBONE).
    final_sans: Vec<Identity>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::config::Config;
    use crate::proxy::connection_manager::ConnectionManager;
    use crate::proxy::{LocalWorkloadInformation, pool::WorkloadHBONEPool};
    use crate::state::WorkloadInfo;
    use crate::test_helpers::helpers::{initialize_telemetry, test_proxy_metrics};
    use crate::test_helpers::new_proxy_state;
    use crate::xds::istio::workload::TunnelProtocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::address::Type as XdsAddressType;
    use crate::xds::istio::workload::{IpFamilies, Port};
    use crate::xds::istio::workload::{
        NamespacedHostname as XdsNamespacedHostname, NetworkAddress as XdsNetworkAddress, PortList,
    };
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
                disable_inbound_freebind: false,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(
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
                        .as_ref()
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
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_wrong_network() {
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
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 0, 0, 2])],
                    network: "remote".to_string(),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_double_hbone() {
        // example.com service has a workload on remote network.
        // E/W gateway is addressed by an IP.
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
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Address(
                                XdsNetworkAddress {
                                    network: "remote".to_string(),
                                    address: vec![10, 22, 1, 1],
                                },
                            ),
                        ),
                        hbone_mtls_port: 15009,
                    }),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
                    network: "remote".to_string(),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
        // example.com service has a workload on remote network.
        // E/W gateway is addressed by a hostname.
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
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Service(XdsService {
                    hostname: "ew-gtw".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 4],
                    }],
                    ports: vec![Port {
                        service_port: 15009,
                        target_port: 15009,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 6])],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        hbone_mtls_port: 15009,
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Hostname(
                                XdsNamespacedHostname {
                                    namespace: Default::default(),
                                    hostname: "ew-gtw".into(),
                                },
                            ),
                        ),
                    }),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 5])],
                    network: "remote".to_string(),
                    services: std::collections::HashMap::from([(
                        "/ew-gtw".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 15009,
                                target_port: 15008,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "127.0.0.5:15008",
            }),
        )
        .await;
        // example.com service has a waypoint and waypoint workload is on remote network.
        // E/W gateway is addressed by an IP.
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
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                    waypoint: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Hostname(
                                XdsNamespacedHostname {
                                    namespace: Default::default(),
                                    hostname: "waypoint.com".into(),
                                },
                            ),
                        ),
                        hbone_mtls_port: 15008,
                    }),
                    ..Default::default()
                }),
                XdsAddressType::Service(XdsService {
                    hostname: "waypoint.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 4],
                    }],
                    ports: vec![Port {
                        service_port: 15008,
                        target_port: 15008,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "Kubernetes//Pod/default/remote-waypoint-pod".to_string(),
                    addresses: vec![],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Address(
                                XdsNetworkAddress {
                                    network: "remote".to_string(),
                                    address: vec![10, 22, 1, 1],
                                },
                            ),
                        ),
                        hbone_mtls_port: 15009,
                    }),
                    services: std::collections::HashMap::from([(
                        "/waypoint.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 15008,
                                target_port: 15008,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "Kubernetes//Pod/default/remote-ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
                    network: "remote".to_string(),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_failover_to_remote() {
        // Similar to the double HBONE test that we already have, but it sets up a scenario when
        // load balancing logic will pick a workload on a remote cluster when local workloads are
        // unhealthy, thus showing the expected failover behavior.
        let service = XdsAddressType::Service(XdsService {
            hostname: "example.com".to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "".to_string(),
                address: vec![127, 0, 0, 3],
            }],
            ports: vec![Port {
                service_port: 80,
                target_port: 8080,
            }],
            // Prefer routing to workloads on the same network, but when nothing is healthy locally
            // allow failing over to remote networks.
            load_balancing: Some(xds::istio::workload::LoadBalancing {
                routing_preference: vec![
                    xds::istio::workload::load_balancing::Scope::Network.into(),
                ],
                mode: xds::istio::workload::load_balancing::Mode::Failover.into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let ew_gateway = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/remote-ew-gtw".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
            network: "remote".to_string(),
            ..Default::default()
        });
        let remote_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/remote-example.com-pod".to_string(),
            addresses: vec![],
            network: "remote".to_string(),
            network_gateway: Some(xds::istio::workload::GatewayAddress {
                destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                    XdsNetworkAddress {
                        network: "remote".to_string(),
                        address: vec![10, 22, 1, 1],
                    },
                )),
                hbone_mtls_port: 15009,
            }),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            ..Default::default()
        });
        let healthy_local_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/local-example.com-pod".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
            network: "".to_string(),
            tunnel_protocol: xds::istio::workload::TunnelProtocol::Hbone.into(),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            status: xds::istio::workload::WorkloadStatus::Healthy.into(),
            ..Default::default()
        });
        let unhealthy_local_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/local-example.com-pod".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
            network: "".to_string(),
            tunnel_protocol: xds::istio::workload::TunnelProtocol::Hbone.into(),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            status: xds::istio::workload::WorkloadStatus::Unhealthy.into(),
            ..Default::default()
        });

        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                service.clone(),
                ew_gateway.clone(),
                remote_workload.clone(),
                healthy_local_workload.clone(),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:8080",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;

        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                service.clone(),
                ew_gateway.clone(),
                remote_workload.clone(),
                unhealthy_local_workload.clone(),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::TCP,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::HBONE,
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
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "[ff06::c3]:15008",
            }),
        )
        .await;
    }

    #[test]
    fn build_forwarded() {
        assert_eq!(
            super::build_forwarded("127.0.0.1:80".parse().unwrap(), &None),
            r#"for="127.0.0.1:80""#,
        );
        assert_eq!(
            super::build_forwarded("[::1]:80".parse().unwrap(), &None),
            r#"for="[::1]:80""#,
        );
        assert_eq!(
            super::build_forwarded(
                "127.0.0.1:80".parse().unwrap(),
                &Some(ServiceDescription {
                    hostname: "example.com".into(),
                    name: Default::default(),
                    namespace: Default::default(),
                }),
            ),
            r#"for="127.0.0.1:80";host=example.com"#,
        );
    }

    #[derive(PartialEq, Debug)]
    struct ExpectedRequest<'a> {
        protocol: OutboundProtocol,
        hbone_destination: &'a str,
        destination: &'a str,
    }
}
