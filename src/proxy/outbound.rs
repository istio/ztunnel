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

use std::time::Instant;

use drain::Watch;
use futures_util::TryFutureExt;

use hyper::header::FORWARDED;
use tokio::io::AsyncWriteExt;

use tokio::net::TcpStream;

use tracing::{debug, error, info, info_span, trace_span, Instrument};

use crate::config::ProxyMode;
use crate::identity::Identity;

use crate::proxy::metrics::Reporter;
use crate::proxy::{metrics, pool, ConnectionOpen, ConnectionResult};
use crate::proxy::{util, Error, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};

use crate::proxy::h2::H2Stream;
use crate::state::service::ServiceDescription;
use crate::state::workload::{address::Address, NetworkAddress, Protocol, Workload};
use crate::{assertions, copy, proxy, socket};

pub struct Outbound {
    pi: Arc<ProxyInputs>,
    drain: Watch,
    listener: socket::Listener,
    enable_orig_src: bool,
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum OutboundProxyError {
    #[error("General")]
    General,
    #[error("NotAllowed")]
    NotAllowed,
    #[error("NetworkUnreachable")]
    NetworkUnreachable,
    #[error("HostUnreachable")]
    HostUnreachable,
    #[error("ConnectionRefused")]
    ConnectionRefused,
    #[error("CommandNotSupported")]
    CommandNotSupported,
}

impl Outbound {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: Watch) -> Result<Outbound, Error> {
        let listener = pi
            .socket_factory
            .tcp_bind(pi.cfg.outbound_addr)
            .map_err(|e| Error::Bind(pi.cfg.outbound_addr, e))?;
        let enable_orig_src = super::maybe_set_transparent(&pi, &listener)?;

        info!(
            address=%listener.local_addr(),
            component="outbound",
            transparent=enable_orig_src,
            "listener established",
        );
        Ok(Outbound {
            pi,
            listener,
            drain,
            enable_orig_src,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub(super) async fn run(self) {
        // Since we are spawning autonomous tasks to handle outbound connections for a single workload,
        // we can have situations where the workload is deleted, but a task is still "stuck"
        // waiting for a server response stream on a HTTP/2 connection or whatnot.
        //
        // So use a drain to nuke tasks that might be stuck sending.
        let (sub_drain_signal, sub_drain) = drain::channel();
        let pool = proxy::pool::WorkloadHBONEPool::new(
            self.pi.cfg.clone(),
            self.enable_orig_src,
            self.pi.socket_factory.clone(),
            self.pi.cert_manager.clone(),
        );
        let accept = async move {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let start_outbound_instant = Instant::now();
                let outbound_drain = sub_drain.clone();
                match socket {
                    Ok((stream, _remote)) => {
                        let mut oc = OutboundConnection {
                            pi: self.pi.clone(),
                            id: TraceParent::new(),
                            pool: pool.clone(),
                            enable_orig_src: self.enable_orig_src,
                            hbone_port: self.pi.cfg.inbound_addr.port(),
                        };
                        stream.set_nodelay(true).unwrap();
                        let span = info_span!("outbound", id=%oc.id);
                        let serve_outbound_connection = (async move {
                            debug!(dur=?start_outbound_instant.elapsed(), "outbound spawn START");
                            // Since this task is spawned, make sure we are guaranteed to terminate
                            tokio::select! {
                                _ = outbound_drain.signaled() => {
                                    debug!("outbound drain signaled");
                                }
                                _ = oc.proxy(stream) => {}
                            }
                            debug!(dur=?start_outbound_instant.elapsed(), "outbound spawn DONE");
                        })
                        .instrument(span);

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
        .in_current_span();

        // Stop accepting once we drain.
        // Note: we are *not* waiting for all connections to be closed. In the future, we may consider
        // this, but will need some timeout period, as we have no back-pressure mechanism on connections.
        tokio::select! {
            res = accept => { res }
            _ = self.drain.signaled() => {
                debug!("outbound drained, dropping any outbound connections");
                sub_drain_signal.drain().await;
                info!("outbound drained");
            }
        }
    }
}

pub(super) struct OutboundConnection {
    pub(super) pi: Arc<ProxyInputs>,
    pub(super) id: TraceParent,
    pub(super) pool: proxy::pool::WorkloadHBONEPool,
    pub(super) enable_orig_src: bool,
    pub(super) hbone_port: u16,
    pub(super) send_socks5_success: bool,
}

impl OutboundConnection {
    async fn proxy(&mut self, source_stream: TcpStream) {
        let source_addr =
            socket::to_canonical(source_stream.peer_addr().expect("must receive peer addr"));
        let dst_addr = socket::orig_dst_addr_or_default(&source_stream);
        self.proxy_to(source_stream, source_addr, dst_addr).await;
    }

    // this is a cancellable outbound proxy. If `out_drain` is a Watch drain, will resolve
    // when the drain is signaled, or the outbound stream is completed, no matter what.
    //
    // If `out_drain` is none, will only resolve when the outbound stream is terminated.
    //
    // If using `proxy_to` in `tokio::spawn` tasks, it is recommended to use a drain, to guarantee termination
    // and prevent "zombie" outbound tasks.
    pub async fn proxy_to_cancellable(
        &mut self,
        stream: TcpStream,
        remote_addr: SocketAddr,
        orig_dst_addr: SocketAddr,
        out_drain: Option<Watch>,
    ) -> Result<(), OutboundProxyError> {
        match out_drain {
            Some(drain) => {
                tokio::select! {
                        _ = drain.signaled() => {
                            info!("drain signaled");
                            Ok(())
                        }
                        res = self.proxy_to(stream, remote_addr, orig_dst_addr) => res
                }
            }
            None => {
                self.proxy_to(stream, remote_addr, orig_dst_addr).await
            }
        }
    }

    async fn proxy_to(
        &mut self,
        mut source_stream: TcpStream,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
    ) -> Result<(), OutboundProxyError> {
        let start = Instant::now();

        // Block calls to ztunnel directly, unless we are in "in-pod".
        // For in-pod, this isn't an issue and is useful: this allows things like prometheus scraping ztunnel.
        if self.pi.cfg.proxy_mode == ProxyMode::Shared
            && Some(dest_addr.ip()) == self.pi.cfg.local_ip
            && !self.pi.cfg.inpod_enabled
        {
            metrics::log_early_deny(source_addr, dest_addr, Reporter::source, Error::SelfCall);
            return Err(OutboundProxyError::NotAllowed);
        }
        let req = match Box::pin(self.build_request(source_addr.ip(), dest_addr)).await {
            Ok(req) => Box::new(req),
            Err(err) => {
                metrics::log_early_deny(source_addr, dest_addr, Reporter::source, err);
                return Err(OutboundProxyError::General);
            }
        };
        // TODO: should we use the original address or the actual address? Both seems nice!
        let _conn_guard = self.pi.connection_manager.track_outbound(
            source_addr,
            dest_addr,
            req.actual_destination,
        );

        let metrics = self.pi.metrics.clone();
        let hbone_target = req.hbone_target_destination;
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
                let r1= Box::pin(self.send_hbone_request(source_addr, &req)).await;
                let Ok(upgraded) = r1 else {
                    result_tracker.record(r1.map(|_| ()));
                    return Err(OutboundProxyError::ConnectionRefused);
                };
                self.maybe_send_socks5_success(&mut source_stream)
                    .and_then(|_| copy::copy_bidirectional(source_stream, upgraded, &result_tracker)).await
            }
            Protocol::TCP => {
                self.proxy_to_tcp(&mut source_stream, &req, &result_tracker)
                    .await
            }
        };
        result_tracker.record(res);
        Ok(())
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
        stream: &mut TcpStream,
        req: &Request,
        connection_stats: &ConnectionResult,
    ) -> Result<(), Error> {
        // Create a TCP connection to upstream
        let local = if self.enable_orig_src {
            super::get_original_src_from_stream(stream)
        } else {
            None
        };
        let mut outbound = super::freebind_connect(
            local,
            req.actual_destination,
            self.pi.socket_factory.as_ref(),
        )
        .await?;

        // Proxying data between downstream and upstream
        copy::copy_bidirectional(stream, &mut outbound, connection_stats).await
    }

    fn conn_metrics_from_request(req: &Request) -> ConnectionOpen {
        ConnectionOpen {
            reporter: Reporter::source,
            derived_source: None,
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
        downstream: IpAddr,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        let state = &self.pi.state;
        // First find the source workload of this traffic. If we don't know where the request is from
        // we will reject it.
        let source_workload = self.fetch_source_workload(downstream).await?;

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
                .fetch_service_waypoint(&target_service, &source_workload)
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
            .fetch_upstream(source_workload.network.clone(), &source_workload, target)
            .await?
        else {
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
                .fetch_workload_waypoint(&us.workload, &source_workload)
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

    async fn fetch_source_workload(&self, downstream: IpAddr) -> Result<Arc<Workload>, Error> {
        let downstream_network_addr = NetworkAddress {
            network: self.pi.cfg.network.clone(),
            address: downstream,
        };
        let source_workload = match self.pi.state.fetch_workload(&downstream_network_addr).await {
            Some(wl) => wl,
            None => return Err(Error::UnknownSource(downstream)),
        };
        if let Some(ref wl_info) = self.pi.proxy_workload_info {
            // make sure that the workload we fetched matches the workload info we got over ZDS.
            if !wl_info.matches(&source_workload) {
                return Err(Error::MismatchedSource(downstream, wl_info.clone()));
            }
        }
        Ok(source_workload)
    }
    async fn maybe_send_socks5_success(&mut self, stream: &mut TcpStream) -> Result<(), Error> {
        if !self.send_socks5_success {
            return Ok(())
        }
        // Send dummy values - the client generally ignores it.
        let buf = [
            0x05u8, // version
            0x00, // Success
            0x00, // reserved
            0x01, 0x00, 0x00, 0x00, 0x00, // IPv4
            0x00, 0x00, // port
        ];
        stream.write_all(&buf).await?;
        Ok(())
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
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::config::Config;
    use crate::proxy::connection_manager::ConnectionManager;
    use crate::test_helpers::helpers::test_proxy_metrics;
    use crate::test_helpers::new_proxy_state;
    use crate::xds::istio::workload::address::Type as XdsAddressType;
    use crate::xds::istio::workload::NetworkAddress as XdsNetworkAddress;
    use crate::xds::istio::workload::Port;
    use crate::xds::istio::workload::Service as XdsService;
    use crate::xds::istio::workload::TunnelProtocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::{identity, xds};

    async fn run_build_request(
        from: &str,
        to: &str,
        xds: XdsAddressType,
        expect: Option<ExpectedRequest<'_>>,
    ) {
        let cfg = Arc::new(Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        });
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 1])],
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
        let state = match xds {
            XdsAddressType::Workload(wl) => new_proxy_state(&[source, waypoint, wl], &[], &[]),
            XdsAddressType::Service(svc) => new_proxy_state(&[source, waypoint], &[svc], &[]),
        };

        let sock_fact = std::sync::Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let original_src = false; // for testing, not needed
        let outbound = OutboundConnection {
            pi: Arc::new(ProxyInputs {
                cert_manager: identity::mock::new_secret_manager(Duration::from_secs(10)),
                state,
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sock_fact.clone(),
                proxy_workload_info: None,
                connection_manager: ConnectionManager::default(),
            }),
            id: TraceParent::new(),
            pool: pool::WorkloadHBONEPool::new(
                cfg.clone(),
                original_src,
                sock_fact,
                cert_mgr.clone(),
            ),
            enable_orig_src: cfg.require_original_source.unwrap_or_default(),
            hbone_port: cfg.inbound_addr.port(),
        };

        let req = outbound
            .build_request(from.parse().unwrap(), to.parse().unwrap())
            .await
            .ok();
        if let Some(r) = req {
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
    async fn build_request_unknown_source() {
        run_build_request(
            "1.2.3.4",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                ..Default::default()
            }),
            None,
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
                    hbone_single_tls_port: 15003,
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
                    hbone_single_tls_port: 15003,
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
                    hbone_single_tls_port: 15003,
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

    #[derive(PartialEq, Debug)]
    struct ExpectedRequest<'a> {
        protocol: Protocol,
        hbone_destination: &'a str,
        destination: &'a str,
    }
}
