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
use std::time::Instant;

use boring::ssl::ConnectConfiguration;
use drain::Watch;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::identity::CertificateProvider;
use crate::proxy::inbound::{Inbound, InboundConnect};
use crate::proxy::Error;
use crate::socket::relay;
use crate::workload::{Protocol, Workload, WorkloadInformation};
use crate::{identity, socket};

pub struct Outbound {
    cfg: Config,
    cert_manager: Box<dyn CertificateProvider>,
    workloads: WorkloadInformation,
    listener: TcpListener,
    drain: Watch,
    hbone_port: u16,
}

impl Outbound {
    pub async fn new(
        cfg: Config,
        cert_manager: Box<dyn CertificateProvider>,
        workloads: WorkloadInformation,
        hbone_port: u16,
        drain: Watch,
    ) -> Result<Outbound, Error> {
        let listener: TcpListener = TcpListener::bind(cfg.outbound_addr)
            .await
            .map_err(|e| Error::Bind(cfg.outbound_addr, e))?;
        match socket::set_transparent(&listener) {
            Err(_e) => info!("running without transparent mode"),
            _ => info!("running with transparent mode"),
        };

        Ok(Outbound {
            cfg,
            cert_manager,
            workloads,
            listener,
            hbone_port,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    pub(super) async fn run(self) {
        info!("outbound listener established {}", self.address());
        let accept = async move {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let start_outbound_instant = Instant::now();
                match socket {
                    Ok((stream, _remote)) => {
                        let cfg = self.cfg.clone();
                        let mut oc = OutboundConnection {
                            cert_manager: self.cert_manager.clone(),
                            workloads: self.workloads.clone(),
                            cfg,
                            hbone_port: self.hbone_port,
                        };
                        tokio::spawn(async move {
                            let res = oc.proxy(stream).await;
                            match res {
                                Ok(_) => info!(
                                    "outbound proxy complete ({:?})",
                                    start_outbound_instant.elapsed()
                                ),
                                Err(ref e) => warn!(
                                    "outbound proxy failed: {} ({:?})",
                                    e,
                                    start_outbound_instant.elapsed()
                                ),
                            };
                        });
                    }
                    Err(e) => error!("Failed TCP handshake {}", e),
                }
            }
        };

        // Stop accepting once we drain.
        // Note: we are *not* waiting for all connections to be closed. In the future, we may consider
        // this, but will need some timeout period, as we have no back-pressure mechanism on connections.
        tokio::select! {
            res = accept => { res }
            _ = self.drain.signaled() => {
                info!("outbound drained");
            }
        }
    }
}

pub struct OutboundConnection {
    pub cert_manager: Box<dyn CertificateProvider>,
    pub workloads: WorkloadInformation,
    // TODO: Config may be excessively large, maybe we store a scoped OutboundConfig intended for cloning.
    pub cfg: Config,
    pub hbone_port: u16,
}

impl OutboundConnection {
    async fn proxy(&mut self, stream: TcpStream) -> Result<(), Error> {
        let peer = stream.peer_addr().expect("must receive peer addr");
        let remote_addr = super::to_canonical_ip(peer);
        let orig = socket::orig_dst_addr_or_default(&stream);
        self.proxy_to(stream, remote_addr, orig).await
    }

    pub async fn proxy_to(
        &mut self,
        mut stream: TcpStream,
        remote_addr: IpAddr,
        orig: SocketAddr,
    ) -> Result<(), Error> {
        let req = self.build_request(remote_addr, orig).await?;
        debug!(
            "request from {} to {} via {} type {:#?} dir {:#?}",
            req.source.name, orig, req.gateway, req.request_type, req.direction
        );
        if req.request_type == RequestType::DirectLocal {
            // For same node, we just access it directly rather than making a full network connection.
            // Pass our `stream` over to the inbound handler, which will process as usual
            info!("Proxying to {} using node local fast path", req.destination);
            return Inbound::handle_inbound(InboundConnect::DirectPath(stream), req.destination)
                .await
                .map_err(Error::Io);
        }
        match req.protocol {
            Protocol::Hbone => {
                info!(
                    "Proxying to {} using HBONE via {} type {:#?}",
                    req.destination, req.gateway, req.request_type
                );

                // Using the raw connection API, instead of client, is a bit annoying, but the only reasonable
                // way to work around https://github.com/hyperium/hyper/issues/2863
                // Eventually we will need to implement our own smarter pooling, TLS handshaking, etc anyways.
                let mut builder = hyper::client::conn::Builder::new();
                let builder = builder
                    .http2_only(true)
                    .http2_initial_stream_window_size(self.cfg.window_size)
                    .http2_max_frame_size(self.cfg.frame_size)
                    .http2_initial_connection_window_size(self.cfg.connection_window_size);

                let request = hyper::Request::builder()
                    .uri(&req.destination.to_string())
                    .method(hyper::Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .header("baggage", baggage(&req))
                    .body(hyper::Body::empty())
                    .unwrap();

                let mut request_sender = if self.cfg.tls {
                    let id = &req.source.identity();
                    let cert = self.cert_manager.fetch_certificate(id).await?;
                    let connector = cert
                        .connector(&req.destination_identity)?
                        .configure()
                        .expect("configure");
                    let tcp_stream = TcpStream::connect(req.gateway).await?;
                    tcp_stream.set_nodelay(true)?;
                    let tls_stream = connect_tls(connector, tcp_stream).await?;
                    let (request_sender, connection) = builder
                        .handshake(tls_stream)
                        .await
                        .map_err(Error::HttpHandshake)?;
                    // spawn a task to poll the connection and drive the HTTP state
                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            error!("Error in HBONE connection handshake: {:?}", e);
                        }
                    });
                    request_sender
                } else {
                    let tcp_stream = TcpStream::connect(req.gateway).await?;
                    tcp_stream.set_nodelay(true)?;
                    let (request_sender, connection) = builder
                        .handshake::<TcpStream, hyper::Body>(tcp_stream)
                        .await?;
                    // spawn a task to poll the connection and drive the HTTP state
                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            error!("Error in connection: {}", e);
                        }
                    });
                    request_sender
                };

                let response = request_sender.send_request(request).await?;

                let code = response.status();
                match hyper::upgrade::on(response).await {
                    Ok(mut upgraded) => {
                        super::copy_hbone("hbone client", &mut upgraded, &mut stream)
                            .await
                            .expect("hbone client copy");
                    }
                    Err(e) => error!("upgrade error: {}, {}", e, code),
                }
                info!("request complete");
                Ok(())
            }
            Protocol::Tcp => {
                info!(
                    "Proxying to {} using TCP via {} type {:?}",
                    req.destination, req.gateway, req.request_type
                );
                // Create a TCP connection to upstream
                let mut outbound = TcpStream::connect(req.gateway).await?;
                // Proxying data between downstrean and upstream
                relay(&mut stream, &mut outbound).await?;

                // TODO: metrics, time, more info, etc.
                // Probably shouldn't log at start
                info!(
                    "Proxying complete to {} using TCP via {} type {:?}",
                    req.destination, req.gateway, req.request_type
                );
                Ok(())
            }
        }
    }

    async fn build_request(
        &self,
        downstream: IpAddr,
        target: SocketAddr,
    ) -> Result<Request, Error> {
        let source_workload = match self.workloads.fetch_workload(&downstream).await {
            Some(wl) => wl,
            None => return Err(Error::UnknownSource(downstream)),
        };

        // TODO: we want a single lock for source and upstream probably...?
        let us = self.workloads.find_upstream(target, self.hbone_port).await;
        if us.is_none() {
            // For case no upstream found, passthrough it
            return Ok(Request {
                protocol: Protocol::Tcp,
                source: source_workload,
                destination: target,
                destination_identity: None,
                gateway: target,
                direction: Direction::Outbound,
                request_type: RequestType::Passthrough,
            });
        }

        // For case source client has enabled waypoint
        if !source_workload.waypoint_addresses.is_empty() {
            let waypoint_address = source_workload.choose_waypoint_address().unwrap();
            let destination_identity = Some(source_workload.identity());
            return Ok(Request {
                // Always use HBONE here
                protocol: Protocol::Hbone,
                source: source_workload,
                // Load balancing decision is deferred to remote proxy
                destination: target,
                destination_identity,
                // Send to the remote proxy
                gateway: SocketAddr::from((waypoint_address, 15001)),
                // Let the client remote know we are on the outbound path. The remote proxy should strictly
                // validate the identity when we declare this
                direction: Direction::Outbound,
                // Source has a remote proxy. We should delegate everything to that proxy - do not even resolve VIP.
                // TODO: add client skipping
                request_type: RequestType::ToClientWaypoint,
            });
        }
        
        let us = us.unwrap();
        // For case upstream server has enabled waypoint
        if !us.workload.waypoint_addresses.is_empty() {
            let waypoint_address = us.workload.choose_waypoint_address().unwrap();
            // Even in this case, we are picking a single upstream pod and deciding if it has a remote proxy.
            // Typically this is all or nothing, but if not we should probably send to remote proxy if *any* upstream has one.
            return Ok(Request {
                // Always use HBONE here
                protocol: Protocol::Hbone,
                source: source_workload,
                // Use the original VIP, not translated
                destination: target,
                gateway: SocketAddr::from((waypoint_address, 15006)),
                destination_identity: us.workload.identity().into(),
                // Let the client remote know we are on the inbound path.
                direction: Direction::Inbound,
                request_type: RequestType::ToServerWaypoint,
            });
        }
        // For case source client and upstream server are on the same node
        if !us.workload.node.is_empty()
            && self.cfg.local_node == Some(us.workload.node.clone())
            && us.workload.protocol == Protocol::Hbone
        {
            return Ok(Request {
                protocol: Protocol::Hbone,
                source: source_workload,
                destination: SocketAddr::from((us.workload.workload_ip, us.port)),
                destination_identity: us.workload.identity().into(),
                // We would want to send to 127.0.0.1:15008 in theory. However, the inbound listener
                // expects to lookup the desired certificate based on the destination IP. If we send directly,
                // we would try to lookup an IP for 127.0.0.1.
                // Instead, we send to the actual IP, but iptables in the pod ensures traffic is redirected to 15008.
                gateway: SocketAddr::from((
                    us.workload
                        .gateway_address
                        .expect("todo: refactor gateway ip handling")
                        .ip(),
                    15088,
                )),
                direction: Direction::Outbound,
                // Sending to a node on the same node (ourselves).
                // In the future this could be optimized to avoid a full network traversal.
                request_type: RequestType::DirectLocal,
            });
        }
        // For case no waypoint for both side and direct to remote node proxy
        Ok(Request {
            protocol: us.workload.protocol,
            source: source_workload,
            destination: SocketAddr::from((us.workload.workload_ip, us.port)),
            destination_identity: us.workload.identity().into(),
            gateway: us
                .workload
                .gateway_address
                .expect("todo: refactor gateway ip handling"),
            direction: Direction::Outbound,
            request_type: RequestType::Direct,
        })
    }
}

fn baggage(r: &Request) -> String {
    format!("k8s.cluster.name={cluster},k8s.namespace.name={namespace},k8s.{workload_type}.name={workload_name},service.name={name},service.version={version}",
            cluster = "Kubernetes",// todo
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
    direction: Direction,
    source: Workload,
    destination: SocketAddr,
    destination_identity: Option<identity::Identity>,
    gateway: SocketAddr,
    request_type: RequestType,
}

#[derive(Debug)]
enum Direction {
    Inbound,
    Outbound,
}

#[derive(PartialEq, Debug)]
enum RequestType {
    /// ToClientWaypoint refers to requests targeting a client waypoint proxy
    ToClientWaypoint,
    /// ToServerWaypoint refers to requests targeting a server waypoint proxy
    ToServerWaypoint,
    /// Direct requests are made directly to a intended backend pod
    Direct,
    /// DirectLocal requests are made directly to an intended backend pod *on the same node*
    DirectLocal,
    /// Passthrough refers to requests with an unknown target
    Passthrough,
}

async fn connect_tls(
    mut connector: ConnectConfiguration,
    stream: TcpStream,
) -> Result<tokio_boring::SslStream<TcpStream>, tokio_boring::HandshakeError<TcpStream>> {
    connector.set_verify_hostname(false);
    connector.set_use_server_name_indication(false);
    tokio_boring::connect(connector, "", stream).await
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;

    use crate::workload;
    use crate::xds::istio::workload::Port as XdsPort;
    use crate::xds::istio::workload::PortList as XdsPortList;
    use crate::xds::istio::workload::Protocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;

    use super::*;

    async fn run_build_request(
        from: &str,
        to: &str,
        xds: XdsWorkload,
        expect: Option<ExpectedRequest<'_>>,
    ) {
        let cfg = Config {
            local_node: Some("local-node".to_string()),
            ..Default::default()
        };
        let source = XdsWorkload {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            address: Bytes::copy_from_slice(&[127, 0, 0, 1]),
            node: "local-node".to_string(),
            ..Default::default()
        };
        let wl = workload::WorkloadStore::test_store(vec![source, xds]).unwrap();

        let wi = WorkloadInformation {
            info: Arc::new(Mutex::new(wl)),
            demand: None,
        };
        let outbound = OutboundConnection {
            cert_manager: Box::new(identity::SecretManager::new(cfg.clone())),
            workloads: wi,
            hbone_port: 15008,
            cfg,
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
                    destination: &r.destination.to_string(),
                    gateway: &r.gateway.to_string(),
                    request_type: r.request_type,
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
            XdsWorkload {
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::Tcp,
                destination: "1.2.3.4:80",
                gateway: "1.2.3.4:80",
                request_type: RequestType::Passthrough,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Direct as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::Tcp,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:80",
                request_type: RequestType::Direct,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Http as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::Hbone,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:15008",
                request_type: RequestType::Direct,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Direct as i32,
                node: "local-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::Tcp,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:80",
                request_type: RequestType::Direct,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Http as i32,
                node: "local-node".to_string(),
                ..Default::default()
            },
            Some(ExpectedRequest {
                protocol: Protocol::Hbone,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:15088",
                request_type: RequestType::DirectLocal,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_unknown_source() {
        run_build_request(
            "1.2.3.4",
            "127.0.0.2:80",
            XdsWorkload {
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                ..Default::default()
            },
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request() {
        let cfg = Config {
            local_node: Some("local-node".to_string()),
            ..Default::default()
        };
        let wl = workload::WorkloadStore::test_store(vec![
            XdsWorkload {
                name: "source-workload".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 1]),
                node: "local-node".to_string(),
                ..Default::default()
            },
            XdsWorkload {
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 2]),
                protocol: XdsProtocol::Direct as i32,
                node: "remote-node".to_string(),
                virtual_ips: Default::default(),
                ..Default::default()
            },
            XdsWorkload {
                name: "test-hbone".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 3]),
                protocol: XdsProtocol::Http as i32,
                node: "remote-node".to_string(),
                virtual_ips: Default::default(),
                ..Default::default()
            },
            XdsWorkload {
                name: "test-tcp-local".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 4]),
                protocol: XdsProtocol::Direct as i32,
                node: "local-node".to_string(),
                virtual_ips: Default::default(),
                ..Default::default()
            },
            XdsWorkload {
                name: "test-hbone".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 5]),
                protocol: XdsProtocol::Http as i32,
                node: "local-node".to_string(),
                virtual_ips: Default::default(),
                ..Default::default()
            },
            XdsWorkload {
                name: "test-hbone-vip".to_string(),
                namespace: "ns".to_string(),
                address: Bytes::copy_from_slice(&[127, 0, 0, 6]),
                protocol: XdsProtocol::Http as i32,
                node: "local-node".to_string(),
                virtual_ips: HashMap::from([(
                    "127.0.1.1".to_string(),
                    XdsPortList {
                        ports: vec![XdsPort {
                            service_port: 80,
                            target_port: 8080,
                        }],
                    },
                )]),
                ..Default::default()
            },
        ])
        .unwrap();
        let wi = WorkloadInformation {
            info: Arc::new(Mutex::new(wl)),
            demand: None,
        };
        let outbound = OutboundConnection {
            cert_manager: Box::new(identity::SecretManager::new(cfg.clone())),
            workloads: wi,
            hbone_port: 15008,
            cfg,
        };

        compare(
            &outbound,
            "127.0.0.1",
            "1.2.3.4:80",
            false,
            ExpectedRequest {
                protocol: Protocol::Tcp,
                destination: "1.2.3.4:80",
                gateway: "1.2.3.4:80",
                request_type: RequestType::Passthrough,
            },
            "unknown dest",
        )
        .await;

        compare(
            &outbound,
            "127.0.0.1",
            "127.0.0.2:80",
            false,
            ExpectedRequest {
                protocol: Protocol::Tcp,
                destination: "127.0.0.2:80",
                gateway: "127.0.0.2:80",
                request_type: RequestType::Direct,
            },
            "known dest, remote node, TCP",
        )
        .await;

        compare(
            &outbound,
            "127.0.0.1",
            "127.0.0.3:80",
            false,
            ExpectedRequest {
                protocol: Protocol::Hbone,
                destination: "127.0.0.3:80",
                gateway: "127.0.0.3:15008",
                request_type: RequestType::Direct,
            },
            "known dest, remote node, HBONE",
        )
        .await;

        compare(
            &outbound,
            "127.0.0.1",
            "127.0.0.4:80",
            false,
            ExpectedRequest {
                protocol: Protocol::Tcp,
                destination: "127.0.0.4:80",
                gateway: "127.0.0.4:80",
                request_type: RequestType::Direct,
            },
            "known dest, local node, TCP",
        )
        .await;

        compare(
            &outbound,
            "127.0.0.1",
            "127.0.0.5:80",
            false,
            ExpectedRequest {
                protocol: Protocol::Hbone,
                destination: "127.0.0.5:80",
                gateway: "127.0.0.5:15088",
                request_type: RequestType::DirectLocal,
            },
            "known dest, local node, HBONE",
        )
        .await;

        compare(
            &outbound,
            "127.0.0.1",
            "127.0.1.1:80",
            false,
            ExpectedRequest {
                protocol: Protocol::Hbone,
                destination: "127.0.0.6:8080",
                gateway: "127.0.0.6:15088",
                request_type: RequestType::DirectLocal,
            },
            "known dest, local node, HBONE",
        )
        .await;

        // build_request fails
        compare(
            &outbound,
            "127.0.1.1",
            "127.0.0.5:80",
            true,
            ExpectedRequest {
                protocol: Protocol::Hbone,
                destination: "127.0.0.5:80",
                gateway: "127.0.0.5:15088",
                request_type: RequestType::DirectLocal,
            },
            "known dest, local node, HBONE",
        )
        .await;
    }

    #[derive(PartialEq, Debug)]
    struct ExpectedRequest<'a> {
        protocol: Protocol,
        destination: &'a str,
        gateway: &'a str,
        request_type: RequestType,
    }

    async fn compare(
        outbound: &OutboundConnection,
        downstream: &str,
        to: &str,
        expect_err: bool,
        exp: ExpectedRequest<'_>,
        name: &str,
    ) {
        let req = outbound
            .build_request(downstream.parse().unwrap(), to.parse().unwrap())
            .await;
        if let Ok(req) = req {
            let req = ExpectedRequest {
                protocol: req.protocol,
                destination: &req.destination.to_string(),
                gateway: &req.gateway.to_string(),
                request_type: req.request_type,
            };
            assert_eq!(exp, req, "{}", name);
        } else {
            assert!(expect_err)
        }
    }
}
