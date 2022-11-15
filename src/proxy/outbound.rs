use std::net::{IpAddr, SocketAddr};

use boring::ssl::ConnectConfiguration;
use drain::Watch;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::config::Config;
use crate::proxy::Error;
use crate::workload::{Protocol, Workload, WorkloadInformation};
use crate::{identity, socket};

pub struct Outbound {
    cfg: Config,
    cert_manager: identity::SecretManager,
    workloads: WorkloadInformation,
    listener: TcpListener,
    drain: Watch,
}

impl Outbound {
    pub async fn new(
        cfg: Config,
        cert_manager: identity::SecretManager,
        workloads: WorkloadInformation,
        drain: Watch,
    ) -> Result<Outbound, Error> {
        let listener: TcpListener = TcpListener::bind(cfg.outbound_addr)
            .await
            .map_err(Error::Bind)?;
        match socket::set_transparent(&listener) {
            Err(_e) => info!("running without transparent mode"),
            _ => info!("running with transparent mode"),
        };

        Ok(Outbound {
            cfg,
            cert_manager,
            workloads,
            listener,
            drain,
        })
    }

    pub(super) async fn run(self) {
        let addr = self.listener.local_addr().unwrap();
        info!("outbound listener established {}", addr);

        let accept = async move {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                match socket {
                    Ok((stream, remote)) => {
                        info!("accepted outbound connection from {}", remote);
                        let cfg = self.cfg.clone();
                        let oc = OutboundConnection {
                            cert_manager: self.cert_manager.clone(),
                            workloads: self.workloads.clone(),
                            cfg,
                        };
                        tokio::spawn(async move {
                            let res = oc.proxy(stream).await;
                            match res {
                                Ok(_) => info!("outbound proxy complete"),
                                Err(ref e) => warn!("outbound proxy failed: {}", e),
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

struct OutboundConnection {
    cert_manager: identity::SecretManager,
    workloads: WorkloadInformation,
    // TODO: Config may be excessively large, maybe we store a scoped OutboundConfig intended for cloning.
    cfg: Config,
}

impl OutboundConnection {
    async fn proxy(&self, mut stream: TcpStream) -> Result<(), Error> {
        let remote_addr =
            super::to_canonical_ip(stream.peer_addr().expect("must receive peer addr"));
        let orig = socket::orig_dst_addr(&stream).expect("must have original dst enabled");
        let req = self.build_request(remote_addr, orig).await;
        debug!("request from {} to {}", req.source.name, orig);
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
                    let id = req.source.identity();
                    let cert = self.cert_manager.fetch_certificate(id).await?;
                    let connector = cert.connector()?.configure()?;
                    let tcp_stream = TcpStream::connect(req.gateway).await?;
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
                let mut outbound = TcpStream::connect(req.gateway).await?;

                let (mut ri, mut wi) = stream.split();
                let (mut ro, mut wo) = outbound.split();

                let client_to_server = async {
                    tokio::io::copy(&mut ri, &mut wo).await?;
                    wo.shutdown().await
                };

                let server_to_client = async {
                    tokio::io::copy(&mut ro, &mut wi).await?;
                    wi.shutdown().await
                };

                tokio::try_join!(client_to_server, server_to_client)?;

                Ok(())
            }
        }
    }

    async fn build_request(&self, downstream: IpAddr, target: SocketAddr) -> Request {
        let (source_workload, waypoint_address, us, is_vip) = {
            let source_workload = self
                .workloads
                .fetch_workload(&downstream)
                .await
                .expect("todo: source must be found");

            let waypoint_address = source_workload.waypoint_address;

            // TODO: we want a single lock for source and upstream probably...?
            let (us, is_vip) = self.workloads.find_upstream(target).await;
            (source_workload, waypoint_address, us, is_vip)
        };
        let mut req = Request {
            protocol: us.workload.protocol,
            source: source_workload,
            destination: SocketAddr::from((us.workload.workload_ip, us.port)),
            gateway: us
                .workload
                .gateway_ip
                .expect("todo: refactor gateway ip handling"),
            direction: Direction::Outbound, // TODO set this
            request_type: RequestType::Direct,
        };
        if waypoint_address.is_some() {
            // Source has a remote proxy. We should delegate everything to that proxy - do not even resolve VIP.
            // TODO: add client skipping
            req.request_type = RequestType::ToClientWaypoint;
            // Let the client remote know we are on the outbound path. The remote proxy should strictly
            // validate the identity when we declare this
            req.direction = Direction::Outbound;
            // Load balancing decision is deferred to remote proxy
            req.destination = target;
            // Send to the remote proxy
            req.gateway = SocketAddr::from((waypoint_address.unwrap(), 15001));
            // Always use HBONE here
            req.protocol = Protocol::Hbone;
        } else if us.workload.waypoint_address.is_some() {
            // TODO: even in this case, we are picking a single upstream pod and deciding if it has a remote proxy.
            // Typically this is all or nothing, but if not we should probably send to remote proxy if *any* upstream has one.
            if is_vip {
                // Use the original VIP, not translated
                req.destination = target
            }
            req.request_type = RequestType::ToServerWaypoint;
            // Always use HBONE here
            req.protocol = Protocol::Hbone;
            // Let the client remote know we are on the inbound path.
            req.direction = Direction::Inbound;
            req.gateway = SocketAddr::from((us.workload.waypoint_address.unwrap(), 15006));
        } else if !us.workload.node.is_empty()
            && self.cfg.local_node == Some(us.workload.node)
            && req.protocol == Protocol::Hbone
        {
            // Sending to a node on the same node (ourselves).
            // In the future this could be optimized to avoid a full network traversal.
            req.request_type = RequestType::DirectLocal;
            // We would want to send to 127.0.0.1:15008 in theory. However, the inbound listener
            // expects to lookup the desired certificate based on the destination IP. If we send directly,
            // we would try to lookup an IP for 127.0.0.1.
            // Instead, we send to the actual IP, but iptables in the pod ensures traffic is redirected to 15008.
            req.gateway = SocketAddr::from((req.gateway.ip(), 15088));
        } else if us.workload.name.is_empty() {
            req.request_type = RequestType::Passthrough;
        } else {
            req.request_type = RequestType::Direct;
        }
        req
    }
}

fn baggage(r: &Request) -> String {
    format!("k8s.cluster.name={cluster},k8s.namespace.name={namespace},k8s.{workload_type}.name={workload_name},service.name={name},service.version={version}",
        cluster="Kubernetes",// todo
        namespace=r.source.namespace,
        workload_type=r.source.workload_type,
        workload_name=r.source.workload_name,
        name=r.source.canonical_name,
        version=r.source.canonical_revision,
    )
}

#[derive(Debug)]
struct Request {
    protocol: Protocol,
    direction: Direction,
    source: Workload,
    destination: SocketAddr,
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
    ToClientWaypoint,
    ToServerWaypoint,
    Direct,
    DirectLocal,
    Passthrough,
}

async fn connect_tls(
    mut connector: ConnectConfiguration,
    stream: TcpStream,
) -> Result<tokio_boring::SslStream<TcpStream>, tokio_boring::HandshakeError<TcpStream>> {
    connector.set_verify_hostname(false);
    connector.set_use_server_name_indication(false);
    let addr = stream.local_addr();
    connector.set_verify_callback(boring::ssl::SslVerifyMode::PEER, move |_, x509| {
        info!("TLS callback for {:?}: {:?}", addr, x509.error());
        true
    });
    tokio_boring::connect(connector, "", stream).await
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bytes::Bytes;

    use crate::workload;
    use crate::xds::istio::workload::Protocol as XdsProtocol;
    use crate::xds::istio::workload::Workload as XdsWorkload;

    use super::*;

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
        ])
        .unwrap();
        let wi = WorkloadInformation {
            info: Arc::new(Mutex::new(wl)),
            demand: None,
        };
        let outbound = OutboundConnection {
            cert_manager: identity::SecretManager::new(cfg.clone()),
            workloads: wi,
            cfg,
        };

        compare(
            &outbound,
            "1.2.3.4:80",
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
            "127.0.0.2:80",
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
            "127.0.0.3:80",
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
            "127.0.0.4:80",
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
            "127.0.0.5:80",
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
        to: &str,
        exp: ExpectedRequest<'_>,
        name: &str,
    ) {
        let req = outbound
            .build_request("127.0.0.1".parse().unwrap(), to.parse().unwrap())
            .await;
        let req = ExpectedRequest {
            protocol: req.protocol,
            destination: &req.destination.to_string(),
            gateway: &req.gateway.to_string(),
            request_type: req.request_type,
        };
        assert_eq!(exp, req, "{}", name);
    }
}
