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

use std::collections::HashSet;
use std::fmt::Debug;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use drain::Watch;

use rand::Rng;

use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;
use tracing::{error, trace, warn, Instrument};

use inbound::Inbound;
pub use metrics::*;

use crate::identity::{Identity, SecretManager};

use crate::proxy::connection_manager::{ConnectionManager, PolicyWatcher};
use crate::proxy::inbound_passthrough::InboundPassthrough;
use crate::proxy::outbound::Outbound;
use crate::proxy::socks5::Socks5;
use crate::rbac::Connection;
use crate::state::service::{endpoint_uid, Service, ServiceDescription};
use crate::state::workload::address::Address;
use crate::state::workload::{network_addr, GatewayAddress, Workload};
use crate::state::{DemandProxyState, WorkloadInfo};
use crate::{config, identity, socket, tls};

pub mod connection_manager;
pub mod h2_client;
mod inbound;
mod inbound_passthrough;
#[allow(non_camel_case_types)]
pub mod metrics;
mod outbound;
pub mod pool;
mod socks5;
mod util;

pub trait SocketFactory {
    fn new_tcp_v4(&self) -> std::io::Result<TcpSocket>;

    fn new_tcp_v6(&self) -> std::io::Result<TcpSocket>;

    fn tcp_bind(&self, addr: SocketAddr) -> std::io::Result<TcpListener>;

    fn udp_bind(&self, addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket>;
}

#[derive(Clone, Copy, Default)]
pub struct DefaultSocketFactory;

impl SocketFactory for DefaultSocketFactory {
    fn new_tcp_v4(&self) -> std::io::Result<TcpSocket> {
        TcpSocket::new_v4()
    }

    fn new_tcp_v6(&self) -> std::io::Result<TcpSocket> {
        TcpSocket::new_v6()
    }

    fn tcp_bind(&self, addr: SocketAddr) -> std::io::Result<TcpListener> {
        let std_sock = std::net::TcpListener::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        TcpListener::from_std(std_sock)
    }

    fn udp_bind(&self, addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std_sock)
    }
}

pub struct Proxy {
    inbound: Inbound,
    inbound_passthrough: InboundPassthrough,
    outbound: Outbound,
    socks5: Option<Socks5>,
    policy_watcher: PolicyWatcher,
    illegal_ports: Arc<HashSet<u16>>,
}

#[derive(Clone)]
pub(super) struct ProxyInputs {
    cfg: Arc<config::Config>,
    cert_manager: Arc<SecretManager>,
    connection_manager: ConnectionManager,
    hbone_port: u16,
    pub state: DemandProxyState,
    metrics: Arc<Metrics>,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    proxy_workload_info: Option<Arc<WorkloadInfo>>,
}

#[allow(clippy::too_many_arguments)]
impl ProxyInputs {
    pub fn new(
        cfg: Arc<config::Config>,
        cert_manager: Arc<SecretManager>,
        connection_manager: ConnectionManager,
        state: DemandProxyState,
        metrics: Arc<Metrics>,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        proxy_workload_info: Option<WorkloadInfo>,
    ) -> Self {
        Self {
            cfg,
            state,
            cert_manager,
            metrics,
            connection_manager,
            hbone_port: 0,
            socket_factory,
            proxy_workload_info: proxy_workload_info.map(Arc::new),
        }
    }
}

impl Proxy {
    pub async fn new(
        cfg: Arc<config::Config>,
        state: DemandProxyState,
        cert_manager: Arc<SecretManager>,
        metrics: Metrics,
        drain: Watch,
    ) -> Result<Proxy, Error> {
        let metrics = Arc::new(metrics);
        let socket_factory = Arc::new(DefaultSocketFactory);

        let pi = ProxyInputs {
            cfg,
            state,
            cert_manager,
            connection_manager: ConnectionManager::default(),
            metrics,
            hbone_port: 0,
            socket_factory,
            proxy_workload_info: None,
        };
        Self::from_inputs(pi, drain).await
    }
    pub(super) async fn from_inputs(mut pi: ProxyInputs, drain: Watch) -> Result<Self, Error> {
        // illegal_ports are internal ports that clients are not authorized to send to
        let mut illegal_ports: HashSet<u16> = HashSet::new();
        // We setup all the listeners first so we can capture any errors that should block startup
        let inbound = Inbound::new(pi.clone(), drain.clone()).await?;
        pi.hbone_port = inbound.address().port();
        //  HBONE doesn't have redirection, so we cannot have loops, but this would allow multiple layers of HBONE.
        // This might be desirable in the future, but for now just ban it.
        illegal_ports.insert(inbound.address().port());

        let inbound_passthrough = InboundPassthrough::new(pi.clone(), drain.clone()).await?;
        illegal_ports.insert(inbound_passthrough.address().port());
        let outbound = Outbound::new(pi.clone(), drain.clone()).await?;
        illegal_ports.insert(outbound.address().port());
        let socks5 = if pi.cfg.socks5_addr.is_some() {
            let socks5 = Socks5::new(pi.clone(), drain.clone()).await?;
            illegal_ports.insert(socks5.address().port());
            Some(socks5)
        } else {
            None
        };
        let policy_watcher = PolicyWatcher::new(pi.state, drain, pi.connection_manager);

        Ok(Proxy {
            inbound,
            inbound_passthrough,
            outbound,
            socks5,
            policy_watcher,
            illegal_ports: Arc::new(illegal_ports),
        })
    }

    pub async fn run(self) {
        let mut tasks = vec![
            tokio::spawn(
                self.inbound_passthrough
                    .run(self.illegal_ports.clone())
                    .in_current_span(),
            ),
            tokio::spawn(
                self.inbound
                    .run(self.illegal_ports.clone())
                    .in_current_span(),
            ),
            tokio::spawn(self.outbound.run().in_current_span()),
            tokio::spawn(self.policy_watcher.run().in_current_span()),
        ];
        if let Some(socks5) = self.socks5 {
            tasks.push(tokio::spawn(socks5.run().in_current_span()));
        }

        futures::future::join_all(tasks).await;
    }

    pub fn addresses(&self) -> Addresses {
        Addresses {
            outbound: self.outbound.address(),
            inbound: self.inbound.address(),
            socks5: self.socks5.as_ref().map(|s| s.address()),
        }
    }
}

#[derive(Copy, Clone)]
pub struct Addresses {
    pub outbound: SocketAddr,
    pub inbound: SocketAddr,
    pub socks5: Option<SocketAddr>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to bind to address {0}: {1}")]
    Bind(SocketAddr, io::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("connection failed: {0}")]
    ConnectionFailed(io::Error),

    #[error("connection closed due to policy change")]
    AuthorizationPolicyLateRejection,

    #[error("connection closed due to policy rejection")]
    AuthorizationPolicyRejection,

    #[error("pool is already connecting")]
    WorkloadHBONEPoolAlreadyConnecting,

    #[error("connection streams maxed out")]
    WorkloadHBONEPoolConnStreamsMaxed,

    #[error("pool draining")]
    WorkloadHBONEPoolDraining,

    #[error("{0}")]
    Generic(Box<dyn std::error::Error + Send + Sync>),

    #[error("http handshake failed: {0}")]
    HttpHandshake(#[source] hyper::Error),

    #[error("http2 handshake failed: {0}")]
    Http2Handshake(#[source] h2::Error),

    #[error("http failed: {0}")]
    Http(#[from] hyper::Error),

    #[error("h2 failed: {0}")]
    H2(#[from] h2::Error),

    #[error("no upgrade available: {0}")]
    NoUpgrade(hyper::Error),

    #[error("http status: {0}")]
    HttpStatus(hyper::StatusCode),

    #[error("expected method CONNECT, got {0}")]
    NonConnectMethod(String),

    #[error("invalid CONNECT address {0}")]
    ConnectAddress(String),

    #[error("tls error: {0}")]
    Tls(#[from] tls::Error),

    #[error("identity error: {0}")]
    Identity(#[from] identity::Error),

    #[error("unknown source: {0}")]
    UnknownSource(IpAddr),

    #[error("invalid source: {0}, should match {1:?}")]
    MismatchedSource(IpAddr, Arc<WorkloadInfo>),

    #[error("unknown waypoint: {0}")]
    UnknownWaypoint(String),

    #[error("unknown destination: {0}")]
    UnknownDestination(IpAddr),

    #[error("no valid routing destination for workload: {0}")]
    NoValidDestination(Box<Workload>),

    #[error("no ip addresses were resolved for workload: {0}")]
    NoResolvedAddresses(String),

    #[error(
        "ip addresses were resolved for workload {0}, but valid dns response had no A/AAAA records"
    )]
    EmptyResolvedAddresses(String),

    #[error("attempted recursive call to ourselves")]
    SelfCall,

    #[error("no gateway address: {0}")]
    NoGatewayAddress(Box<Workload>),

    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),

    #[error("ip mismatch: {0} != {1}")]
    IPMismatch(IpAddr, IpAddr),

    #[error("bug: connection seen twice")]
    DoubleConnection,
}

const PROXY_PROTOCOL_AUTHORITY_TLV: u8 = 0xD0;

pub async fn write_proxy_protocol<T>(
    stream: &mut TcpStream,
    addresses: T,
    src_id: Option<Identity>,
) -> io::Result<()>
where
    T: Into<ppp::v2::Addresses>,
{
    use ppp::v2::{Builder, Command, Protocol, Version};
    use tokio::io::AsyncWriteExt;

    let mut builder =
        Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Stream, addresses);

    if let Some(id) = src_id {
        builder = builder.write_tlv(PROXY_PROTOCOL_AUTHORITY_TLV, id.to_string().as_bytes())?;
    }

    let header = builder.build()?;
    stream.write_all(&header).await
}

/// Represents a traceparent, as defined by https://www.w3.org/TR/trace-context/
#[derive(Eq, PartialEq)]
pub struct TraceParent {
    version: u8,
    trace_id: u128,
    parent_id: u64,
    flags: u8,
}

pub const BAGGAGE_HEADER: &str = "baggage";
pub const TRACEPARENT_HEADER: &str = "traceparent";

impl TraceParent {
    pub fn header(&self) -> hyper::header::HeaderValue {
        hyper::header::HeaderValue::from_bytes(format!("{self:?}").as_bytes()).unwrap()
    }
}
impl TraceParent {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            version: 0,
            trace_id: rng.gen(),
            parent_id: rng.gen(),
            flags: 0,
        }
    }
}

impl fmt::Debug for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}-{:032x}-{:016x}-{:02x}",
            self.version, self.trace_id, self.parent_id, self.flags
        )
    }
}

impl fmt::Display for TraceParent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:032x}", self.trace_id,)
    }
}

impl TryFrom<&str> for TraceParent {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() != 55 {
            anyhow::bail!("traceparent malformed length was {}", value.len())
        }

        let segs: Vec<&str> = value.split('-').collect();

        Ok(Self {
            version: u8::from_str_radix(segs[0], 16)?,
            trace_id: u128::from_str_radix(segs[1], 16)?,
            parent_id: u64::from_str_radix(segs[2], 16)?,
            flags: u8::from_str_radix(segs[3], 16)?,
        })
    }
}

pub(super) fn maybe_set_transparent(
    pi: &ProxyInputs,
    listener: &TcpListener,
) -> Result<bool, Error> {
    Ok(match pi.cfg.enable_original_source {
        Some(true) => {
            // Explicitly enabled. Return error if we cannot set it.
            socket::set_transparent(listener)?;
            true
        }
        Some(false) => {
            // Explicitly disabled, don't even attempt to set it.
            false
        }
        None => {
            // Best effort
            socket::set_transparent(listener).is_ok()
        }
    })
}

pub fn get_original_src_from_stream(stream: &TcpStream) -> Option<IpAddr> {
    stream
        .peer_addr()
        .map_or(None, |sa| Some(socket::to_canonical(sa).ip()))
}

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn freebind_connect(
    local: Option<IpAddr>,
    addr: SocketAddr,
    socket_factory: &(dyn SocketFactory + Send + Sync),
) -> io::Result<TcpStream> {
    async fn connect(
        local: Option<IpAddr>,
        addr: SocketAddr,
        socket_factory: &(dyn SocketFactory + Send + Sync),
    ) -> io::Result<TcpStream> {
        let create_socket = |is_ipv4: bool| {
            if is_ipv4 {
                socket_factory.new_tcp_v4()
            } else {
                socket_factory.new_tcp_v6()
            }
        };

        // we don't need original src with inpod outbound mode.
        // we do need it in inbound and inbound passthrough TODO: refactor so this is derived from config
        // local = None; // commented out for now as we only want to disable this in inpod + outbound mode

        match local {
            None => {
                let socket = create_socket(addr.is_ipv4())?;
                trace!(dest=%addr, "no local address, connect directly");
                Ok(socket.connect(addr).await?)
            }
            // TODO: Need figure out how to handle case of loadbalancing to itself.
            //       We use ztunnel addr instead, otherwise app side will be confused.
            Some(src) if src == socket::to_canonical(addr).ip() => {
                let socket = create_socket(addr.is_ipv4())?;
                trace!(%src, dest=%addr, "dest and source are the same, connect directly");
                Ok(socket.connect(addr).await?)
            }
            Some(src) => {
                let socket = create_socket(src.is_ipv4())?;
                let local_addr = SocketAddr::new(src, 0);
                match socket::set_freebind_and_transparent(&socket) {
                    Err(err) => warn!("failed to set freebind: {:?}", err),
                    _ => {
                        if let Err(err) = socket.bind(local_addr) {
                            warn!("failed to bind local addr: {:?}", err)
                        }
                    }
                };
                trace!(%src, dest=%addr, "connect with source IP");
                Ok(socket.connect(addr).await?)
            }
        }
    }
    // Wrap the entire connect function in a timeout
    timeout(CONNECTION_TIMEOUT, connect(local, addr, socket_factory))
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?
}

// guess_inbound_service selects an upstream service for inbound metrics.
// There may be many services for a single workload. We find the the first one with an applicable port
// as a best guess.
pub fn guess_inbound_service(
    conn: &Connection,
    for_host_header: &Option<String>,
    upstream_service: Vec<Arc<Service>>,
    dest: &Workload,
) -> Option<ServiceDescription> {
    // First, if the client told us what Service they were reaching, look for that
    // Note: the set of Services we look for is bounded, so we won't blindly trust bogus info.
    if let Some(found) = upstream_service
        .iter()
        .find(|s| for_host_header.as_deref() == Some(s.hostname.as_ref()))
        .map(|s| ServiceDescription::from(s.as_ref()))
    {
        return Some(found);
    }
    let dport = conn.dst.port();
    let netaddr = network_addr(&dest.network, conn.dst.ip());
    let euid = endpoint_uid(&dest.uid, Some(&netaddr));
    upstream_service
        .iter()
        .find(|s| {
            for (sport, tport) in s.ports.iter() {
                if tport == &dport {
                    // TargetPort directly matches
                    return true;
                }
                // The service itself didn't have a explicit TargetPort match, but an endpoint might.
                // This happens when there is a named port (in Kubernetes, anyways).
                if s.endpoints.get(&euid).and_then(|e| e.port.get(sport)) == Some(&dport) {
                    // Named port matched
                    return true;
                }
                // no match
            }
            false
        })
        .map(|s| ServiceDescription::from(s.as_ref()))
}

// Checks that the source identiy and address match the upstream's waypoint
async fn check_from_waypoint(
    state: &DemandProxyState,
    upstream: &Workload,
    src_identity: Option<&Identity>,
    src_ip: &IpAddr,
) -> bool {
    let is_waypoint = |wl: &Workload| {
        Some(wl.identity()).as_ref() == src_identity && wl.workload_ips.contains(src_ip)
    };
    check_gateway_address(state, upstream.waypoint.as_ref(), is_waypoint).await
}

// Checks if the connection's source identity is the identity for the upstream's network
// gateway
async fn check_from_network_gateway(
    state: &DemandProxyState,
    upstream: &Workload,
    src_identity: Option<&Identity>,
) -> bool {
    let is_gateway = |wl: &Workload| Some(wl.identity()).as_ref() == src_identity;
    check_gateway_address(state, upstream.network_gateway.as_ref(), is_gateway).await
}

// Check if the source's identity matches any workloads that make up the given gateway
// TODO: This can be made more accurate by also checking addresses.
async fn check_gateway_address<F>(
    state: &DemandProxyState,
    gateway_address: Option<&GatewayAddress>,
    predicate: F,
) -> bool
where
    F: Fn(&Workload) -> bool,
{
    let Some(gateway_address) = gateway_address else {
        return false;
    };

    match state.fetch_destination(&gateway_address.destination).await {
        Some(Address::Workload(wl)) => return predicate(&wl),
        Some(Address::Service(svc)) => {
            for (_ep_uid, ep) in svc.endpoints.iter() {
                // fetch workloads by workload UID since we may not have an IP for an endpoint (e.g., endpoint is just a hostname)
                let wl = state.fetch_workload_by_uid(&ep.workload_uid).await;
                if wl.as_ref().is_some_and(&predicate) {
                    return true;
                }
            }
        }
        None => {}
    };

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    use crate::state::service::endpoint_uid;
    use crate::state::workload::{NamespacedHostname, NetworkAddress};
    use crate::{
        identity::Identity,
        state::{
            self,
            service::{Endpoint, Service},
            workload::gatewayaddress::Destination,
        },
    };
    use std::{collections::HashMap, net::Ipv4Addr, sync::RwLock};

    #[tokio::test]
    async fn check_gateway() {
        let w = mock_default_gateway_workload();
        let s = mock_default_gateway_service();
        let mut state = state::ProxyState::default();
        state.workloads.insert(w);
        state.services.insert(s);
        let state = state::DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );

        let gateawy_id = Identity::Spiffe {
            trust_domain: "cluster.local".to_string(),
            namespace: "gatewayns".to_string(),
            service_account: "default".to_string(),
        };
        let from_gw_conn = Some(gateawy_id);
        let not_from_gw_conn = Some(Identity::default());

        let upstream_with_address = mock_wokload_with_gateway(Some(mock_default_gateway_address()));
        assert!(
            check_from_network_gateway(&state, &upstream_with_address, from_gw_conn.as_ref(),)
                .await
        );
        assert!(
            !check_from_network_gateway(&state, &upstream_with_address, not_from_gw_conn.as_ref(),)
                .await
        );

        // using hostname (will check the service variant of address::Address)
        let upstream_with_hostname =
            mock_wokload_with_gateway(Some(mock_default_gateway_hostname()));
        assert!(
            check_from_network_gateway(&state, &upstream_with_hostname, from_gw_conn.as_ref(),)
                .await
        );
        assert!(
            !check_from_network_gateway(&state, &upstream_with_hostname, not_from_gw_conn.as_ref())
                .await
        );
    }

    // private helpers
    fn mock_wokload_with_gateway(gw: Option<GatewayAddress>) -> Workload {
        Workload {
            workload_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            waypoint: None,
            network_gateway: gw,
            gateway_address: None,
            protocol: Default::default(),
            uid: "".to_string(),
            name: "app".to_string(),
            namespace: "appns".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            network: "".to_string(),
            workload_name: "app".to_string(),
            workload_type: "deployment".to_string(),
            canonical_name: "app".to_string(),
            canonical_revision: "".to_string(),
            hostname: "".to_string(),
            node: "".to_string(),
            status: Default::default(),
            cluster_id: "Kubernetes".to_string(),

            authorization_policies: Vec::new(),
            native_tunnel: false,
            application_tunnel: None,
            locality: Default::default(),
        }
    }

    fn mock_default_gateway_workload() -> Workload {
        Workload {
            workload_ips: vec![IpAddr::V4(mock_default_gateway_ipaddr())],
            waypoint: None,
            network_gateway: None,
            gateway_address: None,
            protocol: Default::default(),
            uid: "".to_string(),
            name: "gateway".to_string(),
            namespace: "gatewayns".to_string(),
            trust_domain: "cluster.local".to_string(),
            service_account: "default".to_string(),
            network: "".to_string(),
            workload_name: "gateway".to_string(),
            workload_type: "deployment".to_string(),
            canonical_name: "".to_string(),
            canonical_revision: "".to_string(),
            hostname: "".to_string(),
            node: "".to_string(),
            status: Default::default(),
            cluster_id: "Kubernetes".to_string(),

            authorization_policies: Vec::new(),
            native_tunnel: false,
            application_tunnel: None,
            locality: Default::default(),
        }
    }

    fn mock_default_gateway_service() -> Service {
        let vip1 = NetworkAddress {
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 10, 1)),
            network: "".to_string(),
        };
        let vips = vec![vip1];
        let mut ports = HashMap::new();
        ports.insert(8080, 80);
        let mut endpoints = HashMap::new();
        let addr = Some(NetworkAddress {
            network: "".to_string(),
            address: IpAddr::V4(mock_default_gateway_ipaddr()),
        });
        endpoints.insert(
            endpoint_uid(&mock_default_gateway_workload().uid, addr.as_ref()),
            Endpoint {
                workload_uid: mock_default_gateway_workload().uid,
                service: NamespacedHostname {
                    namespace: "gatewayns".to_string(),
                    hostname: "gateway".to_string(),
                },
                address: addr,
                port: ports.clone(),
            },
        );
        Service {
            name: "gateway".to_string(),
            namespace: "gatewayns".to_string(),
            hostname: "gateway".to_string(),
            vips,
            ports,
            endpoints,
            subject_alt_names: vec![],
            waypoint: None,
            load_balancer: None,
        }
    }

    fn mock_default_gateway_address() -> GatewayAddress {
        GatewayAddress {
            destination: Destination::Address(NetworkAddress {
                network: "".to_string(),
                address: IpAddr::V4(mock_default_gateway_ipaddr()),
            }),
            hbone_mtls_port: 15008,
            hbone_single_tls_port: Some(15003),
        }
    }

    fn mock_default_gateway_hostname() -> GatewayAddress {
        GatewayAddress {
            destination: Destination::Hostname(state::workload::NamespacedHostname {
                namespace: "gatewayns".to_string(),
                hostname: "gateway".to_string(),
            }),
            hbone_mtls_port: 15008,
            hbone_single_tls_port: Some(15003),
        }
    }

    fn mock_default_gateway_ipaddr() -> Ipv4Addr {
        Ipv4Addr::new(127, 0, 0, 100)
    }
}
