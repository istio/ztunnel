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

use std::fmt::Debug;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, io};

use hickory_proto::error::ProtoError;

use crate::strng::Strng;
use rand::Rng;
use socket2::TcpKeepalive;
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::time::timeout;
use tracing::{debug, trace, warn, Instrument};

use inbound::Inbound;
pub use metrics::*;

use crate::identity::{Identity, SecretManager};

use crate::dns::resolver::Resolver;
use crate::drain::DrainWatcher;
use crate::proxy::connection_manager::{ConnectionManager, PolicyWatcher};
use crate::proxy::inbound_passthrough::InboundPassthrough;
use crate::proxy::outbound::Outbound;
use crate::proxy::socks5::Socks5;
use crate::rbac::Connection;
use crate::state::service::{Service, ServiceDescription};
use crate::state::workload::address::Address;
use crate::state::workload::{GatewayAddress, Workload};
use crate::state::{DemandProxyState, WorkloadInfo};
use crate::{config, identity, socket, tls};

pub mod connection_manager;
mod h2;
mod inbound;
mod inbound_passthrough;
#[allow(non_camel_case_types)]
pub mod metrics;
mod outbound;
pub mod pool;
mod socks5;
pub mod util;

pub trait SocketFactory {
    fn new_tcp_v4(&self) -> std::io::Result<TcpSocket>;

    fn new_tcp_v6(&self) -> std::io::Result<TcpSocket>;

    fn tcp_bind(&self, addr: SocketAddr) -> std::io::Result<socket::Listener>;

    fn udp_bind(&self, addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket>;

    fn ipv6_enabled_localhost(&self) -> std::io::Result<bool>;
}

#[derive(Clone, Copy, Default)]
pub struct DefaultSocketFactory(pub config::SocketConfig);

impl SocketFactory for DefaultSocketFactory {
    fn new_tcp_v4(&self) -> std::io::Result<TcpSocket> {
        TcpSocket::new_v4().and_then(|s| {
            self.setup_socket(&s)?;
            Ok(s)
        })
    }

    fn new_tcp_v6(&self) -> std::io::Result<TcpSocket> {
        TcpSocket::new_v6().and_then(|s| {
            self.setup_socket(&s)?;
            Ok(s)
        })
    }

    fn tcp_bind(&self, addr: SocketAddr) -> std::io::Result<socket::Listener> {
        let std_sock = std::net::TcpListener::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        TcpListener::from_std(std_sock).map(socket::Listener::new)
    }

    fn udp_bind(&self, addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
        let std_sock = std::net::UdpSocket::bind(addr)?;
        std_sock.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(std_sock)
    }

    fn ipv6_enabled_localhost(&self) -> io::Result<bool> {
        ipv6_enabled_on_localhost()
    }
}

impl DefaultSocketFactory {
    fn setup_socket(&self, s: &TcpSocket) -> io::Result<()> {
        s.set_nodelay(true)?;
        let cfg = self.0;
        if cfg.keepalive_enabled {
            let ka = TcpKeepalive::new()
                .with_time(cfg.keepalive_time)
                .with_retries(cfg.keepalive_retries)
                .with_interval(cfg.keepalive_interval);
            tracing::trace!(
                "set keepalive: {:?}",
                socket2::SockRef::from(&s).set_tcp_keepalive(&ka)
            );
        }
        if cfg.user_timeout_enabled {
            // https://blog.cloudflare.com/when-tcp-sockets-refuse-to-die/
            // TCP_USER_TIMEOUT = TCP_KEEPIDLE + TCP_KEEPINTVL * TCP_KEEPCNT.
            let ut = cfg.keepalive_time + cfg.keepalive_retries * cfg.keepalive_interval;
            tracing::trace!(
                "set user timeout: {:?}",
                socket2::SockRef::from(&s).set_tcp_user_timeout(Some(ut))
            );
        }
        Ok(())
    }
}

pub struct MarkSocketFactory {
    pub inner: DefaultSocketFactory,
    pub mark: u32,
}

impl SocketFactory for MarkSocketFactory {
    fn new_tcp_v4(&self) -> io::Result<TcpSocket> {
        self.inner.new_tcp_v4().and_then(|s| {
            socket::set_mark(&s, self.mark)?;
            Ok(s)
        })
    }

    fn new_tcp_v6(&self) -> io::Result<TcpSocket> {
        self.inner.new_tcp_v6().and_then(|s| {
            socket::set_mark(&s, self.mark)?;
            Ok(s)
        })
    }

    fn tcp_bind(&self, addr: SocketAddr) -> io::Result<socket::Listener> {
        self.inner.tcp_bind(addr)
    }

    fn udp_bind(&self, addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
        self.inner.udp_bind(addr)
    }

    fn ipv6_enabled_localhost(&self) -> io::Result<bool> {
        self.inner.ipv6_enabled_localhost()
    }
}

pub struct Proxy {
    inbound: Inbound,
    inbound_passthrough: InboundPassthrough,
    outbound: Outbound,
    socks5: Option<Socks5>,
    policy_watcher: PolicyWatcher,
}

pub struct LocalWorkloadInformation {
    wi: Arc<WorkloadInfo>,
    state: DemandProxyState,
    // full_cert_manager gives access to the full SecretManager. This MUST only be given restricted
    // access to the appropriate certificates
    full_cert_manager: Arc<SecretManager>,
}

impl LocalWorkloadInformation {
    pub fn new(
        wi: Arc<WorkloadInfo>,
        state: DemandProxyState,
        cert_manager: Arc<SecretManager>,
    ) -> LocalWorkloadInformation {
        LocalWorkloadInformation {
            wi,
            state,
            full_cert_manager: cert_manager,
        }
    }

    pub async fn get_workload(&self) -> Result<Arc<Workload>, Error> {
        get_workload(&self.state, self.wi.clone()).await
    }

    pub async fn fetch_certificate(
        &self,
    ) -> Result<Arc<tls::WorkloadCertificate>, identity::Error> {
        // We don't know the trust domain until we get the workload from XDS, so fetch that
        let wl = self
            .get_workload()
            .await
            .map_err(|_| identity::Error::UnknownWorkload(self.workload_info()))?;
        let id = &Identity::Spiffe {
            trust_domain: wl.trust_domain.clone(),
            namespace: (&self.wi.namespace).into(),
            service_account: (&self.wi.service_account).into(),
        };
        self.full_cert_manager.fetch_certificate(id).await
    }

    pub fn workload_info(&self) -> Arc<WorkloadInfo> {
        self.wi.clone()
    }

    pub fn as_fetcher(&self) -> Arc<LocalWorkloadFetcher> {
        LocalWorkloadFetcher::new(self.wi.clone(), self.state.clone())
    }
}

/// LocalWorkloadFetcher is essentially LocalWorkloadInformation without CA access.
/// This is used to down-scope the LocalWorkloadInformation for components who should not have access
/// to certificates.
pub struct LocalWorkloadFetcher {
    wi: Arc<WorkloadInfo>,
    state: DemandProxyState,
}

impl LocalWorkloadFetcher {
    pub fn new(wi: Arc<WorkloadInfo>, state: DemandProxyState) -> Arc<Self> {
        Arc::new(LocalWorkloadFetcher { wi, state })
    }
    pub async fn get_workload(&self) -> Result<Arc<Workload>, Error> {
        get_workload(&self.state, self.wi.clone()).await
    }
}

async fn get_workload(
    state: &DemandProxyState,
    wi: Arc<WorkloadInfo>,
) -> Result<Arc<Workload>, Error> {
    state
        .wait_for_workload(&wi, Duration::from_secs(5))
        .await
        .ok_or_else(|| Error::UnknownSourceWorkload(wi.clone()))
}

#[derive(Clone)]
pub(super) struct ProxyInputs {
    cfg: Arc<config::Config>,
    connection_manager: ConnectionManager,
    pub state: DemandProxyState,
    metrics: Arc<Metrics>,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    local_workload_information: Arc<LocalWorkloadInformation>,
    resolver: Option<Arc<dyn Resolver + Send + Sync>>,
}

#[allow(clippy::too_many_arguments)]
impl ProxyInputs {
    pub fn new(
        cfg: Arc<config::Config>,
        connection_manager: ConnectionManager,
        state: DemandProxyState,
        metrics: Arc<Metrics>,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        resolver: Option<Arc<dyn Resolver + Send + Sync>>,
        local_workload_information: Arc<LocalWorkloadInformation>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            state,
            metrics,
            connection_manager,
            socket_factory,
            local_workload_information,
            resolver,
        })
    }
}

impl Proxy {
    #[allow(unused_mut)]
    pub(super) async fn from_inputs(
        mut pi: Arc<ProxyInputs>,
        drain: DrainWatcher,
    ) -> Result<Self, Error> {
        // We setup all the listeners first so we can capture any errors that should block startup
        let inbound = Inbound::new(pi.clone(), drain.clone()).await?;

        // This exists for `direct` integ tests, no other reason
        #[cfg(any(test, feature = "testing"))]
        if pi.cfg.fake_self_inbound {
            warn!("TEST FAKE - overriding inbound address for test");
            let mut old_cfg = (*pi.cfg).clone();
            old_cfg.inbound_addr = inbound.address();
            let mut new_pi = (*pi).clone();
            new_pi.cfg = Arc::new(old_cfg);
            std::mem::swap(&mut pi, &mut Arc::new(new_pi));
            warn!("TEST FAKE: new address is {:?}", pi.cfg.inbound_addr);
        }

        let inbound_passthrough = InboundPassthrough::new(pi.clone(), drain.clone()).await?;
        let outbound = Outbound::new(pi.clone(), drain.clone()).await?;
        let socks5 = if pi.cfg.socks5_addr.is_some() {
            let socks5 = Socks5::new(pi.clone(), drain.clone()).await?;
            Some(socks5)
        } else {
            None
        };
        let policy_watcher =
            PolicyWatcher::new(pi.state.clone(), drain, pi.connection_manager.clone());

        Ok(Proxy {
            inbound,
            inbound_passthrough,
            outbound,
            socks5,
            policy_watcher,
        })
    }

    pub async fn run(self) {
        let mut tasks = vec![
            tokio::spawn(self.inbound_passthrough.run().in_current_span()),
            tokio::spawn(self.policy_watcher.run().in_current_span()),
            tokio::spawn(self.inbound.run().in_current_span()),
            tokio::spawn(self.outbound.run().in_current_span()),
        ];

        if let Some(socks5) = self.socks5 {
            tasks.push(tokio::spawn(socks5.run().in_current_span()));
        };

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

#[derive(Debug, PartialEq, Eq)]
pub enum AuthorizationRejectionError {
    NoWorkload,
    WorkloadMismatch,
    ExplicitlyDenied(Strng, Strng),
    NotAllowed,
}
impl fmt::Display for AuthorizationRejectionError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoWorkload => write!(fmt, "workload not found"),
            Self::WorkloadMismatch => write!(fmt, "workload mismatch"),
            Self::ExplicitlyDenied(a, b) => write!(fmt, "explicitly denied by: {}/{}", a, b),
            Self::NotAllowed => write!(fmt, "allow policies exist, but none allowed"),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to bind to address {0}: {1}")]
    Bind(SocketAddr, io::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("while closing connection: {0}")]
    ShutdownError(Box<Error>),

    #[error("connection timed out, maybe a NetworkPolicy is blocking HBONE port 15008: {0}")]
    MaybeHBONENetworkPolicyError(io::Error),

    #[error("destination disconnected before all data was written")]
    BackendDisconnected,
    #[error("receive: {0}")]
    ReceiveError(Box<Error>),

    #[error("client disconnected before all data was written")]
    ClientDisconnected,
    #[error("send: {0}")]
    SendError(Box<Error>),

    #[error("connection failed: {0}")]
    ConnectionFailed(io::Error),

    #[error("connection tracking failed")]
    ConnectionTrackingFailed,

    #[error("connection closed due to policy change")]
    AuthorizationPolicyLateRejection,

    #[error("connection closed due to policy rejection: {0}")]
    AuthorizationPolicyRejection(AuthorizationRejectionError),

    #[error("pool draining")]
    WorkloadHBONEPoolDraining,

    #[error("{0}")]
    Generic(Box<dyn std::error::Error + Send + Sync>),

    #[error("{0}")]
    Anyhow(anyhow::Error),

    #[error("http2 handshake failed: {0}")]
    Http2Handshake(#[source] ::h2::Error),

    #[error("h2 failed: {0}")]
    H2(#[from] ::h2::Error),

    #[error("http status: {0}")]
    HttpStatus(http::StatusCode),

    #[error("expected method CONNECT, got {0}")]
    NonConnectMethod(String),

    #[error("invalid CONNECT address {0}")]
    ConnectAddress(String),

    #[error("tls error: {0}")]
    Tls(#[from] tls::Error),

    #[error("identity error: {0}")]
    Identity(#[from] identity::Error),

    #[error("failed to fetch information about local workload: {0}")]
    UnknownSourceWorkload(Arc<WorkloadInfo>),

    #[error("unknown waypoint: {0}")]
    UnknownWaypoint(String),

    #[error("no valid routing destination for workload: {0}")]
    NoValidDestination(Box<Workload>),

    #[error("no healthy upstream: {0}")]
    NoHealthyUpstream(SocketAddr),

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

    #[error("connection failed to drain within the timeout")]
    DrainTimeOut,
    #[error("connection closed due to connection drain")]
    ClosedFromDrain,

    #[error("dns: {0}")]
    Dns(#[from] ProtoError),
    #[error("dns lookup: {0}")]
    DnsLookup(#[from] hickory_server::authority::LookupError),
    #[error("dns response had no valid IP addresses")]
    DnsEmpty,
}

// Custom TLV for proxy protocol for the identity of the source
const PROXY_PROTOCOL_AUTHORITY_TLV: u8 = 0xD0;
// Custom TLV for including the svc hostname in the proxy protocol header
const PROXY_PROTOCOL_SVC_HOSTNAME_TLV: u8 = 0xD1;

pub async fn write_proxy_protocol<T>(
    stream: &mut TcpStream,
    addresses: T,
    src_id: Option<Identity>,
    svc_hostname: Option<Strng>,
) -> io::Result<()>
where
    T: Into<ppp::v2::Addresses> + std::fmt::Debug,
{
    use ppp::v2::{Builder, Command, Protocol, Version};
    use tokio::io::AsyncWriteExt;

    // When the hbone_addr populated from the authority header contains a svc hostname, the address included
    // with respect to the hbone_addr is the SocketAddr <dst svc IP>:<original dst port>.
    // This is done since addresses doesn't support hostnames.
    // See ref https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
    debug!("writing proxy protocol addresses: {:?}", addresses);
    let mut builder =
        Builder::with_addresses(Version::Two | Command::Proxy, Protocol::Stream, addresses);

    if let Some(id) = src_id {
        builder = builder.write_tlv(PROXY_PROTOCOL_AUTHORITY_TLV, id.to_string().as_bytes())?;
    }

    // svc_hostname is None when the hbone_addr does not contain a svc hostname.
    if let Some(svc_host) = svc_hostname {
        builder = builder.write_tlv(PROXY_PROTOCOL_SVC_HOSTNAME_TLV, svc_host.as_bytes())?;
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
    listener: &socket::Listener,
) -> Result<bool, Error> {
    Ok(match pi.cfg.require_original_source {
        Some(true) => {
            // Explicitly enabled. Return error if we cannot set it.
            listener.set_transparent()?;
            true
        }
        Some(false) => {
            // Explicitly disabled, don't even attempt to set it.
            false
        }
        None => {
            // Best effort
            listener.set_transparent().is_ok()
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
                if s.endpoints.get(&dest.uid).and_then(|e| e.port.get(sport)) == Some(&dport) {
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
        Some(Address::Workload(wl)) => return predicate(wl.as_ref()),
        Some(Address::Service(svc)) => {
            for ep in svc.endpoints.iter() {
                // fetch workloads by workload UID since we may not have an IP for an endpoint (e.g., endpoint is just a hostname)
                let wl = state.fetch_workload_by_uid(&ep.workload_uid).await;
                if wl.as_ref().is_some_and(|wl| predicate(wl.as_ref())) {
                    return true;
                }
            }
        }
        None => {}
    };

    false
}

const IPV6_DISABLED_LO: &str = "/proc/sys/net/ipv6/conf/lo/disable_ipv6";

fn read_sysctl(key: &str) -> io::Result<String> {
    let mut file = File::open(key)?;
    let mut data = String::new();
    file.read_to_string(&mut data)?;
    Ok(data.trim().to_string())
}

pub fn ipv6_enabled_on_localhost() -> io::Result<bool> {
    read_sysctl(IPV6_DISABLED_LO).map(|s| s != "1")
}

#[cfg(test)]
mod tests {
    use super::*;

    use hickory_resolver::config::{ResolverConfig, ResolverOpts};

    use crate::state::service::EndpointSet;
    use crate::state::workload::NetworkAddress;
    use crate::{
        identity::Identity,
        state::{
            self,
            service::{Endpoint, Service},
            workload::gatewayaddress::Destination,
        },
    };
    use prometheus_client::registry::Registry;
    use std::{collections::HashMap, net::Ipv4Addr, sync::RwLock};

    #[tokio::test]
    async fn check_gateway() {
        let w = mock_default_gateway_workload();
        let s = mock_default_gateway_service();
        let mut state = state::ProxyState::new(None);
        state.workloads.insert(Arc::new(w));
        state.services.insert(s);
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let state = state::DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );

        let gateawy_id = Identity::Spiffe {
            trust_domain: "cluster.local".into(),
            namespace: "gatewayns".into(),
            service_account: "default".into(),
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
            protocol: Default::default(),
            network_mode: Default::default(),
            uid: "".into(),
            name: "app".into(),
            namespace: "appns".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            network: "".into(),
            workload_name: "app".into(),
            workload_type: "deployment".into(),
            canonical_name: "app".into(),
            canonical_revision: "".into(),
            hostname: "".into(),
            node: "".into(),
            status: Default::default(),
            cluster_id: "Kubernetes".into(),

            authorization_policies: Vec::new(),
            native_tunnel: false,
            application_tunnel: None,
            locality: Default::default(),
            services: Default::default(),
        }
    }

    fn mock_default_gateway_workload() -> Workload {
        Workload {
            workload_ips: vec![IpAddr::V4(mock_default_gateway_ipaddr())],
            waypoint: None,
            network_gateway: None,
            protocol: Default::default(),
            network_mode: Default::default(),
            uid: "".into(),
            name: "gateway".into(),
            namespace: "gatewayns".into(),
            trust_domain: "cluster.local".into(),
            service_account: "default".into(),
            network: "".into(),
            workload_name: "gateway".into(),
            workload_type: "deployment".into(),
            canonical_name: "".into(),
            canonical_revision: "".into(),
            hostname: "".into(),
            node: "".into(),
            status: Default::default(),
            cluster_id: "Kubernetes".into(),

            authorization_policies: Vec::new(),
            native_tunnel: false,
            application_tunnel: None,
            locality: Default::default(),
            services: Default::default(),
        }
    }

    fn mock_default_gateway_service() -> Service {
        let vip1 = NetworkAddress {
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 10, 1)),
            network: "".into(),
        };
        let vips = vec![vip1];
        let mut ports = HashMap::new();
        ports.insert(8080, 80);
        let endpoints = EndpointSet::from_list([Endpoint {
            workload_uid: mock_default_gateway_workload().uid,
            port: ports.clone(),
            status: state::workload::HealthStatus::Healthy,
        }]);
        Service {
            name: "gateway".into(),
            namespace: "gatewayns".into(),
            hostname: "gateway".into(),
            vips,
            ports,
            endpoints,
            subject_alt_names: vec![],
            waypoint: None,
            load_balancer: None,
            ip_families: None,
        }
    }

    fn mock_default_gateway_address() -> GatewayAddress {
        GatewayAddress {
            destination: Destination::Address(NetworkAddress {
                network: "".into(),
                address: IpAddr::V4(mock_default_gateway_ipaddr()),
            }),
            hbone_mtls_port: 15008,
        }
    }

    fn mock_default_gateway_hostname() -> GatewayAddress {
        GatewayAddress {
            destination: Destination::Hostname(state::workload::NamespacedHostname {
                namespace: "gatewayns".into(),
                hostname: "gateway".into(),
            }),
            hbone_mtls_port: 15008,
        }
    }

    fn mock_default_gateway_ipaddr() -> Ipv4Addr {
        Ipv4Addr::new(127, 0, 0, 100)
    }
}
