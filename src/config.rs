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

use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

use anyhow::anyhow;
use bytes::Bytes;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hyper::http::uri::InvalidUri;
use hyper::Uri;

use crate::identity;
use crate::strng::Strng;
#[cfg(any(test, feature = "testing"))]
use {crate::test_helpers::MpscAckReceiver, crate::xds::LocalConfig, tokio::sync::Mutex};

const ENABLE_PROXY: &str = "ENABLE_PROXY";
const KUBERNETES_SERVICE_HOST: &str = "KUBERNETES_SERVICE_HOST";
const NETWORK: &str = "NETWORK";
const NODE_NAME: &str = "NODE_NAME";
const PROXY_MODE: &str = "PROXY_MODE";
const INPOD_ENABLED: &str = "INPOD_ENABLED";
const INPOD_MARK: &str = "INPOD_MARK";
const INPOD_UDS: &str = "INPOD_UDS";
const INPOD_PORT_REUSE: &str = "INPOD_PORT_REUSE";
const INSTANCE_IP: &str = "INSTANCE_IP";
const CLUSTER_ID: &str = "CLUSTER_ID";
const CLUSTER_DOMAIN: &str = "CLUSTER_DOMAIN";
const LOCAL_XDS_PATH: &str = "LOCAL_XDS_PATH";
const XDS_ON_DEMAND: &str = "XDS_ON_DEMAND";
const XDS_ADDRESS: &str = "XDS_ADDRESS";
const CA_ADDRESS: &str = "CA_ADDRESS";
const SECRET_TTL: &str = "SECRET_TTL";
const FAKE_CA: &str = "FAKE_CA";
const ZTUNNEL_WORKER_THREADS: &str = "ZTUNNEL_WORKER_THREADS";
const POOL_MAX_STREAMS_PER_CONNECTION: &str = "POOL_MAX_STREAMS_PER_CONNECTION";
const POOL_UNUSED_RELEASE_TIMEOUT: &str = "POOL_UNUSED_RELEASE_TIMEOUT";
const CONNECTION_TERMINATION_DEADLINE: &str = "CONNECTION_TERMINATION_DEADLINE";
const ENABLE_ORIG_SRC: &str = "ENABLE_ORIG_SRC";
const PROXY_CONFIG: &str = "PROXY_CONFIG";
const IPV6_DISABLED: &str = "IPV6_DISABLED";

const UNSTABLE_ENABLE_SOCKS5: &str = "UNSTABLE_ENABLE_SOCKS5";

const DEFAULT_WORKER_THREADS: u16 = 2;
const DEFAULT_ADMIN_PORT: u16 = 15000;
const DEFAULT_READINESS_PORT: u16 = 15021;
const DEFAULT_STATS_PORT: u16 = 15020;
const DEFAULT_DNS_PORT: u16 = 15053;
const DEFAULT_CONNECTION_TERMINATION_DEADLINE: Duration = Duration::from_secs(5);
const DEFAULT_CLUSTER_ID: &str = "Kubernetes";
const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";
const DEFAULT_TTL: Duration = Duration::from_secs(60 * 60 * 24); // 24 hours
const DEFAULT_POOL_UNUSED_RELEASE_TIMEOUT: Duration = Duration::from_secs(60 * 5); // 5 minutes
const DEFAULT_POOL_MAX_STREAMS_PER_CONNECTION: u16 = 100; //Go: 100, Hyper: 200, Envoy: 2147483647 (lol), Spec recommended minimum 100

const DEFAULT_INPOD_MARK: u32 = 1337;

const ISTIO_META_PREFIX: &str = "ISTIO_META_";
const DNS_CAPTURE_METADATA: &str = "DNS_CAPTURE";
const DNS_PROXY_ADDR_METADATA: &str = "DNS_PROXY_ADDR";

/// Fetch the XDS/CA root cert file path based on below constants
const XDS_ROOT_CA_ENV: &str = "XDS_ROOT_CA";
const CA_ROOT_CA_ENV: &str = "CA_ROOT_CA";
const DEFAULT_ROOT_CERT_PROVIDER: &str = "./var/run/secrets/istio/root-cert.pem";
const DEFAULT_TOKEN_PROVIDER: &str = "./var/run/secrets/tokens/istio-token";
const CERT_SYSTEM: &str = "SYSTEM";

const PROXY_MODE_DEDICATED: &str = "dedicated";
const PROXY_MODE_SHARED: &str = "shared";

#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub enum RootCert {
    File(PathBuf),
    Static(#[serde(skip)] Bytes),
    Default,
}

#[derive(Clone, Debug)]
pub enum ConfigSource {
    File(PathBuf),
    Static(Bytes),
    #[cfg(any(test, feature = "testing"))]
    Dynamic(Arc<Mutex<MpscAckReceiver<LocalConfig>>>),
}

impl ConfigSource {
    pub async fn read_to_string(&self) -> anyhow::Result<String> {
        Ok(match self {
            ConfigSource::File(path) => tokio::fs::read_to_string(path).await?,
            ConfigSource::Static(data) => std::str::from_utf8(data).map(|s| s.to_string())?,
            #[cfg(any(test, feature = "testing"))]
            _ => "{}".to_string(),
        })
    }
}

#[derive(serde::Serialize, Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyMode {
    #[default]
    Shared,
    Dedicated,
}

#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// If true, the HBONE proxy will be used.
    pub proxy: bool,
    /// If true, a DNS proxy will be used.
    pub dns_proxy: bool,

    pub window_size: u32,
    pub connection_window_size: u32,
    pub frame_size: u32,

    // The limit of how many streams a single HBONE pool connection will be limited to, before
    // spawning a new conn rather than reusing an existing one, even to a dest that already has an open connection.
    //
    // This can be used to effect flow control for "connection storms" when workload clients
    // (such as loadgen clients) open many connections all at once.
    //
    // Note that this will only be checked when a *new* connection
    // is requested from the pool, and not on every *stream* queued on that connection.
    // So if you request a single connection from a pool configured wiht a max streamcount of 200,
    // and queue 500 streams on it, you will still exceed this limit and are at the mercy of hyper's
    // default stream queuing.
    pub pool_max_streams_per_conn: u16,

    pub pool_unused_release_timeout: Duration,

    pub socks5_addr: Option<SocketAddr>,
    pub admin_addr: SocketAddr,
    pub stats_addr: SocketAddr,
    pub readiness_addr: SocketAddr,
    pub inbound_addr: SocketAddr,
    pub inbound_plaintext_addr: SocketAddr,
    pub outbound_addr: SocketAddr,
    /// The socket address for the DNS proxy. Only applies if `dns_proxy` is true.
    pub dns_proxy_addr: Address,
    /// Populated with the internal ports of all the proxy handlers defined above.
    /// illegal_ports are internal ports that clients are not authorized to send to
    pub illegal_ports: HashSet<u16>,
    /// The network of the node this ztunnel is running on.
    pub network: Strng,
    /// The name of the node this ztunnel is running as.
    pub local_node: Option<String>,
    /// The proxy mode of ztunnel, Shared or Dedicated, default to Shared.
    pub proxy_mode: ProxyMode,
    /// The local_ip we are running at.
    pub local_ip: Option<IpAddr>,
    /// The Cluster ID of the cluster that his ztunnel belongs to
    pub cluster_id: String,
    /// The domain of the cluster that this ztunnel belongs to
    pub cluster_domain: String,

    /// CA address to use. If fake_ca is set, this will be None.
    /// Note: we do not implicitly use None when set to "" since using the fake_ca is not secure.
    pub ca_address: Option<String>,
    /// Root cert for CA TLS verification.
    pub ca_root_cert: RootCert,
    /// XDS address to use. If unset, XDS will not be used.
    pub xds_address: Option<String>,
    /// Root cert for XDS TLS verification.
    pub xds_root_cert: RootCert,
    /// TTL for CSR requests
    pub secret_ttl: Duration,
    /// YAML config for local XDS workloads
    #[serde(skip_serializing)]
    pub local_xds_config: Option<ConfigSource>,
    /// If true, on-demand XDS will be used
    pub xds_on_demand: bool,

    /// If true, then use builtin fake CA with self-signed certificates.
    pub fake_ca: bool,
    // If true, then force config to use the linux-assigned listener address:port instead
    // of the well-known config addr:port socketaddress. Used by `direct` tests.
    pub fake_self_inbound: bool,
    #[serde(skip_serializing)]
    pub auth: identity::AuthSource,
    // How long ztunnel should wait for in-flight requesthandlers to finish processing
    // before giving up when ztunnel is self-terminating (when instructed via the Admin API)
    pub self_termination_deadline: Duration,

    pub proxy_metadata: HashMap<String, String>,

    /// Specify the number of worker threads the Tokio Runtime will use.
    pub num_worker_threads: usize,

    // If set, explicitly configure whether to use original source.
    // If unset (recommended), this is automatically detected based on permissions.
    pub require_original_source: Option<bool>,

    // CLI args passed to ztunnel at runtime
    pub proxy_args: String,

    // System dns resolver config used for on-demand ztunnel dns resolution
    pub dns_resolver_cfg: ResolverConfig,

    // System dns resolver opts used for on-demand ztunnel dns resolution
    pub dns_resolver_opts: ResolverOpts,

    pub inpod_enabled: bool,
    pub inpod_uds: PathBuf,
    pub inpod_port_reuse: bool,
    pub inpod_mark: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid env var {0}={1}")]
    EnvVar(String, String),
    #[error("error parsing proxy config: {0}")]
    ProxyConfig(anyhow::Error),
    #[error("invalid uri: {0}")]
    InvalidUri(#[from] Arc<InvalidUri>),
}

impl From<InvalidUri> for Error {
    fn from(err: InvalidUri) -> Self {
        Error::InvalidUri(Arc::new(err))
    }
}

fn parse<T: FromStr>(env: &str) -> Result<Option<T>, Error> {
    match env::var(env) {
        Ok(val) => val
            .parse()
            .map(|v| Some(v))
            .map_err(|_| Error::EnvVar(env.to_string(), val)),
        Err(_) => Ok(None),
    }
}

fn parse_default<T: FromStr>(env: &str, default: T) -> Result<T, Error> {
    parse(env).map(|v| v.unwrap_or(default))
}

fn parse_args() -> String {
    let cli_args: Vec<String> = env::args().collect();
    cli_args[1..].join(" ")
}

pub fn parse_config() -> Result<Config, Error> {
    let pc = parse_proxy_config()?;
    construct_config(pc)
}

fn parse_proxy_config() -> Result<ProxyConfig, Error> {
    let mesh_config_path = "./etc/istio/config/mesh";
    let pc_env = parse::<String>(PROXY_CONFIG)?;
    let pc_env = pc_env.as_deref();
    construct_proxy_config(mesh_config_path, pc_env).map_err(Error::ProxyConfig)
}

pub fn construct_config(pc: ProxyConfig) -> Result<Config, Error> {
    let ipv6_enabled = !parse::<bool>(IPV6_DISABLED)?.unwrap_or_default();
    let bind_wildcard = if ipv6_enabled {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    };
    let default_istiod_address = if env::var(KUBERNETES_SERVICE_HOST).is_ok() {
        "https://istiod.istio-system.svc:15012".to_string()
    } else {
        "https://localhost:15012".to_string()
    };
    let xds_address = validate_uri(empty_to_none(
        parse(XDS_ADDRESS)?
            .or(pc.discovery_address)
            .or_else(|| Some(default_istiod_address.clone())),
    ))?;

    let istio_meta_cluster_id = ISTIO_META_PREFIX.to_owned() + CLUSTER_ID;
    let cluster_id: String = match parse::<String>(&istio_meta_cluster_id)? {
        Some(id) => id,
        None => parse_default::<String>(CLUSTER_ID, DEFAULT_CLUSTER_ID.to_string())?,
    };
    let cluster_domain = parse_default(CLUSTER_DOMAIN, DEFAULT_CLUSTER_DOMAIN.to_string())?;

    let fake_ca = parse_default(FAKE_CA, false)?;
    let ca_address = validate_uri(empty_to_none(if fake_ca {
        None
    } else {
        Some(parse_default(CA_ADDRESS, default_istiod_address)?)
    }))?;

    let xds_root_cert_provider =
        parse_default(XDS_ROOT_CA_ENV, DEFAULT_ROOT_CERT_PROVIDER.to_string())?;
    let xds_root_cert = if Path::new(&xds_root_cert_provider).exists() {
        RootCert::File(xds_root_cert_provider.into())
    } else if xds_root_cert_provider.eq(&CERT_SYSTEM.to_string()) {
        // handle SYSTEM special case for xds
        RootCert::Default
    } else {
        RootCert::Static(Bytes::from(xds_root_cert_provider))
    };

    let ca_root_cert_provider =
        parse_default(CA_ROOT_CA_ENV, DEFAULT_ROOT_CERT_PROVIDER.to_string())?;
    let ca_root_cert = if Path::new(&ca_root_cert_provider).exists() {
        RootCert::File(ca_root_cert_provider.into())
    } else if ca_root_cert_provider.eq(&CERT_SYSTEM.to_string()) {
        // handle SYSTEM special case for ca
        RootCert::Default
    } else {
        RootCert::Static(Bytes::from(ca_root_cert_provider))
    };

    let auth = match std::fs::read(DEFAULT_TOKEN_PROVIDER) {
        Ok(_) => {
            identity::AuthSource::Token(PathBuf::from(DEFAULT_TOKEN_PROVIDER), cluster_id.clone())
        }
        Err(_) => identity::AuthSource::None,
    };

    use hickory_resolver::system_conf::read_system_conf;
    let (dns_resolver_cfg, mut dns_resolver_opts) = read_system_conf().unwrap();
    // Increase some defaults. Note these are NOT coming from /etc/resolv.conf (only some fields do, we don't override those),
    // but rather hickory's hardcoded defaults
    dns_resolver_opts.cache_size = 4096;
    // TODO: should we override server_ordering_strategy based on our IP support?

    let dns_proxy_addr: Address = match pc.proxy_metadata.get(DNS_PROXY_ADDR_METADATA) {
        Some(dns_addr) => Address::from_str(ipv6_enabled, dns_addr)
            .unwrap_or_else(|_| panic!("failed to parse DNS_PROXY_ADDR: {}", dns_addr)),
        None => Address::Localhost(ipv6_enabled, DEFAULT_DNS_PORT),
    };

    let socks5_addr = if let Some(true) = parse(UNSTABLE_ENABLE_SOCKS5)? {
        // TODO: use Address::Localhost for dual stack binding
        Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15080))
    } else {
        None
    };

    let inbound_addr = SocketAddr::new(bind_wildcard, 15008);
    let inbound_plaintext_addr = SocketAddr::new(bind_wildcard, 15006);
    let outbound_addr = SocketAddr::new(bind_wildcard, 15001);

    let mut illegal_ports = HashSet::from([
        // HBONE doesn't have redirection, so we cannot have loops, but this would allow multiple layers of HBONE.
        // This might be desirable in the future, but for now just ban it.
        inbound_addr.port(),
        inbound_plaintext_addr.port(),
        outbound_addr.port(),
    ]);

    if let Some(addr) = socks5_addr {
        illegal_ports.insert(addr.port());
    }

    validate_config(Config {
        proxy: parse_default(ENABLE_PROXY, true)?,
        dns_proxy: pc
            .proxy_metadata
            .get(DNS_CAPTURE_METADATA)
            .map_or(false, |value| value.to_lowercase() == "true"),

        pool_max_streams_per_conn: parse_default(
            POOL_MAX_STREAMS_PER_CONNECTION,
            DEFAULT_POOL_MAX_STREAMS_PER_CONNECTION,
        )?,

        pool_unused_release_timeout: match parse::<String>(POOL_UNUSED_RELEASE_TIMEOUT)? {
            Some(ttl) => duration_str::parse(ttl).unwrap_or(DEFAULT_POOL_UNUSED_RELEASE_TIMEOUT),
            None => DEFAULT_POOL_UNUSED_RELEASE_TIMEOUT,
        },

        window_size: 4 * 1024 * 1024,
        connection_window_size: 4 * 1024 * 1024,
        frame_size: 1024 * 1024,

        self_termination_deadline: match parse::<String>(CONNECTION_TERMINATION_DEADLINE)? {
            Some(ttl) => {
                duration_str::parse(ttl).unwrap_or(DEFAULT_CONNECTION_TERMINATION_DEADLINE)
            }
            None => DEFAULT_CONNECTION_TERMINATION_DEADLINE,
        },

        // admin API should only be accessible over localhost
        // TODO: use Address::Localhost for dual stack binding
        admin_addr: SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            pc.proxy_admin_port.unwrap_or(DEFAULT_ADMIN_PORT),
        ),
        stats_addr: SocketAddr::new(bind_wildcard, pc.stats_port.unwrap_or(DEFAULT_STATS_PORT)),
        readiness_addr: SocketAddr::new(
            bind_wildcard,
            DEFAULT_READINESS_PORT, // There is no config for this in ProxyConfig currently
        ),

        socks5_addr,
        inbound_addr,
        inbound_plaintext_addr,
        outbound_addr,
        dns_proxy_addr,

        illegal_ports,

        network: parse(NETWORK)?.unwrap_or_default(),
        local_node: parse(NODE_NAME)?,
        proxy_mode: match parse::<String>(PROXY_MODE)? {
            Some(proxy_mode) => match proxy_mode.as_str() {
                PROXY_MODE_DEDICATED => ProxyMode::Dedicated,
                PROXY_MODE_SHARED => ProxyMode::Shared,
                _ => return Err(Error::EnvVar(PROXY_MODE.to_string(), proxy_mode)),
            },
            None => ProxyMode::Shared,
        },
        local_ip: parse(INSTANCE_IP)?,
        cluster_id,
        cluster_domain,

        xds_address,
        xds_root_cert,
        ca_address,
        ca_root_cert,
        secret_ttl: match parse::<String>(SECRET_TTL)? {
            Some(ttl) => duration_str::parse(ttl).unwrap_or(DEFAULT_TTL),
            None => DEFAULT_TTL,
        },
        local_xds_config: parse::<PathBuf>(LOCAL_XDS_PATH)?.map(ConfigSource::File),
        xds_on_demand: parse_default(XDS_ON_DEMAND, false)?,
        proxy_metadata: pc.proxy_metadata,

        fake_ca,
        auth,

        num_worker_threads: parse_default(
            ZTUNNEL_WORKER_THREADS,
            pc.concurrency.unwrap_or(DEFAULT_WORKER_THREADS).into(),
        )?,

        require_original_source: parse(ENABLE_ORIG_SRC)?,
        proxy_args: parse_args(),
        dns_resolver_cfg,
        dns_resolver_opts,
        inpod_enabled: parse_default(INPOD_ENABLED, false)?,
        inpod_uds: parse_default(INPOD_UDS, PathBuf::from("/var/run/ztunnel/ztunnel.sock"))?,
        inpod_port_reuse: parse_default(INPOD_PORT_REUSE, true)?,
        inpod_mark: parse_default(INPOD_MARK, DEFAULT_INPOD_MARK)?,
        fake_self_inbound: false,
    })
}

fn validate_config(cfg: Config) -> Result<Config, Error> {
    if cfg.dns_proxy && cfg.xds_on_demand {
        return Err(Error::ProxyConfig(anyhow!(
            "DNS proxy does not currently support on-demand mode"
        )));
    }

    if !cfg.proxy && !cfg.dns_proxy {
        return Err(Error::ProxyConfig(anyhow!(
            "ztunnel run without any servers enabled"
        )));
    }

    Ok(cfg)
}

// tries to parse the URI so we can fail early
fn validate_uri(uri_str: Option<String>) -> Result<Option<String>, Error> {
    let Some(uri_str) = uri_str else {
        return Ok(uri_str);
    };
    let uri = Uri::try_from(&uri_str)?;
    if uri.scheme().is_none() {
        return Ok(Some("https://".to_owned() + &uri_str));
    }
    Ok(Some(uri_str))
}

#[derive(serde::Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MeshConfig {
    pub default_config: Option<ProxyConfig>,
}

#[derive(serde::Deserialize, Default, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    pub discovery_address: Option<String>,
    pub proxy_admin_port: Option<u16>,
    pub stats_port: Option<u16>,
    pub concurrency: Option<u16>,
    pub termination_drain_duration: Option<Duration>,
    pub proxy_metadata: HashMap<String, String>,
}

impl ProxyConfig {
    fn merge(mut self, other: Self) -> Self {
        self.discovery_address = other.discovery_address.or(self.discovery_address); // clone not required; self is moved and discovery_address is an owned type
        self.proxy_admin_port = other.proxy_admin_port.or(self.proxy_admin_port);
        self.stats_port = other.stats_port.or(self.stats_port);
        self.concurrency = other.concurrency.or(self.concurrency);
        self.proxy_metadata.extend(other.proxy_metadata);
        self.termination_drain_duration = other
            .termination_drain_duration
            .or(self.termination_drain_duration);
        self
    }
}

fn construct_proxy_config(mc_path: &str, pc_env: Option<&str>) -> anyhow::Result<ProxyConfig> {
    let mesh_config = match fs::File::open(mc_path) {
        Ok(f) => serde_yaml::from_reader(f)
            .map(|v: MeshConfig| v.default_config)
            .map_err(anyhow::Error::new),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(anyhow!(e))
            }
        }
    }
    .map_err(|e| anyhow!("failed parsing mesh config file {}: {}", mc_path, e))?;

    let proxy_config_env = pc_env
        .map(|pc_env| {
            if pc_env.is_empty() {
                Ok(None)
            } else {
                serde_yaml::from_str(pc_env)
            }
        })
        .unwrap_or(Ok(None))
        .map_err(|e| anyhow!("failed parsing proxy config env: {}", e))?;

    let mut pc = [mesh_config, proxy_config_env]
        .into_iter()
        .flatten()
        .fold(ProxyConfig::default(), |pc, v| pc.merge(v));

    // only include ISTIO_META_ prefixed fields in this map
    // TODO we could use any other items here for the various env vars for construct_config?
    // https://istio.io/latest/docs/reference/config/istio.mesh.v1alpha1/#:~:text=Additional%20environment%20variables
    pc.proxy_metadata = pc
        .proxy_metadata
        .into_iter()
        .map(|(k, v)| {
            if k.starts_with(ISTIO_META_PREFIX) {
                (k.strip_prefix(ISTIO_META_PREFIX).unwrap().to_string(), v)
            } else {
                (k, v)
            }
        })
        .collect();

    let istio_env_vars: Vec<(String, String)> = env::vars()
        .filter(|(key, _)| key.starts_with(ISTIO_META_PREFIX))
        .map(|(key, val)| (key.trim_start_matches(ISTIO_META_PREFIX).to_string(), val))
        .collect();
    pc.proxy_metadata.extend(istio_env_vars);

    // TODO if certain fields like trustDomainAliases are added, make sure they merge like:
    // https://github.com/istio/istio/blob/bdd47796d696ea5db604b623c51567d13ff7c11b/pkg/config/mesh/mesh.go#L244

    Ok(pc)
}

pub fn empty_to_none<A: AsRef<str>>(inp: Option<A>) -> Option<A> {
    if let Some(inner) = &inp {
        if inner.as_ref().is_empty() {
            return None;
        }
    }
    inp
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
// Address is a wrapper around either a normal SocketAddr or "bind to localhost on IPv4 and IPv6"
pub enum Address {
    // Bind to localhost (dual stack) on a specific port
    // (ipv6_enabled, port)
    Localhost(bool, u16),
    // Bind to an explicit IP/port
    SocketAddr(SocketAddr),
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Localhost(_, port) => write!(f, "localhost:{port}"),
            Address::SocketAddr(s) => write!(f, "{s}"),
        }
    }
}

impl IntoIterator for Address {
    type Item = SocketAddr;
    type IntoIter = <Vec<std::net::SocketAddr> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            Address::Localhost(ipv6_enabled, port) => {
                if ipv6_enabled {
                    vec![
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
                        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
                    ]
                    .into_iter()
                } else {
                    vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)].into_iter()
                }
            }
            Address::SocketAddr(s) => vec![s].into_iter(),
        }
    }
}

impl Address {
    fn from_str(ipv6_enabled: bool, s: &str) -> anyhow::Result<Self> {
        if s.starts_with("localhost:") {
            let (_host, ports) = s.split_once(':').expect("already checked it has a :");
            let port: u16 = ports.parse()?;
            Ok(Address::Localhost(ipv6_enabled, port))
        } else {
            Ok(Address::SocketAddr(s.parse()?))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn config_from_proxyconfig() {
        let default_config = construct_config(ProxyConfig::default())
            .expect("could not build Config without ProxyConfig");

        // mesh config only
        let mesh_config_path = "./src/test_helpers/mesh_config.yaml";
        let pc = construct_proxy_config(mesh_config_path, None).unwrap();
        let cfg = construct_config(pc).unwrap();
        assert_eq!(cfg.stats_addr.port(), 15888);
        assert_eq!(cfg.admin_addr.port(), 15099);
        // TODO remove prefix
        assert_eq!(cfg.proxy_metadata["FOO"], "foo");
        assert_eq!(cfg.cluster_id, "Kubernetes");

        // env only
        let pc_env = Some(
            r#"{
            "discoveryAddress": "istiod-rev0.istio-system-2:15012",
            "proxyAdminPort": 15999,
            "proxyMetadata": {
              "ISTIO_META_BAR": "bar",
              "ISTIO_META_FOOBAR": "foobar-overwritten",
              "NO_PREFIX": "no-prefix"
            }
        }"#,
        );

        env::set_var("ISTIO_META_INCLUDE_THIS", "foobar-env");
        env::set_var("NOT_INCLUDE", "not-include");
        env::set_var("ISTIO_META_CLUSTER_ID", "test-cluster");

        let pc = construct_proxy_config("", pc_env).unwrap();
        let cfg = construct_config(pc).unwrap();
        assert_eq!(
            cfg.readiness_addr.port(),
            default_config.readiness_addr.port()
        );
        assert_eq!(
            cfg.xds_address.unwrap(),
            "https://istiod-rev0.istio-system-2:15012"
        );
        assert_eq!(cfg.proxy_metadata["BAR"], "bar");
        assert_eq!(cfg.proxy_metadata["FOOBAR"], "foobar-overwritten");
        assert_eq!(cfg.cluster_id, "test-cluster");

        // both (with a field override and metadata override)
        let pc = construct_proxy_config(mesh_config_path, pc_env).unwrap();
        let cfg = construct_config(pc).unwrap();

        env::remove_var("ISTIO_META_INCLUDE_THIS");
        env::remove_var("NOT_INCLUDE");
        assert_eq!(cfg.stats_addr.port(), 15888);
        assert_eq!(cfg.admin_addr.port(), 15999);
        assert_eq!(cfg.proxy_metadata["FOO"], "foo");
        assert_eq!(cfg.proxy_metadata["BAR"], "bar");
        assert_eq!(cfg.proxy_metadata["FOOBAR"], "foobar-overwritten");
        assert_eq!(cfg.proxy_metadata["NO_PREFIX"], "no-prefix");
        assert_eq!(cfg.proxy_metadata["INCLUDE_THIS"], "foobar-env");
    }
}
