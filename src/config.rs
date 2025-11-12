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

use serde::ser::SerializeSeq;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use std::{cmp, env, fs};
use tonic::metadata::{AsciiMetadataKey, AsciiMetadataValue};

use anyhow::anyhow;
use bytes::Bytes;
use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
use hyper::Uri;
use hyper::http::uri::InvalidUri;

use crate::strng::Strng;
use crate::{identity, state};
#[cfg(any(test, feature = "testing"))]
use {crate::test_helpers::MpscAckReceiver, crate::xds::LocalConfig, tokio::sync::Mutex};

const ENABLE_PROXY: &str = "ENABLE_PROXY";
const TRANSPARENT_NETWORK_POLICIES: &str = "TRANSPARENT_NETWORK_POLICIES";
const KUBERNETES_SERVICE_HOST: &str = "KUBERNETES_SERVICE_HOST";
const NETWORK: &str = "NETWORK";
const NODE_NAME: &str = "NODE_NAME";
const PROXY_MODE: &str = "PROXY_MODE";
const PROXY_WORKLOAD_INFO: &str = "PROXY_WORKLOAD_INFO";
const PACKET_MARK: &str = "PACKET_MARK";
const KEEPALIVE_TIME: &str = "KEEPALIVE_TIME";
const KEEPALIVE_INTERVAL: &str = "KEEPALIVE_INTERVAL";
const KEEPALIVE_RETRIES: &str = "KEEPALIVE_RETRIES";
const KEEPALIVE_ENABLED: &str = "KEEPALIVE_ENABLED";
const USER_TIMEOUT_ENABLED: &str = "USER_TIMEOUT_ENABLED";
const INPOD_UDS: &str = "INPOD_UDS";
const INPOD_PORT_REUSE: &str = "INPOD_PORT_REUSE";
const CLUSTER_ID: &str = "CLUSTER_ID";
const CLUSTER_DOMAIN: &str = "CLUSTER_DOMAIN";
const LOCAL_XDS_PATH: &str = "LOCAL_XDS_PATH";
const LOCAL_XDS: &str = "LOCAL_XDS";
const XDS_ON_DEMAND: &str = "XDS_ON_DEMAND";
const XDS_ADDRESS: &str = "XDS_ADDRESS";
const PREFERED_SERVICE_NAMESPACE: &str = "PREFERED_SERVICE_NAMESPACE";
const CA_ADDRESS: &str = "CA_ADDRESS";
const SECRET_TTL: &str = "SECRET_TTL";
const FAKE_CA: &str = "FAKE_CA";
const ZTUNNEL_WORKER_THREADS: &str = "ZTUNNEL_WORKER_THREADS";
const ZTUNNEL_CPU_LIMIT: &str = "ZTUNNEL_CPU_LIMIT";
const POOL_MAX_STREAMS_PER_CONNECTION: &str = "POOL_MAX_STREAMS_PER_CONNECTION";
const POOL_UNUSED_RELEASE_TIMEOUT: &str = "POOL_UNUSED_RELEASE_TIMEOUT";
// CONNECTION_TERMINATION_DEADLINE configures an explicit deadline
const CONNECTION_TERMINATION_DEADLINE: &str = "CONNECTION_TERMINATION_DEADLINE";
// TERMINATION_GRACE_PERIOD_SECONDS configures the Kubernetes terminationGracePeriodSeconds configuration.
// This is not used exactly as the grace period, as we want to have some period before Kubenetes sends us a SIGKILL to forceful shutdown.
// (Our forceful shutdown is more graceful than a SIGKILL, as we can close connections cleanly).
const TERMINATION_GRACE_PERIOD_SECONDS: &str = "TERMINATION_GRACE_PERIOD_SECONDS";
const ENABLE_ORIG_SRC: &str = "ENABLE_ORIG_SRC";
const PROXY_CONFIG: &str = "PROXY_CONFIG";
const IPV6_ENABLED: &str = "IPV6_ENABLED";

const HTTP2_STREAM_WINDOW_SIZE: &str = "HTTP2_STREAM_WINDOW_SIZE";
const HTTP2_CONNECTION_WINDOW_SIZE: &str = "HTTP2_CONNECTION_WINDOW_SIZE";
const HTTP2_FRAME_SIZE: &str = "HTTP2_FRAME_SIZE";

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

const ISTIO_XDS_HEADER_PREFIX: &str = "XDS_HEADER_";
const ISTIO_CA_HEADER_PREFIX: &str = "CA_HEADER_";

/// Fetch the XDS/CA root cert file path based on below constants
const XDS_ROOT_CA_ENV: &str = "XDS_ROOT_CA";
const CA_ROOT_CA_ENV: &str = "CA_ROOT_CA";
const ALT_XDS_HOSTNAME: &str = "ALT_XDS_HOSTNAME";
const ALT_CA_HOSTNAME: &str = "ALT_CA_HOSTNAME";
const DEFAULT_ROOT_CERT_PROVIDER: &str = "./var/run/secrets/istio/root-cert.pem";
const TOKEN_PROVIDER_ENV: &str = "AUTH_TOKEN";
const DEFAULT_TOKEN_PROVIDER: &str = "./var/run/secrets/tokens/istio-token";
const CERT_SYSTEM: &str = "SYSTEM";

const PROXY_MODE_DEDICATED: &str = "dedicated";
const PROXY_MODE_SHARED: &str = "shared";

const LOCALHOST_APP_TUNNEL: &str = "LOCALHOST_APP_TUNNEL";

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

#[derive(Clone, Debug)]
pub struct MetadataVector {
    pub vec: Vec<(AsciiMetadataKey, AsciiMetadataValue)>,
}

impl serde::Serialize for MetadataVector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq: <S as serde::Serializer>::SerializeSeq =
            serializer.serialize_seq(Some(self.vec.len()))?;

        for (k, v) in &self.vec {
            let serialized_key = k.to_string();

            match v.to_str() {
                Ok(serialized_val) => {
                    seq.serialize_element(&(serialized_key, serialized_val))?;
                }
                Err(_) => {
                    return Err(serde::ser::Error::custom(
                        "failed to serialize metadata value",
                    ));
                }
            }
        }
        seq.end()
    }
}

#[derive(serde::Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// If true, the HBONE proxy will be used.
    pub proxy: bool,
    /// If true, a DNS proxy will be used.
    pub dns_proxy: bool,
    /// If true, the communicatin will be stablished by the original destination port.
    pub transparent_network_policies: bool,

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
    pub admin_addr: Address,
    pub stats_addr: Address,
    pub readiness_addr: Address,
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
    pub proxy_workload_information: Option<state::WorkloadInfo>,
    /// The Cluster ID of the cluster that his ztunnel belongs to
    pub cluster_id: String,
    /// The domain of the cluster that this ztunnel belongs to
    pub cluster_domain: String,

    /// CA address to use. If fake_ca is set, this will be None.
    /// Note: we do not implicitly use None when set to "" since using the fake_ca is not secure.
    pub ca_address: Option<String>,
    /// Root cert for CA TLS verification.
    pub ca_root_cert: RootCert,
    // Allow custom alternative CA hostname verification
    pub alt_ca_hostname: Option<String>,
    /// XDS address to use. If unset, XDS will not be used.
    pub xds_address: Option<String>,
    /// Root cert for XDS TLS verification.
    pub xds_root_cert: RootCert,
    // Allow custom alternative XDS hostname verification
    pub alt_xds_hostname: Option<String>,

    /// Prefered service namespace to use for service resolution.
    /// If unset, local namespaces is preferred and other namespaces have equal priority.
    /// If set, the local namespace is preferred, then the defined prefered_service_namespace
    /// and finally other namespaces at an equal priority.
    pub prefered_service_namespace: Option<String>,

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

    pub inpod_uds: PathBuf,
    pub inpod_port_reuse: bool,

    // Mark to assign to all packets.
    // This is required for in-pod mode.
    // For dedicated mode, it is not strictly required, but can be useful in some environments to
    // distinguish proxy traffic from application traffic.
    pub packet_mark: Option<u32>,

    pub socket_config: SocketConfig,

    // Headers to be added to XDS discovery requests
    pub xds_headers: MetadataVector,

    // Headers to be added to certificate requests
    pub ca_headers: MetadataVector,

    // If true, when AppTunnel is set for
    pub localhost_app_tunnel: bool,

    pub ztunnel_identity: Option<identity::Identity>,

    pub ztunnel_workload: Option<state::WorkloadInfo>,

    pub ipv6_enabled: bool,
}

#[derive(serde::Serialize, Clone, Copy, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SocketConfig {
    pub keepalive_time: Duration,
    pub keepalive_interval: Duration,
    pub keepalive_retries: u32,
    pub keepalive_enabled: bool,
    pub user_timeout_enabled: bool,
}

impl Default for SocketConfig {
    fn default() -> Self {
        Self {
            keepalive_time: Duration::from_secs(180),
            keepalive_interval: Duration::from_secs(180),
            keepalive_retries: 9,
            keepalive_enabled: true,
            // Might be a good idea but for now we haven't proven this out enough.
            user_timeout_enabled: false,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid env var {0}={1} ({2})")]
    EnvVar(String, String, String),
    #[error("error parsing proxy config: {0}")]
    ProxyConfig(anyhow::Error),
    #[error("invalid uri: {0}")]
    InvalidUri(#[from] Arc<InvalidUri>),
    #[error("invalid configuration: {0}")]
    InvalidState(String),
    #[error("failed to parse header key: {0}")]
    InvalidHeaderKey(String),
    #[error("failed to parse header value: {0}")]
    InvalidHeaderValue(String),
}

impl From<InvalidUri> for Error {
    fn from(err: InvalidUri) -> Self {
        Error::InvalidUri(Arc::new(err))
    }
}

fn parse<T: FromStr>(env: &str) -> Result<Option<T>, Error>
where
    <T as FromStr>::Err: ToString,
{
    match env::var(env) {
        Ok(val) => val
            .parse()
            .map(|v| Some(v))
            .map_err(|e: <T as FromStr>::Err| Error::EnvVar(env.to_string(), val, e.to_string())),
        Err(_) => Ok(None),
    }
}

fn parse_default<T: FromStr>(env: &str, default: T) -> Result<T, Error>
where
    <T as FromStr>::Err: std::error::Error + Sync + Send,
{
    parse(env).map(|v| v.unwrap_or(default))
}

fn parse_duration(env: &str) -> Result<Option<Duration>, Error> {
    parse::<String>(env)?
        .map(|ds| {
            duration_str::parse(&ds).map_err(|e| Error::EnvVar(env.to_string(), ds, e.to_string()))
        })
        .transpose()
}

fn parse_duration_default(env: &str, default: Duration) -> Result<Duration, Error> {
    parse_duration(env).map(|v| v.unwrap_or(default))
}

fn parse_args() -> String {
    let cli_args: Vec<String> = env::args().collect();
    cli_args[1..].join(" ")
}

fn parse_headers(prefix: &str) -> Result<MetadataVector, Error> {
    let mut metadata: MetadataVector = MetadataVector { vec: Vec::new() };

    for (key, value) in env::vars() {
        let stripped_key: Option<&str> = key.strip_prefix(prefix);
        match stripped_key {
            Some(stripped_key) => {
                // attempt to parse the stripped key
                let metadata_key = AsciiMetadataKey::from_str(stripped_key)
                    .map_err(|_| Error::InvalidHeaderKey(key))?;
                // attempt to parse the value
                let metadata_value = AsciiMetadataValue::from_str(&value)
                    .map_err(|_| Error::InvalidHeaderValue(value))?;
                metadata.vec.push((metadata_key, metadata_value));
            }
            None => continue,
        }
    }

    Ok(metadata)
}

fn get_cpu_count() -> Result<usize, Error> {
    // Allow overriding the count with an env var. This can be used to pass the CPU limit on Kubernetes
    // from the downward API.
    // Note the downward API will return the total thread count ("logical cores") if no limit is set,
    // so it is really the same as num_cpus.
    // We allow num_cpus for cases its not set (not on Kubernetes, etc).
    match parse::<usize>(ZTUNNEL_CPU_LIMIT)? {
        Some(limit) => Ok(limit),
        // This is *logical cores*
        None => Ok(num_cpus::get()),
    }
}

/// Parse worker threads configuration, supporting both fixed numbers and percentages
fn parse_worker_threads(default: usize) -> Result<usize, Error> {
    match parse::<String>(ZTUNNEL_WORKER_THREADS)? {
        Some(value) => {
            if let Some(percent_str) = value.strip_suffix('%') {
                // Parse as percentage
                let percent: f64 = percent_str.parse().map_err(|e| {
                    Error::EnvVar(
                        ZTUNNEL_WORKER_THREADS.to_string(),
                        value.clone(),
                        format!("invalid percentage: {e}"),
                    )
                })?;

                if percent <= 0.0 || percent > 100.0 {
                    return Err(Error::EnvVar(
                        ZTUNNEL_WORKER_THREADS.to_string(),
                        value,
                        "percentage must be between 0 and 100".to_string(),
                    ));
                }

                let cpu_count = get_cpu_count()?;
                // Round up, minimum of 1
                let threads = ((cpu_count as f64 * percent / 100.0).ceil() as usize).max(1);
                Ok(threads)
            } else {
                // Parse as fixed number
                value.parse::<usize>().map_err(|e| {
                    Error::EnvVar(
                        ZTUNNEL_WORKER_THREADS.to_string(),
                        value,
                        format!("invalid number: {e}"),
                    )
                })
            }
        }
        None => Ok(default),
    }
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
    let ipv6_enabled = parse::<bool>(IPV6_ENABLED)?.unwrap_or(true);
    let ipv6_localhost_enabled = if ipv6_enabled {
        // IPv6 may be generally enabled, but not on localhost. In that case, we do not want to bind on IPv6.
        crate::proxy::ipv6_enabled_on_localhost().unwrap_or_else(|e| {
            warn!(err=?e, "failed to determine if IPv6 was disabled; continuing anyways, but this may fail");
            true
        })
    } else {
        false
    };
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

    let prefered_service_namespace = match parse::<String>(PREFERED_SERVICE_NAMESPACE) {
        Ok(ns) => ns,
        Err(e) => {
            warn!(err=?e, "failed to parse {PREFERED_SERVICE_NAMESPACE}, continuing with default behavior");
            None
        }
    };

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

    let auth = match parse::<String>(TOKEN_PROVIDER_ENV)? {
        None => {
            // If nothing is set, conditionally use the default if it exists
            if Path::new(&DEFAULT_TOKEN_PROVIDER).exists() {
                identity::AuthSource::Token(
                    PathBuf::from(DEFAULT_TOKEN_PROVIDER),
                    cluster_id.clone(),
                )
            } else {
                identity::AuthSource::None
            }
        }
        Some(p) if Path::new(&p).exists() => {
            // This is a file
            identity::AuthSource::Token(PathBuf::from(p), cluster_id.clone())
        }
        Some(p) => {
            // This is a static
            identity::AuthSource::StaticToken(p, cluster_id.clone())
        }
    };

    use hickory_resolver::system_conf::read_system_conf;
    use tracing::warn;
    let (dns_resolver_cfg, mut dns_resolver_opts) = read_system_conf().unwrap();
    // Increase some defaults. Note these are NOT coming from /etc/resolv.conf (only some fields do, we don't override those),
    // but rather hickory's hardcoded defaults
    dns_resolver_opts.cache_size = 4096;
    dns_resolver_opts.ip_strategy = if ipv6_enabled {
        // Lookup both in parallel. We will do filtering in a later stage to only appropriate IP families
        // If we did one of the XThenY strategies we would not be able to control selection of correct IP family;
        // for instance, could not prefer v4 for v4 requests.
        // This can result in either incorrectly skewing towards one IP version (not so bad) or attempting
        // to send to an unsupported IP version (results in traffic breaking).
        // A possible alternative would be to set this per-request to prefer the correct IP family;
        // however, this is not easy to accomplish with the current setup.
        LookupIpStrategy::Ipv4AndIpv6
    } else {
        LookupIpStrategy::Ipv4Only
    };

    // Note: since DNS proxy runs in the pod network namespace, we will recompute IPv6 enablement
    // on a pod-by-pod basis.
    let dns_proxy_addr: Address = match pc.proxy_metadata.get(DNS_PROXY_ADDR_METADATA) {
        Some(dns_addr) => Address::new(ipv6_localhost_enabled, dns_addr)
            .unwrap_or_else(|_| panic!("failed to parse DNS_PROXY_ADDR: {dns_addr}")),
        None => Address::Localhost(ipv6_localhost_enabled, DEFAULT_DNS_PORT),
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

    let proxy_mode = match parse::<String>(PROXY_MODE)? {
        Some(proxy_mode) => match proxy_mode.as_str() {
            PROXY_MODE_DEDICATED => ProxyMode::Dedicated,
            PROXY_MODE_SHARED => ProxyMode::Shared,
            _ => {
                return Err(Error::EnvVar(
                    PROXY_MODE.to_string(),
                    proxy_mode,
                    format!(
                        "PROXY_MODE must be one of {PROXY_MODE_DEDICATED}, {PROXY_MODE_SHARED}"
                    ),
                ));
            }
        },
        None => ProxyMode::Shared,
    };
    let proxy_workload_information = if proxy_mode != ProxyMode::Shared {
        let Some(raw) = parse::<String>(PROXY_WORKLOAD_INFO)? else {
            // TODO: in the future, we can provide a mode where we automatically detect based on IP address.
            return Err(Error::InvalidState(format!(
                "{PROXY_MODE}={PROXY_MODE_DEDICATED} requires {PROXY_WORKLOAD_INFO} to be set"
            )));
        };
        let s: Vec<&str> = raw.splitn(3, "/").collect();
        let &[ns, name, sa] = &s[..] else {
            return Err(Error::InvalidState(format!(
                "{PROXY_WORKLOAD_INFO} must match the format 'namespace/name/service-account' (got {s:?})"
            )));
        };
        Some(state::WorkloadInfo {
            name: name.to_string(),
            namespace: ns.to_string(),
            service_account: sa.to_string(),
        })
    } else {
        None
    };

    let local_xds_config = match (
        parse::<PathBuf>(LOCAL_XDS_PATH)?,
        parse::<String>(LOCAL_XDS)?,
    ) {
        (Some(_), Some(_)) => {
            return Err(Error::InvalidState(format!(
                "only one of {LOCAL_XDS_PATH} or {LOCAL_XDS} may be set"
            )));
        }
        (Some(f), _) => Some(ConfigSource::File(f)),
        (_, Some(d)) => Some(ConfigSource::Static(Bytes::from(d))),
        _ => None,
    };

    let socket_config_defaults = SocketConfig::default();

    // Read ztunnel identity and workload info from Downward API if available
    let (ztunnel_identity, ztunnel_workload) = match (
        parse::<String>("POD_NAMESPACE")?,
        parse::<String>("SERVICE_ACCOUNT")?,
        parse::<String>("POD_NAME")?,
    ) {
        (Some(namespace), Some(service_account), Some(pod_name)) => {
            let trust_domain = std::env::var("TRUST_DOMAIN")
                .unwrap_or_else(|_| crate::identity::manager::DEFAULT_TRUST_DOMAIN.to_string());

            let identity = identity::Identity::from_parts(
                trust_domain.into(),
                namespace.clone().into(),
                service_account.clone().into(),
            );

            let workload = state::WorkloadInfo::new(pod_name, namespace, service_account);

            (Some(identity), Some(workload))
        }
        _ => (None, None),
    };

    validate_config(Config {
        proxy: parse_default(ENABLE_PROXY, true)?,
        transparent_network_policies: parse_default(TRANSPARENT_NETWORK_POLICIES, false)?,
        // Enable by default; running the server is not an issue, clients still need to opt-in to sending their
        // DNS requests to Ztunnel.
        dns_proxy: pc
            .proxy_metadata
            .get(DNS_CAPTURE_METADATA)
            .is_none_or(|value| value.to_lowercase() == "true"),

        pool_max_streams_per_conn: parse_default(
            POOL_MAX_STREAMS_PER_CONNECTION,
            DEFAULT_POOL_MAX_STREAMS_PER_CONNECTION,
        )?,

        pool_unused_release_timeout: parse_duration_default(
            POOL_UNUSED_RELEASE_TIMEOUT,
            DEFAULT_POOL_UNUSED_RELEASE_TIMEOUT,
        )?,

        // window size: per-stream limit
        window_size: parse_default(HTTP2_STREAM_WINDOW_SIZE, 4 * 1024 * 1024)?,
        // connection window size: per connection.
        // Setting this to the same value as window_size can introduce deadlocks in some applications
        // where clients do not read data on streamA until they receive data on streamB.
        // If streamA consumes the entire connection window, we enter a deadlock.
        // A 4x limit should be appropriate without introducing too much potential buffering.
        connection_window_size: parse_default(HTTP2_CONNECTION_WINDOW_SIZE, 16 * 1024 * 1024)?,
        frame_size: parse_default(HTTP2_FRAME_SIZE, 1024 * 1024)?,

        self_termination_deadline: match parse_duration(CONNECTION_TERMINATION_DEADLINE)? {
            Some(period) => period,
            None => match parse::<u64>(TERMINATION_GRACE_PERIOD_SECONDS)? {
                // We want our drain period to be less than Kubernetes, so we can use the last few seconds
                // to abruptly terminate anything remaining before Kubernetes SIGKILLs us.
                // We could just take the SIGKILL, but it is even more abrupt (TCP RST vs RST_STREAM/TLS close, etc)
                // Note: we do this in code instead of in configuration so that we can use downward API to expose this variable
                // if it is added to Kubernetes (https://github.com/kubernetes/kubernetes/pull/125746).
                Some(secs) => Duration::from_secs(cmp::max(
                    if secs > 10 {
                        secs - 5
                    } else {
                        // If the grace period is really low give less buffer
                        secs - 1
                    },
                    1,
                )),
                None => DEFAULT_CONNECTION_TERMINATION_DEADLINE,
            },
        },

        // admin API should only be accessible over localhost
        admin_addr: Address::Localhost(
            ipv6_localhost_enabled,
            pc.proxy_admin_port.unwrap_or(DEFAULT_ADMIN_PORT),
        ),
        stats_addr: Address::SocketAddr(SocketAddr::new(
            bind_wildcard,
            pc.stats_port.unwrap_or(DEFAULT_STATS_PORT),
        )),
        readiness_addr: Address::SocketAddr(SocketAddr::new(
            bind_wildcard,
            DEFAULT_READINESS_PORT, // There is no config for this in ProxyConfig currently
        )),

        socks5_addr,
        inbound_addr,
        inbound_plaintext_addr,
        outbound_addr,
        dns_proxy_addr,

        illegal_ports,

        network: parse(NETWORK)?.unwrap_or_default(),
        local_node: parse(NODE_NAME)?,
        proxy_mode,
        proxy_workload_information,
        cluster_id,
        cluster_domain,

        xds_address,
        xds_root_cert,
        prefered_service_namespace,
        ca_address,
        ca_root_cert,
        alt_xds_hostname: parse(ALT_XDS_HOSTNAME)?,
        alt_ca_hostname: parse(ALT_CA_HOSTNAME)?,

        secret_ttl: parse_duration_default(SECRET_TTL, DEFAULT_TTL)?,
        local_xds_config,
        xds_on_demand: parse_default(XDS_ON_DEMAND, false)?,
        proxy_metadata: pc.proxy_metadata,

        fake_ca,
        auth,

        num_worker_threads: parse_worker_threads(
            pc.concurrency.unwrap_or(DEFAULT_WORKER_THREADS).into(),
        )?,

        require_original_source: parse(ENABLE_ORIG_SRC)?,
        proxy_args: parse_args(),
        dns_resolver_cfg,
        dns_resolver_opts,
        inpod_uds: parse_default(INPOD_UDS, PathBuf::from("/var/run/ztunnel/ztunnel.sock"))?,
        inpod_port_reuse: parse_default(INPOD_PORT_REUSE, true)?,
        socket_config: SocketConfig {
            // Our goal with keepalives is to stop things from dropping our connection prematurely.
            // So we want this to be a short enough interval to achieve that goal, without causing
            // excessive pings.
            //
            // Note that keepalives are not hop-by-hop. So without setting keepalives in Ztunnel,
            // an application may rely on keepalives which are now only going to the local Ztunnel.
            // This results in hitting timeout's and unexpected behavior. This only impacts TCP keepalives;
            // application level keepalives work fine.
            //
            // Some popular services, like Google LBs have a 10 minute timeout, so we will aim to be
            // well below that.
            // Other systems' defaults:
            // * Go: 15s/15s, 9 retries
            // * Linux: 2hr delay, 75s interval, 9 retries (note: its off by default, though)
            // * Envoy: no default
            // * Linkerd2: 10s delay (then hitting Linux level settings for the rest)
            //
            // Note that because keepalives are a property of the socket (which has two ends), not the connection,
            // we cannot somehow read what the peer set and forward it (which would be neat).
            keepalive_time: parse_duration_default(
                KEEPALIVE_TIME,
                socket_config_defaults.keepalive_time,
            )?,
            keepalive_interval: parse_duration_default(
                KEEPALIVE_INTERVAL,
                socket_config_defaults.keepalive_interval,
            )?,
            keepalive_retries: parse_default(
                KEEPALIVE_RETRIES,
                socket_config_defaults.keepalive_retries,
            )?,
            keepalive_enabled: parse_default(
                KEEPALIVE_ENABLED,
                socket_config_defaults.keepalive_enabled,
            )?,
            user_timeout_enabled: parse_default(
                USER_TIMEOUT_ENABLED,
                socket_config_defaults.user_timeout_enabled,
            )?,
        },
        packet_mark: parse(PACKET_MARK)?.or_else(|| {
            if proxy_mode == ProxyMode::Shared {
                // For inpod, mark is required so default it
                Some(DEFAULT_INPOD_MARK)
            } else {
                None
            }
        }),
        fake_self_inbound: false,
        xds_headers: parse_headers(ISTIO_XDS_HEADER_PREFIX)?,
        ca_headers: parse_headers(ISTIO_CA_HEADER_PREFIX)?,

        localhost_app_tunnel: parse_default(LOCALHOST_APP_TUNNEL, true)?,
        ztunnel_identity,
        ztunnel_workload,
        ipv6_enabled,
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
    pub proxy_metadata: HashMap<String, String>,
}

impl ProxyConfig {
    fn merge(mut self, other: Self) -> Self {
        self.discovery_address = other.discovery_address.or(self.discovery_address); // clone not required; self is moved and discovery_address is an owned type
        self.proxy_admin_port = other.proxy_admin_port.or(self.proxy_admin_port);
        self.stats_port = other.stats_port.or(self.stats_port);
        self.concurrency = other.concurrency.or(self.concurrency);
        self.proxy_metadata.extend(other.proxy_metadata);
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
    if let Some(inner) = &inp
        && inner.as_ref().is_empty()
    {
        return None;
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
    fn new(ipv6_enabled: bool, s: &str) -> anyhow::Result<Self> {
        if s.starts_with("localhost:") {
            let (_host, ports) = s.split_once(':').expect("already checked it has a :");
            let port: u16 = ports.parse()?;
            Ok(Address::Localhost(ipv6_enabled, port))
        } else {
            Ok(Address::SocketAddr(s.parse()?))
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::Localhost(_, port) => *port,
            Address::SocketAddr(s) => s.port(),
        }
    }

    // with_ipv6 unconditionally overrides the IPv6 setting for the address
    pub fn with_ipv6(self, ipv6: bool) -> Self {
        match self {
            Address::Localhost(_, port) => Address::Localhost(ipv6, port),
            x => x,
        }
    }

    // maybe_downgrade_ipv6 updates the V6 setting, ONLY if the address was already V6
    pub fn maybe_downgrade_ipv6(self, updated_v6: bool) -> Self {
        match self {
            Address::Localhost(true, port) => Address::Localhost(updated_v6, port),
            x => x,
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

        unsafe {
            env::set_var("ISTIO_META_INCLUDE_THIS", "foobar-env");
            env::set_var("NOT_INCLUDE", "not-include");
            env::set_var("ISTIO_META_CLUSTER_ID", "test-cluster");
            env::set_var("XDS_HEADER_HEADER_FOO", "foo");
            env::set_var("XDS_HEADER_HEADER_BAR", "bar");
            env::set_var("CA_HEADER_HEADER_BAZ", "baz");
        }

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
        assert_eq!(cfg.proxy_metadata["NO_PREFIX"], "no-prefix");
        assert_eq!(cfg.proxy_metadata["INCLUDE_THIS"], "foobar-env");
        assert_eq!(cfg.proxy_metadata.get("NOT_INCLUDE"), None);
        assert_eq!(cfg.proxy_metadata["CLUSTER_ID"], "test-cluster");
        assert_eq!(cfg.cluster_id, "test-cluster");

        let mut expected_xds_headers = HashMap::new();
        expected_xds_headers.insert("HEADER_FOO".to_string(), "foo".to_string());
        expected_xds_headers.insert("HEADER_BAR".to_string(), "bar".to_string());

        let mut expected_ca_headers = HashMap::new();
        expected_ca_headers.insert("HEADER_BAZ".to_string(), "baz".to_string());

        validate_metadata_vector(&cfg.xds_headers, expected_xds_headers.clone());

        validate_metadata_vector(&cfg.ca_headers, expected_ca_headers.clone());

        // both (with a field override and metadata override)
        let pc = construct_proxy_config(mesh_config_path, pc_env).unwrap();
        let cfg = construct_config(pc).unwrap();

        unsafe {
            env::remove_var("ISTIO_META_INCLUDE_THIS");
            env::remove_var("NOT_INCLUDE");
        }

        assert_eq!(cfg.stats_addr.port(), 15888);
        assert_eq!(cfg.admin_addr.port(), 15999);
        assert_eq!(cfg.proxy_metadata["FOO"], "foo");
        assert_eq!(cfg.proxy_metadata["BAR"], "bar");
        assert_eq!(cfg.proxy_metadata["FOOBAR"], "foobar-overwritten");
        assert_eq!(cfg.proxy_metadata["NO_PREFIX"], "no-prefix");
        assert_eq!(cfg.proxy_metadata["INCLUDE_THIS"], "foobar-env");
        assert_eq!(cfg.proxy_metadata["CLUSTER_ID"], "test-cluster");
        assert_eq!(cfg.cluster_id, "test-cluster");

        validate_metadata_vector(&cfg.xds_headers, expected_xds_headers.clone());

        validate_metadata_vector(&cfg.ca_headers, expected_ca_headers.clone());
    }

    fn validate_metadata_vector(metadata: &MetadataVector, header_map: HashMap<String, String>) {
        for (k, v) in header_map {
            let key: AsciiMetadataKey = AsciiMetadataKey::from_str(&k).unwrap();
            let value: AsciiMetadataValue = AsciiMetadataValue::from_str(&v).unwrap();
            assert!(metadata.vec.contains(&(key, value)));
        }
    }

    #[test]
    fn test_parse_worker_threads() {
        unsafe {
            // Test fixed number
            env::set_var(ZTUNNEL_WORKER_THREADS, "4");
            assert_eq!(parse_worker_threads(2).unwrap(), 4);

            // Test percentage with CPU limit
            env::set_var(ZTUNNEL_CPU_LIMIT, "8");
            env::set_var(ZTUNNEL_WORKER_THREADS, "50%");
            assert_eq!(parse_worker_threads(2).unwrap(), 4); // 50% of 8 CPUs = 4 threads

            // Test percentage with CPU limit
            env::set_var(ZTUNNEL_CPU_LIMIT, "16");
            env::set_var(ZTUNNEL_WORKER_THREADS, "30%");
            assert_eq!(parse_worker_threads(2).unwrap(), 5); // Round up to 5

            // Test low percentage that rounds up to 1
            env::set_var(ZTUNNEL_CPU_LIMIT, "4");
            env::set_var(ZTUNNEL_WORKER_THREADS, "10%");
            assert_eq!(parse_worker_threads(2).unwrap(), 1); // 10% of 4 CPUs = 0.4, rounds up to 1

            // Test default when no env var is set
            env::remove_var(ZTUNNEL_WORKER_THREADS);
            assert_eq!(parse_worker_threads(2).unwrap(), 2);

            // Test without CPU limit (should use system CPU count)
            env::remove_var(ZTUNNEL_CPU_LIMIT);
            let system_cpus = num_cpus::get();
            assert_eq!(get_cpu_count().unwrap(), system_cpus);

            // Test with CPU limit
            env::set_var(ZTUNNEL_CPU_LIMIT, "12");
            assert_eq!(get_cpu_count().unwrap(), 12);

            // Clean up
            env::remove_var(ZTUNNEL_WORKER_THREADS);
            env::remove_var(ZTUNNEL_CPU_LIMIT);
        }
    }
}
