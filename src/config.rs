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

use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use tokio::time;

use crate::identity;

const KUBERNETES_SERVICE_HOST: &str = "KUBERNETES_SERVICE_HOST";
const NODE_NAME: &str = "NODE_NAME";
const LOCAL_XDS_PATH: &str = "LOCAL_XDS_PATH";
const XDS_ON_DEMAND: &str = "XDS_ON_DEMAND";
const XDS_ADDRESS: &str = "XDS_ADDRESS";
const CA_ADDRESS: &str = "CA_ADDRESS";
const TERMINATION_GRACE_PERIOD: &str = "TERMINATION_GRACE_PERIOD";
const FAKE_CA: &str = "FAKE_CA";
const ZTUNNEL_WORKER_THREADS: &str = "ZTUNNEL_WORKER_THREADS";
const ENABLE_ORIG_SRC: &str = "ENABLE_ORIG_SRC";
const PROXY_CONFIG: &str = "PROXY_CONFIG";

const DEFAULT_WORKER_THREADS: u16 = 2;
const DEFAULT_ADMIN_PORT: u16 = 15000;
const DEFAULT_STATUS_PORT: u16 = 15021;
const DEFAULT_DRAIN_DURATION: Duration = Duration::from_secs(5);

#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub enum RootCert {
    File(PathBuf),
    Static(Bytes),
    Default,
}

#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub enum ConfigSource {
    File(PathBuf),
    Static(Bytes),
}

impl ConfigSource {
    pub async fn read_to_string(&self) -> anyhow::Result<String> {
        Ok(match self {
            ConfigSource::File(path) => tokio::fs::read_to_string(path).await?,
            ConfigSource::Static(data) => std::str::from_utf8(data).map(|s| s.to_string())?,
        })
    }
}

#[derive(serde::Serialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub window_size: u32,
    pub connection_window_size: u32,
    pub frame_size: u32,

    pub socks5_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub readiness_addr: SocketAddr,
    pub inbound_addr: SocketAddr,
    pub inbound_plaintext_addr: SocketAddr,
    pub outbound_addr: SocketAddr,

    /// The name of the node this ztunnel is running as.
    pub local_node: Option<String>,

    /// CA address to use. If fake_ca is set, this will be None.
    /// Note: we do not implicitly use None when set to "" since using the fake_ca is not secure.
    pub ca_address: Option<String>,
    /// Root cert for CA TLS verification.
    pub ca_root_cert: RootCert,
    /// XDS address to use. If unset, XDS will not be used.
    pub xds_address: Option<String>,
    /// Root cert for XDS TLS verification.
    pub xds_root_cert: RootCert,
    /// YAML config for local XDS workloads
    #[serde(skip_serializing)]
    pub local_xds_config: Option<ConfigSource>,
    /// If true, on-demand XDS will be used
    pub xds_on_demand: bool,

    /// If true, then use builtin fake CA with self-signed certificates.
    pub fake_ca: bool,
    #[serde(skip_serializing)]
    pub auth: identity::AuthSource,
    pub termination_grace_period: time::Duration,

    pub proxy_metadata: HashMap<String, String>,

    /// Specify the number of worker threads the Tokio Runtime will use.
    pub num_worker_threads: usize,

    // If true, then use original source proxying
    pub enable_original_source: Option<bool>,

    // CLI args passed to ztunnel at runtime
    pub proxy_args: String,

    // For testing purposes the use of zero copy can be disabled to test with
    // buffered copy in downstream/upstream relay.
    // Can be removed when we support metrics for zero copy as well.
    pub zero_copy_enabled: bool,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid env var {0}={1}")]
    EnvVar(String, String),
    #[error("error parsing proxy config: {0}")]
    ProxyConfig(anyhow::Error),
}

/// GoDuration wraps a Duration to implement golang Duration parsing semantics
struct GoDuration(Duration);

impl FromStr for GoDuration {
    type Err = go_parse_duration::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        go_parse_duration::parse_duration(s).map(|ns| GoDuration(Duration::from_nanos(ns as u64)))
    }
}

fn parse<T: FromStr>(env: &str) -> Result<Option<T>, Error> {
    match std::env::var(env) {
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
    let cli_args: Vec<String> = std::env::args().collect();
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
    let default_istiod_address = if std::env::var(KUBERNETES_SERVICE_HOST).is_ok() {
        "https://istiod.istio-system.svc:15012".to_string()
    } else {
        "https://localhost:15012".to_string()
    };
    let xds_address = empty_to_none(
        parse(XDS_ADDRESS)?
            .or(pc.discovery_address)
            .or_else(|| Some(default_istiod_address.clone())),
    );

    let fake_ca = parse_default(FAKE_CA, false)?;
    let ca_address = empty_to_none(if fake_ca {
        None
    } else {
        Some(parse_default(CA_ADDRESS, default_istiod_address)?)
    });

    Ok(Config {
        window_size: 4 * 1024 * 1024,
        connection_window_size: 4 * 1024 * 1024,
        frame_size: 1024 * 1024,

        termination_grace_period: parse(TERMINATION_GRACE_PERIOD)?
            .map(|gd: GoDuration| gd.0)
            .or(pc.termination_drain_duration)
            .unwrap_or(DEFAULT_DRAIN_DURATION),

        // admin API should only be accessible over localhost
        admin_addr: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            pc.proxy_admin_port.unwrap_or(DEFAULT_ADMIN_PORT),
        ),
        readiness_addr: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            pc.status_port.unwrap_or(DEFAULT_STATUS_PORT),
        ),

        socks5_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15080),
        inbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15008),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15006),
        outbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15001),

        local_node: parse(NODE_NAME)?,

        xds_address,
        // TODO: full FindRootCAForXDS logic like in Istio
        xds_root_cert: RootCert::File("./var/run/secrets/istio/root-cert.pem".parse().unwrap()),
        ca_address,
        // TODO: full FindRootCAForCA logic like in Istio
        ca_root_cert: RootCert::File("./var/run/secrets/istio/root-cert.pem".parse().unwrap()),
        local_xds_config: parse::<PathBuf>(LOCAL_XDS_PATH)?.map(ConfigSource::File),
        xds_on_demand: parse_default(XDS_ON_DEMAND, false)?,
        proxy_metadata: pc.proxy_metadata,

        fake_ca,
        auth: identity::AuthSource::Token(PathBuf::from(r"./var/run/secrets/tokens/istio-token")),

        num_worker_threads: parse_default(
            ZTUNNEL_WORKER_THREADS,
            pc.concurrency
                .unwrap_or(DEFAULT_WORKER_THREADS)
                .try_into()
                .expect("concurrency cannot be negative"),
        )?,

        enable_original_source: parse(ENABLE_ORIG_SRC)?,
        proxy_args: parse_args(),
        zero_copy_enabled: true,
    })
}

#[derive(serde::Deserialize, Default, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MeshConfig {
    pub default_config: Option<ProxyConfig>,
}

#[derive(serde::Deserialize, Default, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProxyConfig {
    pub discovery_address: Option<String>,
    pub proxy_admin_port: Option<u16>,
    pub status_port: Option<u16>,
    pub concurrency: Option<u16>,
    pub termination_drain_duration: Option<Duration>,
    pub proxy_metadata: HashMap<String, String>,
}

impl ProxyConfig {
    fn merge(mut self, other: Self) -> Self {
        self.discovery_address = other
            .discovery_address
            .or_else(|| self.discovery_address.clone());
        self.proxy_admin_port = other.proxy_admin_port.or(self.proxy_admin_port);
        self.status_port = other.status_port.or(self.status_port);
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
        .filter_map(|(k, v)| Some((k.strip_prefix("")?.to_string(), v)))
        .collect();

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
        assert_eq!(cfg.readiness_addr.port(), 15888);
        assert_eq!(cfg.admin_addr.port(), 15099);
        // TODO remove prefix
        assert_eq!(cfg.proxy_metadata["ISTIO_META_FOO"], "foo");

        // env only
        let pc_env = Some(
            r#"{ 
            "discoveryAddress": "istiod-rev0.istio-system-2:15012", 
            "proxyAdminPort": 15999,
            "proxyMetadata": {
              "ISTIO_META_BAR": "bar",
              "ISTIO_META_FOOBAR": "foobar-overwritten",
            }
        }"#,
        );
        let pc = construct_proxy_config("", pc_env).unwrap();
        let cfg = construct_config(pc).unwrap();
        assert_eq!(
            cfg.readiness_addr.port(),
            default_config.readiness_addr.port()
        );
        assert_eq!(cfg.xds_address.unwrap(), "istiod-rev0.istio-system-2:15012");
        assert_eq!(cfg.proxy_metadata["ISTIO_META_BAR"], "bar");
        assert_eq!(
            cfg.proxy_metadata["ISTIO_META_FOOBAR"],
            "foobar-overwritten"
        );

        // both (with a field override and metadata override)
        let pc = construct_proxy_config(mesh_config_path, pc_env).unwrap();
        let cfg = construct_config(pc).unwrap();
        assert_eq!(cfg.readiness_addr.port(), 15888);
        assert_eq!(cfg.admin_addr.port(), 15999);
        assert_eq!(cfg.proxy_metadata["ISTIO_META_FOO"], "foo");
        assert_eq!(cfg.proxy_metadata["ISTIO_META_BAR"], "bar");
        assert_eq!(
            cfg.proxy_metadata["ISTIO_META_FOOBAR"],
            "foobar-overwritten"
        );
    }
}
