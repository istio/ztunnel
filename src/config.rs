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
use tracing::warn;

use crate::identity;
use crate::xds::istio::mesh::ProxyConfig;

const KUBERNETES_SERVICE_HOST: &str = "KUBERNETES_SERVICE_HOST";
const NODE_NAME: &str = "NODE_NAME";
const LOCAL_XDS_PATH: &str = "LOCAL_XDS_PATH";
const XDS_ON_DEMAND: &str = "XDS_ON_DEMAND";
const XDS_ADDRESS: &str = "XDS_ADDRESS";
const CA_ADDRESS: &str = "CA_ADDRESS";
const TERMINATION_GRACE_PERIOD: &str = "TERMINATION_GRACE_PERIOD";
const FAKE_CA: &str = "FAKE_CA";
const ZTUNNEL_WORKER_THREADS: &str = "ZTUNNEL_WORKER_THREADS";
const PROXY_CONFIG: &str = "PROXY_CONFIG";

const DEFAULT_WORKER_THREADS: i32 = 2;
const DEFAULT_ADMIN_PORT: i32 = 15021;
const DEFAULT_STATUS_PORT: i32 = 15020;
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

    // CLI args passed to ztunnel at runtime
    pub proxy_args: String,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid env var {0}={1}")]
    EnvVar(String, String),
    #[error("error occurred: {0}")]
    Other(anyhow::Error),
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
    let mesh_config_path = "./etc/istio/config/mesh";
    let pc_env = parse::<String>("PROXY_CONFIG")?;
    let pc = construct_proxy_config(mesh_config_path, pc_env.as_deref()).map_err(Error::Other)?;
    construct_config(pc)
}

pub fn construct_config(pc: ProxyConfig) -> Result<Config, Error> {
    let xds_address =
        Some(parse_default(XDS_ADDRESS, pc.discovery_address.clone())?).filter(|s| !s.is_empty());

    let fake_ca = parse_default(FAKE_CA, false)?;
    let ca_address = if fake_ca {
        None
    } else {
        Some(parse_default(CA_ADDRESS, pc.discovery_address)?)
    };

    Ok(Config {
        window_size: 4 * 1024 * 1024,
        connection_window_size: 4 * 1024 * 1024,
        frame_size: 1024 * 1024,

        termination_grace_period: parse_default(
            TERMINATION_GRACE_PERIOD,
            GoDuration(
                pc.termination_drain_duration
                    .map(|v| v.try_into().unwrap())
                    .unwrap_or(DEFAULT_DRAIN_DURATION),
            ),
        )?
        .0,

        // admin API should only be accessible over localhost
        admin_addr: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            pc.proxy_admin_port
                .try_into()
                .expect("proxy_admin_port is a valid port number"),
        ),
        readiness_addr: SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            pc.status_port
                .try_into()
                .expect("status_port is a valid port number"),
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

        proxy_args: parse_args(),
    })
}

pub fn default_proxy_config() -> ProxyConfig {
    ProxyConfig {
        proxy_admin_port: DEFAULT_ADMIN_PORT,
        status_port: DEFAULT_STATUS_PORT,
        concurrency: Some(DEFAULT_WORKER_THREADS),
        discovery_address: if std::env::var(KUBERNETES_SERVICE_HOST).is_ok() {
            "https://istiod.istio-system.svc:15012".to_string()
        } else {
            "https://localhost:15012".to_string()
        },
        termination_drain_duration: Some(DEFAULT_DRAIN_DURATION.try_into().unwrap()),
        ..Default::default()
    }
}

fn construct_proxy_config(
    mesh_config_path: &str,
    pc_env: Option<&str>,
) -> anyhow::Result<ProxyConfig> {
    let mesh_config:Option<serde_yaml::Value> = match fs::File::open(mesh_config_path) {
        Ok(f) => serde_yaml::from_reader(f)
            .map(Some)
            .map_err(anyhow::Error::new),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(anyhow!(e))
            }
        }
    }?;
    let proxy_config_env = pc_env.map(serde_yaml::from_str).unwrap_or(Ok(None))?;

    let yaml = match (mesh_config, proxy_config_env) {
        (Some(mc), Some(pc_env)) => {
            let mut mc = mc
                .get("defaultConfig")
                .unwrap_or(&serde_yaml::Value::Null)
                .clone();
            merge_yaml(&mut mc, pc_env);
            Some(mc)
        }
        (Some(mc), None) => Some(
            mc.get("defaultConfig")
                .unwrap_or(&serde_yaml::Value::Null)
                .clone(),
        ),
        (None, Some(pc_env)) => Some(pc_env),
        (None, None) => None,
    };
    
    if let Some(yaml) = yaml {
        serde_yaml::from_value(yaml).map_err(anyhow::Error::new)
    } else {
        Ok(default_proxy_config())
    }
}

fn merge_yaml(a: &mut serde_yaml::Value, b: serde_yaml::Value) {
    match (a, b) {
        (a @ &mut serde_yaml::Value::Mapping(_), serde_yaml::Value::Mapping(b)) => {
            let a = a.as_mapping_mut().unwrap();
            for (k, v) in b {
                if v.is_sequence() && a.contains_key(&k) && a[&k].is_sequence() {
                    let mut _b = a.get(&k).unwrap().as_sequence().unwrap().to_owned();
                    _b.append(&mut v.as_sequence().unwrap().to_owned());
                    a[&k] = serde_yaml::Value::from(_b);
                    continue;
                }
                if !a.contains_key(&k) {
                    a.insert(k.to_owned(), v.to_owned());
                } else {
                    merge_yaml(&mut a[&k], v);
                }
            }
        }
        (a, b) => *a = b,
    }
}

#[cfg(test)]
pub mod tests {
    use super::{construct_config, construct_proxy_config, default_proxy_config};
    use crate::xds::istio::mesh::ProxyConfig;

    #[test]
    fn config_from_proxyconfig() {
        // mesh config only
        let mesh_config_path = "./src/test_helpers/mesh_config.yaml";
        let pc = construct_proxy_config(mesh_config_path, None).unwrap();
        let cfg = construct_config(pc).unwrap();
        assert_eq!(cfg.readiness_addr.port(), 15888);
        assert_eq!(cfg.admin_addr.port(), 15099);
        // TODO remove prefix
        assert_eq!(cfg.proxy_metadata["ISTIO_META_FOO"], "bar");

        // env only
        let pc_env = Some(
            r#"{ 
            "discoveryAddress": "istiod-rev0.istio-system-2:15012", 
            "proxyAdminPort": 15999 
        }"#,
        );
        let pc = construct_proxy_config("", pc_env).unwrap();
        let cfg = construct_config(pc).unwrap();
        assert_eq!(
            cfg.readiness_addr.port(),
            default_proxy_config().status_port as u16
        );
        assert_eq!(cfg.xds_address.unwrap(), "istiod-rev0.istio-system-2:15012");

        // both (with one override)
        let pc = construct_proxy_config(mesh_config_path, pc_env).unwrap();
        let cfg = construct_config(pc).unwrap();
        assert_eq!(cfg.readiness_addr.port(), 15888);
        assert_eq!(cfg.admin_addr.port(), 15999);
    }

    #[test]
    fn test_default_from_yaml() {
        // this is sort of "testing a library" but it's nice to check it does what we expect
        let from_yaml: ProxyConfig = serde_yaml::from_value(serde_yaml::Value::Null).unwrap();
        assert_eq!(default_proxy_config().status_port, from_yaml.status_port);
    }
}
