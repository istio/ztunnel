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

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use tokio::time;

use crate::identity;

const KUBERNETES_SERVICE_HOST: &str = "KUBERNETES_SERVICE_HOST";
const NODE_NAME: &str = "NODE_NAME";
const LOCAL_XDS_PATH: &str = "LOCAL_XDS_PATH";
const XDS_ON_DEMAND: &str = "XDS_ON_DEMAND";
const XDS_ADDRESS: &str = "XDS_ADDRESS";
const TERMINATION_GRACE_PERIOD: &str = "TERMINATION_GRACE_PERIOD";
const FAKE_CA: &str = "FAKE_CA";
const ZTUNNEL_WORKER_THREADS: &str = "ZTUNNEL_WORKER_THREADS";

const DEFAULT_WORKER_THREADS: usize = 2;

#[derive(Clone, Debug)]
pub struct Config {
    pub window_size: u32,
    pub connection_window_size: u32,
    pub frame_size: u32,

    pub socks5_addr: SocketAddr,
    pub admin_addr: SocketAddr,
    pub inbound_addr: SocketAddr,
    pub inbound_plaintext_addr: SocketAddr,
    pub outbound_addr: SocketAddr,

    /// The name of the node this ztunnel is running as.
    pub local_node: Option<String>,

    /// XDS address to use. If unset, XDS will not be used.
    pub xds_address: Option<String>,
    /// Filepath to a local xds file for workloads, as YAML.
    pub local_xds_path: Option<String>,
    /// If true, on-demand XDS will be used
    pub xds_on_demand: bool,

    /// If true, then use builtin fake CA with self-signed certificates.
    pub fake_ca: bool,
    pub auth: identity::AuthSource,

    pub termination_grace_period: time::Duration,

    /// Specify the number of worker threads the Tokio Runtime will use.
    pub num_worker_threads: usize,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid env var {0}={1}")]
    RequestFailure(String, String),
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
            .map_err(|_| Error::RequestFailure(env.to_string(), val)),
        Err(_) => Ok(None),
    }
}

fn parse_default<T: FromStr>(env: &str, default: T) -> Result<T, Error> {
    parse(env).map(|v| v.unwrap_or(default))
}

pub fn parse_config() -> Result<Config, Error> {
    let default_xds_address = if std::env::var(KUBERNETES_SERVICE_HOST).is_ok() {
        "https://istiod.istio-system:15012".to_string()
    } else {
        "https://localhost:15012".to_string()
    };
    let xds_address =
        Some(parse_default(XDS_ADDRESS, default_xds_address)?).filter(|s| !s.is_empty());
    Ok(Config {
        window_size: 4 * 1024 * 1024,
        connection_window_size: 4 * 1024 * 1024,
        frame_size: 1024 * 1024,

        termination_grace_period: parse_default(
            TERMINATION_GRACE_PERIOD,
            GoDuration(Duration::from_secs(5)),
        )?
        .0,

        admin_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15021),
        socks5_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15080),
        inbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15008),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15006),
        outbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15001),

        local_node: parse(NODE_NAME)?,

        xds_address,
        local_xds_path: parse(LOCAL_XDS_PATH)?,
        xds_on_demand: parse_default(XDS_ON_DEMAND, false)?,

        fake_ca: parse_default(FAKE_CA, false)?,
        auth: identity::AuthSource::Token(PathBuf::from(r"./var/run/secrets/tokens/istio-token")),

        num_worker_threads: parse_default(ZTUNNEL_WORKER_THREADS, DEFAULT_WORKER_THREADS)?,
    })
}
