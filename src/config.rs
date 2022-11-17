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

use crate::identity;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;

#[derive(Clone, Debug)]
pub struct Config {
    pub tls: bool,

    pub window_size: u32,
    pub connection_window_size: u32,
    pub frame_size: u32,

    pub inbound_addr: SocketAddr,
    pub inbound_plaintext_addr: SocketAddr,
    pub outbound_addr: SocketAddr,

    /// The name of the node this ztunnel is running as.
    pub local_node: Option<String>,

    /// Filepath to a local xds file for workloads, as YAML.
    pub local_xds_path: Option<String>,
    /// If true, on-demand XDS will be used
    pub xds_on_demand: bool,

    pub auth: identity::AuthSource,

    pub termination_grace_period: time::Duration,

    /// Specify the number of worker threads the Tokio Runtime will use.
    pub num_worker_threads: usize,
}

const DEFAULT_WOKRER_THREADS: usize = 2;

impl Default for Config {
    fn default() -> Config {
        Config {
            tls: std::env::var("TLS").unwrap_or_else(|_| "".into()) != "off",
            window_size: 4 * 1024 * 1024,
            connection_window_size: 4 * 1024 * 1024,
            frame_size: 1024 * 1024,

            termination_grace_period: Duration::from_secs(5),

            inbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15008),
            inbound_plaintext_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15006),
            outbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 15001),

            local_node: Some(std::env::var("NODE_NAME").unwrap_or_else(|_| "".into()))
                .filter(|s| !s.is_empty()),

            local_xds_path: Some(std::env::var("LOCAL_XDS_PATH").unwrap_or_else(|_| "".into()))
                .filter(|s| !s.is_empty()),
            xds_on_demand: std::env::var("XDS_ON_DEMAND").unwrap_or_else(|_| "".into()) == "on",

            auth: identity::AuthSource::Token(PathBuf::from(
                r"./var/run/secrets/tokens/istio-token",
            )),

            num_worker_threads: std::env::var("ZTUNNEL_WOKRER_THREADS")
                .ok()
                .map(|v| {
                    v.parse::<usize>()
                        .ok()
                        .filter(|n| *n > 0)
                        .unwrap_or(DEFAULT_WOKRER_THREADS)
                })
                .unwrap_or(DEFAULT_WOKRER_THREADS),
        }
    }
}
