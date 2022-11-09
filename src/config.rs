use crate::identity;
use std::net::SocketAddr;
use std::path::PathBuf;

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
}

impl Default for Config {
    fn default() -> Config {
        Config {
            tls: std::env::var("TLS").unwrap_or_else(|_| "".into()) != "off",
            window_size: 4 * 1024 * 1024,
            connection_window_size: 4 * 1024 * 1024,
            frame_size: 1024 * 1024,

            inbound_addr: "[::]:15008".parse().unwrap(),
            inbound_plaintext_addr: "[::]:15006".parse().unwrap(),
            outbound_addr: "[::]:15001".parse().unwrap(),

            local_node: Some(std::env::var("NODE_NAME").unwrap_or_else(|_| "".into()))
                .filter(|s| !s.is_empty()),

            local_xds_path: Some(std::env::var("LOCAL_XDS_PATH").unwrap_or_else(|_| "".into()))
                .filter(|s| !s.is_empty()),
            xds_on_demand: std::env::var("XDS_ON_DEMAND").unwrap_or_else(|_| "".into()) == "on",

            auth: identity::AuthSource::Token(PathBuf::from(
                r"./var/run/secrets/tokens/istio-token",
            )),
        }
    }
}
