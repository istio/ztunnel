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
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use bytes::{BufMut, Bytes};

use crate::config;
use crate::config::ConfigSource;
use crate::workload::Protocol::{HBONE, TCP};
use crate::workload::{LocalWorkload, Workload};

pub mod app;
pub mod ca;
pub mod helpers;
pub mod tcp;

pub fn test_config_with_port_and_node(port: u16, node: Option<String>) -> config::Config {
    config::Config {
        xds_address: None,
        fake_ca: true,
        local_xds_config: Some(ConfigSource::Static(local_xds_config(port).unwrap())),
        socks5_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        inbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        admin_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        readiness_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        outbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        local_node: node,
        ..config::parse_config().unwrap()
    }
}

pub fn test_config_with_port(port: u16) -> config::Config {
    test_config_with_port_and_node(port, None)
}

pub fn test_config() -> config::Config {
    test_config_with_port(80)
}

const HBONE_IP: &str = "127.0.0.1";
const TCP_IP: &str = "127.0.0.2";
const TEST_VIP: &str = "127.10.0.1";

fn local_xds_config(echo_port: u16) -> anyhow::Result<Bytes> {
    let mut b = bytes::BytesMut::new().writer();
    let res: Vec<LocalWorkload> = vec![
        LocalWorkload {
            workload: Workload {
                workload_ip: HBONE_IP.parse()?,
                protocol: HBONE,
                name: "local-hbone".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
                node: "local".to_string(),

                waypoint_addresses: vec![],
                gateway_address: None,
                workload_name: "".to_string(),
                workload_type: "".to_string(),
                canonical_name: "".to_string(),
                canonical_revision: "".to_string(),
                native_hbone: false,
            },
            vips: HashMap::from([(TEST_VIP.to_string(), HashMap::from([(80u16, echo_port)]))]),
        },
        LocalWorkload {
            workload: Workload {
                workload_ip: TCP_IP.parse()?,
                protocol: TCP,
                name: "local-tcp".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
                node: "local".to_string(),

                waypoint_addresses: vec![],
                gateway_address: None,
                workload_name: "".to_string(),
                workload_type: "".to_string(),
                canonical_name: "".to_string(),
                canonical_revision: "".to_string(),
                native_hbone: false,
            },
            vips: HashMap::from([(TEST_VIP.to_string(), HashMap::from([(80u16, echo_port)]))]),
        },
    ];
    serde_yaml::to_writer(&mut b, &res)?;
    Ok(b.into_inner().freeze())
}
