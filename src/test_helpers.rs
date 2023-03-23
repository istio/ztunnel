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
use std::default::Default;
use std::fmt::Debug;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Add;
use std::time::{Duration, SystemTime};

use bytes::{BufMut, Bytes};
use tracing::trace;

use crate::config::ConfigSource;
use crate::config::{self, RootCert};
use crate::workload::Protocol::{HBONE, TCP};
use crate::workload::{LocalConfig, LocalWorkload, Workload};

pub mod app;
pub mod ca;
pub mod components;
pub mod helpers;
pub mod netns;
pub mod tcp;
pub mod xds;

pub fn test_config_with_waypoint(addr: IpAddr) -> config::Config {
    config::Config {
        local_xds_config: Some(ConfigSource::Static(
            local_xds_config(80, Some(addr)).unwrap(),
        )),
        ..test_config()
    }
}

pub fn test_config_with_port_xds_addr_and_root_cert(
    port: u16,
    xds_addr: Option<String>,
    xds_root_cert: Option<RootCert>,
) -> config::Config {
    config::Config {
        xds_address: xds_addr,
        fake_ca: true,
        // TODO: full FindRootCAForXDS logic like in Istio
        xds_root_cert: match xds_root_cert {
            Some(cert) => cert,
            None => RootCert::File("./var/run/secrets/istio/root-cert.pem".parse().unwrap()),
        },
        local_xds_config: Some(ConfigSource::Static(local_xds_config(port, None).unwrap())),
        // Switch all addressed to localhost (so we don't make a bunch of ports expose on public internet when someone runs a test),
        // and port 0 (to avoid port conflicts)
        // inbound_addr cannot do localhost since we abuse that its listening on all of 127.0.0.0/8 range.
        inbound_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        socks5_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        admin_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        readiness_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        stats_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        outbound_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        ..config::parse_config().unwrap()
    }
}

pub fn test_config_with_port(port: u16) -> config::Config {
    test_config_with_port_xds_addr_and_root_cert(port, None, None)
}

pub fn test_config() -> config::Config {
    test_config_with_port(80)
}

// Define some test workloads. Intentionally do not use 127.0.0.1 to avoid accidentally using a workload
pub const TEST_WORKLOAD_SOURCE: &str = "127.0.0.2";
pub const TEST_WORKLOAD_HBONE: &str = "127.0.0.3";
pub const TEST_WORKLOAD_TCP: &str = "127.0.0.4";
pub const TEST_WORKLOAD_WAYPOINT: &str = "127.0.0.4";
pub const TEST_VIP: &str = "127.10.0.1";

pub fn test_default_workload() -> Workload {
    Workload {
        workload_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        waypoint_addresses: Vec::new(),
        gateway_address: None,
        protocol: Default::default(),
        name: "".to_string(),
        namespace: "".to_string(),
        trust_domain: "cluster.local".to_string(),
        service_account: "default".to_string(),
        workload_name: "".to_string(),
        workload_type: "deployment".to_string(),
        canonical_name: "".to_string(),
        canonical_revision: "".to_string(),
        node: "".to_string(),
        status: Default::default(),
        cluster_id: "Kubernetes".to_string(),

        authorization_policies: Vec::new(),
        native_hbone: false,
    }
}

fn local_xds_config(echo_port: u16, waypoint_ip: Option<IpAddr>) -> anyhow::Result<Bytes> {
    let mut res: Vec<LocalWorkload> = vec![
        LocalWorkload {
            workload: Workload {
                workload_ip: TEST_WORKLOAD_HBONE.parse()?,
                protocol: HBONE,
                name: "local-hbone".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
                node: "local".to_string(),
                ..test_default_workload()
            },
            vips: HashMap::from([(TEST_VIP.to_string(), HashMap::from([(80u16, echo_port)]))]),
        },
        LocalWorkload {
            workload: Workload {
                workload_ip: TEST_WORKLOAD_TCP.parse()?,
                protocol: TCP,
                name: "local-tcp".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
                node: "local".to_string(),
                ..test_default_workload()
            },
            vips: HashMap::from([(TEST_VIP.to_string(), HashMap::from([(80u16, echo_port)]))]),
        },
        LocalWorkload {
            workload: Workload {
                workload_ip: TEST_WORKLOAD_SOURCE.parse()?,
                protocol: TCP,
                name: "local-source".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
                node: "local".to_string(),
                ..test_default_workload()
            },
            vips: Default::default(),
        },
    ];
    if let Some(waypoint_ip) = waypoint_ip {
        res.push(LocalWorkload {
            workload: Workload {
                workload_ip: TEST_WORKLOAD_WAYPOINT.parse()?,
                protocol: HBONE,
                name: "local-waypoint".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
                node: "local".to_string(),
                waypoint_addresses: vec![waypoint_ip],
                ..test_default_workload()
            },
            vips: Default::default(),
        })
    }
    let lc = LocalConfig {
        workloads: res,
        policies: vec![],
        services: vec![],
    };
    let mut b = bytes::BytesMut::new().writer();
    serde_yaml::to_writer(&mut b, &lc)?;
    Ok(b.into_inner().freeze())
}

pub async fn assert_eventually<F, T, Fut>(dur: Duration, f: F, expected: T)
where
    F: Fn() -> Fut,
    Fut: Future<Output = T>,
    T: Eq + Debug,
{
    let mut delay = Duration::from_millis(10);
    let end = SystemTime::now().add(dur);
    let mut last: T;
    let mut attempts = 0;
    loop {
        attempts += 1;
        last = f().await;
        if last == expected {
            return;
        }
        trace!("attempt {attempts} with delay {delay:?}");
        if SystemTime::now().add(delay) > end {
            panic!("assert_eventually failed after {attempts}: last response: {last:?}")
        }
        tokio::time::sleep(delay).await;
        delay *= 2;
    }
}
