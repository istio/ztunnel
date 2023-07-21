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

use crate::config::ConfigSource;
use crate::config::{self, RootCert};
use crate::state::service::{Endpoint, Service};
use crate::state::workload::Protocol;
use crate::state::workload::Protocol::{HBONE, TCP};
use crate::state::workload::{
    gatewayaddress, GatewayAddress, NamespacedHostname, NetworkAddress, Workload,
};
use crate::state::{DemandProxyState, ProxyState};
use crate::xds::istio::security::Authorization as XdsAuthorization;
use crate::xds::istio::workload::Service as XdsService;
use crate::xds::istio::workload::Workload as XdsWorkload;
use crate::xds::{LocalConfig, LocalWorkload, ProxyStateUpdater};
use bytes::{BufMut, Bytes};
use http_body_util::{BodyExt, Full};
use hyper::Response;
use std::collections::HashMap;
use std::default::Default;
use std::fmt::Debug;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Add;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tracing::trace;
use trust_dns_resolver::config::*;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

pub mod app;
pub mod ca;
pub mod dns;
pub mod helpers;
pub mod tcp;
pub mod xds;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod netns;

pub fn test_config_with_waypoint(addr: IpAddr) -> config::Config {
    config::Config {
        local_xds_config: Some(ConfigSource::Static(
            local_xds_config(80, Some(addr), vec![]).unwrap(),
        )),
        ..test_config()
    }
}

pub fn test_config_with_port_xds_addr_and_root_cert(
    port: u16,
    xds_addr: Option<String>,
    xds_root_cert: Option<RootCert>,
    xds_config: Option<ConfigSource>,
) -> config::Config {
    config::Config {
        xds_address: xds_addr,
        fake_ca: true,
        dns_proxy: true,
        // TODO: full FindRootCAForXDS logic like in Istio
        xds_root_cert: match xds_root_cert {
            Some(cert) => cert,
            None => RootCert::File("./var/run/secrets/istio/root-cert.pem".parse().unwrap()),
        },
        local_xds_config: match xds_config {
            Some(c) => Some(c),
            None => Some(ConfigSource::Static(
                local_xds_config(port, None, vec![]).unwrap(),
            )),
        },
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
        dns_proxy_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        ..config::parse_config().unwrap()
    }
}

pub async fn add_nip_io_nameserver(mut cfg: config::Config) -> config::Config {
    // add nip.io as a nameserver so our test hostnames can resolve to reliable IPs
    let r = TokioAsyncResolver::new(
        ResolverConfig::default(),
        ResolverOpts::default(),
        TokioHandle,
    )
    .unwrap();
    let resp = r.lookup_ip("nip.io").await.unwrap();
    let ips = resp.iter().collect::<Vec<_>>();
    assert!(!ips.is_empty());
    for ip in ips {
        let name_server = NameServerConfig {
            socket_addr: SocketAddr::new(ip, 53),
            protocol: trust_dns_resolver::config::Protocol::Udp,
            tls_dns_name: None,
            trust_nx_responses: false,
            bind_addr: None,
        };
        cfg.dns_resolver_config.add_name_server(name_server);
    }
    cfg
}

pub fn test_config_with_port(port: u16) -> config::Config {
    test_config_with_port_xds_addr_and_root_cert(port, None, None, None)
}

pub fn test_config() -> config::Config {
    test_config_with_port(80)
}

// Define some test workloads. Intentionally do not use 127.0.0.1 to avoid accidentally using a workload
pub const TEST_WORKLOAD_SOURCE: &str = "127.0.0.2";
pub const TEST_WORKLOAD_HBONE: &str = "127.0.0.3";
pub const TEST_WORKLOAD_TCP: &str = "127.0.0.4";
pub const TEST_WORKLOAD_WAYPOINT: &str = "127.0.0.5";
pub const TEST_VIP: &str = "127.10.0.1";
pub const TEST_VIP_DNS: &str = "127.10.0.2";
pub const TEST_SERVICE_NAMESPACE: &str = "default";
pub const TEST_SERVICE_NAME: &str = "local-vip";
pub const TEST_SERVICE_HOST: &str = "local-vip.default.svc.cluster.local";
pub const TEST_SERVICE_DNS_HBONE_NAME: &str = "local-vip-async-dns";
pub const TEST_SERVICE_DNS_HBONE_HOST: &str = "local-vip-async-dns.default.svc.cluster.local";

pub fn localhost_error_message() -> String {
    let addrs = &[
        TEST_WORKLOAD_SOURCE,
        TEST_WORKLOAD_HBONE,
        TEST_WORKLOAD_TCP,
        TEST_VIP,
    ];
    format!(
        "These tests use the following loopback addresses: {:?}. \
    Your OS may require an explicit alias for each. If so, you'll need to manually \
    configure your system for each IP (e.g. `sudo ifconfig lo0 alias 127.0.0.2 up`).",
        addrs
    )
}

pub fn mock_default_service() -> Service {
    let vip1 = NetworkAddress {
        address: IpAddr::V4(Ipv4Addr::new(127, 0, 10, 1)),
        network: "".to_string(),
    };
    let vips = vec![vip1];
    let mut ports = HashMap::new();
    ports.insert(8080, 80);
    let endpoints = HashMap::new();
    Service {
        name: "".to_string(),
        namespace: "default".to_string(),
        hostname: "defaulthost".to_string(),
        vips,
        ports,
        endpoints,
        subject_alt_names: vec![],
    }
}

pub fn test_default_workload() -> Workload {
    Workload {
        workload_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        waypoint: None,
        network_gateway: None,
        gateway_address: None,
        protocol: Default::default(),
        uid: "".to_string(),
        name: "".to_string(),
        namespace: "".to_string(),
        trust_domain: "cluster.local".to_string(),
        service_account: "default".to_string(),
        network: "".to_string(),
        workload_name: "".to_string(),
        workload_type: "deployment".to_string(),
        canonical_name: "".to_string(),
        canonical_revision: "".to_string(),
        hostname: "".to_string(),
        node: "".to_string(),
        status: Default::default(),
        cluster_id: "Kubernetes".to_string(),

        authorization_policies: Vec::new(),
        native_tunnel: false,
    }
}

fn test_custom_workload(
    ip_str: &str,
    name: &str,
    protocol: Protocol,
    echo_port: u16,
    services_vec: Vec<&Service>,
    hostname_only: bool,
) -> anyhow::Result<LocalWorkload> {
    let host = match hostname_only {
        true => format!("example.{}.nip.io.", ip_str),
        false => "".to_string(),
    };
    let wips = match hostname_only {
        true => vec![],
        false => vec![ip_str.parse()?],
    };
    let workload = Workload {
        workload_ips: wips,
        hostname: host,
        protocol,
        uid: format!("cluster1//v1/Pod/default/{}", name),
        name: name.to_string(),
        namespace: "default".to_string(),
        service_account: "default".to_string(),
        node: "local".to_string(),
        ..test_default_workload()
    };
    let mut services = HashMap::new();
    for s in services_vec.iter() {
        let key = format!("{}/{}", s.namespace, s.hostname);
        services.insert(key, HashMap::from([(80u16, echo_port)]));
    }
    Ok(LocalWorkload { workload, services })
}

fn test_custom_svc(
    name: &str,
    hostname: &str,
    vip: &str,
    workload_name: &str,
    endpoint: &str,
    echo_port: u16,
) -> anyhow::Result<Service> {
    let addr = match endpoint.is_empty() {
        true => None,
        false => Some(NetworkAddress {
            network: "".to_string(),
            address: endpoint.parse()?,
        }),
    };
    Ok(Service {
        name: name.to_string(),
        namespace: TEST_SERVICE_NAMESPACE.to_string(),
        hostname: hostname.to_string(),
        vips: vec![NetworkAddress {
            network: "".to_string(),
            address: vip.parse()?,
        }],
        ports: HashMap::from([(80u16, echo_port)]),
        endpoints: HashMap::from([(
            format!("cluster1//v1/Pod/default/{}", workload_name),
            Endpoint {
                workload_uid: format!("cluster1//v1/Pod/default/{}", workload_name),
                service: NamespacedHostname {
                    namespace: TEST_SERVICE_NAMESPACE.to_string(),
                    hostname: hostname.to_string(),
                },
                address: addr,
                port: HashMap::from([(80u16, echo_port)]),
            },
        )]),
        subject_alt_names: vec!["spiffe://cluster.local/ns/default/sa/default".to_string()],
    })
}

pub fn local_xds_config(
    echo_port: u16,
    waypoint_ip: Option<IpAddr>,
    policies: Vec<crate::rbac::Authorization>,
) -> anyhow::Result<Bytes> {
    let default_svc = test_custom_svc(
        TEST_SERVICE_NAME,
        TEST_SERVICE_HOST,
        TEST_VIP,
        "local-hbone",
        TEST_WORKLOAD_HBONE,
        echo_port,
    )?;
    let dns_svc = test_custom_svc(
        TEST_SERVICE_DNS_HBONE_NAME,
        TEST_SERVICE_DNS_HBONE_HOST,
        TEST_VIP_DNS,
        "local-tcp-via-dns",
        "",
        echo_port,
    )?;

    let mut res: Vec<LocalWorkload> = vec![
        test_custom_workload(
            TEST_WORKLOAD_SOURCE,
            "local-source",
            TCP,
            echo_port,
            vec![&default_svc],
            false,
        )?,
        test_custom_workload(
            TEST_WORKLOAD_HBONE,
            "local-hbone",
            HBONE,
            echo_port,
            vec![&default_svc],
            false,
        )?,
        test_custom_workload(
            TEST_WORKLOAD_TCP,
            "local-tcp-via-dns",
            TCP,
            echo_port,
            vec![&dns_svc],
            true,
        )?,
        test_custom_workload(
            TEST_WORKLOAD_TCP,
            "local-tcp",
            TCP,
            echo_port,
            vec![],
            false,
        )?,
    ];
    if let Some(waypoint_ip) = waypoint_ip {
        res.push(LocalWorkload {
            workload: Workload {
                workload_ips: vec![TEST_WORKLOAD_WAYPOINT.parse()?],
                protocol: HBONE,
                uid: "cluster1//v1/Pod/default/local-waypoint".to_string(),
                name: "local-waypoint".to_string(),
                namespace: "default".to_string(),
                service_account: "default".to_string(),
                node: "local".to_string(),
                waypoint: Some(GatewayAddress {
                    destination: gatewayaddress::Destination::Address(NetworkAddress {
                        network: "".to_string(),
                        address: waypoint_ip,
                    }),
                    port: 15008,
                }),
                ..test_default_workload()
            },
            services: Default::default(),
        })
    }
    let svcs: Vec<Service> = vec![default_svc, dns_svc];
    let lc = LocalConfig {
        workloads: res,
        policies,
        services: svcs,
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

pub fn new_proxy_state(
    xds_workloads: &[XdsWorkload],
    xds_services: &[XdsService],
    xds_authorizations: &[XdsAuthorization],
) -> DemandProxyState {
    let state = Arc::new(RwLock::new(ProxyState::default()));
    let updater = ProxyStateUpdater::new_no_fetch(state.clone());

    for w in xds_workloads {
        updater.insert_workload(w.clone()).unwrap();
    }
    for s in xds_services {
        updater.insert_service(s.clone()).unwrap();
    }
    for a in xds_authorizations {
        updater.insert_authorization(a.clone()).unwrap();
    }
    DemandProxyState::new(state, None)
}

pub async fn get_response_str(resp: Response<Full<Bytes>>) -> String {
    let resp_bytes = resp
        .body()
        .clone()
        .frame()
        .await
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    String::from(std::str::from_utf8(&resp_bytes).unwrap())
}
