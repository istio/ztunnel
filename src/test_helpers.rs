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
use crate::xds::istio::workload::address;
use crate::xds::istio::workload::Address as XdsAddress;
use crate::xds::istio::workload::Service as XdsService;
use crate::xds::istio::workload::Workload as XdsWorkload;
use crate::xds::{Handler, LocalConfig, LocalWorkload, ProxyStateUpdater, XdsResource, XdsUpdate};
use anyhow::anyhow;
use bytes::{BufMut, Bytes};
use hickory_resolver::config::*;

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
use tokio::sync::mpsc::error::SendError;
use tokio::time::timeout;
use tracing::{debug, trace};

pub mod app;
pub mod ca;
pub mod dns;
pub mod helpers;
#[cfg(target_os = "linux")]
pub mod inpod;
pub mod tcp;
pub mod xds;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod netns;

pub fn can_run_privilged_test() -> bool {
    let is_root = unsafe { libc::getuid() } == 0;
    if !is_root && std::env::var("CI").is_ok() {
        panic!("CI tests should run as root to have full coverage");
    }
    is_root
}

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
        socks5_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)),
        admin_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        readiness_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        stats_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        outbound_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        dns_proxy_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        ..config::parse_config().unwrap()
    }
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
        name: "".into(),
        namespace: "default".into(),
        hostname: "defaulthost".into(),
        vips,
        ports,
        endpoints,
        subject_alt_names: vec![],
        waypoint: None,
        load_balancer: None,
    }
}

pub fn test_default_workload() -> Workload {
    Workload {
        workload_ips: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        waypoint: None,
        network_gateway: None,
        gateway_address: None,
        protocol: Default::default(),
        uid: "".into(),
        name: "".into(),
        namespace: "".into(),
        trust_domain: "cluster.local".into(),
        service_account: "default".into(),
        network: "".into(),
        workload_name: "".into(),
        workload_type: "deployment".into(),
        canonical_name: "".into(),
        canonical_revision: "".into(),
        hostname: "".into(),
        node: "".into(),
        status: Default::default(),
        cluster_id: "Kubernetes".into(),

        authorization_policies: Vec::new(),
        native_tunnel: false,
        application_tunnel: None,
        locality: Default::default(),
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
        hostname: host.into(),
        protocol,
        uid: format!("cluster1//v1/Pod/default/{}", name).into(),
        name: name.into(),
        namespace: "default".into(),
        service_account: "default".into(),
        node: "local".into(),
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
        name: name.into(),
        namespace: TEST_SERVICE_NAMESPACE.into(),
        hostname: hostname.into(),
        vips: vec![NetworkAddress {
            network: "".into(),
            address: vip.parse()?,
        }],
        ports: HashMap::from([(80u16, echo_port)]),
        endpoints: HashMap::from([(
            format!("cluster1//v1/Pod/default/{}", workload_name).into(),
            Endpoint {
                workload_uid: format!("cluster1//v1/Pod/default/{}", workload_name).into(),
                service: NamespacedHostname {
                    namespace: TEST_SERVICE_NAMESPACE.into(),
                    hostname: hostname.into(),
                },
                address: addr,
                port: HashMap::from([(80u16, echo_port)]),
            },
        )]),
        subject_alt_names: vec!["spiffe://cluster.local/ns/default/sa/default".into()],
        waypoint: None,
        load_balancer: None,
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
                uid: "cluster1//v1/Pod/default/local-waypoint".into(),
                name: "local-waypoint".into(),
                namespace: "default".into(),
                service_account: "default".into(),
                node: "local".into(),
                waypoint: Some(GatewayAddress {
                    destination: gatewayaddress::Destination::Address(NetworkAddress {
                        network: "".into(),
                        address: waypoint_ip,
                    }),
                    hbone_mtls_port: 15008,
                    hbone_single_tls_port: Some(15003),
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
        let res = XdsResource {
            name: w.name.as_str().into(),
            resource: XdsAddress {
                r#type: Some(address::Type::Workload(w.clone())),
            },
        };
        let handler = &updater as &dyn Handler<XdsAddress>;
        handler
            .handle(Box::new(&mut vec![XdsUpdate::Update(res)].into_iter()))
            .unwrap();
    }
    for s in xds_services {
        let res = XdsResource {
            name: s.name.as_str().into(),
            resource: XdsAddress {
                r#type: Some(address::Type::Service(s.clone())),
            },
        };
        let handler = &updater as &dyn Handler<XdsAddress>;
        handler
            .handle(Box::new(&mut vec![XdsUpdate::Update(res)].into_iter()))
            .unwrap();
    }
    for a in xds_authorizations {
        let res = XdsResource {
            name: a.name.as_str().into(),
            resource: a.clone(),
        };
        let handler = &updater as &dyn Handler<XdsAuthorization>;
        handler
            .handle(Box::new(&mut vec![XdsUpdate::Update(res)].into_iter()))
            .unwrap();
    }
    DemandProxyState::new(
        state,
        None,
        ResolverConfig::default(),
        ResolverOpts::default(),
    )
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

#[derive(Debug)]
pub struct MpscAckSender<T> {
    tx: tokio::sync::mpsc::Sender<T>,
    ack_rx: tokio::sync::mpsc::Receiver<()>,
}

#[derive(Debug)]
pub struct MpscAckReceiver<T> {
    rx: tokio::sync::mpsc::Receiver<T>,
    ack_tx: tokio::sync::mpsc::Sender<()>,
}

impl<T: Send + Sync + 'static> MpscAckSender<T> {
    pub async fn send_and_wait(&mut self, t: T) -> anyhow::Result<()> {
        debug!("send message");
        self.tx.send(t).await?;
        debug!("wait for ack...");
        timeout(Duration::from_secs(2), self.ack_rx.recv())
            .await?
            .ok_or(anyhow!("failed to receive ack"))?;
        debug!("got ack");
        Ok(())
    }
    pub async fn send(&mut self, t: T) -> anyhow::Result<()> {
        debug!("send message");
        self.tx.send(t).await?;
        Ok(())
    }
    pub async fn wait(&mut self) -> anyhow::Result<()> {
        debug!("wait for ack...");

        timeout(Duration::from_secs(2), self.ack_rx.recv())
            .await?
            .ok_or(anyhow!("failed to receive ack"))?;
        debug!("got ack");
        Ok(())
    }
}

impl<T> MpscAckReceiver<T> {
    pub async fn recv(&mut self) -> Option<T> {
        debug!("recv message");
        self.rx.recv().await
    }
    pub async fn ack(&mut self) -> Result<(), SendError<()>> {
        debug!("sending ack");
        self.ack_tx.send(()).await
    }
}

/// mpsc_ack is a small helper around mpsc that requires ACKing a message.
/// This allows sending a message and waiting until it was full processed, not just read.
/// Users MUST wait for each ACK after reading.
pub fn mpsc_ack<T>(buffer: usize) -> (MpscAckSender<T>, MpscAckReceiver<T>) {
    let (tx, rx) = tokio::sync::mpsc::channel::<T>(buffer);
    let (ack_tx, ack_rx) = tokio::sync::mpsc::channel::<()>(1);
    (MpscAckSender { tx, ack_rx }, MpscAckReceiver { rx, ack_tx })
}
