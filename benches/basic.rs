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

use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use pprof::criterion::{Output, PProfProfiler};
use prometheus_client::registry::Registry;
use tokio::runtime::Runtime;
use ztunnel::state::workload::Workload;
use ztunnel::state::{DemandProxyState, ProxyState, ServiceResolutionMode};
use ztunnel::strng;
use ztunnel::xds::ProxyStateUpdateMutator;
use ztunnel::xds::istio::workload::LoadBalancing;
use ztunnel::xds::istio::workload::Port;
use ztunnel::xds::istio::workload::Service as XdsService;
use ztunnel::xds::istio::workload::Workload as XdsWorkload;
use ztunnel::xds::istio::workload::load_balancing;
use ztunnel::xds::istio::workload::{NetworkAddress as XdsNetworkAddress, PortList};

pub fn xds(c: &mut Criterion) {
    use ztunnel::xds::istio::workload::Port;
    use ztunnel::xds::istio::workload::Service as XdsService;
    use ztunnel::xds::istio::workload::Workload as XdsWorkload;
    use ztunnel::xds::istio::workload::{NetworkAddress as XdsNetworkAddress, PortList};
    let mut c = c.benchmark_group("xds");
    c.measurement_time(Duration::from_secs(5));
    c.bench_function("insert-remove", |b| {
        b.iter(|| {
            let svc = XdsService {
                hostname: "example.com".to_string(),
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                }],
                ..Default::default()
            };
            let mut state = ProxyState::new(None);
            let updater = ProxyStateUpdateMutator::new_no_fetch();
            updater.insert_service(&mut state, svc).unwrap();
            const WORKLOAD_COUNT: usize = 1000;
            for i in 0..WORKLOAD_COUNT {
                updater
                    .insert_workload(
                        &mut state,
                        XdsWorkload {
                            uid: format!("cluster1//v1/Pod/default/{i}"),
                            addresses: vec![Bytes::copy_from_slice(&[
                                127,
                                0,
                                (i / 255) as u8,
                                (i % 255) as u8,
                            ])],
                            services: std::collections::HashMap::from([(
                                "/example.com".to_string(),
                                PortList {
                                    ports: vec![Port {
                                        service_port: 80,
                                        target_port: 1234,
                                    }],
                                },
                            )]),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            for i in 0..WORKLOAD_COUNT {
                updater.remove(&mut state, &strng::format!("cluster1//v1/Pod/default/{i}"));
            }
        })
    });
}

pub fn load_balance(c: &mut Criterion) {
    let mut c = c.benchmark_group("load_balance");
    c.throughput(Throughput::Elements(1));
    c.measurement_time(Duration::from_secs(5));
    let mut run = move |name, wl_count, lb: Option<LoadBalancing>| {
        let (rt, demand, src_wl, svc_addr) = build_load_balancer(wl_count, lb.clone());
        c.bench_function(name, move |b| {
            b.to_async(&rt).iter(|| async {
                demand
                    .fetch_upstream(
                        "".into(),
                        &src_wl,
                        svc_addr,
                        ServiceResolutionMode::Standard,
                    )
                    .await
                    .unwrap()
            })
        });
    };
    run("basic-10", 10, None);
    run("basic-1000", 1000, None);
    run("basic-10000", 10000, None);
    let locality = Some(LoadBalancing {
        routing_preference: vec![
            load_balancing::Scope::Network as i32,
            load_balancing::Scope::Region as i32,
            load_balancing::Scope::Zone as i32,
            load_balancing::Scope::Subzone as i32,
        ],
        mode: load_balancing::Mode::Failover as i32,
        health_policy: 0,
        dns_connect_strategy: 0,
    });
    run("locality-10", 10, locality.clone());
    run("locality-1000", 1000, locality.clone());
    run("locality-10000", 10000, locality.clone());
}

fn build_load_balancer(
    wl_count: usize,
    load_balancing: Option<LoadBalancing>,
) -> (Runtime, DemandProxyState, Arc<Workload>, SocketAddr) {
    let svc = XdsService {
        hostname: "example.com".to_string(),
        addresses: vec![XdsNetworkAddress {
            network: "".to_string(),
            address: vec![127, 0, 0, 3],
        }],
        ports: vec![Port {
            service_port: 80,
            target_port: 0,
        }],
        load_balancing,
        ..Default::default()
    };
    let mut state = ProxyState::new(None);
    let updater = ProxyStateUpdateMutator::new_no_fetch();
    updater.insert_service(&mut state, svc).unwrap();
    for i in 0..wl_count {
        updater
            .insert_workload(
                &mut state,
                XdsWorkload {
                    uid: format!("cluster1//v1/Pod/default/{i}"),
                    addresses: vec![Bytes::copy_from_slice(&[
                        127,
                        0,
                        (i / 255) as u8,
                        (i % 255) as u8,
                    ])],
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 1234,
                            }],
                        },
                    )]),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let mut registry = Registry::default();
    let metrics = Arc::new(ztunnel::proxy::Metrics::new(&mut registry));
    let demand = DemandProxyState::new(
        Arc::new(RwLock::new(state)),
        None,
        ResolverConfig::default(),
        ResolverOpts::default(),
        metrics,
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let src_wl = rt
        .block_on(demand.fetch_workload_by_uid(&"cluster1//v1/Pod/default/0".into()))
        .unwrap();
    let svc_addr: SocketAddr = "127.0.0.3:80".parse().unwrap();
    (rt, demand, src_wl, svc_addr)
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Protobuf))
        .warm_up_time(Duration::from_millis(1));
    targets = xds, load_balance
}

criterion_main!(benches);
