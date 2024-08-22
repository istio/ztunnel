use std::cmp::Ordering::{Equal, Greater, Less};
use std::future::Future;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{io, thread};

use bytes::{BufMut, Bytes};
use criterion::measurement::Measurement;
use criterion::{
    criterion_group, criterion_main, BenchmarkGroup, Criterion, SamplingMode, Throughput,
};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use pprof::criterion::{Output, PProfProfiler};
use prometheus_client::registry::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::info;

use ztunnel::rbac::{Authorization, RbacMatch, StringMatch};
use ztunnel::state::workload::{Protocol, Workload};
use ztunnel::state::{DemandProxyState, ProxyRbacContext, ProxyState};
use ztunnel::test_helpers::app::{DestinationAddr, TestApp};
use ztunnel::test_helpers::linux::{TestMode, WorkloadManager};
use ztunnel::test_helpers::tcp::Mode;
use ztunnel::test_helpers::{helpers, tcp};
use ztunnel::xds::{LocalWorkload, ProxyStateUpdateMutator, ProxyStateUpdater};
use ztunnel::{app, identity, metrics, proxy, rbac, setup_netns_test, strng, test_helpers};

pub fn xds(c: &mut Criterion) {
    use ztunnel::xds::istio::workload::address::Type as XdsAddressType;
    use ztunnel::xds::istio::workload::TunnelProtocol as XdsProtocol;
    use ztunnel::xds::istio::workload::Workload as XdsWorkload;
    use ztunnel::xds::istio::workload::{IpFamilies, Port};
    use ztunnel::xds::istio::workload::{NetworkAddress as XdsNetworkAddress, PortList};
    use ztunnel::xds::istio::workload::{NetworkMode, Service as XdsService};
    let mut c = c.benchmark_group("xds");
    // let updater = ProxyStateUpdater::new(state.clone(), Arc::new(ztunnel::cert_fetcher::NoCertFetcher()));
    let mut state = ProxyState::default();
    let updater = ProxyStateUpdateMutator::new_no_fetch();
    let svc = XdsService {
        hostname: "example.com".to_string(),
        addresses: vec![XdsNetworkAddress {
            network: "".to_string(),
            address: vec![127, 0, 0, 3],
        }],
        ..Default::default()
    };
    updater.insert_service(&mut state, svc).unwrap();

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
            let mut state = ProxyState::default();
            let updater = ProxyStateUpdateMutator::new_no_fetch();
            updater.insert_service(&mut state, svc).unwrap();
            const WORKLOAD_COUNT: usize = 500;
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
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Protobuf))
        .warm_up_time(Duration::from_millis(1));
    targets = xds
}

criterion_main!(benches);
