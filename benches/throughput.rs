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

use std::cmp::Ordering::{Equal, Greater, Less};
use std::future::Future;
use std::io::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{io, thread};

use bytes::BufMut;
use criterion::measurement::Measurement;
use criterion::{
    BenchmarkGroup, Criterion, SamplingMode, Throughput, criterion_group, criterion_main,
};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use pprof::criterion::{Output, PProfProfiler};
use prometheus_client::registry::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::info;

use ztunnel::rbac::{Authorization, RbacMatch, StringMatch};
use ztunnel::state::workload::{InboundProtocol, Workload};
use ztunnel::state::{DemandProxyState, ProxyRbacContext, ProxyState};
use ztunnel::test_helpers::app::{DestinationAddr, TestApp};
use ztunnel::test_helpers::linux::{TestMode, WorkloadManager};
use ztunnel::test_helpers::tcp::Mode;
use ztunnel::test_helpers::{helpers, tcp, test_default_workload};
use ztunnel::xds::LocalWorkload;
use ztunnel::{app, identity, metrics, proxy, rbac, setup_netns_test, strng, test_helpers};

const KB: usize = 1024;
const MB: usize = 1024 * KB;
const GB: usize = 1024 * MB;
// Must be less than or equal to 254
const MAX_HBONE_WORKLOADS: u8 = 64;

const N_RULES: usize = 10;
const N_POLICIES: usize = 10_000;
const DUMMY_NETWORK: &str = "198.51.100.0/24";

#[ctor::ctor]
fn initialize_namespace_tests() {
    ztunnel::test_helpers::namespaced::initialize_namespace_tests();
}

fn create_test_policies() -> Vec<Authorization> {
    let mut policies: Vec<Authorization> = vec![];
    let mut rules = vec![];
    for _ in 0..N_RULES {
        rules.push(vec![vec![RbacMatch {
            namespaces: vec![
                StringMatch::Prefix("random-prefix-2b123".into()),
                StringMatch::Suffix("random-postix-2b723".into()),
                StringMatch::Exact("random-exac-2bc13".into()),
            ],
            not_namespaces: vec![],
            service_accounts: vec![],
            not_service_accounts: vec![],
            principals: vec![
                StringMatch::Prefix("random-prefix-2b123".into()),
                StringMatch::Suffix("random-postix-2b723".into()),
                StringMatch::Exact("random-exac-2bc13".into()),
            ],
            not_principals: vec![],
            source_ips: vec![DUMMY_NETWORK.parse().unwrap()],
            not_source_ips: vec![],
            destination_ips: vec![DUMMY_NETWORK.parse().unwrap()],
            not_destination_ips: vec![],
            destination_ports: vec![0],
            not_destination_ports: vec![],
        }]]);
    }

    for i in 0..N_POLICIES {
        policies.push(Authorization {
            name: strng::format!("policy {i}"),
            action: ztunnel::rbac::RbacAction::Deny,
            scope: ztunnel::rbac::RbacScope::Global,
            namespace: "default".into(),
            rules: rules.clone(),
            dry_run: false,
        });
    }

    policies
}

fn run_async_blocking<Fut, O>(f: Fut) -> O
where
    Fut: Future<Output = O>,
    O: Send + 'static,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub enum WorkloadMode {
    HBONE,
    TcpClient,
    Direct,
}

#[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
pub enum TestTrafficMode {
    // Each iteration sends a new request
    Request,
    // Each iteration establishes a new connection
    Connection,
}

#[allow(clippy::type_complexity)]
fn initialize_environment(
    ztunnel_mode: WorkloadMode,
    traffic_mode: TestTrafficMode,
    echo_mode: Mode,
    clients: usize,
) -> anyhow::Result<(
    WorkloadManager,
    SyncSender<usize>,
    Receiver<Result<(), io::Error>>,
)> {
    let mut manager = setup_netns_test!(TestMode::Shared);
    let (server, mut manager) = run_async_blocking(async move {
        if ztunnel_mode != WorkloadMode::Direct {
            // we need a client ztunnel
            manager.deploy_ztunnel("LOCAL").await.unwrap();
        }
        if ztunnel_mode == WorkloadMode::HBONE {
            // we need a server ztunnel
            manager.deploy_ztunnel("REMOTE").await.unwrap();
        }

        let server = manager
            .workload_builder("server", "REMOTE")
            .register()
            .await
            .unwrap();
        (server, manager)
    });
    server
        .run_ready(move |ready| async move {
            let echo = tcp::TestServer::new(echo_mode, 8080).await;
            ready.set_ready();
            echo.run().await;
            Ok(())
        })
        .unwrap();
    let echo_addr = SocketAddr::new(manager.resolver().resolve("server").unwrap(), 8080);
    let (tx, rx) = std::sync::mpsc::sync_channel::<usize>(0);
    let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<Result<(), io::Error>>(0);

    let client_mode = match echo_mode {
        Mode::ReadWrite => Mode::ReadWrite,
        Mode::ReadDoubleWrite => Mode::ReadDoubleWrite,
        Mode::Write => Mode::Read,
        Mode::Read => Mode::Write,
        Mode::Forward(_) => todo!("not implemented for benchmark"),
        Mode::ForwardProxyProtocol => todo!("not implemented for benchmark"),
    };
    let clients: Vec<_> = (0..clients)
        .map(|id| spawn_client(id, &mut manager, traffic_mode, echo_addr, client_mode))
        .collect();
    thread::spawn(move || {
        while let Ok(size) = rx.recv() {
            // Send request to all clients
            for c in &clients {
                c.tx.send(size).unwrap()
            }
            // Then wait for all completions -- this must be done in a separate loop to allow parallel processing.
            for c in &clients {
                if let Err(e) = c.ack.recv().unwrap() {
                    // Failed
                    ack_tx.send(Err(e)).unwrap();
                    return;
                }
            }
            // Success
            ack_tx.send(Ok(())).unwrap();
        }
    });
    Ok((manager, tx, ack_rx))
}

fn spawn_client(
    i: usize,
    manager: &mut WorkloadManager,
    traffic_mode: TestTrafficMode,
    echo_addr: SocketAddr,
    client_mode: Mode,
) -> TestClient {
    let client = run_async_blocking(async move {
        manager
            .workload_builder(&format!("client-{i}"), "LOCAL")
            .register()
            .await
            .unwrap()
    });

    let (tx, rx) = std::sync::mpsc::sync_channel::<usize>(0);
    let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<Result<(), io::Error>>(0);
    if traffic_mode == TestTrafficMode::Request {
        client
            .run_ready(move |ready| async move {
                let mut conn = TcpStream::connect(echo_addr).await.unwrap();
                conn.set_nodelay(true).unwrap();
                info!("setup complete");

                // warmup: send 1 byte so we ensure we have the full connection setup.
                tcp::run_client(&mut conn, 1, client_mode).await.unwrap();
                info!("warmup complete");
                ready.set_ready();

                // Accept requests and process them
                while let Ok(size) = rx.recv() {
                    // Send `size` bytes.
                    let res = tcp::run_client(&mut conn, size, client_mode).await;
                    // Report we are done.
                    ack_tx.send(res).unwrap();
                }
                Ok(())
            })
            .unwrap();
    } else {
        client
            .run_ready(move |ready| async move {
                ready.set_ready();
                // Accept requests and process them
                while let Ok(size) = rx.recv() {
                    // Open connection
                    let mut conn = TcpStream::connect(echo_addr).await.unwrap();
                    conn.set_nodelay(true).unwrap();
                    // Send `size` bytes.
                    let res = tcp::run_client(&mut conn, size, client_mode).await;
                    // Report we are done.
                    ack_tx.send(res).unwrap();
                }
                Ok(())
            })
            .unwrap();
    }

    TestClient { tx, ack: ack_rx }
}

struct TestClient {
    tx: SyncSender<usize>,
    ack: Receiver<Result<(), Error>>,
}

pub fn throughput(c: &mut Criterion) {
    const THROUGHPUT_SEND_SIZE: usize = GB;
    fn run_throughput<T: Measurement>(
        c: &mut BenchmarkGroup<T>,
        name: &str,
        mode: WorkloadMode,
        clients: usize,
    ) {
        let (_manager, tx, ack) =
            initialize_environment(mode, TestTrafficMode::Request, Mode::Read, clients).unwrap();
        let size = THROUGHPUT_SEND_SIZE / clients;
        c.bench_function(name, |b| {
            b.iter(|| {
                tx.send(size).unwrap();
                ack.recv().unwrap().unwrap();
            })
        });
    }

    let mut c = c.benchmark_group("throughput");

    // Measure in bits, not bytes, to match tools like iperf
    c.throughput(Throughput::Elements((THROUGHPUT_SEND_SIZE * 8) as u64));
    // Test takes a while, so reduce how many iterations we run
    c.sample_size(10);
    c.sampling_mode(SamplingMode::Flat);
    c.measurement_time(Duration::from_secs(5));
    // Send request in various modes.
    // Each test will use a pre-existing connection and send 1GB for multiple iterations
    for clients in [1, 2, 8] {
        run_throughput(
            &mut c,
            &format!("direct{clients}"),
            WorkloadMode::Direct,
            clients,
        );
        run_throughput(
            &mut c,
            &format!("tcp{clients}"),
            WorkloadMode::TcpClient,
            clients,
        );
        run_throughput(
            &mut c,
            &format!("hbone{clients}"),
            WorkloadMode::HBONE,
            clients,
        );
    }
}

pub fn latency(c: &mut Criterion) {
    const LATENCY_SEND_SIZE: usize = KB;
    fn run_latency<T: Measurement>(c: &mut BenchmarkGroup<T>, name: &str, mode: WorkloadMode) {
        let (_manager, tx, ack) =
            initialize_environment(mode, TestTrafficMode::Request, Mode::Read, 1).unwrap();
        c.bench_function(name, |b| {
            b.iter(|| {
                tx.send(LATENCY_SEND_SIZE).unwrap();
                ack.recv().unwrap().unwrap();
            })
        });
    }

    let mut c = c.benchmark_group("latency");

    // Measure in RPS
    c.throughput(Throughput::Elements(1));
    // Test takes a while, so reduce how many iterations we run
    // Send request in various modes.
    // Each test will use a pre-existing connection and send 1GB for multiple iterations
    run_latency(&mut c, "direct", WorkloadMode::Direct);
    run_latency(&mut c, "tcp", WorkloadMode::TcpClient);
    run_latency(&mut c, "hbone", WorkloadMode::HBONE);
}

pub fn connections(c: &mut Criterion) {
    fn run_connections<T: Measurement>(c: &mut BenchmarkGroup<T>, name: &str, mode: WorkloadMode) {
        let (_manager, tx, ack) =
            initialize_environment(mode, TestTrafficMode::Connection, Mode::ReadWrite, 1).unwrap();
        c.bench_function(name, |b| {
            b.iter(|| {
                tx.send(1).unwrap();
                ack.recv().unwrap().unwrap();
            })
        });
    }

    let mut c = c.benchmark_group("connections");

    // Measure in connections/s
    c.throughput(Throughput::Elements(1));
    // Send request in various modes.
    // Each test will use a pre-existing connection and send 1GB for multiple iterations
    run_connections(&mut c, "direct", WorkloadMode::Direct);
    run_connections(&mut c, "tcp", WorkloadMode::TcpClient);
    run_connections(&mut c, "hbone", WorkloadMode::HBONE);
}

pub fn rbac(c: &mut Criterion) {
    let policies = create_test_policies();
    let mut state = ProxyState::new(None);
    for p in policies {
        state.policies.insert(p.to_key(), p);
    }

    let mut registry = Registry::default();
    let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
    let mock_proxy_state = DemandProxyState::new(
        Arc::new(RwLock::new(state)),
        None,
        ResolverConfig::default(),
        ResolverOpts::default(),
        metrics,
    );
    let rc = ProxyRbacContext {
        conn: rbac::Connection {
            src: "127.0.0.1:12345".parse().unwrap(),
            dst: "127.0.0.2:12345".parse().unwrap(),
            src_identity: None,
            dst_network: "".into(),
        },
        dest_workload: Arc::new(test_default_workload()),
    };
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    c.bench_function("rbac", |b| {
        b.to_async(&rt).iter(|| async {
            let _ = mock_proxy_state.assert_rbac(&rc).await;
        })
    });
}

pub fn metrics(c: &mut Criterion) {
    let mut registry = Registry::default();
    let metrics = proxy::Metrics::new(metrics::sub_registry(&mut registry));

    let mut c = c.benchmark_group("metrics");
    c.bench_function("write", |b| {
        b.iter(|| {
            let co = proxy::ConnectionOpen {
                reporter: Default::default(),
                source: Some(Arc::new(test_helpers::test_default_workload())),
                derived_source: None,
                destination: None,
                destination_service: None,
                connection_security_policy: Default::default(),
            };
            let tl = proxy::CommonTrafficLabels::from(co);
            metrics.connection_opens.get_or_create(&tl).inc();
        })
    });
    c.bench_function("encode", |b| {
        b.iter(|| {
            let mut buf = String::new();
            prometheus_client::encoding::text::encode(&mut buf, &registry).unwrap();
        })
    });
}

/// Iterate through possible IP pairs restricted to 0 < ip_pair.0 < ip_pair.1 <= MAX_HBONE_WORKLOADS.
fn next_ip_pair(ip_pair: (u8, u8)) -> (u8, u8) {
    if ip_pair.0 == 0 || ip_pair.1 == 0 {
        panic!("Invalid host");
    }
    match (
        Ord::cmp(&ip_pair.0, &(MAX_HBONE_WORKLOADS - 1)),
        Ord::cmp(&ip_pair.1, &MAX_HBONE_WORKLOADS),
    ) {
        (Greater, _) | (_, Greater) | (Equal, Equal) => panic!("Invalid host"),
        (_, Less) => (ip_pair.0, ip_pair.1 + 1),
        (Less, Equal) => (ip_pair.0 + 1, ip_pair.0 + 2),
    }
}

/// Reserve IPs in 127.0.1.0/24 for these HBONE connection tests.
/// Thus, we identify hosts by a u8 which represents an IP in the form 127.0.1.x.
fn hbone_connection_ip(x: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 1, x))
}

fn hbone_connection_config() -> ztunnel::config::ConfigSource {
    let mut workloads: Vec<LocalWorkload> = Vec::with_capacity(MAX_HBONE_WORKLOADS as usize);
    // We can't create one work load with many IPs because ztunnel could connect to any one causing
    // inconsistent behavior. Instead, we create one workload per IP.
    for i in 1..MAX_HBONE_WORKLOADS + 1 {
        let lwl = LocalWorkload {
            workload: Workload {
                workload_ips: vec![hbone_connection_ip(i)],
                protocol: InboundProtocol::HBONE,
                uid: strng::format!("cluster1//v1/Pod/default/remote{i}"),
                name: strng::format!("workload-{i}"),
                namespace: strng::format!("namespace-{i}"),
                service_account: strng::format!("service-account-{i}"),
                ..test_helpers::test_default_workload()
            },
            services: Default::default(),
        };
        workloads.push(lwl);
    }
    let lwl = LocalWorkload {
        workload: Workload {
            workload_ips: vec![],
            protocol: InboundProtocol::HBONE,
            uid: "cluster1//v1/Pod/default/local-source".into(),
            name: "local-source".into(),
            namespace: "default".into(),
            service_account: "default".into(),
            ..test_helpers::test_default_workload()
        },
        services: Default::default(),
    };
    workloads.push(lwl);

    let lc = ztunnel::xds::LocalConfig {
        workloads,
        policies: vec![],
        services: vec![],
    };
    let mut b = bytes::BytesMut::new().writer();
    serde_yaml::to_writer(&mut b, &lc).ok();
    let b = b.into_inner().freeze();
    ztunnel::config::ConfigSource::Static(b)
}

/// Benchmark how long it takes to establish a new HBONE connection.
/// This is tricky because ztunnel will keep a connection pool.
/// Repeated connections from the same source to the same destination will use the pooled
/// connection. Instead, we register MAX_HBONE_WORKLOADS giving us O(MAX_HBONE_WORKLOADS^2)
/// source/destination IP combinations which is (hopefully) enough.
fn hbone_connections(c: &mut Criterion) {
    helpers::run_command("ip link set dev lo up").unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // Global setup: spin up an echo server and ztunnel instance
    let (echo_addr, ta) = rt.block_on(async move {
        let registry = Registry::default();
        let identity_metrics = Arc::new(identity::metrics::Metrics::new());
        let cert_manager = identity::mock::new_secret_manager_with_metrics(
            Duration::from_secs(10),
            identity_metrics.clone(),
        );
        let port = 80;
        let config_source = Some(hbone_connection_config());
        let config = test_helpers::test_config_with_port_xds_addr_and_root_cert(
            port,
            None,
            None,
            config_source,
        );
        let app = app::build_with_cert_and_registry(
            Arc::new(config),
            cert_manager.clone(),
            identity_metrics,
            registry,
        )
            .await
            .unwrap();
        let ta = TestApp::from((&app, cert_manager));
        ta.ready().await;

        let echo = tcp::TestServer::new(Mode::ReadWrite, 0).await;
        let echo_addr = echo.address();
        drop(tokio::spawn(async move {
            let _ = tokio::join!(app.wait_termination(), echo.run());
        }));
        (echo_addr, ta)
    });

    let ta: Arc<Mutex<TestApp>> = Arc::new(Mutex::new(ta));
    let addresses = Arc::new(Mutex::new((1u8, 2u8)));

    let mut c = c.benchmark_group("hbone_connections");
    // WARNING: increasing the measurement time could lead to running out of IP pairs or having too
    // many open connections.
    c.measurement_time(Duration::from_secs(5));
    // Connections/second
    c.throughput(Throughput::Elements(1));
    c.bench_function("connect_request_response", |b| {
        b.to_async(&rt).iter(|| async {
            let bench = async {
                let mut addresses = addresses.lock().await;
                let ta = ta.lock().await;

                // Get next address pair
                *addresses = next_ip_pair(*addresses);
                let source_addr = hbone_connection_ip(addresses.0);
                let dest_addr = hbone_connection_ip(addresses.1);

                // Start HBONE connection
                let mut hbone = ta
                    .socks5_connect(DestinationAddr::Ip(helpers::with_ip(echo_addr, dest_addr)), source_addr)
                    .await;

                // TCP ping
                hbone.write_u8(42).await.ok();
                hbone.read_u8().await.ok();
            };

            // If misconfigured, `socks5_connect` will silently fail causing subsequent commands
            // to hang. Panic if too slow.
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(1)) => panic!("Timeout: Test is hanging."),
                _ = bench => ()
            };
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Protobuf))
        .warm_up_time(Duration::from_millis(1));
    targets = hbone_connections
}

criterion_main!(benches);
