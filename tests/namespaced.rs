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

#[cfg(all(test, target_os = "linux"))]
mod namespaced {
    use bytes::Bytes;
    use futures::future::poll_fn;
    use http_body_util::Empty;
    use std::collections::HashMap;
    use ztunnel::state::workload::ApplicationTunnel;
    use ztunnel::state::workload::application_tunnel::Protocol;
    use ztunnel::state::workload::gatewayaddress::Destination;
    use ztunnel::state::workload::{GatewayAddress, NamespacedHostname};
    use ztunnel::test_helpers::linux::TestMode;

    use std::net::{IpAddr, SocketAddr};

    use anyhow::Context;
    use std::str::FromStr;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use ztunnel::rbac::{Authorization, RbacMatch, StringMatch};

    use hyper::{Method, StatusCode};
    use hyper_util::rt::TokioIo;

    use WorkloadMode::Uncaptured;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tracing::{error, info};

    use ztunnel::state::workload::NetworkAddress;
    use ztunnel::test_helpers::app::{ParsedMetrics, TestApp};
    use ztunnel::test_helpers::linux::TestMode::{Dedicated, Shared};
    use ztunnel::test_helpers::linux::WorkloadManager;
    use ztunnel::test_helpers::netns::{Namespace, Resolver};
    use ztunnel::test_helpers::*;

    use ztunnel::{identity, strng, telemetry};

    use crate::namespaced::WorkloadMode::Captured;
    use ztunnel::setup_netns_test;

    const WAYPOINT_MESSAGE: &[u8] = b"waypoint\n";

    /// initialize_namespace_tests sets up the namespace tests.
    #[ctor::ctor]
    fn initialize_namespace_tests() {
        ztunnel::test_helpers::namespaced::initialize_namespace_tests();
    }

    #[tokio::test]
    async fn local_captured_inpod() {
        simple_client_server_test(
            setup_netns_test!(Shared),
            Captured(DEFAULT_NODE),
            Captured(DEFAULT_NODE),
        )
        .await
    }

    #[tokio::test]
    async fn server_uncaptured_inpod() {
        simple_client_server_test(
            setup_netns_test!(Shared),
            Captured(DEFAULT_NODE),
            Uncaptured,
        )
        .await
    }

    #[tokio::test]
    async fn client_uncaptured_inpod() {
        simple_client_server_test(
            setup_netns_test!(Shared),
            Captured(DEFAULT_NODE),
            Uncaptured,
        )
        .await
    }

    #[tokio::test]
    async fn cross_node_captured_inpod() {
        simple_client_server_test(
            setup_netns_test!(Shared),
            Captured(DEFAULT_NODE),
            Captured(REMOTE_NODE),
        )
        .await
    }

    // Intentionally, we do not have a 'local_captured_sharednode'
    // This is not currently supported since https://github.com/istio/ztunnel/commit/12d154cceb1d20eb1f11ae43c2310e66e93c7120

    #[tokio::test]
    async fn server_uncaptured_dedicated() {
        simple_client_server_test(
            setup_netns_test!(Dedicated),
            Captured(DEFAULT_NODE),
            Uncaptured,
        )
        .await
    }

    #[tokio::test]
    async fn client_uncaptured_dedicated() {
        simple_client_server_test(
            setup_netns_test!(Dedicated),
            Captured(DEFAULT_NODE),
            Uncaptured,
        )
        .await
    }

    #[tokio::test]
    async fn cross_node_captured_dedicated() {
        simple_client_server_test(
            setup_netns_test!(Dedicated),
            Captured(DEFAULT_NODE),
            Captured(REMOTE_NODE),
        )
        .await
    }

    #[tokio::test]
    async fn workload_waypoint() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        let waypoint = manager.register_waypoint("waypoint", DEFAULT_NODE).await?;
        let waypoint_ip = waypoint.ip();
        run_hbone_server(
            waypoint,
            "waypoint",
            tcp::Mode::ReadWrite,
            WAYPOINT_MESSAGE.into(),
        )?;

        manager
            .workload_builder("server", DEFAULT_NODE)
            .waypoint(waypoint_ip)
            .register()
            .await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let server_ip = manager.resolver().resolve("server")?;
        run_tcp_to_hbone_client(client, manager.resolver(), "server")?;

        let metrics = [
            (CONNECTIONS_OPENED, 1),
            (CONNECTIONS_CLOSED, 1),
            (BYTES_RECV, REQ_SIZE),
            (BYTES_SENT, HBONE_REQ_SIZE),
        ];
        verify_metrics(&zt, &metrics, &source_labels()).await;
        let sent = format!("{REQ_SIZE}");
        let recv = format!("{HBONE_REQ_SIZE}");
        let hbone_addr = format!("{server_ip}:8080");
        let dst_addr = format!("{waypoint_ip}:15008");
        let want = HashMap::from([
            ("scope", "access"),
            ("src.workload", "client"),
            ("dst.workload", "waypoint"),
            ("dst.namespace", "default"),
            ("dst.hbone_addr", &hbone_addr),
            ("dst.addr", &dst_addr),
            ("bytes_sent", &sent),
            ("bytes_recv", &recv),
            ("direction", "outbound"),
            ("message", "connection complete"),
            (
                "src.identity",
                "spiffe://cluster.local/ns/default/sa/client",
            ),
            (
                "dst.identity",
                "spiffe://cluster.local/ns/default/sa/waypoint",
            ),
        ]);
        telemetry::testing::assert_contains(want);
        Ok(())
    }

    #[tokio::test]
    async fn double_hbone1() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        // Service that resolves to workload with ew gateway
        // The 8080 port mappings don't actually matter because the
        // final ztunnel is actually an hbone echo server that doesn't
        // forward anything.
        manager
            .service_builder("remote")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: TEST_VIP.parse::<IpAddr>()?,
            }])
            .subject_alt_names(vec!["spiffe://cluster.local/ns/default/sa/echo".into()])
            .ports(HashMap::from([(8080, 8080)]))
            .register()
            .await?;

        // This is the e/w gateway that is supposed to be in the remote cluster/network.
        let actual_ew_gtw = manager
            .workload_builder("actual-ew-gtw", "remote-node")
            .hbone()
            .network("remote".into())
            .register()
            .await?;

        // This is the workload in the local cluster that represents the workloads in the remote cluster.
        // Its local in the sense that the it shows up in the local cluster's xds, but it
        // represents workloads in the remote cluster.
        // Its a little weird because we do give it a namespaced/ip,
        // but that's because of how the tests infra works.
        let _local_remote_workload = manager
            .workload_builder("local-remote-workload", "remote-node")
            .hbone()
            .network("remote".into())
            .network_gateway(GatewayAddress {
                destination: Destination::Address(NetworkAddress {
                    network: "remote".into(),
                    address: actual_ew_gtw.ip(),
                }),
                hbone_mtls_port: 15008,
            })
            .identity(identity::Identity::Spiffe {
                trust_domain: "cluster.local".into(),
                namespace: "default".into(),
                service_account: "actual-ew-gtw".into(),
            })
            .service("default/remote.default.svc.cluster.local", 8080, 8080)
            .register()
            .await?;
        let echo = manager
            .workload_builder("echo", "remote-node2")
            .register()
            .await?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let echo_hbone_addr = SocketAddr::new(echo.ip(), 15008);

        // No need to run local_remote_workload, as it doesn't actually exist.
        run_hbone_server(
            echo.clone(),
            "echo",
            tcp::Mode::ReadWrite,
            WAYPOINT_MESSAGE.into(),
        )?;
        run_hbone_server(
            actual_ew_gtw.clone(),
            "actual-ew-gtw",
            tcp::Mode::Forward(echo_hbone_addr),
            b"".into(),
        )?;

        run_tcp_to_hbone_client(
            client.clone(),
            manager.resolver(),
            &format!("{TEST_VIP}:8080"),
        )?;

        let metrics = [
            (CONNECTIONS_OPENED, 1),
            (CONNECTIONS_CLOSED, 1),
            (BYTES_RECV, REQ_SIZE),
            (BYTES_SENT, HBONE_REQ_SIZE),
        ];
        verify_metrics(&zt, &metrics, &source_labels()).await;

        let sent = format!("{REQ_SIZE}");
        let recv = format!("{HBONE_REQ_SIZE}");
        let dst_addr = format!("{}:15008", actual_ew_gtw.ip());
        let want = HashMap::from([
            ("scope", "access"),
            ("src.workload", "client"),
            ("dst.workload", "echo"),
            ("dst.hbone_addr", "remote.default.svc.cluster.local:8080"),
            ("dst.addr", &dst_addr),
            ("bytes_sent", &sent),
            ("bytes_recv", &recv),
            ("direction", "outbound"),
            ("message", "connection complete"),
            (
                "src.identity",
                "spiffe://cluster.local/ns/default/sa/client",
            ),
            ("dst.identity", "spiffe://cluster.local/ns/default/sa/echo"),
        ]);
        telemetry::testing::assert_contains(want);
        Ok(())
    }

    #[tokio::test]
    async fn double_hbone2() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let _zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        // Service that resolves to workload with ew gateway that uses service addressing
        manager
            .service_builder("remote-svc-gtw")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: TEST_VIP2.parse::<IpAddr>()?,
            }])
            .subject_alt_names(vec!["spiffe://cluster.local/ns/default/sa/echo".into()])
            .ports(HashMap::from([(8080, 8080)]))
            .register()
            .await?;

        // Service that resolves to the ew gateway.
        manager
            .service_builder("ew-gtw-svc")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: TEST_VIP3.parse::<IpAddr>()?,
            }])
            .ports(HashMap::from([(15009u16, 15008u16)]))
            .register()
            .await?;

        // This is the e/w gateway that is supposed to be in the remote cluster/network.
        let actual_ew_gtw = manager
            .workload_builder("actual-ew-gtw", "remote-node")
            .hbone()
            .service(
                "default/ew-gtw-svc.default.svc.cluster.local",
                15009u16,
                15008u16,
            )
            .network("remote".into())
            .register()
            .await?;

        // Like local_remote_workload, but the network gateway is service addressed
        let _local_remote_workload_svc_gtw = manager
            .workload_builder("local-remote-workload-svc-gtw", "remote-node")
            .hbone()
            .network("remote".into())
            .network_gateway(GatewayAddress {
                destination: Destination::Hostname(NamespacedHostname {
                    namespace: "default".into(),
                    hostname: "ew-gtw-svc.default.svc.cluster.local".into(),
                }),
                hbone_mtls_port: 15009,
            })
            .service(
                "default/remote-svc-gtw.default.svc.cluster.local",
                8080,
                8080,
            )
            .register()
            .await?;

        let echo = manager
            .workload_builder("echo", "remote-node2")
            .register()
            .await?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;
        let echo_addr = SocketAddr::new(echo.ip(), 15008);
        // No need to run local_remote_workload, as it doesn't actually exist.

        run_hbone_server(echo, "echo", tcp::Mode::ReadWrite, WAYPOINT_MESSAGE.into())?;
        run_hbone_server(
            actual_ew_gtw,
            "actual-ew-gtw",
            tcp::Mode::Forward(echo_addr),
            b"".into(),
        )?;

        run_tcp_to_hbone_client(
            client.clone(),
            manager.resolver(),
            &format!("{TEST_VIP2}:8080"),
        )?;

        Ok(())
    }

    #[tokio::test]
    async fn service_waypoint() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        let waypoint = manager.register_waypoint("waypoint", DEFAULT_NODE).await?;
        let waypoint_ip = waypoint.ip();
        run_hbone_server(
            waypoint,
            "waypoint",
            tcp::Mode::ReadWrite,
            WAYPOINT_MESSAGE.into(),
        )?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        manager
            .service_builder("service")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: TEST_VIP.parse::<IpAddr>()?,
            }])
            .ports(HashMap::from([(80u16, 80u16)]))
            .waypoint(waypoint_ip)
            .register()
            .await?;

        run_tcp_to_hbone_client(client, manager.resolver(), &format!("{TEST_VIP}:80"))?;

        let metrics = [
            (CONNECTIONS_OPENED, 1),
            (CONNECTIONS_CLOSED, 1),
            (BYTES_RECV, REQ_SIZE),
            (BYTES_SENT, HBONE_REQ_SIZE),
        ];
        verify_metrics(&zt, &metrics, &source_labels()).await;

        let sent = format!("{REQ_SIZE}");
        let recv = format!("{HBONE_REQ_SIZE}");
        let hbone_addr = format!("{TEST_VIP}:80");
        let dst_addr = format!("{waypoint_ip}:15008");
        let want = HashMap::from([
            ("scope", "access"),
            ("src.workload", "client"),
            ("dst.workload", "waypoint"),
            ("dst.hbone_addr", &hbone_addr),
            ("dst.addr", &dst_addr),
            ("bytes_sent", &sent),
            ("bytes_recv", &recv),
            ("direction", "outbound"),
            ("message", "connection complete"),
            (
                "src.identity",
                "spiffe://cluster.local/ns/default/sa/client",
            ),
            (
                "dst.identity",
                "spiffe://cluster.local/ns/default/sa/waypoint",
            ),
        ]);
        telemetry::testing::assert_contains(want);
        Ok(())
    }

    #[tokio::test]
    async fn service_waypoint_hostname() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        manager
            .service_builder("waypoint")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: TEST_VIP.parse::<IpAddr>()?,
            }])
            .ports(HashMap::from([(15008u16, 15008u16)]))
            .register()
            .await?;
        let waypoint = manager
            .workload_builder("waypoint", DEFAULT_NODE)
            .uncaptured()
            .service(
                "default/waypoint.default.svc.cluster.local",
                80,
                SERVER_PORT,
            )
            .register()
            .await?;
        run_hbone_server(
            waypoint,
            "waypoint",
            tcp::Mode::ReadWrite,
            WAYPOINT_MESSAGE.into(),
        )?;

        manager
            .workload_builder("server", DEFAULT_NODE)
            .waypoint_hostname("waypoint.default.svc.cluster.local")
            .register()
            .await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let server_ip = manager.resolver().resolve("server")?;
        let waypoint_pod_ip = manager.resolver().resolve("waypoint")?;
        run_tcp_to_hbone_client(client, manager.resolver(), "server")?;

        let metrics = [
            (CONNECTIONS_OPENED, 1),
            (CONNECTIONS_CLOSED, 1),
            (BYTES_RECV, REQ_SIZE),
            (BYTES_SENT, HBONE_REQ_SIZE),
        ];
        verify_metrics(&zt, &metrics, &source_labels()).await;

        let sent = format!("{REQ_SIZE}");
        let recv = format!("{HBONE_REQ_SIZE}");
        let hbone_addr = format!("{server_ip}:8080");
        let dst_addr = format!("{waypoint_pod_ip}:15008");
        let want = HashMap::from([
            ("scope", "access"),
            ("src.workload", "client"),
            ("dst.workload", "waypoint"),
            ("dst.hbone_addr", &hbone_addr),
            ("dst.addr", &dst_addr),
            ("bytes_sent", &sent),
            ("bytes_recv", &recv),
            ("direction", "outbound"),
            ("message", "connection complete"),
            (
                "src.identity",
                "spiffe://cluster.local/ns/default/sa/client",
            ),
            (
                "dst.identity",
                "spiffe://cluster.local/ns/default/sa/waypoint",
            ),
        ]);
        telemetry::testing::assert_contains(want);
        Ok(())
    }

    #[tokio::test]
    async fn service_waypoint_workload_hostname() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        let waypoint = manager
            .workload_builder("waypoint", DEFAULT_NODE)
            .uncaptured()
            .mutate_workload(|w| w.hostname = "waypoint.example.com".into())
            .register()
            .await?;
        run_hbone_server(
            waypoint,
            "waypoint",
            tcp::Mode::ReadWrite,
            WAYPOINT_MESSAGE.into(),
        )?;

        manager
            .workload_builder("server", DEFAULT_NODE)
            .waypoint_hostname("waypoint.example.com")
            .register()
            .await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let server_ip = manager.resolver().resolve("server")?;
        let waypoint_pod_ip = manager.resolver().resolve("waypoint")?;
        run_tcp_to_hbone_client(client, manager.resolver(), "server")?;

        let metrics = [
            (CONNECTIONS_OPENED, 1),
            (CONNECTIONS_CLOSED, 1),
            (BYTES_RECV, REQ_SIZE),
            (BYTES_SENT, HBONE_REQ_SIZE),
        ];
        verify_metrics(&zt, &metrics, &source_labels()).await;

        let sent = format!("{REQ_SIZE}");
        let recv = format!("{HBONE_REQ_SIZE}");
        let hbone_addr = format!("{server_ip}:8080");
        let dst_addr = format!("{waypoint_pod_ip}:15008");
        let want = HashMap::from([
            ("scope", "access"),
            ("src.workload", "client"),
            ("dst.workload", "waypoint"),
            ("dst.hbone_addr", &hbone_addr),
            ("dst.addr", &dst_addr),
            ("bytes_sent", &sent),
            ("bytes_recv", &recv),
            ("direction", "outbound"),
            ("message", "connection complete"),
            (
                "src.identity",
                "spiffe://cluster.local/ns/default/sa/client",
            ),
            (
                "dst.identity",
                "spiffe://cluster.local/ns/default/sa/waypoint",
            ),
        ]);
        telemetry::testing::assert_contains(want);
        Ok(())
    }

    #[tokio::test]
    async fn sandwich_waypoint_plain() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let _zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        let waypoint = manager
            .workload_builder("waypoint", DEFAULT_NODE)
            .mutate_workload(|w| {
                w.application_tunnel = Some(ApplicationTunnel {
                    protocol: Protocol::NONE,
                    port: None,
                });
            })
            .register()
            .await?;
        let waypoint_ip = waypoint.ip();

        let server = manager
            .workload_builder("server", DEFAULT_NODE)
            .waypoint(waypoint_ip)
            .register()
            .await?;
        run_tcp_proxy_server(waypoint, SocketAddr::new(server.ip(), SERVER_PORT))?;
        run_tcp_server(server)?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let _server_ip = manager.resolver().resolve("server")?;
        run_tcp_client(client, manager.resolver(), "server")?;
        Ok(())
    }

    #[tokio::test]
    async fn sandwich_waypoint_proxy_protocol() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);

        let _zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        // waypoint referenced via vip
        let waypoint_ip = TEST_VIP.parse::<IpAddr>()?;
        // service with no ports (workload app tunnel makes this work)
        manager
            .service_builder("waypoint")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: waypoint_ip,
            }])
            .register()
            .await?;

        let waypoint = manager
            .workload_builder("waypoint", DEFAULT_NODE)
            .service(
                "default/waypoint.default.svc.cluster.local",
                PROXY_PROTOCOL_PORT,
                PROXY_PROTOCOL_PORT,
            )
            .mutate_workload(|w| {
                w.application_tunnel = Some(ApplicationTunnel {
                    protocol: Protocol::PROXY,
                    port: Some(PROXY_PROTOCOL_PORT),
                });
            })
            .register()
            .await?;

        let server = manager
            .workload_builder("server", DEFAULT_NODE)
            .waypoint(waypoint_ip)
            .register()
            .await?;
        run_tcp_proxy_protocol_server(waypoint)?;
        run_tcp_server(server)?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let _server_ip = manager.resolver().resolve("server")?;
        run_tcp_client(client, manager.resolver(), "server")?;
        Ok(())
    }

    #[tokio::test]
    async fn service_loadbalancing() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);
        let local = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let remote = manager.deploy_ztunnel(REMOTE_NODE).await?;
        manager
            .service_builder("service")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: TEST_VIP.parse::<IpAddr>()?,
            }])
            .ports(HashMap::from([(80u16, 80u16)]))
            .register()
            .await?;
        run_tcp_server(
            manager
                .workload_builder("server1", DEFAULT_NODE)
                .service("default/service.default.svc.cluster.local", 80, SERVER_PORT)
                .register()
                .await?,
        )?;
        run_tcp_server(
            manager
                .workload_builder("server2", REMOTE_NODE)
                .hbone()
                .service("default/service.default.svc.cluster.local", 80, SERVER_PORT)
                .register()
                .await?,
        )?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        // first just send a single request
        run_tcp_client_iters(&client, 1, manager.resolver(), &format!("{TEST_VIP}:80"))?;

        let metrics = [
            (CONNECTIONS_OPENED, 1),
            (CONNECTIONS_CLOSED, 1),
            // Traffic is 11 bytes sent, 22 received by the client. But Istio reports them backwards (https://github.com/istio/istio/issues/32399) .
            (BYTES_RECV, REQ_SIZE),
            (BYTES_SENT, REQ_SIZE * 2),
        ];

        // Ensure we picked exactly one destination
        let local_metrics = verify_metrics(&local, &metrics, &source_labels()).await;
        let lb_to_nodelocal = local_metrics.query_sum(
            CONNECTIONS_OPENED,
            &HashMap::from([(
                "destination_principal".into(),
                "spiffe://cluster.local/ns/default/sa/server1".into(),
            )]),
        ) > 0;
        let lb_to_remote = local_metrics.query_sum(
            CONNECTIONS_OPENED,
            &HashMap::from([(
                "destination_principal".into(),
                "spiffe://cluster.local/ns/default/sa/server2".into(),
            )]),
        ) > 0;
        assert!(lb_to_nodelocal || lb_to_remote);
        if lb_to_nodelocal {
            assert!(!lb_to_remote);
        }
        // Verify we report the service information in metrics as well
        verify_metrics(
            &local,
            &metrics,
            &HashMap::from([
                ("reporter".to_string(), "source".to_string()),
                (
                    "destination_service".to_string(),
                    "service.default.svc.cluster.local".to_string(),
                ),
                (
                    "destination_service_name".to_string(),
                    "service".to_string(),
                ),
                (
                    "destination_service_namespace".to_string(),
                    "default".to_string(),
                ),
            ]),
        )
        .await;

        // response needed is opposite of what we got before
        let _needed_response = match lb_to_nodelocal {
            true => "mutual_tls".to_string(), // we got node local so need remote
            false => "unknown".to_string(),   // we got remote so need node local
        };

        // run 50 requests so chance of flake here is small
        run_tcp_client_iters(&client, 50, manager.resolver(), &format!("{TEST_VIP}:80"))?;

        // now we should have hit both backends
        verify_metric_exists(
            &local,
            CONNECTIONS_OPENED,
            &HashMap::from([(
                "destination_principal".into(),
                "spiffe://cluster.local/ns/default/sa/server1".into(),
            )]),
        )
        .await;
        verify_metric_exists(
            &local,
            CONNECTIONS_OPENED,
            &HashMap::from([(
                "destination_principal".into(),
                "spiffe://cluster.local/ns/default/sa/server2".into(),
            )]),
        )
        .await;

        // Now we should have hit the remote
        verify_metric_exists(
            &remote,
            CONNECTIONS_OPENED,
            &HashMap::from([
                ("reporter".to_string(), "destination".to_string()),
                (
                    "destination_service".to_string(),
                    "service.default.svc.cluster.local".to_string(),
                ),
                (
                    "destination_service_name".to_string(),
                    "service".to_string(),
                ),
                (
                    "destination_service_namespace".to_string(),
                    "default".to_string(),
                ),
                (
                    "destination_principal".into(),
                    "spiffe://cluster.local/ns/default/sa/server2".into(),
                ),
            ]),
        )
        .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_ztunnel_shutdown() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);
        let local = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let server = manager
            .workload_builder("server", DEFAULT_NODE)
            .register()
            .await?;
        run_tcp_server(server)?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;
        let (mut tx, rx) = mpsc_ack(1);
        let srv = resolve_target(manager.resolver(), "server");

        // Run a client which will send some traffic when signaled to do so
        let cjh = run_long_running_tcp_client(&client, rx, srv).unwrap();

        // First, send the initial request and wait for it
        tx.send_and_wait(()).await?;
        // Now start shutdown. Ztunnel should keep things working since we have pending open connections
        local.shutdown.shutdown_now().await;
        // Requests should still succeed...
        tx.send_and_wait(()).await?;
        // Close the connection
        drop(tx);

        cjh.join().unwrap()?;

        assert_eventually(
            Duration::from_secs(2),
            || async {
                client
                    .run_and_wait(move || async move { Ok(TcpStream::connect(srv).await?) })
                    .is_err()
            },
            true,
        )
        .await;
        // let res = client.run_and_wait(move || async move { Ok(TcpStream::connect(srv).await?) });
        // assert!(res.is_err(), "requests should fail after shutdown");
        Ok(())
    }

    #[tokio::test]
    async fn test_server_shutdown() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);
        manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let server = manager
            .workload_builder("server", DEFAULT_NODE)
            .register()
            .await?;
        run_tcp_server(server)?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;
        let (mut tx, rx) = mpsc_ack(1);
        let srv = resolve_target(manager.resolver(), "server");

        // Run a client which will send some traffic when signaled to do so
        let cjh = run_long_running_tcp_client(&client, rx, srv).unwrap();

        // First, send the initial request and wait for it
        tx.send_and_wait(()).await?;
        // Now shutdown the server. In real world, the server app would shutdown, then ztunnel would remove itself.
        // In this test, we will leave the server app running, but shutdown ztunnel.
        manager.delete_workload("server").await.unwrap();

        // In shared mode, verify that new connections succeed but data transfer fails
        client
            .run_and_wait(move || async move {
                let mut stream = TcpStream::connect(srv).await.unwrap();
                // We should be able to connect (since client is running), but not send a request
                const BODY: &[u8] = b"hello world";
                stream.write_all(BODY).await.unwrap();
                let mut buf = [0; BODY.len() * 2];
                let send = stream.read_exact(&mut buf).await;
                assert!(send.is_err());
                Ok(())
            })
            .unwrap();

        // The long running connection should also fail on next attempt
        let tx_send_result = tx.send_and_wait(()).await;
        assert!(
            tx_send_result.is_err(),
            "long running connection should fail after workload deletion"
        );

        drop(tx);
        assert!(cjh.join().unwrap().is_err());
        Ok(())
    }

    fn run_long_running_tcp_client(
        client: &Namespace,
        mut rx: MpscAckReceiver<()>,
        srv: SocketAddr,
    ) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
        async fn double_read_write_stream(stream: &mut TcpStream) -> anyhow::Result<usize> {
            const BODY: &[u8] = b"hello world";
            stream.write_all(BODY).await?;
            let mut buf = [0; BODY.len() * 2];
            stream.read_exact(&mut buf).await?;
            assert_eq!(b"hello worldhello world", &buf);
            Ok(BODY.len() * 2)
        }
        client.run(move || async move {
            let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(srv)).await??;
            while let Some(()) = rx.recv().await {
                timeout(
                    Duration::from_secs(5),
                    double_read_write_stream(&mut stream),
                )
                .await??;
                rx.ack().await.unwrap();
            }
            Ok(())
        })
    }

    #[tokio::test]
    async fn test_policy() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);
        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        manager
            .add_policy(Authorization {
                name: "deny_bypass".into(),
                namespace: "default".into(),
                scope: ztunnel::rbac::RbacScope::Namespace,
                action: ztunnel::rbac::RbacAction::Allow,
                rules: vec![vec![vec![RbacMatch {
                    principals: vec![StringMatch::Exact(
                        "spiffe://cluster.local/ns/default/sa/waypoint".into(),
                    )],
                    ..Default::default()
                }]]],
                dry_run: false,
            })
            .await?;
        let _ = manager
            .workload_builder("server", DEFAULT_NODE)
            .register()
            .await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .uncaptured()
            .register()
            .await?;

        let srv = resolve_target(manager.resolver(), "server");
        client
            .run(move || async move {
                let builder =
                    hyper::client::conn::http2::Builder::new(ztunnel::hyper_util::TokioExecutor);

                let request = hyper::Request::builder()
                    .uri(srv.to_string())
                    .method(Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(Empty::<Bytes>::new())
                    .unwrap();

                let id = &identity::Identity::default();
                let dst_id =
                    identity::Identity::from_str("spiffe://cluster.local/ns/default/sa/server")
                        .unwrap();
                let cert = zt
                    .cert_manager
                    .fetch_certificate(&id.to_composite_id())
                    .await?;
                let connector = cert.outbound_connector(vec![dst_id]).unwrap();
                let hbone = SocketAddr::new(srv.ip(), 15008);
                let tcp_stream = TcpStream::connect(hbone).await.unwrap();
                let tls_stream = connector.connect(tcp_stream).await.unwrap();
                let (mut request_sender, connection) =
                    builder.handshake(TokioIo::new(tls_stream)).await.unwrap();
                // spawn a task to poll the connection and drive the HTTP state
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!("Error in HBONE connection handshake: {:?}", e);
                    }
                });

                let response = request_sender.send_request(request).await.unwrap();
                assert_eq!(response.status(), hyper::StatusCode::UNAUTHORIZED);
                Ok(())
            })?
            .join()
            .unwrap()?;
        telemetry::testing::assert_contains(HashMap::from([
            ("scope", "access"),
            (
                "error",
                "connection closed due to policy rejection: allow policies exist, but none allowed",
            ),
        ]));
        Ok(())
    }

    #[tokio::test]
    async fn hbone_ip_mismatch() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);
        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let _server = manager
            .workload_builder("server", DEFAULT_NODE)
            .register()
            .await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .uncaptured()
            .register()
            .await?;

        let srv = resolve_target(manager.resolver(), "server");
        let clt = resolve_target(manager.resolver(), "client");
        client
            .run(move || async move {
                let builder =
                    hyper::client::conn::http2::Builder::new(ztunnel::hyper_util::TokioExecutor);

                let request = hyper::Request::builder()
                    .uri(clt.to_string())
                    .method(Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(Empty::<Bytes>::new())
                    .unwrap();

                let id = &identity::Identity::default();
                let dst_id =
                    identity::Identity::from_str("spiffe://cluster.local/ns/default/sa/server")
                        .unwrap();
                let cert = zt
                    .cert_manager
                    .fetch_certificate(&id.to_composite_id())
                    .await?;
                let connector = cert.outbound_connector(vec![dst_id]).unwrap();
                let tcp_stream = TcpStream::connect(SocketAddr::from((srv.ip(), 15008)))
                    .await
                    .unwrap();
                let tls_stream = connector.connect(tcp_stream).await.unwrap();
                let (mut request_sender, connection) =
                    builder.handshake(TokioIo::new(tls_stream)).await.unwrap();
                // spawn a task to poll the connection and drive the HTTP state
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!("Error in HBONE connection handshake: {:?}", e);
                    }
                });

                let response = request_sender.send_request(request).await.unwrap();
                // We sent to server IP directly but requested client IP. Should be rejected
                assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
                Ok(())
            })?
            .join()
            .unwrap()?;
        let e = format!("ip mismatch: {} != {}", srv.ip(), clt.ip());
        telemetry::testing::assert_contains(HashMap::from([("scope", "access"), ("error", &e)]));
        Ok(())
    }

    #[tokio::test]
    async fn test_svc_hostname_port() -> anyhow::Result<()> {
        test_svc_hostname(8080u16, ztunnel::function!()).await
    }

    #[tokio::test]
    async fn test_svc_hostname_named_port() -> anyhow::Result<()> {
        test_svc_hostname(0u16, ztunnel::function!()).await
    }

    async fn test_svc_hostname(svc_target_port: u16, function_name: &str) -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared, function_name);
        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        manager
            .service_builder("server")
            .addresses(vec![NetworkAddress {
                network: strng::EMPTY,
                address: TEST_VIP.parse::<IpAddr>()?,
            }])
            .ports(HashMap::from([(80u16, svc_target_port)]))
            .register()
            .await?;
        let server = manager
            .workload_builder("server", DEFAULT_NODE)
            .service(
                format!("default/{SERVER_HOSTNAME}").as_str(),
                80,
                SERVER_PORT,
            )
            .register()
            .await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .uncaptured()
            .register()
            .await?;

        run_tcp_server(server)?;
        let srv = resolve_target(manager.resolver(), "server");
        client
            .run(move || async move {
                let builder =
                    hyper::client::conn::http2::Builder::new(ztunnel::hyper_util::TokioExecutor);

                let request = hyper::Request::builder()
                    .uri(format!("{SERVER_HOSTNAME}:80"))
                    .method(Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(Empty::<Bytes>::new())
                    .unwrap();

                let id = &identity::Identity::default();
                let dst_id =
                    identity::Identity::from_str("spiffe://cluster.local/ns/default/sa/server")
                        .unwrap();
                let cert = zt
                    .cert_manager
                    .fetch_certificate(&id.to_composite_id())
                    .await?;
                let connector = cert.outbound_connector(vec![dst_id]).unwrap();
                let tcp_stream = TcpStream::connect(SocketAddr::from((srv.ip(), 15008)))
                    .await
                    .unwrap();
                let tls_stream = connector.connect(tcp_stream).await.unwrap();
                let (mut request_sender, connection) =
                    builder.handshake(TokioIo::new(tls_stream)).await.unwrap();
                // spawn a task to poll the connection and drive the HTTP state
                tokio::spawn(async move {
                    if let Err(e) = connection.await {
                        error!("Error in HBONE connection handshake: {:?}", e);
                    }
                });

                let response = request_sender.send_request(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                Ok(())
            })?
            .join()
            .unwrap()?;
        Ok(())
    }

    #[tokio::test]
    async fn malicious_calls_inpod() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);
        let _ztunnel = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;
        let uncaptured = manager
            .workload_builder("uncaptured", DEFAULT_NODE)
            .uncaptured()
            .register()
            .await?;

        let zt = manager.resolve("ztunnel-node")?;
        let ourself = manager.resolve("client")?;
        let localhost: IpAddr = "127.0.0.1".parse()?;
        malicious_calls_test(
            client,
            vec![
                (zt, 15001, Request), // Outbound: should be blocked due to recursive call
                (zt, 15006, Request), // Inbound: should be blocked due to recursive call
                (zt, 15008, Request), // HBONE: Connection succeeds (ztunnel listens) but request fails due to TLS
                // Localhost still get connection established, as ztunnel accepts anything. But they are dropped immediately.
                (zt, 15080, Request),      // socks5: localhost
                (zt, 15000, Request),      // admin: localhost
                (zt, 15020, Http),         // Stats: accept connection and returns a HTTP error
                (zt, 15021, Http),         // Readiness: accept connection and returns a HTTP error
                (ourself, 15001, Request), // Outbound: should be blocked due to recursive call
                (ourself, 15006, Request), // Inbound: should be blocked due to recursive call
                (ourself, 15008, Request), // HBONE: expected TLS, reject
                // Localhost still get connection established, as ztunnel accepts anything. But they are dropped immediately.
                (ourself, 15080, Connection), // socks5: current disabled, so we just cannot connect
                (ourself, 15000, Connection), // admin: doesn't exist on this network
                (ourself, 15020, Connection), // Stats: doesn't exist on this network
                (ourself, 15021, Connection), // Readiness: doesn't exist on this network
                (localhost, 15001, Request),  // Outbound: should be blocked due to recursive call
                (localhost, 15006, Request),  // Inbound: should be blocked due to recursive call
                (localhost, 15008, Request),  // HBONE: expected TLS, reject
                // Localhost still get connection established, as ztunnel accepts anything. But they are dropped immediately.
                (localhost, 15080, Connection), // socks5: current disabled, so we just cannot connect
                (localhost, 15000, Connection), // admin: doesn't exist on this network
                (localhost, 15020, Connection), // Stats: doesn't exist on this network
                (localhost, 15021, Connection), // Readiness: doesn't exist on this network
            ],
        )
        .await?;

        malicious_calls_test(
            uncaptured,
            vec![
                // Ztunnel doesn't listen on these ports...
                (zt, 15001, Connection), // Outbound: should be blocked due to recursive call
                (zt, 15006, Connection), // Inbound: should be blocked due to recursive call
                (zt, 15008, Request), // HBONE: Connection succeeds (ztunnel listens) but request fails due to TLS
                // Localhost is not accessible
                (zt, 15080, Connection), // socks5: localhost
                (zt, 15000, Connection), // admin: localhost
                (zt, 15020, Http),       // Stats: accept connection and returns a HTTP error
                (zt, 15021, Http),       // Readiness: accept connection and returns a HTTP error
                // All are accepted as "inbound plaintext" but then immediately closed
                (ourself, 15001, Request),
                (ourself, 15006, Request),
                (ourself, 15008, Request),
                (ourself, 15080, Request),
                (ourself, 15000, Request),
                (ourself, 15020, Request),
                (ourself, 15021, Request),
            ],
        )
        .await
    }

    #[tokio::test]
    async fn trust_domain_mismatch_rejected() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(Shared);
        let id = identity::Identity::Spiffe {
            trust_domain: "clusterset.local".into(), // change to mismatched trustdomain
            service_account: "my-app".into(),
            namespace: "default".into(),
        };

        let _ = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        run_tcp_server(
            manager
                .workload_builder("server", DEFAULT_NODE)
                .register()
                .await?,
        )?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .identity(id)
            .register()
            .await?;

        let srv = resolve_target(manager.resolver(), "server");

        client
            .run(move || async move {
                let mut tcp_stream = TcpStream::connect(&srv.to_string()).await?;
                tcp_stream.write_all(b"hello world!").await?;
                let mut buf = [0; 10];
                let mut buf = ReadBuf::new(&mut buf);

                let result = poll_fn(|cx| tcp_stream.poll_peek(cx, &mut buf)).await;
                assert!(result.is_err()); // expect a connection reset due to TLS SAN mismatch
                assert_eq!(
                    result.err().unwrap().kind(),
                    std::io::ErrorKind::ConnectionReset
                );

                Ok(())
            })?
            .join()
            .unwrap()?;
        Ok(())
    }

    #[tokio::test]
    async fn test_prefetch_forget_certs() -> anyhow::Result<()> {
        // TODO: this test doesn't really need namespacing, but the direct test doesn't allow dynamic config changes.
        let mut manager = setup_netns_test!(Shared);
        let id1 = identity::Identity::Spiffe {
            trust_domain: "cluster.local".into(),
            service_account: "sa1".into(),
            namespace: "default".into(),
        };
        let id1s = id1.to_string();

        let ta = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let ztunnel_identity_obj = ta.ztunnel_identity.as_ref().unwrap().clone();
        ta.cert_manager
            .fetch_certificate(&ztunnel_identity_obj.to_composite_id())
            .await?;
        let ztunnel_identity_str = ztunnel_identity_obj.to_string();

        let check = |want: Vec<String>, help: &str| {
            let cm = ta.cert_manager.clone();
            let help = help.to_string();
            let mut sorted_want = want.clone();
            sorted_want.sort();
            async move {
                let res = check_eventually(
                    Duration::from_secs(2),
                    || async {
                        let mut certs = cm.collect_certs(|a, _b| a.to_string()).await;
                        certs.sort();
                        certs
                    },
                    sorted_want,
                )
                .await;
                assert!(res.is_ok(), "{}: got {:?}", help, res.err().unwrap());
            }
        };
        check(
            vec![ztunnel_identity_str.clone()],
            "initially only ztunnel cert",
        )
        .await;

        manager
            .workload_builder("id1-a-remote-node", REMOTE_NODE)
            .identity(id1.clone())
            .register()
            .await?;
        check(
            vec![ztunnel_identity_str.clone()],
            "we should not prefetch remote nodes",
        )
        .await;

        manager
            .workload_builder("id1-a-same-node", DEFAULT_NODE)
            .identity(id1.clone())
            .register()
            .await?;
        check(
            vec![ztunnel_identity_str.clone(), id1s.clone()],
            "we should prefetch our nodes",
        )
        .await;

        manager
            .workload_builder("id1-b-same-node", DEFAULT_NODE)
            .identity(id1.clone())
            .register()
            .await?;
        check(
            vec![ztunnel_identity_str.clone(), id1s.clone()],
            "multiple of same identity shouldn't do anything",
        )
        .await;
        manager.delete_workload("id1-a-remote-node").await?;
        // Deleting remote node should not affect local certs if local workloads still exist
        check(
            vec![ztunnel_identity_str.clone(), id1s.clone()],
            "removing remote node shouldn't impact anything",
        )
        .await;
        manager.delete_workload("id1-b-same-node").await?;
        // Deleting one local node shouldn't impact certs if another local workload still exists
        check(
            vec![ztunnel_identity_str.clone(), id1s.clone()],
            "removing local node shouldn't impact anything if I still have some running",
        )
        .await;
        manager.delete_workload("id1-a-same-node").await?;
        // After deleting all workloads using sa1, give cert manager time to clean up
        tokio::time::sleep(Duration::from_millis(100)).await;

        // In shared mode, certificates may be kept alive by the inbound listener
        // for handling inbound connections, even after workload deletion
        let expected_certs = match manager.mode() {
            TestMode::Shared => vec![ztunnel_identity_str.clone(), id1s.clone()],
            TestMode::Dedicated => vec![ztunnel_identity_str.clone()],
        };
        check(
            expected_certs,
            "removing final workload should clear certs except those needed by inbound listener",
        )
        .await;
        Ok(())
    }

    #[tokio::test]
    async fn test_hbone_metrics_access() -> Result<(), anyhow::Error> {
        let mut manager = setup_netns_test!(Shared);

        // Deploy ztunnel for the node
        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let ztunnel_node_ip = manager.resolve("ztunnel-node")?;
        // Use the actual metrics address ztunnel is listening on (e.g., [::]:15020)
        // but combine it with the node IP for the client to target.
        let target_metrics_addr = SocketAddr::new(ztunnel_node_ip, zt.metrics_address.port());
        let target_metrics_url = format!("http://{target_metrics_addr}/metrics");

        // Deploy a client workload (simulating Prometheus)
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let zt_identity_str = zt.ztunnel_identity.as_ref().unwrap().to_string();

        // Client makes a standard HTTP GET request to ztunnel's metrics endpoint
        // Ztunnel's outbound capture should intercept this, initiate HBONE to its own inbound,
        // which then proxies to the internal metrics server.
        client
            .run(move || async move {
                info!(target=%target_metrics_url, "Client attempting standard HTTP GET to metrics endpoint");

                let client = hyper_util::client::legacy::Client::builder(
                    ztunnel::hyper_util::TokioExecutor,
                )
                .build_http();

                let req = hyper::Request::builder()
                    .method(Method::GET)
                    .uri(&target_metrics_url)
                    .body(Empty::<Bytes>::new())?;

                let response = client.request(req).await?;

                info!("Received response status: {:?}", response.status());
                assert_eq!(response.status(), StatusCode::OK, "GET request failed");

                let body_bytes = http_body_util::BodyExt::collect(response.into_body())
                    .await?
                    .to_bytes();
                let response_str = String::from_utf8_lossy(&body_bytes);

                assert!(
                    response_str.contains("# TYPE"),
                    "Expected Prometheus metrics (# TYPE) in response, got:\n{response_str}",
                );
                info!("Successfully verified metrics response body");

                Ok(())
            })?
            .join()
            .unwrap()?;

        // Verify metrics from the DESTINATION perspective (ztunnel handling its own inbound)
        let metrics = [
            (CONNECTIONS_OPENED, 1), // One connection opened (client -> zt inbound via HBONE)
            (CONNECTIONS_CLOSED, 1), // One connection closed
        ];
        verify_metrics(&zt, &metrics, &destination_labels()).await;

        // Verify INBOUND telemetry log for the metrics connection
        let dst_addr_log = format!("{ztunnel_node_ip}:15008");
        let dst_hbone_addr_log = format!("{target_metrics_addr}");

        // We don't know exact byte counts, so omit them from the check for now
        let want = HashMap::from([
            ("scope", "access"),
            ("src.workload", "client"),
            ("dst.workload", "ztunnel-node"), // ztunnel's workload name
            ("dst.addr", dst_addr_log.as_str()), // Connected to HBONE port
            ("dst.hbone_addr", dst_hbone_addr_log.as_str()), // Original target
            ("direction", "inbound"),
            ("message", "connection complete"), // Assuming success
            (
                "src.identity",
                "spiffe://cluster.local/ns/default/sa/client",
            ), // Client identity
            ("dst.identity", zt_identity_str.as_str()), // Ztunnel identity
        ]);
        telemetry::testing::assert_contains(want);

        Ok(())
    }

    const TEST_VIP: &str = "10.10.0.1";
    const TEST_VIP2: &str = "10.10.0.2";
    const TEST_VIP3: &str = "10.10.0.3";

    const SERVER_PORT: u16 = 8080;
    const SERVER_HOSTNAME: &str = "server.default.svc.cluster.local";
    const PROXY_PROTOCOL_PORT: u16 = 15088;

    const DEFAULT_NODE: &str = "node";
    const REMOTE_NODE: &str = "remote-node";
    const UNCAPTURED_NODE: &str = "remote-node";

    const CONNECTIONS_OPENED: &str = "istio_tcp_connections_opened_total";
    const CONNECTIONS_CLOSED: &str = "istio_tcp_connections_closed_total";
    const BYTES_RECV: &str = "istio_tcp_received_bytes_total";
    const BYTES_SENT: &str = "istio_tcp_sent_bytes_total";
    const REQ_SIZE: u64 = b"hello world".len() as u64;
    const HBONE_REQ_SIZE: u64 = b"hello world".len() as u64 + b"waypoint\n".len() as u64;

    #[derive(Clone, Copy, Ord, PartialOrd, PartialEq, Eq)]
    pub enum WorkloadMode {
        Captured(&'static str),
        Uncaptured,
    }

    impl WorkloadMode {
        fn node(&self) -> &'static str {
            match self {
                Captured(n) => n,
                Uncaptured => UNCAPTURED_NODE,
            }
        }
    }

    async fn simple_client_server_test(
        mut manager: WorkloadManager,
        client_node: WorkloadMode,
        server_node: WorkloadMode,
    ) {
        // Simple test of client -> server, with the configured mode and nodes
        let client_ztunnel = match client_node {
            // Note: we always deploy as 'dedicated', just it will be ignored if we are shared
            Captured(node) => Some(
                manager
                    .deploy_dedicated_ztunnel(
                        node,
                        Some(WorkloadInfo {
                            name: "client".to_string(),
                            namespace: "default".to_string(),
                            service_account: "client".to_string(),
                        }),
                    )
                    .await
                    .unwrap(),
            ),
            Uncaptured => None,
        };
        let server_ztunnel = match server_node {
            Captured(node) => {
                if node == client_node.node() {
                    client_ztunnel.clone()
                } else {
                    Some(
                        manager
                            .deploy_dedicated_ztunnel(
                                node,
                                Some(WorkloadInfo {
                                    name: "server".to_string(),
                                    namespace: "default".to_string(),
                                    service_account: "server".to_string(),
                                }),
                            )
                            .await
                            .unwrap(),
                    )
                }
            }
            Uncaptured => None,
        };
        let server = manager
            .workload_builder("server", server_node.node())
            .register()
            .await
            .unwrap();
        run_tcp_server(server).expect("tcp server");

        let client = manager
            .workload_builder("client", client_node.node())
            .register()
            .await
            .unwrap();
        let target = if manager.mode() == Dedicated && !matches!(server_node, Uncaptured) {
            "ztunnel-remote-node"
        } else {
            "server"
        };
        run_tcp_client(client, manager.resolver(), target).expect("tcp client");

        let metrics = [
            (CONNECTIONS_OPENED, 1),
            (CONNECTIONS_CLOSED, 1),
            // Traffic is 11 bytes sent, 22 received by the client. But Istio reports them backwards (https://github.com/istio/istio/issues/32399) .
            (BYTES_RECV, REQ_SIZE),
            (BYTES_SENT, REQ_SIZE * 2),
        ];
        if let Some(ref zt) = server_ztunnel {
            let _remote_metrics = verify_metrics(zt, &metrics, &destination_labels()).await;
            let mut want = HashMap::from([
                ("scope", "access"),
                ("src.workload", "client"),
                ("dst.workload", "server"),
                ("bytes_sent", "22"),
                ("bytes_recv", "11"),
                ("direction", "inbound"),
                ("message", "connection complete"),
            ]);
            if client_ztunnel.is_some() {
                want.insert(
                    "src.identity",
                    "spiffe://cluster.local/ns/default/sa/client",
                );
                want.insert(
                    "dst.identity",
                    "spiffe://cluster.local/ns/default/sa/server",
                );
            } else {
                want.insert("src.identity", "");
                want.insert("dst.identity", "");
            }
            telemetry::testing::assert_contains(want);
        }
        if let Some(zt) = client_ztunnel {
            let _remote_metrics = verify_metrics(&zt, &metrics, &source_labels()).await;
            let mut want = HashMap::from([
                ("scope", "access"),
                ("src.workload", "client"),
                ("dst.workload", "server"),
                ("bytes_sent", "11"),
                ("bytes_recv", "22"),
                ("direction", "outbound"),
                ("message", "connection complete"),
            ]);
            if server_ztunnel.is_some() {
                want.insert(
                    "src.identity",
                    "spiffe://cluster.local/ns/default/sa/client",
                );
                want.insert(
                    "dst.identity",
                    "spiffe://cluster.local/ns/default/sa/server",
                );
            } else {
                want.insert("src.identity", "");
                want.insert("dst.identity", "");
            }
            telemetry::testing::assert_contains(want);
        }
    }

    fn destination_labels() -> HashMap<String, String> {
        HashMap::from([("reporter".to_string(), "destination".to_string())])
    }

    fn source_labels() -> HashMap<String, String> {
        HashMap::from([("reporter".to_string(), "source".to_string())])
    }

    async fn verify_metrics(
        ztunnel: &TestApp,
        assertions: &[(&str, u64)],
        labels: &HashMap<String, String>,
    ) -> ParsedMetrics {
        // Wait for metrics to populate...
        for i in 0..10 {
            let m = ztunnel.metrics().await.unwrap();
            let mut found = true;
            for (metric, _) in assertions {
                if m.query_sum(metric, labels) == 0 {
                    found = false
                }
            }
            if found {
                break;
            }
            tokio::time::sleep(Duration::from_millis(i * 10)).await;
        }
        let metrics = ztunnel.metrics().await.unwrap();

        // Now run our assertions
        for (metric, expected) in assertions {
            assert_eq!(
                metrics.query_sum(metric, labels),
                *expected,
                "{} with {:?} failed, dump: {}",
                metric,
                labels,
                metrics.dump()
            );
        }
        metrics
    }

    async fn verify_metric_exists(
        ztunnel: &TestApp,
        want_metric: &str,
        labels: &HashMap<String, String>,
    ) -> ParsedMetrics {
        // Wait for metrics to populate...
        for i in 0..10 {
            let m = ztunnel.metrics().await.unwrap();
            if m.query_sum(want_metric, labels) > 0 {
                return m;
            }
            tokio::time::sleep(Duration::from_millis(i * 10)).await;
        }
        let got = ztunnel.metrics().await.unwrap();
        panic!(
            "{} with {:?} failed, dump: {}",
            want_metric,
            labels,
            got.dump()
        );
    }

    fn resolve_target(resolver: Resolver, target: &str) -> SocketAddr {
        // We accept a ip:port, ip, or name (which is resolved).
        target.parse::<SocketAddr>().unwrap_or_else(|_| {
            let ip = target
                .parse::<IpAddr>()
                .unwrap_or_else(|_| resolver.resolve(target).unwrap());
            SocketAddr::new(ip, SERVER_PORT)
        })
    }

    /// run_tcp_client runs a simple client that reads and writes some data, asserting it flows end to end
    fn run_tcp_client(client: Namespace, resolver: Resolver, target: &str) -> anyhow::Result<()> {
        run_tcp_client_iters(&client, 1, resolver, target)
    }

    fn run_tcp_client_iters(
        client: &Namespace,
        iters: usize,
        resolver: Resolver,
        target: &str,
    ) -> anyhow::Result<()> {
        let srv = resolve_target(resolver, target);
        client
            .run(move || async move {
                for attempt in 0..iters {
                    info!("Running client attempt {attempt} to {srv}");
                    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(srv))
                        .await
                        .context("connection timeout")?
                        .context("connection failed")?;
                    timeout(
                        Duration::from_secs(5),
                        double_read_write_stream(&mut stream),
                    )
                    .await
                    .context("write timeout")?
                    .context("write failed")?;
                }
                Ok(())
            })
            .context("run client failed")?
            .join()
            .unwrap()
    }

    /// run_tcp_client runs a simple client that reads and writes some data, asserting it flows end to end
    fn run_tcp_to_hbone_client(
        client: Namespace,
        resolver: Resolver,
        target: &str,
    ) -> anyhow::Result<()> {
        let srv = resolve_target(resolver, target);
        client
            .run(move || async move {
                info!("Running client to {srv}");
                let mut stream = TcpStream::connect(srv).await.unwrap();
                hbone_read_write_stream(&mut stream).await;
                Ok(())
            })?
            .join()
            .unwrap()
    }

    /// run_tcp_server deploys a simple echo server in the provided namespace
    fn run_tcp_server(server: Namespace) -> anyhow::Result<()> {
        server.run_ready(|ready| async move {
            let echo = tcp::TestServer::new(tcp::Mode::ReadDoubleWrite, SERVER_PORT).await;
            info!("Running echo server at {}", echo.address());
            ready.set_ready();
            echo.run().await;
            Ok(())
        })?;
        Ok(())
    }

    /// run_tcp_proxy_server deploys a simple tcp proxying in the provided namespace
    fn run_tcp_proxy_server(server: Namespace, target: SocketAddr) -> anyhow::Result<()> {
        server.run_ready(move |ready| async move {
            let echo = tcp::TestServer::new(tcp::Mode::Forward(target), SERVER_PORT).await;
            info!("Running echo server at {}", echo.address());
            ready.set_ready();
            echo.run().await;
            Ok(())
        })?;
        Ok(())
    }

    /// run_tcp_proxy_server deploys a simple tcp proxying in the provided namespace
    fn run_tcp_proxy_protocol_server(server: Namespace) -> anyhow::Result<()> {
        server.run_ready(move |ready| async move {
            let echo =
                tcp::TestServer::new(tcp::Mode::ForwardProxyProtocol, PROXY_PROTOCOL_PORT).await;
            info!("Running echo server at {}", echo.address());
            ready.set_ready();
            echo.run().await;
            Ok(())
        })?;
        Ok(())
    }

    /// run_hbone_server deploys a simple echo server, deployed over HBONE, in the provided namespace
    fn run_hbone_server(
        server: Namespace,
        name: &str,
        mode: tcp::Mode,
        waypoint_message: Vec<u8>,
    ) -> anyhow::Result<()> {
        let name = name.to_string();
        server.run_ready(move |ready| async move {
            let echo = tcp::HboneTestServer::new(mode, &name, waypoint_message).await;
            info!("Running hbone echo server at {}", echo.address());
            ready.set_ready();
            echo.run().await;
            Ok(())
        })?;
        Ok(())
    }

    async fn double_read_write_stream(stream: &mut TcpStream) -> anyhow::Result<usize> {
        const BODY: &[u8] = b"hello world";
        stream.write_all(BODY).await?;
        let mut buf = [0; BODY.len() * 2];
        stream.read_exact(&mut buf).await?;
        assert_eq!(b"hello worldhello world", &buf);
        Ok(BODY.len() * 2)
    }

    async fn hbone_read_write_stream(stream: &mut TcpStream) {
        const BODY: &[u8] = b"hello world";
        stream.write_all(BODY).await.unwrap();
        let mut buf = [0; BODY.len() + WAYPOINT_MESSAGE.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!([WAYPOINT_MESSAGE, BODY].concat(), buf);
    }

    #[derive(PartialEq, Copy, Clone, Debug)]
    enum Failure {
        /// Cannot even connect
        Connection,
        /// Can connect, but cannot send bytes
        Request,
        /// Can connect, but get a HTTP error
        Http,
    }
    use Failure::*;
    use ztunnel::state::WorkloadInfo;

    async fn malicious_calls_test(
        client: Namespace,
        cases: Vec<(IpAddr, u16, Failure)>,
    ) -> anyhow::Result<()> {
        async fn send_traffic(stream: &mut TcpStream) -> anyhow::Result<()> {
            const BODY: &[u8] = b"hello world\r\n\r\n";
            stream.write_all(BODY).await?;
            let mut buf: [u8; BODY.len()] = [0; BODY.len()];
            stream.read_exact(&mut buf).await?;
            if &buf[..12] != b"HTTP/1.1 400" {
                anyhow::bail!(
                    "expected http error, got {}",
                    std::str::from_utf8(&buf).unwrap()
                );
            }
            Ok(())
        }
        client
            .run(move || async move {
                for (target, port, failure) in cases {
                    let tgt = SocketAddr::from((target, port));
                    info!("send to {tgt}, want {failure:?} error");
                    let stream = timeout(Duration::from_secs(1), TcpStream::connect(tgt)).await?;
                    error!("stream {stream:?}");
                    if failure == Connection {
                        assert!(stream.is_err(), "expected connection to fail for {tgt}");
                        continue;
                    }
                    let mut stream = stream.unwrap();

                    let res = timeout(Duration::from_secs(1), send_traffic(&mut stream)).await?;
                    if failure == Request {
                        assert!(res.is_err(), "expected request to fail for {tgt}");
                        continue;
                    }
                    res.unwrap();
                }
                Ok(())
            })?
            .join()
            .unwrap()?;
        Ok(())
    }
}
