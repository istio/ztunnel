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
    use hyper::body::Incoming;
    use hyper::Response;
    use std::collections::HashMap;
    use std::fs;
    use std::fs::File;
    use std::net::{IpAddr, SocketAddr};
    use ztunnel::identity::SecretManager;

    use std::path::PathBuf;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;
    use ztunnel::rbac::{Authorization, RbacMatch, StringMatch};

    use hyper::Method;
    use hyper_util::rt::TokioIo;
    use libc::getpid;

    use nix::unistd::mkdtemp;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tracing::{error, info};
    use WorkloadMode::Uncaptured;

    use ztunnel::state::workload::{ApplicationTunnel, NetworkAddress};
    use ztunnel::test_helpers::app::ParsedMetrics;
    use ztunnel::test_helpers::app::TestApp;
    use ztunnel::test_helpers::helpers::initialize_telemetry;
    use ztunnel::{identity, telemetry};

    use crate::namespaced::WorkloadMode::Captured;
    use ztunnel::test_helpers::linux::TestMode::{InPod, SharedNode};
    use ztunnel::test_helpers::linux::WorkloadManager;
    use ztunnel::test_helpers::netns::{Namespace, Resolver};
    use ztunnel::test_helpers::*;

    macro_rules! function {
        () => {{
            fn f() {}
            fn type_name_of<T>(_: T) -> &'static str {
                std::any::type_name::<T>()
            }
            let name = type_name_of(f);
            &name[..name.len() - 3]
        }};
    }

    /// setup_netns_test prepares a test using network namespaces. This checks we have root,
    /// and automatically setups up a namespace based on the test name (to avoid conflicts).
    macro_rules! setup_netns_test {
        ($mode:expr) => {{
            if unsafe { libc::getuid() } != 0 {
                panic!("CI tests should run as root; this is supposed to happen automatically?");
            }
            initialize_telemetry();
            let f = function!()
                .strip_prefix(module_path!())
                .unwrap()
                .strip_prefix("::")
                .unwrap()
                .strip_suffix("::{{closure}}")
                .unwrap();
            WorkloadManager::new(f, $mode)?
        }};
    }

    #[tokio::test]
    async fn local_captured_inpod() -> anyhow::Result<()> {
        simple_client_server_test(
            setup_netns_test!(InPod),
            Captured(DEFAULT_NODE),
            Captured(DEFAULT_NODE),
        )
        .await
    }

    #[tokio::test]
    async fn server_uncaptured_inpod() -> anyhow::Result<()> {
        simple_client_server_test(setup_netns_test!(InPod), Captured(DEFAULT_NODE), Uncaptured)
            .await
    }

    #[tokio::test]
    async fn client_uncaptured_inpod() -> anyhow::Result<()> {
        simple_client_server_test(setup_netns_test!(InPod), Captured(DEFAULT_NODE), Uncaptured)
            .await
    }

    #[tokio::test]
    async fn cross_node_captured_inpod() -> anyhow::Result<()> {
        simple_client_server_test(
            setup_netns_test!(InPod),
            Captured(DEFAULT_NODE),
            Captured(REMOTE_NODE),
        )
        .await
    }

    // Intentionally, we do not have a 'local_captured_sharednode'
    // This is not currently supported since https://github.com/istio/ztunnel/commit/12d154cceb1d20eb1f11ae43c2310e66e93c7120

    #[tokio::test]
    async fn server_uncaptured_sharednode() -> anyhow::Result<()> {
        simple_client_server_test(
            setup_netns_test!(SharedNode),
            Captured(DEFAULT_NODE),
            Uncaptured,
        )
        .await
    }

    #[tokio::test]
    async fn client_uncaptured_sharednode() -> anyhow::Result<()> {
        simple_client_server_test(
            setup_netns_test!(SharedNode),
            Captured(DEFAULT_NODE),
            Uncaptured,
        )
        .await
    }

    #[tokio::test]
    async fn cross_node_captured_sharednode() -> anyhow::Result<()> {
        simple_client_server_test(
            setup_netns_test!(SharedNode),
            Captured(DEFAULT_NODE),
            Captured(REMOTE_NODE),
        )
        .await
    }

    #[tokio::test]
    async fn workload_waypoint() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);

        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        let waypoint = manager.register_waypoint("waypoint", DEFAULT_NODE).await?;
        let waypoint_ip = waypoint.ip();
        run_hbone_server(waypoint, "waypoint")?;

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
            ("target", "access"),
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
    async fn service_waypoint() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);

        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        let waypoint = manager.register_waypoint("waypoint", DEFAULT_NODE).await?;
        let waypoint_ip = waypoint.ip();
        run_hbone_server(waypoint, "waypoint")?;

        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        manager
            .service_builder("service")
            .addresses(vec![NetworkAddress {
                network: "".to_string(),
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
            ("target", "access"),
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
        let mut manager = setup_netns_test!(InPod);

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
    async fn service_loadbalancing() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);
        let local = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let remote = manager.deploy_ztunnel(REMOTE_NODE).await?;
        manager
            .service_builder("service")
            .addresses(vec![NetworkAddress {
                network: "".to_string(),
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
    async fn test_policy() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);
        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        manager
            .add_policy(Authorization {
                name: "allow_specific_principal".to_string(),
                namespace: "default".to_string(),
                scope: ztunnel::rbac::RbacScope::Namespace,
                action: ztunnel::rbac::RbacAction::Allow,
                rules: vec![vec![vec![RbacMatch {
                    principals: vec![StringMatch::Exact(
                        "spiffe://cluster.local/ns/default/sa/only-allow-this-client".to_string(),
                    )],
                    ..Default::default()
                }]]],
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
        let server_addr = resolve_target(manager.resolver(), "server");
        let response = run_hbone_with_identities(
            client,
            server_addr.to_string(),
            server_addr,
            zt.cert_manager.clone(),
            "spiffe://cluster.local/ns/default/sa/client",
            "spiffe://cluster.local/ns/default/sa/server",
        )?;
        assert_eq!(response.status(), hyper::StatusCode::UNAUTHORIZED);
        telemetry::testing::assert_contains(HashMap::from([
            ("target", "access"),
            ("error", "connection closed due to policy rejection"),
        ]));
        Ok(())
    }

    #[tokio::test]
    async fn waypoint_skip_rbac() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);
        manager
            .add_policy(Authorization {
                name: "allow_specific_principal".to_string(),
                namespace: "default".to_string(),
                scope: ztunnel::rbac::RbacScope::Namespace,
                action: ztunnel::rbac::RbacAction::Allow,
                rules: vec![vec![vec![RbacMatch {
                    principals: vec![StringMatch::Exact(
                        "spiffe://cluster.local/ns/default/sa/only-allow-this-client".to_string(),
                    )],
                    ..Default::default()
                }]]],
            })
            .await?;
        let zt = manager.deploy_ztunnel(DEFAULT_NODE).await?;

        // waypoint is attached to a service
        let svc_waypoint = manager
            .register_waypoint("svc-waypoint", DEFAULT_NODE)
            .await?;
        manager
            .service_builder("service")
            .addresses(vec![NetworkAddress {
                network: "".to_string(),
                address: TEST_VIP.parse::<IpAddr>()?,
            }])
            .ports(HashMap::from([(80u16, 80u16)]))
            .waypoint(svc_waypoint.ip())
            .register()
            .await?;

        // server also has a workload waypoint
        let wl_waypoint = manager
            .register_waypoint("wl-waypoint", DEFAULT_NODE)
            .await?;
        let server = manager
            .workload_builder("server", DEFAULT_NODE)
            .waypoint(wl_waypoint.ip())
            .service("default/service.default.svc.cluster.local", 80, SERVER_PORT)
            .register()
            .await?;
        run_tcp_server(server)?;

        // make a request directly from each waypoint to the server via ztunnel
        for wp in [svc_waypoint, wl_waypoint] {
            let srv = resolve_target(manager.resolver(), "server");
            let src_id = wp.identity().to_string();
            let response = run_hbone_with_identities(
                wp,
                // HBONE host header is client IP/port
                srv.to_string(),
                // but we're actually connecting to the server-ip:15008
                srv,
                zt.cert_manager.clone(),
                &src_id,
                "spiffe://cluster.local/ns/default/sa/server",
            )?;
            assert_eq!(response.status(), hyper::StatusCode::OK);
        }
        Ok(())
    }

    #[tokio::test]
    async fn hbone_ip_mismatch() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);
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
        let response = run_hbone_with_identities(
            client,
            // HBONE host header is client IP/port
            clt.to_string(),
            // but we're actually connecting to the server-ip:15008
            srv,
            zt.cert_manager.clone(),
            "spiffe://cluster.local/ns/default/sa/client",
            "spiffe://cluster.local/ns/default/sa/server",
        )?;
        assert_eq!(response.status(), hyper::StatusCode::BAD_REQUEST);
        let e = format!("ip mismatch: {} != {}", srv.ip(), clt.ip());
        telemetry::testing::assert_contains(HashMap::from([("target", "access"), ("error", &e)]));
        Ok(())
    }

    #[tokio::test]
    async fn malicious_calls_inpod() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);
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
        malicious_calls_test(
            client,
            vec![
                (zt, 15001, Request), // Outbound: should be blocked due to recursive call
                (zt, 15006, Request), // Inbound: should be blocked due to recursive call
                (zt, 15008, Request), // HBONE: expected TLS, reject
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
            ],
        )
        .await?;

        malicious_calls_test(
            uncaptured,
            vec![
                // Ztunnel doesn't listen on these ports...
                (zt, 15001, Connection), // Outbound: should be blocked due to recursive call
                (zt, 15006, Connection), // Inbound: should be blocked due to recursive call
                (zt, 15008, Connection), // HBONE: expected TLS, reject
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
    async fn malicious_calls_sharednode() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(SharedNode);
        let _ztunnel = manager.deploy_ztunnel(DEFAULT_NODE).await?;
        let client = manager
            .workload_builder("client", DEFAULT_NODE)
            .register()
            .await?;

        let zt = manager.resolve("ztunnel-node")?;
        malicious_calls_test(
            client,
            vec![
                (zt, 15001, Request),    // Outbound: should be blocked due to recursive call
                (zt, 15006, Request),    // Inbound: should be blocked due to recursive call
                (zt, 15008, Request),    // HBONE: expected TLS, reject
                (zt, 15080, Connection), // Socks5: only localhost
                (zt, 15000, Connection), // Admin: only localhost
                (zt, 15020, Http),       // Stats: accept connection and returns a HTTP error
                (zt, 15021, Http),       // Readiness: accept connection and returns a HTTP error
            ],
        )
        .await
    }

    #[tokio::test]
    async fn trust_domain_mismatch_rejected() -> anyhow::Result<()> {
        let mut manager = setup_netns_test!(InPod);
        let id = identity::Identity::Spiffe {
            trust_domain: "clusterset.local".to_string(), // change to mismatched trustdomain
            service_account: "my-app".to_string(),
            namespace: "default".to_string(),
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

    /// initialize_namespace_tests sets up the namespace tests.
    /// These utilize the `unshare` syscall to setup an environment where we:
    /// * Are "root"
    /// * Have our own network namespace to mess with (and create other network namespaces within)
    /// * Have a few shared files re-mounted to not impact the host
    /// The special ctor macro ensures this is run *before* any code. In particular, before tokio runtime.
    #[ctor::ctor]
    fn initialize_namespace_tests() {
        use libc::getuid;
        use nix::mount::{mount, MsFlags};
        use nix::sched::{unshare, CloneFlags};
        use std::io::Write;

        // First, drop into a new user namespace.
        let original_uid = unsafe { getuid() };
        unshare(CloneFlags::CLONE_NEWUSER).unwrap();
        let mut data_file = File::create("/proc/self/uid_map").expect("creation failed");

        // Map our current user to root in the new network namespace
        data_file
            .write_all(format!("{} {} 1", 0, original_uid).as_bytes())
            .expect("write failed");

        // Setup a new network namespace
        unshare(CloneFlags::CLONE_NEWNET).unwrap();

        // Setup a new mount namespace
        unshare(CloneFlags::CLONE_NEWNS).unwrap();

        // Temporary directory will hold all our mounts
        let tp = std::env::temp_dir().join("ztunnel_namespaced.XXXXXX");
        let tmp = mkdtemp(&tp).expect("tmp dir");

        // Create /var/run/netns and if it doesn't exist. Technically this requires root, but any system should have this
        fs::create_dir_all("/var/run/netns")
            .expect("host netns dir doesn't exist and we are not root");
        let _ = File::create_new("/run/xtables.lock");
        // Bind mount /var/run/netns so we can make our own independent network namespaces
        fs::create_dir(tmp.join("netns")).expect("netns dir");
        mount(
            Some(&tmp.join("netns")),
            "/var/run/netns",
            None::<&PathBuf>,
            MsFlags::MS_BIND,
            None::<&PathBuf>,
        )
        .expect("network namespace bindmount");

        // Bind xtables lock so we can access it (otherwise, permission denied)
        File::create(tmp.join("xtables.lock")).expect("xtables file");
        mount(
            Some(&tmp.join("xtables.lock")),
            "/run/xtables.lock",
            None::<&PathBuf>,
            MsFlags::MS_BIND,
            None::<&PathBuf>,
        )
        .expect("xtables bindmount");

        let pid = unsafe { getpid() };
        eprintln!("Starting test in {tmp:?}. Debug with `sudo nsenter --mount --net -t {pid}`");
    }

    const TEST_VIP: &str = "10.10.0.1";

    const SERVER_PORT: u16 = 8080;

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
    ) -> anyhow::Result<()> {
        // Simple test of client -> server, with the configured mode and nodes
        let client_ztunnel = match client_node {
            Captured(node) => Some(manager.deploy_ztunnel(node).await?),
            Uncaptured => None,
        };
        let server_ztunnel = match server_node {
            Captured(node) => {
                if node == client_node.node() {
                    client_ztunnel.clone()
                } else {
                    Some(manager.deploy_ztunnel(node).await?)
                }
            }
            Uncaptured => None,
        };
        let server = manager
            .workload_builder("server", server_node.node())
            .register()
            .await?;
        run_tcp_server(server)?;

        let client = manager
            .workload_builder("client", client_node.node())
            .register()
            .await?;
        run_tcp_client(client, manager.resolver(), "server")?;

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
                ("target", "access"),
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
            }
            telemetry::testing::assert_contains(want);
        }
        if let Some(zt) = client_ztunnel {
            let _remote_metrics = verify_metrics(&zt, &metrics, &source_labels()).await;
            let mut want = HashMap::from([
                ("target", "access"),
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
            }
            telemetry::testing::assert_contains(want);
        }
        Ok(())
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

    // make an HBONE request directly authorized with a given source identity and validating a
    // given destination identity
    fn run_hbone_with_identities(
        client: Namespace,
        hbone_target: String,
        conn_target: SocketAddr,
        cert_manager: Arc<SecretManager>,
        client_id: &str,
        server_id: &str,
    ) -> anyhow::Result<Response<Incoming>> {
        let hbone_conn_addr = SocketAddr::new(conn_target.ip(), 15008);
        let src_id = identity::Identity::from_str(client_id).unwrap();
        let dst_id = identity::Identity::from_str(server_id).unwrap();
        client
            .run(move || async move {
                let builder =
                    hyper::client::conn::http2::Builder::new(ztunnel::hyper_util::TokioExecutor);

                let request = hyper::Request::builder()
                    .uri(hbone_target)
                    .method(Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(Empty::<Bytes>::new())
                    .unwrap();

                let cert = cert_manager.fetch_certificate(&src_id).await?;
                let connector = cert.outbound_connector(vec![dst_id]).unwrap();
                let tcp_stream = TcpStream::connect(hbone_conn_addr).await.unwrap();
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
                Ok(response)
            })?
            .join()
            .unwrap()
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
                        .unwrap()
                        .unwrap();
                    timeout(
                        Duration::from_secs(5),
                        double_read_write_stream(&mut stream),
                    )
                    .await
                    .unwrap();
                }
                Ok(())
            })?
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

    /// run_hbone_server deploys a simple echo server, deployed over HBONE, in the provided namespace
    fn run_hbone_server(server: Namespace, name: &str) -> anyhow::Result<()> {
        let name = name.to_string();
        server.run_ready(move |ready| async move {
            let echo = tcp::HboneTestServer::new(tcp::Mode::ReadWrite, &name).await;
            info!("Running hbone echo server at {}", echo.address());
            ready.set_ready();
            echo.run().await;
            Ok(())
        })?;
        Ok(())
    }

    async fn double_read_write_stream(stream: &mut TcpStream) -> usize {
        const BODY: &[u8] = b"hello world";
        stream.write_all(BODY).await.unwrap();
        let mut buf = [0; BODY.len() * 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(b"hello worldhello world", &buf);
        BODY.len() * 2
    }

    async fn hbone_read_write_stream(stream: &mut TcpStream) {
        const BODY: &[u8] = b"hello world";
        const WAYPOINT_MESSAGE: &[u8] = b"waypoint\n";
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
    use ztunnel::state::workload::application_tunnel::Protocol;
    use Failure::*;

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
                        assert!(stream.is_err());
                        continue;
                    }
                    let mut stream = stream.unwrap();

                    let res = timeout(Duration::from_secs(1), send_traffic(&mut stream)).await?;
                    if failure == Request {
                        assert!(res.is_err());
                        continue;
                    }
                    res.unwrap();
                }
                Ok(())
            })?
            .join()
            .unwrap()?;
        println!("got here!!");
        Ok(())
    }
}
