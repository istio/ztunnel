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

use std::future::Future;

use crate::proxyfactory::ProxyFactory;

use crate::drain;
use anyhow::Context;
use prometheus_client::registry::Registry;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use tokio::task::JoinSet;
use tracing::{Instrument, debug, info, warn};

use crate::identity::SecretManager;
use crate::state::ProxyStateManager;
use crate::{admin, config, metrics, proxy, readiness, signal};
use crate::{dns, xds};

const XDS_LOW_UNHEALTHY_THRESHOLD_WARNING: std::time::Duration = std::time::Duration::from_secs(15);

pub async fn build_with_cert(
    config: Arc<config::Config>,
    cert_manager: Arc<SecretManager>,
) -> anyhow::Result<Bound> {
    // Startup orchestration overview:
    //
    //  ┌─────────────────────────────────────────────────────────────────┐
    //  │ 1. Bootstrap                                                    │
    //  │    data plane pool, drain channel, readiness tasks, metrics     │
    //  └──────────────────────────┬──────────────────────────────────────┘
    //                             │
    //  ┌──────────────────────────▼──────────────────────────────────────┐
    //  │ 2. ProxyStateManager (creates xDS client)                       │
    //  └──────────────────────────┬──────────────────────────────────────┘
    //                             │
    //  ┌──────────────────────────▼──────────────────────────────────────┐
    //  │ 3. xDS monitoring task                                          │
    //  │    Phase 1: wait for initial xDS sync → drop "state manager"    │
    //  │    Phase 2: if XDS_UNHEALTHY_THRESHOLD set:                     │
    //  │             non-Synced ──► grace period ──► block readiness      │
    //  │             Synced ACK ──► reset/restore readiness               │
    //  └──────────────────────────┬──────────────────────────────────────┘
    //                             │
    //  ┌──────────────────────────▼──────────────────────────────────────┐
    //  │ 4. Proxy / DNS listeners (wait for xDS sync before accepting)   │
    //  └──────────────────────────┬──────────────────────────────────────┘
    //                             │
    //  ┌──────────────────────────▼──────────────────────────────────────┐
    //  │ 5. Admin + metrics servers                                      │
    //  └─────────────────────────────────────────────────────────────────┘
    //
    // Start the data plane worker pool.
    let (data_plane_pool, data_plane_handle) = new_data_plane_pool(config.num_worker_threads);

    let shutdown = signal::Shutdown::new();
    // Setup a drain channel. drain_tx is used to trigger a drain, which will complete
    // once all drain_rx handlers are dropped.
    // Any component which wants time to gracefully exit should take in a drain_rx clone,
    // await drain_rx.signaled(), then cleanup.
    // Note: there is still a hard timeout if the draining takes too long
    let (drain_tx, drain_rx) = drain::new();

    // Register readiness tasks.
    let ready = readiness::Ready::new();
    let state_mgr_task = ready.register_task("state manager");
    let proxy_task = if config.proxy {
        Some(ready.register_task("proxy"))
    } else {
        None
    };
    let dns_task = if config.dns_proxy {
        Some(ready.register_task("dns proxy"))
    } else {
        None
    };

    // Create and start the readiness server.
    let readiness_server = readiness::Server::new(config.clone(), drain_rx.clone(), ready.clone())
        .await
        .context("readiness server starts")?;
    let readiness_address = readiness_server.address();
    // Run the readiness server in the data plane worker pool.
    data_plane_pool.send(DataPlaneTask {
        block_shutdown: false,
        fut: Box::pin(async move {
            readiness_server.spawn();
            Ok(())
        }),
    })?;

    // Register metrics.
    let mut registry = Registry::default();
    register_process_metrics(&mut registry);
    metrics::tokio_runtime::TokioRuntimeCollector::register(&mut registry, &data_plane_handle);
    let istio_registry = metrics::sub_registry(&mut registry);
    let _ = metrics::meta::Metrics::new(istio_registry);
    let xds_metrics =
        xds::Metrics::new_with_remote_xds(istio_registry, config.xds_address.is_some());
    let xds_monitor_metrics = xds::XdsConnectionMonitorMetrics::new(istio_registry);
    let proxy_metrics = Arc::new(proxy::Metrics::new(istio_registry));
    let dns_metrics = if config.dns_proxy {
        Some(dns::Metrics::new(istio_registry))
    } else {
        None
    };

    #[cfg(not(target_os = "linux"))]
    if config.socket_config.user_timeout_enabled {
        warn!("TCP user timeout is configured but unsupported on non-Linux; setting is disabled");
    }

    let (xds_tx, xds_rx) = tokio::sync::watch::channel(());
    // Create the manager that updates proxy state from XDS.
    let state_mgr = ProxyStateManager::new(
        config.clone(),
        xds_metrics,
        proxy_metrics.clone(),
        xds_tx,
        cert_manager.clone(),
    )
    .await?;
    let xds_connection_state_rx = state_mgr.xds_connection_state();
    #[cfg(any(test, feature = "testing"))]
    let xds_connection_state_for_test = xds_connection_state_rx.clone();
    #[cfg(any(test, feature = "testing"))]
    let xds_startup_for_test = xds_rx.clone();
    #[cfg(any(test, feature = "testing"))]
    let (xds_readiness_monitor_exited_tx, xds_readiness_monitor_exited_for_test) =
        tokio::sync::watch::channel(false);
    let xds_rx_for_task = xds_rx.clone();
    let xds_unhealthy_threshold = config.xds_unhealthy_threshold;
    let remote_xds_configured = xds_connection_state_rx.is_some();
    match (remote_xds_configured, xds_unhealthy_threshold) {
        (true, Some(threshold)) => {
            info!(
                threshold_ms = threshold.as_millis() as u64,
                "xDS readiness re-arm monitor enabled"
            );
            if warn_for_low_xds_unhealthy_threshold(threshold) {
                warn!(
                    threshold_ms = threshold.as_millis() as u64,
                    recommended_minimum_ms = XDS_LOW_UNHEALTHY_THRESHOLD_WARNING.as_millis() as u64,
                    "XDS_UNHEALTHY_THRESHOLD is below the xDS reconnect backoff ceiling; routine reconnects may mark readiness unhealthy"
                );
            }
        }
        (false, Some(_)) => {
            warn!(
                "XDS_UNHEALTHY_THRESHOLD is set but no remote xDS is configured; readiness rearm is inert"
            );
        }
        (_, None) => {
            debug!("xDS readiness re-arm monitor disabled (XDS_UNHEALTHY_THRESHOLD not set)")
        }
    }
    let ready_for_rearm = ready.clone();
    let readiness_gate =
        xds::readiness_monitor::XdsReadinessGate::new(ready_for_rearm, state_mgr_task);
    let readiness_gate_for_panic = readiness_gate.clone();
    tokio::spawn(async move {
        let task = std::panic::AssertUnwindSafe(xds::readiness_monitor::run_readiness_task(
            xds_connection_state_rx,
            xds_rx_for_task,
            readiness_gate,
            xds_unhealthy_threshold,
            xds_monitor_metrics,
        ));
        if futures::FutureExt::catch_unwind(task).await.is_err() {
            // The gate used for panic recovery is owned outside the unwinding
            // future, so any existing blocker is replaced with
            // `xds monitor dead` if the monitor panics.
            xds::readiness_monitor::park_monitor_dead_after_panic(readiness_gate_for_panic)
                .await;
        }
        #[cfg(any(test, feature = "testing"))]
        xds_readiness_monitor_exited_tx.send_replace(true);
    });
    let state = state_mgr.state();

    // Run the XDS state manager in the current tokio worker pool.
    tokio::spawn(state_mgr.run());

    // Create and start the admin server.
    let mut admin_server = admin::Service::new(
        config.clone(),
        state.clone(),
        shutdown.trigger(),
        drain_rx.clone(),
        cert_manager.clone(),
    )
    .await
    .context("admin server starts")?;
    let admin_address = admin_server.address();

    // Optionally create the HBONE proxy.
    let mut proxy_addresses = None;
    let mut tcp_dns_proxy_address: Option<SocketAddr> = None;
    let mut udp_dns_proxy_address: Option<SocketAddr> = None;

    let proxy_gen = ProxyFactory::new(
        config.clone(),
        state.clone(),
        cert_manager.clone(),
        proxy_metrics,
        dns_metrics,
        drain_rx.clone(),
    )
    .map_err(|e| anyhow::anyhow!("failed to start proxy factory {:?}", e))?;

    if config.proxy_mode == config::ProxyMode::Shared {
        tracing::info!("shared proxy mode - in-pod mode enabled");

        // Create ztunnel inbound listener only if its specific identity and workload info are configured.
        if let Some(inbound) = proxy_gen.create_ztunnel_self_proxy_listener().await? {
            // Run the inbound listener in the data plane worker pool
            let mut xds_rx_for_inbound = xds_rx.clone();
            data_plane_pool.send(DataPlaneTask {
                block_shutdown: true,
                fut: Box::pin(async move {
                    tracing::info!("Starting ztunnel inbound listener task");
                    if !wait_for_initial_xds_sync(
                        &mut xds_rx_for_inbound,
                        remote_xds_configured,
                        "ztunnel inbound listener",
                    )
                    .await
                    {
                        return Ok(());
                    }
                    tokio::task::spawn(async move {
                        inbound.run().in_current_span().await;
                    })
                    .await?;
                    Ok(())
                }),
            })?;
        }

        let run_future = init_inpod_proxy_mgr(
            &mut registry,
            &mut admin_server,
            &config,
            proxy_gen,
            ready.clone(),
            drain_rx.clone(),
        )?;

        let mut xds_rx_for_proxy = xds_rx.clone();
        data_plane_pool.send(DataPlaneTask {
            block_shutdown: true,
            fut: Box::pin(async move {
                if !wait_for_initial_xds_sync(
                    &mut xds_rx_for_proxy,
                    remote_xds_configured,
                    "in-pod proxy manager",
                )
                .await
                {
                    return Ok(());
                }
                run_future.in_current_span().await;
                Ok(())
            }),
        })?;
    } else {
        tracing::info!("proxy mode enabled");
        let wli = config
            .proxy_workload_information
            .clone()
            .expect("proxy_workload_information is required for dedicated mode");
        let proxies = proxy_gen.new_proxies_for_dedicated(wli).await?;
        match proxies.proxy {
            Some(proxy) => {
                proxy_addresses = Some(proxy.addresses());

                // Run the HBONE proxy in the data plane worker pool.
                let mut xds_rx_for_proxy = xds_rx.clone();
                data_plane_pool.send(DataPlaneTask {
                    block_shutdown: true,
                    fut: Box::pin(async move {
                        if !wait_for_initial_xds_sync(
                            &mut xds_rx_for_proxy,
                            remote_xds_configured,
                            "dedicated proxy listener",
                        )
                        .await
                        {
                            return Ok(());
                        }
                        proxy.run().in_current_span().await;
                        Ok(())
                    }),
                })?;

                drop(proxy_task);
            }
            None => {
                tracing::info!("no proxy created");
            }
        }

        match proxies.dns_proxy {
            Some(dns_proxy) => {
                // Optional
                tcp_dns_proxy_address = Some(dns_proxy.tcp_address());
                udp_dns_proxy_address = Some(dns_proxy.udp_address());

                // Run the DNS proxy in the data plane worker pool.
                let mut xds_rx_for_dns_proxy = xds_rx.clone();
                data_plane_pool.send(DataPlaneTask {
                    block_shutdown: true,
                    fut: Box::pin(async move {
                        if !wait_for_initial_xds_sync(
                            &mut xds_rx_for_dns_proxy,
                            remote_xds_configured,
                            "DNS proxy listener",
                        )
                        .await
                        {
                            return Ok(());
                        }
                        dns_proxy.run().in_current_span().await;
                        Ok(())
                    }),
                })?;

                drop(dns_task);
            }
            None => {
                tracing::info!("no dns proxy created");
            }
        }
    }

    // Run the admin server in the current tokio worker pool.
    admin_server.spawn();

    // Create and start the metrics server.
    let metrics_server = metrics::Server::new(config.clone(), drain_rx.clone(), registry)
        .await
        .context("stats server starts")?;
    let metrics_address = metrics_server.address();
    // Run the metrics sever in the current tokio worker pool.
    metrics_server.spawn();

    Ok(Bound {
        drain_tx,
        shutdown,
        readiness_address,
        admin_address,
        metrics_address,
        proxy_addresses,
        tcp_dns_proxy_address,
        udp_dns_proxy_address,
        #[cfg(any(test, feature = "testing"))]
        xds_connection_state: xds_connection_state_for_test,
        #[cfg(any(test, feature = "testing"))]
        xds_startup: xds_startup_for_test,
        #[cfg(any(test, feature = "testing"))]
        xds_readiness_monitor_exited: xds_readiness_monitor_exited_for_test,
    })
}

fn register_process_metrics(registry: &mut Registry) {
    #[cfg(unix)]
    registry.register_collector(Box::new(metrics::process::ProcessMetrics::new()));
}

fn warn_for_low_xds_unhealthy_threshold(threshold: std::time::Duration) -> bool {
    threshold <= XDS_LOW_UNHEALTHY_THRESHOLD_WARNING
}

async fn wait_for_initial_xds_sync(
    xds_rx: &mut tokio::sync::watch::Receiver<()>,
    remote_xds_configured: bool,
    component: &'static str,
) -> bool {
    match xds_rx.changed().await {
        Ok(()) => true,
        Err(_) if remote_xds_configured => {
            tracing::error!(
                component,
                "xDS startup signal sender dropped before initial sync; not starting listener"
            );
            false
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_xds_unhealthy_threshold_warning_includes_backoff_ceiling() {
        assert!(warn_for_low_xds_unhealthy_threshold(
            std::time::Duration::from_secs(15)
        ));
        assert!(!warn_for_low_xds_unhealthy_threshold(
            std::time::Duration::from_secs(16)
        ));
    }

    #[tokio::test]
    async fn remote_xds_startup_wait_fails_closed_when_sender_drops() {
        let (tx, mut rx) = tokio::sync::watch::channel(());
        drop(tx);

        assert!(!wait_for_initial_xds_sync(&mut rx, true, "test proxy").await);
    }

    #[tokio::test]
    async fn local_xds_startup_wait_allows_sender_drop() {
        let (tx, mut rx) = tokio::sync::watch::channel(());
        drop(tx);

        assert!(wait_for_initial_xds_sync(&mut rx, false, "test proxy").await);
    }
}

struct DataPlaneTask {
    block_shutdown: bool,
    fut: Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + Sync + 'static>>,
}

fn new_data_plane_pool(
    num_worker_threads: usize,
) -> (mpsc::Sender<DataPlaneTask>, tokio::runtime::Handle) {
    let (tx, rx) = mpsc::channel();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_worker_threads)
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("ztunnel-{id}")
        })
        .enable_all()
        .build()
        .unwrap();

    let handle = runtime.handle().clone();

    let span = tracing::span::Span::current();
    thread::spawn(move || {
        let _span = span.enter();
        runtime.block_on(
            async move {
                let mut join_set = JoinSet::new();

                // Spawn tasks as they're received, until all tasks are spawned.
                let task_iter: mpsc::Iter<DataPlaneTask> = rx.iter();
                for task in task_iter {
                    if task.block_shutdown {
                        // We'll block shutdown on this task.
                        join_set.spawn(task.fut);
                    } else {
                        // We won't block shutdown of this task. Just spawn and forget.
                        tokio::spawn(task.fut);
                    }
                }

                while let Some(join_result) = join_set.join_next().await {
                    match join_result {
                        Ok(result) => {
                            if let Err(e) = result {
                                warn!("data plane task failed: {e}");
                            }
                        }
                        Err(e) => warn!("failed joining data plane task: {e}"),
                    }
                }
            }
            .in_current_span(),
        );
    });

    (tx, handle)
}

pub async fn build(config: Arc<config::Config>) -> anyhow::Result<Bound> {
    let cert_manager = if config.fake_ca {
        mock_secret_manager()
    } else {
        Arc::new(SecretManager::new(config.clone()).await?)
    };
    build_with_cert(config, cert_manager).await
}

#[cfg(feature = "testing")]
fn mock_secret_manager() -> Arc<SecretManager> {
    crate::identity::mock::new_secret_manager(std::time::Duration::from_secs(86400))
}

#[cfg(not(feature = "testing"))]
fn mock_secret_manager() -> Arc<SecretManager> {
    unimplemented!("fake_ca requires --features testing")
}

#[cfg(not(target_os = "linux"))]
fn init_inpod_proxy_mgr(
    _registry: &mut Registry,
    _admin_server: &mut crate::admin::Service,
    _config: &config::Config,
    _proxy_gen: ProxyFactory,
    _ready: readiness::Ready,
    _drain_rx: drain::DrainWatcher,
) -> anyhow::Result<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>> {
    anyhow::bail!("in-pod mode is not supported on non-linux platforms")
}

#[cfg(target_os = "linux")]
fn init_inpod_proxy_mgr(
    registry: &mut Registry,
    admin_server: &mut crate::admin::Service,
    config: &config::Config,
    proxy_gen: ProxyFactory,
    ready: readiness::Ready,
    drain_rx: drain::DrainWatcher,
) -> anyhow::Result<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>> {
    let metrics = Arc::new(crate::inpod::metrics::Metrics::new(
        registry.sub_registry_with_prefix("workload_manager"),
    ));
    let proxy_mgr = crate::inpod::init_and_new(metrics, admin_server, config, proxy_gen, ready)
        .map_err(|e| anyhow::anyhow!("failed to start workload proxy manager {:?}", e))?;

    Ok(Box::pin(async move {
        match proxy_mgr.run(drain_rx).await {
            Ok(()) => (),
            Err(e) => {
                tracing::error!("WorkloadProxyManager run error: {:?}", e);
                std::process::exit(1);
            }
        }
    }))
}

pub struct Bound {
    pub admin_address: SocketAddr,
    pub metrics_address: SocketAddr,
    pub readiness_address: SocketAddr,

    pub proxy_addresses: Option<proxy::Addresses>,
    pub tcp_dns_proxy_address: Option<SocketAddr>,
    pub udp_dns_proxy_address: Option<SocketAddr>,

    pub shutdown: signal::Shutdown,
    drain_tx: drain::DrainTrigger,

    #[cfg(any(test, feature = "testing"))]
    pub(crate) xds_connection_state: Option<tokio::sync::watch::Receiver<xds::XdsConnectionState>>,
    #[cfg(any(test, feature = "testing"))]
    pub(crate) xds_startup: tokio::sync::watch::Receiver<()>,
    #[cfg(any(test, feature = "testing"))]
    pub(crate) xds_readiness_monitor_exited: tokio::sync::watch::Receiver<bool>,
}

impl Bound {
    pub async fn wait_termination(self) -> anyhow::Result<()> {
        // Wait for a signal to shutdown from explicit admin shutdown or signal
        self.shutdown.wait().await;

        // Start a drain; this will attempt to end all connections
        // or itself be interrupted by a stronger TERM signal, whichever comes first.
        self.drain_tx
            .start_drain_and_wait(drain::DrainMode::Graceful)
            .await;

        Ok(())
    }
}
