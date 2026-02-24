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
use spire_api::DelegatedIdentityClient;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use tokio::task::JoinSet;
use tracing::{Instrument, warn};

use crate::identity::SecretManager;
use crate::state::ProxyStateManager;
use crate::{admin, config, metrics, proxy, readiness, signal};
use crate::{dns, xds};

pub async fn build_with_cert(
    config: Arc<config::Config>,
    cert_manager: Arc<SecretManager>,
) -> anyhow::Result<Bound> {
    // Start the data plane worker pool.
    let data_plane_pool = new_data_plane_pool(config.num_worker_threads);

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
    let istio_registry = metrics::sub_registry(&mut registry);
    let _ = metrics::meta::Metrics::new(istio_registry);
    let xds_metrics = xds::Metrics::new(istio_registry);
    let proxy_metrics = Arc::new(proxy::Metrics::new(istio_registry));
    let dns_metrics = if config.dns_proxy {
        Some(dns::Metrics::new(istio_registry))
    } else {
        None
    };

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
    let mut xds_rx_for_task = xds_rx.clone();
    tokio::spawn(async move {
        let _ = xds_rx_for_task.changed().await;
        std::mem::drop(state_mgr_task);
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
                    let _ = xds_rx_for_inbound.changed().await;
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
                let _ = xds_rx_for_proxy.changed().await;
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
                        let _ = xds_rx_for_proxy.changed().await;
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
                        let _ = xds_rx_for_dns_proxy.changed().await;
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
    })
}

fn register_process_metrics(registry: &mut Registry) {
    #[cfg(unix)]
    registry.register_collector(Box::new(metrics::process::ProcessMetrics::new()));
}

struct DataPlaneTask {
    block_shutdown: bool,
    fut: Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + Sync + 'static>>,
}

fn new_data_plane_pool(num_worker_threads: usize) -> mpsc::Sender<DataPlaneTask> {
    let (tx, rx) = mpsc::channel();

    let span = tracing::span::Span::current();
    thread::spawn(move || {
        let _span = span.enter();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(num_worker_threads)
            .thread_name_fn(|| {
                static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
                let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
                // Thread name can only be 16 chars so keep it short
                format!("ztunnel-{id}")
            })
            .enable_all()
            .build()
            .unwrap();
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

    tx
}

pub async fn build(config: Arc<config::Config>) -> anyhow::Result<Bound> {
    let cert_manager = if config.fake_ca {
        mock_secret_manager()
    } else if config.spire_enabled {
        let dc = DelegatedIdentityClient::default().await?;
        Arc::new(SecretManager::new_with_spire_client(config.clone(), dc).await?)
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
