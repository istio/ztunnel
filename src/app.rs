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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use prometheus_client::registry::Registry;
use tokio::task::JoinSet;
use tracing::{warn, Instrument};

use crate::identity::SecretManager;
use crate::state::ProxyStateManager;
use crate::{admin, config, identity, metrics, proxy, readiness, signal};
use crate::{dns, xds};

pub async fn build_with_cert(
    config: config::Config,
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
    let (drain_tx, drain_rx) = drain::channel();

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
    let istio_registry = metrics::sub_registry(&mut registry);
    let _ = metrics::meta::Metrics::new(istio_registry);
    let xds_metrics = xds::Metrics::new(istio_registry);
    let proxy_metrics = if config.proxy {
        Some(proxy::Metrics::new(istio_registry))
    } else {
        None
    };
    let dns_metrics = if config.dns_proxy {
        Some(dns::Metrics::new(istio_registry))
    } else {
        None
    };

    // Create and start the metrics server.
    let metrics_server = metrics::Server::new(config.clone(), drain_rx.clone(), registry)
        .await
        .context("stats server starts")?;
    let metrics_address = metrics_server.address();
    // Run the metrics sever in the current tokio worker pool.
    metrics_server.spawn();

    // Create the manager that updates proxy state from XDS.
    let state_mgr = ProxyStateManager::new(
        config.clone(),
        xds_metrics,
        state_mgr_task,
        cert_manager.clone(),
    )
    .await?;
    let state = state_mgr.state();

    // Create and start the admin server.
    let admin_server = admin::Service::new(
        config.clone(),
        state.clone(),
        shutdown.trigger(),
        drain_rx.clone(),
        cert_manager.clone(),
    )
    .await
    .context("admin server starts")?;
    let admin_address = admin_server.address();
    // Run the admin server in the current tokio worker pool.
    admin_server.spawn();

    // Run the XDS state manager in the current tokio worker pool.
    tokio::spawn(state_mgr.run());

    // Optionally create the HBONE proxy.
    let proxy_addresses = if config.proxy {
        let proxy = proxy::Proxy::new(
            config.clone(),
            state.clone(),
            cert_manager.clone(),
            proxy_metrics.unwrap(),
            drain_rx.clone(),
        )
        .await?;
        let addresses = proxy.addresses();

        // Run the HBONE proxy in the data plane worker pool.
        data_plane_pool.send(DataPlaneTask {
            block_shutdown: true,
            fut: Box::pin(async move {
                proxy.run().in_current_span().await;
                Ok(())
            }),
        })?;

        drop(proxy_task);
        Some(addresses)
    } else {
        None
    };

    // Optionally create the DNS proxy.
    let dns_proxy_address = if config.dns_proxy {
        let dns_proxy = dns::Server::new(
            config.dns_proxy_addr,
            config.network,
            state.clone(),
            dns::forwarder_for_mode(config.proxy_mode)?,
            dns_metrics.unwrap(),
        )
        .await?;
        let address = dns_proxy.address();

        // Run the DNS proxy in the data plane worker pool.
        data_plane_pool.send(DataPlaneTask {
            block_shutdown: true,
            fut: Box::pin(async move {
                dns_proxy.run().in_current_span().await;
                Ok(())
            }),
        })?;

        drop(dns_task);
        Some(address)
    } else {
        None
    };

    Ok(Bound {
        drain_tx,
        shutdown,
        readiness_address,
        admin_address,
        metrics_address,
        proxy_addresses,
        dns_proxy_address,
    })
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
                format!("ztunnel-proxy-{id}")
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

pub async fn build(config: config::Config) -> anyhow::Result<Bound> {
    let cert_manager = if config.fake_ca {
        identity::mock::new_secret_manager(Duration::from_secs(86400))
    } else {
        Arc::new(SecretManager::new(config.clone())?)
    };
    build_with_cert(config, cert_manager).await
}

pub struct Bound {
    pub admin_address: SocketAddr,
    pub metrics_address: SocketAddr,
    pub readiness_address: SocketAddr,

    pub proxy_addresses: Option<proxy::Addresses>,
    pub dns_proxy_address: Option<SocketAddr>,

    pub shutdown: signal::Shutdown,
    drain_tx: drain::Signal,
}

impl Bound {
    pub async fn wait_termination(self) -> anyhow::Result<()> {
        // Wait for a signal to shutdown from explicit admin shutdown or signal
        self.shutdown.wait().await;

        // Start a drain; this will attempt to end all connections
        // or itself be interrupted by a stronger TERM signal, whichever comes first.
        self.drain_tx.drain().await;

        Ok(())
    }
}
