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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use prometheus_client::registry::Registry;
use tokio::time;
use tracing::{error, info, warn};

use crate::identity::CertificateProvider;
use crate::metrics::Metrics;
use crate::{admin, config, identity, proxy, signal, workload};

pub async fn build_with_cert(
    config: config::Config,
    cert_manager: impl CertificateProvider,
) -> anyhow::Result<Bound> {
    let mut registry = Registry::default();
    let metrics = Arc::new(Metrics::from(&mut registry));

    let shutdown = signal::Shutdown::new();
    // Setup a drain channel. drain_tx is used to trigger a drain, which will complete
    // once all drain_rx handlers are dropped.
    // Any component which wants time to gracefully exit should take in a drain_rx clone, await drain_rx.signaled(), then cleanup.
    // Note: there is still a hard timeout if the draining takes too long
    let (drain_tx, drain_rx) = drain::channel();

    let ready = admin::Ready::new();
    let proxy_task = ready.register_task("proxy listeners");

    let workload_manager = workload::WorkloadManager::new(
        config.clone(),
        metrics.clone(),
        ready.register_task("workload manager"),
    )
    .await?;

    let shutdown_trigger = shutdown.trigger();
    let admin = admin::Builder::new(config.clone(), workload_manager.workloads(), ready)
        .bind(registry, shutdown_trigger)
        .expect("admin server starts");
    let admin_address = admin.address();

    let drain_rx_admin = drain_rx.clone();
    let proxy = proxy::Proxy::new(
        config.clone(),
        workload_manager.workloads(),
        Box::new(cert_manager),
        metrics.clone(),
        drain_rx.clone(),
    )
    .await?;
    drop(proxy_task);

    // spawn admin task and xds client task
    admin.spawn(drain_rx_admin);
    tokio::spawn(async move {
        if let Err(e) = workload_manager.run().await {
            error!("workload manager: {}", e);
        }
    });

    let proxy_addresses = proxy.addresses();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(config.num_worker_threads)
            .thread_name_fn(|| {
                static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
                let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
                format!("ztunnel-proxy-{}", id)
            })
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            proxy.run().await;
        });
    });

    Ok(Bound {
        drain_tx,
        config,
        shutdown,
        admin_address,
        proxy_addresses,
    })
}

pub async fn build(config: config::Config) -> anyhow::Result<Bound> {
    if config.fake_ca {
        let cert_manager = identity::mock::MockCaClient::new(Duration::from_secs(86400));
        build_with_cert(config, cert_manager).await
    } else {
        let cert_manager = identity::SecretManager::new(config.clone())?;
        build_with_cert(config, cert_manager).await
    }
}

pub struct Bound {
    pub admin_address: SocketAddr,
    pub proxy_addresses: proxy::Addresses,

    pub shutdown: signal::Shutdown,
    config: config::Config,
    drain_tx: drain::Signal,
}

impl Bound {
    pub async fn wait_termination(self) -> anyhow::Result<()> {
        // Wait for a signal to shutdown from explicit admin shutdown or signal
        self.shutdown.wait().await;

        // Start a drain; this will wait for all drain_rx handles to be dropped before completing,
        // allowing components to terminate.
        // If they take too long, terminate anyways.
        match time::timeout(self.config.termination_grace_period, self.drain_tx.drain()).await {
            Ok(()) => info!("Shutdown completed gracefully"),
            Err(_) => warn!(
                "Graceful shutdown did not complete in {:?}, terminating now",
                self.config.termination_grace_period
            ),
        }
        Ok(())
    }
}
