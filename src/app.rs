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
use std::time::Duration;

use prometheus_client::registry::Registry;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{error, info, warn};

use crate::identity::CertificateProvider;
use crate::monitoring::BuildMetrics;
use crate::{admin, config, identity, proxy, signal, workload};

pub async fn build_with_cert(
    config: config::Config,
    cert_manager: impl CertificateProvider,
) -> anyhow::Result<Bound> {
    let mut registry = Registry::default();
    let ztunnel_registry = registry.sub_registry_with_prefix("istio");
    BuildMetrics::register(ztunnel_registry);

    let shutdown = signal::Shutdown::new();
    // Setup a drain channel. drain_tx is used to trigger a drain, which will complete
    // once all drain_rx handlers are dropped.
    // Any component which wants time to gracefully exit should take in a drain_rx clone, await drain_rx.signaled(), then cleanup.
    // Note: there is still a hard timeout if the draining takes too long
    let (drain_tx, drain_rx) = drain::channel();

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    let ready = admin::Ready::new();
    let proxy_task = ready.register_task("proxy listeners");

    let workload_manager =
        workload::WorkloadManager::new(config.clone(), ztunnel_registry, ready.register_task("workload manager"))
            .await?;

    let admin = admin::Builder::new(config.clone(), workload_manager.workloads(), ready)
        .bind(registry)
        .expect("admin server starts");
    let admin_address = admin.address();
    admin.spawn(&shutdown, drain_rx.clone());

    let proxy = proxy::Proxy::new(
        config.clone(),
        workload_manager.workloads(),
        Box::new(cert_manager),
        drain_rx.clone(),
    )
    .await?;
    drop(proxy_task);

    let proxy_addresses = proxy.addresses();

    tasks.push(tokio::spawn(async move {
        if let Err(e) = workload_manager.run().await {
            error!("workload manager: {}", e);
        }
    }));
    tasks.push(tokio::spawn(proxy.run()));

    Ok(Bound {
        drain_tx,
        config,
        shutdown,
        admin_address,
        proxy_addresses,
        tasks,
    })
}

pub async fn build(config: config::Config) -> anyhow::Result<Bound> {
    if config.fake_ca {
        let cert_manager = identity::mock::MockCaClient::new(Duration::from_secs(86400));
        build_with_cert(config, cert_manager).await
    } else {
        let cert_manager = identity::SecretManager::new(config.clone());
        build_with_cert(config, cert_manager).await
    }
}

pub struct Bound {
    pub admin_address: SocketAddr,
    pub proxy_addresses: proxy::Addresses,

    pub shutdown: signal::Shutdown,
    tasks: Vec<JoinHandle<()>>,
    config: config::Config,
    drain_tx: drain::Signal,
}

impl Bound {
    pub async fn spawn(self) -> anyhow::Result<()> {
        tokio::spawn(async move {
            futures::future::join_all(self.tasks).await;
        });

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
