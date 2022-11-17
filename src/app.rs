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

use crate::{admin, config, identity, proxy, signal, workload};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{error, info, warn};

pub async fn spawn(shutdown: signal::Shutdown, config: config::Config) -> anyhow::Result<()> {
    // Setup a drain channel. drain_tx is used to trigger a drain, which will complete
    // once all drain_rx handlers are dropped.
    // Any component which wants time to gracefully exit should take in a drain_rx clone, await drain_rx.signaled(), then cleanup.
    // Note: there is still a hard timeout if the draining takes too long
    let (drain_tx, drain_rx) = drain::channel();
    let mut tasks: Vec<JoinHandle<()>> = Vec::new();
    let workload_manager = workload::WorkloadManager::new(config.clone());

    let workloads = workload_manager.workloads();
    admin::Builder::new(workloads)
        .set_ready()
        .bind()
        .expect("admin server starts")
        .spawn(&shutdown);
    let workloads = workload_manager.workloads();
    let secrets = identity::SecretManager::new(config.clone());
    let proxy = proxy::Proxy::new(config.clone(), workloads, secrets, drain_rx).await?;
    tasks.push(tokio::spawn(async move {
        if let Err(e) = workload_manager.run().await {
            error!("workload manager: {}", e);
        }
    }));
    tasks.push(tokio::spawn(proxy.run()));

    tokio::spawn(async move {
        futures::future::join_all(tasks).await;
    });

    // Wait for a signal to shutdown
    // There is an explicit way to trigger this from admin server
    shutdown.wait().await;

    // Start a drain; this will wait for all drain_rx handles to be dropped before completing,
    // allowing components to terminate.
    // If they take too long, terminate anyways.
    match time::timeout(config.termination_grace_period, drain_tx.drain()).await {
        Ok(()) => info!("Shutdown completed gracefully"),
        Err(_) => warn!(
            "Graceful shutdown did not complete in {:?}, terminating now",
            config.termination_grace_period
        ),
    }
    Ok(())
}
