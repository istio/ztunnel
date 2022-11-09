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
    admin::Builder::new("[::]:15021".parse().unwrap(), workloads)
        .set_ready()
        .bind()
        .expect("admin server starts")
        .spawn();
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
    // TODO: add a explicit way to trigger this from admin server
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
