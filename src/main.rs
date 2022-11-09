extern crate core;
#[cfg(feature = "gperftools")]
extern crate gperftools;

use tokio::task::JoinHandle;
use tracing::error;

use tracing_subscriber::prelude::*;

mod admin;
mod config;
mod identity;
mod proxy;
mod socket;
mod tls;
mod workload;
mod xds;

// #[global_allocator]
// static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// #[global_allocator]
// static GLOBAL: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

#[cfg(feature = "console")]
fn setup_logging() {
    let console_layer = console_subscriber::spawn();

    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(console_layer)
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(not(feature = "console"))]
fn setup_logging() {
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    setup_logging();

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    let config = config::Config {
        ..Default::default()
    };
    let workload_manager = workload::WorkloadManager::new(config.clone());

    let workloads = workload_manager.workloads();
    admin::Builder::new("[::]:15021".parse().unwrap(), workloads)
        .set_ready()
        .bind()
        .expect("admin server starts")
        .spawn();
    let workloads = workload_manager.workloads();
    let secrets = identity::SecretManager::new(config.clone());
    let proxy = proxy::Proxy::new(config.clone(), workloads, secrets).await?;
    tasks.push(tokio::spawn(async move {
        if let Err(e) = workload_manager.run().await {
            error!("workload manager: {}", e);
        }
    }));
    tasks.push(tokio::spawn(proxy.run()));

    futures::future::join_all(tasks).await;
    Ok(())
}
