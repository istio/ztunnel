extern crate core;
#[cfg(feature = "gperftools")]
extern crate gperftools;

use ztunnel::*;

// #[global_allocator]
// static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// #[global_allocator]
// static GLOBAL: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

fn main() -> anyhow::Result<()> {
    telemetry::setup_logging();
    let config = ztunnel::config::Config {
        ..Default::default()
    };

    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.num_worker_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move { app::spawn(signal::Shutdown::new(), config).await })
}
