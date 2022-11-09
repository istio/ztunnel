extern crate core;
#[cfg(feature = "gperftools")]
extern crate gperftools;

use ztunnel::*;

// #[global_allocator]
// static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// #[global_allocator]
// static GLOBAL: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    telemetry::setup_logging();
    let config = ztunnel::config::Config {
        ..Default::default()
    };
    app::spawn(signal::Shutdown::new(), config).await
}
