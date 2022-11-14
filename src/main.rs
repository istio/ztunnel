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
    let config: config::Config = Default::default();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.num_worker_threads)
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move { run(config).await })
}

async fn run(cfg: config::Config) -> anyhow::Result<()> {
    // For now we don't need a complex CLI, so rather than pull in dependencies just use basic argv[1]
    match std::env::args().nth(1).as_deref() {
        None | Some("proxy") => proxy(cfg).await,
        Some("version") => version().await,
        Some(unknown) => {
            eprintln!("unknown command: {unknown}");
            std::process::exit(1)
        }
    }
}

async fn version() -> anyhow::Result<()> {
    println!("{}", version::BuildInfo::new());
    Ok(())
}

async fn proxy(cfg: config::Config) -> anyhow::Result<()> {
    app::spawn(signal::Shutdown::new(), cfg).await
}
