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
    app::build(cfg).await?.spawn().await
}
