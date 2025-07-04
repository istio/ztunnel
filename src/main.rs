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

use nix::sys::resource::{Resource, getrlimit, setrlimit};
use std::sync::Arc;
use tracing::{info, warn};
use ztunnel::*;

#[cfg(feature = "jemalloc")]
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(feature = "jemalloc")]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

// We use this on Unix systems to increase the number of open file descriptors
// if possible. This is useful for high-load scenarios where the default limit
// is too low, which can lead to droopped connections and other issues:
// see: https://github.com/istio/ztunnel/issues/1585
fn increase_open_files_limit() {
    #[cfg(unix)]
    if let Ok((soft_limit, hard_limit)) = getrlimit(Resource::RLIMIT_NOFILE) {
        if let Err(e) = setrlimit(Resource::RLIMIT_NOFILE, hard_limit, hard_limit) {
            warn!("failed to set file descriptor limits: {e}");
        } else {
            info!(
                "set file descriptor limits from {} to {}",
                soft_limit, hard_limit
            );
        }
    } else {
        warn!("failed to get file descriptor limits");
    }
}

fn main() -> anyhow::Result<()> {
    let _log_flush = telemetry::setup_logging();

    // For now we don't need a complex CLI, so rather than pull in dependencies just use basic argv[1]
    match std::env::args().nth(1).as_deref() {
        None | Some("proxy") => (),
        Some("version") => return version(),
        Some("help") => return help(),
        Some(unknown) => {
            eprintln!("unknown command: {unknown}");
            help().unwrap();
            std::process::exit(1)
        }
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async move {
            let config = Arc::new(config::parse_config()?);
            proxy(config).await
        })
}

fn help() -> anyhow::Result<()> {
    let version = version::BuildInfo::new();
    println!(
        "
Istio Ztunnel ({version})

Commands:
proxy (default) - Start the ztunnel proxy
version         - Print the version of ztunnel
help            - Print commands and version of ztunnel"
    );
    Ok(())
}

fn version() -> anyhow::Result<()> {
    println!("{}", version::BuildInfo::new());
    Ok(())
}

async fn proxy(cfg: Arc<config::Config>) -> anyhow::Result<()> {
    info!("version: {}", version::BuildInfo::new());
    increase_open_files_limit();
    info!("running with config: {}", serde_yaml::to_string(&cfg)?);
    app::build(cfg).await?.wait_termination().await
}
