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

use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, LazyLock};
use std::time::Instant;

use prometheus_client::registry::Registry;
use tempfile::NamedTempFile;
use tracing::debug;

use crate::metrics::sub_registry;
use crate::{proxy, telemetry};

// Ensure that the `tracing` stack is only initialised once.
static TRACING: LazyLock<()> = LazyLock::new(telemetry::testing::setup_test_logging);

pub fn initialize_telemetry() {
    LazyLock::force(&TRACING);
}

pub fn test_proxy_metrics() -> Arc<proxy::Metrics> {
    let mut registry = Registry::default();
    Arc::new(proxy::Metrics::new(sub_registry(&mut registry)))
}

pub fn with_ip(s: SocketAddr, ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, s.port())
}

pub fn run_command(cmd: &str) -> anyhow::Result<()> {
    let now = Instant::now();
    debug!("running command {cmd}");
    let output = Command::new("sh").arg("-c").arg(cmd).output()?;
    debug!(
        "command complete in {:?}; code={}, stdout={}, stderr={}",
        now.elapsed(),
        output.status,
        std::str::from_utf8(&output.stdout)?,
        std::str::from_utf8(&output.stderr)?
    );
    if !output.status.success() {
        anyhow::bail!(
            "command {} exited with code={}, stdout={}, stderr={}",
            cmd.chars().take(50).collect::<String>(),
            output.status,
            std::str::from_utf8(&output.stdout)?,
            std::str::from_utf8(&output.stderr)?
        );
    }
    Ok(())
}

/// Write a CRL PEM to a fresh temp file, ready for CrlManager::new
pub fn crl_file_with(pem: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(pem.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}
