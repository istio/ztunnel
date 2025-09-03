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

use nix::sys::resource::{Resource, getrlimit};
use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric};
use prometheus_client::metrics;
use tracing::error;

// Track open fds
#[derive(Debug)]
pub struct ProcessMetrics {}
const FD_PATH: &str = "/dev/fd";

impl ProcessMetrics {
    pub fn new() -> Self {
        Self {}
    }

    fn encode_open_fds(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        // Count open fds by listing /proc/self/fd
        let open_fds = match std::fs::read_dir(FD_PATH) {
            Ok(entries) => entries.count() as u64,
            Err(e) => {
                error!("Failed to read {}: {}", FD_PATH, e);
                0
            }
        };
        // exclude the fd used to read the directory
        let gauge = metrics::gauge::ConstGauge::new(open_fds - 1);
        let metric_encoder = encoder.encode_descriptor(
            "process_open_fds",
            "Number of open file descriptors",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;
        Ok(())
    }

    fn encode_max_fds(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let fds = match getrlimit(Resource::RLIMIT_NOFILE) {
            Ok((soft_limit, _)) => soft_limit,
            Err(e) => {
                error!("Failed to get rlimit: {}", e);
                return Ok(());
            }
        };
        let gauge = metrics::gauge::ConstGauge::new(fds);
        let metric_encoder = encoder.encode_descriptor(
            "process_max_fds",
            "Maximum number of file descriptors",
            None,
            gauge.metric_type(),
        )?;
        gauge.encode(metric_encoder)?;
        Ok(())
    }
}

impl Default for ProcessMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Collector for ProcessMetrics {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        match self.encode_open_fds(&mut encoder) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to encode open fds: {}", e);
                return Ok(());
            }
        }
        match self.encode_max_fds(&mut encoder) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to encode max fds: {}", e);
            }
        }
        Ok(())
    }
}
