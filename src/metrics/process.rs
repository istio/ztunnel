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
use prometheus_client::registry::Unit;
use std::io::{Read, Seek, SeekFrom};
use tracing::error;

const FD_PATH: &str = "/dev/fd";
const PROC_STAT_PATH: &str = "/proc/self/stat";
const SYSTEM_STAT_PATH: &str = "/proc/stat";

#[derive(Debug)]
struct SystemStat {
    btime: u64,
}

impl SystemStat {
    fn parse(contents: &str) -> Option<Self> {
        const BTIME: &str = "btime ";
        let start = contents.find(BTIME)? + BTIME.len();
        let end = start + contents[start..].find('\n')?;
        Some(Self {
            btime: contents[start..end].parse().ok()?,
        })
    }
}

#[derive(Debug)]
struct ProcessStat {
    starttime: u64,
    vsize: u64,
    rss: u64, // This is %ld formatted, but that's for historical reasons and should be positive
}

impl ProcessStat {
    fn parse(contents: &str) -> Option<ProcessStat> {
        // `contents` is a space delimited array of values that look like
        //
        // 167211 (ztunnel) S 55841 167211 ...
        //
        // Since the process name (ztunnel) could contain spaces, we do `split_whitespace`
        // after the last `)`. `starttime`, `vsize`, and `rss` are the 22nd, 23rd, and 24th elements
        // of `contents` using 1-indexing per proc(5). Since we are skipping the first two elements
        // and have 0-indexing, `starttime` is the 19th element.
        let start = contents.rfind(')')? + 2;
        let mut items = contents[start..].split_whitespace();

        let starttime: u64 = items.nth(19)?.parse().ok()?;
        let vsize: u64 = items.next()?.parse().ok()?;
        let rss: u64 = items.next()?.parse().ok()?;

        Some(ProcessStat {
            starttime,
            vsize,
            rss,
        })
    }
}

// See man 5 process for descriptions of these.
#[derive(Debug)]
pub struct ProcessMetrics {
    // These should never be `None`, but we still try to handle parsing/syscall
    // errors gracefully so it is impossible to panic.
    process_stat: Option<std::fs::File>,
    page_size: Option<u64>,
    clock_ticks_per_second: Option<u64>,
    system_stat: Option<SystemStat>,
}

impl ProcessMetrics {
    fn encode_proc_stat(
        self: &Self,
        encoder: &mut DescriptorEncoder,
    ) -> Result<(), std::fmt::Error> {
        let mut fd = match &self.process_stat {
            Some(fd) => fd,
            None => return Ok(()),
        };

        let mut contents = String::new();
        // We want to seek to the start of the file and reread as
        // contents might have changed.
        if let Err(e) = fd.seek(SeekFrom::Start(0)) {
            tracing::warn!("Failed to seek {}: {}", PROC_STAT_PATH, e);
            return Ok(());
        }
        if let Err(e) = fd.read_to_string(&mut contents) {
            tracing::warn!("Failed to read {}: {}", PROC_STAT_PATH, e);
            return Ok(());
        }

        let stat = match ProcessStat::parse(&contents) {
            Some(stat) => stat,
            None => {
                tracing::warn!("Failed to parse stat file.");
                tracing::debug!(
                    "Failed to parse {} file. Contents: {}",
                    PROC_STAT_PATH,
                    contents
                );
                return Ok(());
            }
        };

        {
            let gauge = metrics::gauge::ConstGauge::new(stat.vsize);
            let metric_encoder = encoder.encode_descriptor(
                "process_virtual_memory",
                "Virtual memory size in bytes.",
                Some(&Unit::Bytes),
                gauge.metric_type(),
            )?;
            gauge.encode(metric_encoder)?;
        }

        if let Some(page_size) = self.page_size {
            let gauge = metrics::gauge::ConstGauge::new(stat.rss * page_size);
            let metric_encoder = encoder.encode_descriptor(
                "process_resident_memory",
                "Resident memory size in bytes.",
                Some(&Unit::Bytes),
                gauge.metric_type(),
            )?;
            gauge.encode(metric_encoder)?;
        }

        if let (Some(system_stat), Some(clock_ticks_per_second)) =
            (&self.system_stat, self.clock_ticks_per_second)
        {
            let gauge = metrics::gauge::ConstGauge::new(
                system_stat.btime + stat.starttime / clock_ticks_per_second,
            );
            let metric_encoder = encoder.encode_descriptor(
                "process_start_time",
                "Start time of the process since unix epoch in seconds.",
                Some(&Unit::Seconds),
                gauge.metric_type(),
            )?;
            gauge.encode(metric_encoder)?;
        }

        Ok(())
    }

    pub fn new() -> Self {
        let proc_stat_fd = match std::fs::File::open(PROC_STAT_PATH) {
            Ok(fd) => Option::Some(fd),
            Err(e) => {
                tracing::warn!("Failed to open {}: {}", PROC_STAT_PATH, e);
                None
            }
        };

        let system_stat = match std::fs::File::open(SYSTEM_STAT_PATH) {
            Ok(mut fd) => {
                let mut contents = String::new();
                match fd.read_to_string(&mut contents) {
                    Err(e) => {
                        tracing::warn!("Failed to read {}: {}", SYSTEM_STAT_PATH, e);
                        None
                    }
                    Ok(_) => {
                        let system_stat = SystemStat::parse(&contents);
                        if system_stat.is_none() {
                            tracing::warn!("Failed to parse {}", SYSTEM_STAT_PATH);
                            tracing::debug!("Failed to parse {}: {}", SYSTEM_STAT_PATH, contents);
                        }
                        system_stat
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to open {}: {}", SYSTEM_STAT_PATH, e);
                None
            }
        };

        let page_size = match nix::unistd::sysconf(nix::unistd::SysconfVar::PAGE_SIZE) {
            Ok(Some(s)) => s.try_into().ok(),
            Err(e) => {
                tracing::warn!("Failed to get page size: {}", e);
                None
            }
            _ => {
                tracing::warn!("Failed to get page size");
                None
            }
        };

        let clock_ticks_per_second = match nix::unistd::sysconf(nix::unistd::SysconfVar::CLK_TCK) {
            Ok(Some(s)) if s > 0 => s.try_into().ok(),
            Err(e) => {
                tracing::warn!("Failed to get clock ticks per second: {}", e);
                None
            }
            _ => {
                tracing::warn!("Failed to get clock ticks per second");
                None
            }
        };

        Self {
            process_stat: proc_stat_fd,
            system_stat,
            page_size,
            clock_ticks_per_second,
        }
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

    fn encode_max_vmem(&self, encoder: &mut DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let max_vmem = match getrlimit(Resource::RLIMIT_AS) {
            // Often, max_vmem is unlimited. This is expressed as a soft limit of
            // 0xFFFFFFFFFFFFFFFF. This gives us a format error if we try to pass this to prometheus
            // despite it being a perfectly valid u64 so we use f64 instead.
            Ok((soft_limit, _)) => soft_limit as f64,
            Err(e) => {
                error!("Failed to get rlimit: {}", e);
                return Ok(());
            }
        };
        let gauge = metrics::gauge::ConstGauge::new(max_vmem);
        let metric_encoder = encoder.encode_descriptor(
            "process_virtual_memory_max",
            "Maximum amount of virtual memory available in bytes.",
            Some(&Unit::Bytes),
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
        match self.encode_proc_stat(&mut encoder) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to encode open process stats: {}", e);
                return Ok(());
            }
        }
        match self.encode_max_vmem(&mut encoder) {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to encode max vmem: {}", e);
                return Ok(());
            }
        }
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
