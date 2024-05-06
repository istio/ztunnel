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

use std::env;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Instant;

use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;

use thiserror::Error;
use tracing::{error, field, info, warn, Event, Subscriber};

use tracing_subscriber::fmt::format::Writer;

use tracing_subscriber::fmt::{format, FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{filter, prelude::*, reload, Layer, Registry};

pub static APPLICATION_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);
static LOG_HANDLE: OnceCell<LogHandle> = OnceCell::new();

pub fn setup_logging() {
    Lazy::force(&APPLICATION_START_TIME);
    tracing_subscriber::registry().with(fmt_layer()).init();
}

fn json_fmt() -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let format = tracing_subscriber::fmt::format().json().flatten_event(true);
    let format = tracing_subscriber::fmt::layer()
        .event_format(format)
        .fmt_fields(format::JsonFields::default());
    Box::new(format)
}

fn plain_fmt() -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let format = tracing_subscriber::fmt::layer()
        .event_format(IstioFormat())
        .fmt_fields(IstioFormat());
    Box::new(format)
}

fn fmt_layer() -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let format = if env::var("LOG_FORMAT").unwrap_or("plain".to_string()) == "json" {
        json_fmt()
    } else {
        plain_fmt()
    };
    let filter = default_filter();
    let (layer, reload) = reload::Layer::new(format.with_filter(filter));
    LOG_HANDLE
        .set(reload)
        .map_or_else(|_| warn!("setup log handler failed"), |_| {});
    Box::new(layer)
}

fn default_filter() -> filter::Targets {
    // Read from env var, but prefix with setting DNS logs to warn as they are noisy; they can be explicitly overriden
    let var: String = env::var("RUST_LOG")
        .map_err(|_| ())
        .map(|v| "hickory_server::server::server_future=off,".to_string() + v.as_str())
        .unwrap_or("hickory_server::server::server_future=off,info".to_string());
    filter::Targets::from_str(&var).expect("static filter should build")
}

// a handle to get and set the log level
type BoxLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;
type FilteredLayer = filter::Filtered<BoxLayer, filter::Targets, Registry>;
type LogHandle = reload::Handle<FilteredLayer, Registry>;

/// set_level dynamically updates the logging level to *include* level. If `reset` is true, it will
/// reset the entire logging configuration first.
pub fn set_level(reset: bool, level: &str) -> Result<(), Error> {
    if let Some(handle) = LOG_HANDLE.get() {
        // new_directive will be current_directive + level
        //it can be duplicate, but the Target's parse() will properly handle it
        let new_directive = if let Ok(current) = handle.with_current(|f| f.filter().to_string()) {
            if reset {
                if level.is_empty() {
                    default_filter().to_string()
                } else {
                    format!("{},{}", default_filter(), level)
                }
            } else {
                format!("{current},{level}")
            }
        } else {
            level.to_string()
        };

        //create the new Targets based on the new directives
        let new_filter = filter::Targets::from_str(&new_directive)?;
        info!("new log filter is {new_filter}");

        //set the new filter
        Ok(handle.modify(|layer| {
            *layer.filter_mut() = new_filter;
        })?)
    } else {
        warn!("failed to get log handle");
        Err(Error::Uninitialized)
    }
}

pub fn get_current_loglevel() -> Result<String, Error> {
    if let Some(handle) = LOG_HANDLE.get() {
        Ok(handle.with_current(|f| f.filter().to_string())?)
    } else {
        Err(Error::Uninitialized)
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("parse failure: {0}")]
    InvalidFilter(#[from] filter::ParseError),
    #[error("reload failure: {0}")]
    Reload(#[from] reload::Error),
    #[error("logging is not initialized")]
    Uninitialized,
}

// IstioFormat encodes logs in the "standard" Istio formatting used in the rest of the code
struct IstioFormat();

struct Visitor<'writer> {
    res: std::fmt::Result,
    is_empty: bool,
    writer: Writer<'writer>,
}

impl<'writer> Visitor<'writer> {
    fn write_padded(&mut self, value: &impl Debug) -> std::fmt::Result {
        let padding = if self.is_empty {
            self.is_empty = false;
            ""
        } else {
            " "
        };
        write!(self.writer, "{}{:?}", padding, value)
    }
}

impl field::Visit for Visitor<'_> {
    fn record_str(&mut self, field: &field::Field, value: &str) {
        if self.res.is_err() {
            return;
        }

        self.record_debug(field, &value)
    }

    fn record_debug(&mut self, field: &field::Field, val: &dyn std::fmt::Debug) {
        self.res = match field.name() {
            // Skip fields that are actually log metadata that have already been handled
            name if name.starts_with("log.") => Ok(()),
            // For the message, write out the message and a tab to separate the future fields
            "message" => write!(self.writer, "{:?}\t", val),
            // For the rest, k=v.
            _ => self.write_padded(&format_args!("{}={:?}", field.name(), val)),
        }
    }
}

impl<'writer> FormatFields<'writer> for IstioFormat {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        writer: Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        let mut visitor = Visitor {
            writer,
            res: Ok(()),
            is_empty: true,
        };
        fields.record(&mut visitor);
        visitor.res
    }
}

impl<S, N> FormatEvent<S, N> for IstioFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result {
        use tracing_log::NormalizeEvent;
        use tracing_subscriber::fmt::time::FormatTime;
        use tracing_subscriber::fmt::time::SystemTime;
        let normalized_meta = event.normalized_metadata();
        SystemTime.format_time(&mut writer)?;
        let meta = normalized_meta.as_ref().unwrap_or_else(|| event.metadata());
        write!(
            writer,
            "\t{}\t",
            meta.level().to_string().to_ascii_lowercase()
        )?;

        let target = meta.target();
        // No need to prefix everything
        let target = target.strip_prefix("ztunnel::").unwrap_or(target);
        write!(writer, "{}", target)?;

        // Write out span fields. Istio logging outside of Rust doesn't really have this concept
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.metadata().name())?;
                let ext = span.extensions();
                if let Some(fields) = &ext.get::<FormattedFields<N>>() {
                    if !fields.is_empty() {
                        write!(writer, "{{{}}}", fields)?;
                    }
                }
            }
        };
        // Insert tab only if there is fields
        if event.fields().any(|_| true) {
            write!(writer, "\t")?;
        }

        ctx.format_fields(writer.by_ref(), event)?;

        writeln!(writer)
    }
}

/// Mod testing gives access to a test logger, which stores logs in memory for querying.
/// Inspired by https://github.com/dbrgn/tracing-test
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use crate::telemetry::{fmt_layer, APPLICATION_START_TIME};
    use itertools::Itertools;
    use once_cell::sync::Lazy;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::io;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use tracing_subscriber::fmt;
    use tracing_subscriber::fmt::format;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    /// assert_contains asserts the logs contain a line with the matching keys.
    /// Common keys to match one are "target" and "message"; most of the rest are custom.
    pub fn assert_contains(want: HashMap<&str, &str>) {
        let logs = {
            let buf = global_buf().lock().unwrap();
            std::str::from_utf8(&buf)
                .expect("Logs contain invalid UTF8")
                .to_string()
        };
        let logs: Vec<serde_json::Value> = logs
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("log must be valid json")
            })
            .collect();
        let matched = logs.iter().find(|log| {
            for (k, v) in &want {
                let Some(have) = log.get(k) else {
                    // Required key not found, continue
                    return false;
                };
                let have = match have {
                    Value::Number(n) => format!("{n}"),
                    Value::String(v) => v.clone(),
                    _ => panic!("assert_contains currently only supports string/number values"),
                };
                // TODO fuzzy match
                if *v != have {
                    // no match
                    return false;
                }
            }
            true
        });
        assert!(
            matched.is_some(),
            "wanted a log line matching {want:?}, got {}",
            logs.iter().map(|x| x.to_string()).join("\n")
        );
    }

    /// MockWriter will store written logs
    #[derive(Debug)]
    pub struct MockWriter<'a> {
        buf: &'a Mutex<Vec<u8>>,
    }

    impl<'a> MockWriter<'a> {
        pub fn new(buf: &'a Mutex<Vec<u8>>) -> Self {
            Self { buf }
        }

        fn buf(&self) -> io::Result<MutexGuard<'a, Vec<u8>>> {
            self.buf
                .lock()
                .map_err(|_| io::Error::from(io::ErrorKind::Other))
        }
    }

    impl<'a> io::Write for MockWriter<'a> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut target = self.buf()?;
            target.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.buf()?.flush()
        }
    }

    impl<'a> fmt::MakeWriter<'_> for MockWriter<'a> {
        type Writer = Self;

        fn make_writer(&self) -> Self::Writer {
            MockWriter::new(self.buf)
        }
    }

    // Global buffer to store logs in
    fn global_buf() -> &'static Mutex<Vec<u8>> {
        static GLOBAL_BUF: OnceLock<Mutex<Vec<u8>>> = OnceLock::new();
        GLOBAL_BUF.get_or_init(|| Mutex::new(vec![]))
    }

    pub fn setup_test_logging() {
        Lazy::force(&APPLICATION_START_TIME);
        let mock_writer = MockWriter::new(global_buf());
        let layer: fmt::Layer<_, _, _, _> = fmt::layer()
            .event_format(tracing_subscriber::fmt::format().json().flatten_event(true))
            .fmt_fields(format::JsonFields::default())
            .with_writer(mock_writer);
        tracing_subscriber::registry()
            .with(fmt_layer())
            .with(layer)
            .init();
    }
}
