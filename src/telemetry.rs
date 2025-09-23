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

use itertools::Itertools;
use std::fmt::Debug;
use std::str::FromStr;
use std::time::Instant;
use std::{env, fmt, io};

use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use serde::Serializer;
use serde::ser::SerializeMap;

use thiserror::Error;
use tracing::{Event, Subscriber, error, field, info, warn};
use tracing_appender::non_blocking::NonBlocking;
use tracing_core::Field;
use tracing_core::field::Visit;
use tracing_core::span::Record;
use tracing_log::NormalizeEvent;

use tracing_subscriber::fmt::format::{JsonVisitor, Writer};

use tracing_subscriber::field::RecordFields;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{Layer, Registry, filter, prelude::*, reload};

pub static APPLICATION_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);
static LOG_HANDLE: OnceCell<LogHandle> = OnceCell::new();

pub fn setup_logging() -> tracing_appender::non_blocking::WorkerGuard {
    Lazy::force(&APPLICATION_START_TIME);
    let (non_blocking, _guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(false)
        .buffered_lines_limit(1000) // Buffer up to 1000 lines to avoid blocking on logs
        .finish(std::io::stdout());
    tracing_subscriber::registry()
        .with(fmt_layer(non_blocking))
        .init();
    _guard
}

fn json_fmt(writer: NonBlocking) -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let format = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .event_format(IstioJsonFormat())
        .fmt_fields(IstioJsonFormat());
    Box::new(format)
}

fn plain_fmt(writer: NonBlocking) -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let format = tracing_subscriber::fmt::layer()
        .with_writer(writer)
        .event_format(IstioFormat())
        .fmt_fields(IstioFormat());
    Box::new(format)
}

fn fmt_layer(writer: NonBlocking) -> Box<dyn Layer<Registry> + Send + Sync + 'static> {
    let format = if env::var("LOG_FORMAT").unwrap_or("plain".to_string()) == "json" {
        json_fmt(writer)
    } else {
        plain_fmt(writer)
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

// IstioFormat encodes logs in the "standard" Istio JSON formatting used in the rest of the code
struct IstioJsonFormat();

// IstioFormat encodes logs in the "standard" Istio formatting used in the rest of the code
struct IstioFormat();

struct Visitor<'writer> {
    res: std::fmt::Result,
    is_empty: bool,
    writer: Writer<'writer>,
}

impl Visitor<'_> {
    fn write_padded(&mut self, value: &impl Debug) -> std::fmt::Result {
        let padding = if self.is_empty {
            self.is_empty = false;
            ""
        } else {
            " "
        };
        write!(self.writer, "{padding}{value:?}")
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
            "message" => write!(self.writer, "{val:?}\t"),
            // For the rest, k=v.
            _ => self.write_padded(&format_args!("{}={val:?}", field.name())),
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
        write!(writer, "{target}")?;

        // Write out span fields. Istio logging outside of Rust doesn't really have this concept
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                write!(writer, ":{}", span.metadata().name())?;
                let ext = span.extensions();
                if let Some(fields) = &ext.get::<FormattedFields<N>>()
                    && !fields.is_empty()
                {
                    write!(writer, "{{{fields}}}")?;
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

struct JsonVisitory<S: SerializeMap> {
    serializer: S,
    state: Result<(), S::Error>,
}

impl<S: SerializeMap> JsonVisitory<S> {
    pub(crate) fn done(self) -> Result<S, S::Error> {
        let JsonVisitory { serializer, state } = self;
        state?;
        Ok(serializer)
    }
}

impl<S: SerializeMap> Visit for JsonVisitory<S> {
    fn record_bool(&mut self, field: &Field, value: bool) {
        // If previous fields serialized successfully, continue serializing,
        // otherwise, short-circuit and do nothing.
        if self.state.is_ok() {
            self.state = self.serializer.serialize_entry(field.name(), &value)
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if self.state.is_ok() {
            self.state = self
                .serializer
                .serialize_entry(field.name(), &format_args!("{value:?}"))
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if self.state.is_ok() {
            self.state = self.serializer.serialize_entry(field.name(), &value)
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if self.state.is_ok() {
            self.state = self.serializer.serialize_entry(field.name(), &value)
        }
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        if self.state.is_ok() {
            self.state = self.serializer.serialize_entry(field.name(), &value)
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if self.state.is_ok() {
            self.state = self.serializer.serialize_entry(field.name(), &value)
        }
    }
}
pub struct WriteAdaptor<'a> {
    fmt_write: &'a mut dyn fmt::Write,
}
impl<'a> WriteAdaptor<'a> {
    pub fn new(fmt_write: &'a mut dyn fmt::Write) -> Self {
        Self { fmt_write }
    }
}
impl io::Write for WriteAdaptor<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s =
            std::str::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.fmt_write.write_str(s).map_err(io::Error::other)?;

        Ok(s.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<S, N> FormatEvent<S, N> for IstioJsonFormat
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        let meta = event.normalized_metadata();
        let meta = meta.as_ref().unwrap_or_else(|| event.metadata());
        let mut write = || {
            let mut timestamp = String::with_capacity(28);
            let mut w = Writer::new(&mut timestamp);
            SystemTime.format_time(&mut w)?;
            let mut sx = serde_json::Serializer::new(WriteAdaptor::new(&mut writer));
            let mut serializer = sx.serialize_map(event.fields().try_len().ok())?;
            serializer.serialize_entry("level", &meta.level().as_str().to_ascii_lowercase())?;
            serializer.serialize_entry("time", &timestamp)?;
            serializer.serialize_entry("scope", meta.target())?;
            let mut v = JsonVisitory {
                serializer,
                state: Ok(()),
            };
            event.record(&mut v);

            let mut serializer = v.done()?;
            if let Some(scope) = ctx.event_scope() {
                for span in scope.from_root() {
                    let ext = span.extensions();
                    if let Some(fields) = &ext.get::<FormattedFields<N>>() {
                        let json = serde_json::from_str::<serde_json::Value>(fields)?;
                        serializer.serialize_entry(span.metadata().name(), &json)?;
                    }
                }
            };
            SerializeMap::end(serializer)?;
            Ok::<(), anyhow::Error>(())
        };
        write().map_err(|_| fmt::Error)?;
        writeln!(writer)
    }
}

// Copied from tracing_subscriber json
impl<'a> FormatFields<'a> for IstioJsonFormat {
    /// Format the provided `fields` to the provided `writer`, returning a result.
    fn format_fields<R: RecordFields>(&self, mut writer: Writer<'_>, fields: R) -> fmt::Result {
        use tracing_subscriber::field::VisitOutput;
        let mut v = JsonVisitor::new(&mut writer);
        fields.record(&mut v);
        v.finish()
    }

    fn add_fields(
        &self,
        _current: &'a mut FormattedFields<Self>,
        _fields: &Record<'_>,
    ) -> fmt::Result {
        // We could implement this but tracing doesn't give us an easy or efficient way to do so.
        // for not just disallow it.
        debug_assert!(false, "add_fields is inefficient and should not be used");
        Ok(())
    }
}

/// Mod testing gives access to a test logger, which stores logs in memory for querying.
/// Inspired by https://github.com/dbrgn/tracing-test
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use crate::telemetry::{APPLICATION_START_TIME, IstioJsonFormat, fmt_layer};
    use itertools::Itertools;
    use once_cell::sync::Lazy;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::fmt::{Display, Formatter};
    use std::io;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use tracing_subscriber::fmt;

    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    #[derive(Debug)]
    pub enum LogError {
        // Wanted to equal the value, its missing
        Missing(String),
        // Want to be absent but it is present
        Present(String),
        // Mismatch: want, got
        Mismatch(String, String),
    }

    impl Display for LogError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                LogError::Missing(_v) => {
                    write!(f, "missing")
                }
                LogError::Present(v) => {
                    write!(f, "{v:?} found unexpectedly")
                }
                LogError::Mismatch(want, got) => {
                    write!(f, "{want:?} != {got:?}")
                }
            }
        }
    }

    /// assert_contains asserts the logs contain a line with the matching keys.
    /// Common keys to match one are "target" and "message"; most of the rest are custom.
    #[track_caller]
    pub fn assert_contains(want: HashMap<&str, &str>) {
        let logs = {
            let buf = global_buf().lock().unwrap();
            std::str::from_utf8(&buf)
                .expect("Logs contain invalid UTF8")
                .to_string()
        };
        let errors: Vec<HashMap<_, _>> = logs
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).expect("log must be valid json")
            })
            .map(|log| {
                let mut errors = HashMap::new();
                for (k, v) in &want {
                    let Some(have) = log.get(k) else {
                        if !v.is_empty() {
                            errors.insert(k.to_string(), LogError::Missing(v.to_string()));
                        }
                        continue;
                    };
                    let have = match have {
                        Value::Number(n) => format!("{n}"),
                        Value::String(v) => v.clone(),
                        _ => panic!("assert_contains currently only supports string/number values"),
                    };
                    if v.is_empty() {
                        errors.insert(k.to_string(), LogError::Present(have));
                        continue;
                    }
                    // TODO fuzzy match
                    if *v != have {
                        errors.insert(k.to_string(), LogError::Mismatch(v.to_string(), have));
                    }
                }
                errors
            })
            .sorted_by_key(|h| h.len())
            .collect();

        let found_exact_match = errors.first().map(|h| h.is_empty()).unwrap_or(false);
        if found_exact_match {
            return;
        }

        let total = errors.len();
        let help = errors
            .iter()
            .take(10)
            .map(|h| {
                h.iter()
                    .sorted_by_key(|(k, _)| *k)
                    .map(|(k, err)| format!("{k}:{err}"))
                    .join("\n")
            })
            .join("\n\n");
        panic!(
            "Analyzed {total} logs but none matched our criteria. Closest 10 matches:\n\n{help}"
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

    impl io::Write for MockWriter<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut target = self.buf()?;
            target.write(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.buf()?.flush()
        }
    }

    impl fmt::MakeWriter<'_> for MockWriter<'_> {
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
        let (non_blocking, _guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
            .lossy(false)
            .buffered_lines_limit(1)
            .finish(std::io::stdout());
        // Ensure we do not close until the program ends
        Box::leak(Box::new(_guard));
        let layer: fmt::Layer<_, _, _, _> = fmt::layer()
            .event_format(IstioJsonFormat())
            .fmt_fields(IstioJsonFormat())
            .with_writer(mock_writer);
        tracing_subscriber::registry()
            .with(fmt_layer(non_blocking))
            .with(layer)
            .init();
    }
}
