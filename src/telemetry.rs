use std::env;
use std::fmt::Debug;

use std::time::Instant;

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

use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;

use thiserror::Error;
use tracing::{error, field, info, warn, Event, Subscriber};

use tracing_subscriber::fmt::format::Writer;

use tracing_subscriber::fmt::{format, FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{filter, filter::EnvFilter, prelude::*, reload, Layer, Registry};

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
    let filter = default_env_filter();
    let (layer, reload) = reload::Layer::new(format.with_filter(filter));
    LOG_HANDLE
        .set(reload)
        .map_or_else(|_| warn!("setup log handler failed"), |_| {});
    Box::new(layer)
}

fn default_env_filter() -> EnvFilter {
    // Read from env var, but prefix with setting DNS logs to warn as they are noisy; they can be explicitly overriden
    let var: String = env::var(EnvFilter::DEFAULT_ENV)
        .map_err(|_| ())
        .map(|v| "hickory_server::server::server_future=off,".to_string() + v.as_str())
        .unwrap_or("hickory_server::server::server_future=off,info".to_string());
    EnvFilter::builder().with_regex(false).parse(var).unwrap()
}

// a handle to get and set the log level
type BoxLayer = Box<dyn Layer<Registry> + Send + Sync + 'static>;
type FilteredLayer = filter::Filtered<BoxLayer, EnvFilter, Registry>;
type LogHandle = reload::Handle<FilteredLayer, Registry>;

/// set_level dynamically updates the logging level to *include* level. If `reset` is true, it will
/// reset the entire logging configuration first.
pub fn set_level(reset: bool, level: &str) -> Result<(), Error> {
    if let Some(handle) = LOG_HANDLE.get() {
        // new_directive will be current_directive + level
        //it can be duplicate, but the envfilter's parse() will properly handle it
        let new_directive = if let Ok(current) = handle.with_current(|f| f.filter().to_string()) {
            if reset {
                format!("{},{}", default_env_filter(), level)
            } else {
                format!("{current},{level}")
            }
        } else {
            level.to_string()
        };

        //create the new EnvFilter based on the new directives
        let new_filter = EnvFilter::builder().parse(new_directive)?;
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
