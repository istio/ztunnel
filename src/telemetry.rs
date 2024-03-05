use std::env;
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
use atty::Stream;
use once_cell::sync::Lazy;
use once_cell::sync::OnceCell;
use thiserror::Error;
use tracing::{error, info, warn};
use tracing_subscriber::fmt::format;
use tracing_subscriber::{filter, filter::EnvFilter, fmt, prelude::*, reload, Layer, Registry};

pub static APPLICATION_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);
static LOG_HANDLE: OnceCell<LogHandle> = OnceCell::new();

#[cfg(feature = "console")]
pub fn setup_logging() {
    Lazy::force(&APPLICATION_START_TIME);
    tracing_subscriber::registry()
        .with(fmt_layer())
        .with(console_subscriber::spawn())
        .init();
}

#[cfg(not(feature = "console"))]
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
    let format = fmt::format();
    let format = if atty::isnt(Stream::Stdout) {
        format.with_ansi(false)
    } else {
        format
    };
    let format = tracing_subscriber::fmt::layer().event_format(format);
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
    EnvFilter::builder()
        .with_regex(false)
        .try_from_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap()
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
