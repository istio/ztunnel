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
use std::time::Instant;
use tracing_subscriber::{
    filter,
    filter::{EnvFilter, LevelFilter},
    prelude::*,
    reload, Layer, Registry,
};
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

pub static APPLICATION_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);
static LOG_HANDLE: OnceCell<LogHandle> = OnceCell::new();

#[cfg(feature = "console")]
pub fn setup_logging() {
    Lazy::force(&APPLICATION_START_TIME);
    tracing_subscriber::registry()
        .with(console_subscriber::spawn())
        .with(fmt_layer())
        .init();
}

#[cfg(not(feature = "console"))]
pub fn setup_logging() {
    Lazy::force(&APPLICATION_START_TIME);
    tracing_subscriber::registry().with(fmt_layer()).init();
}

fn fmt_layer() -> impl Layer<Registry> + Sized {
    let format = fmt::format();
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    let (filter_layer, reload_handle) =
        reload::Layer::new(tracing_subscriber::fmt::layer().with_filter(filter));
    match LOG_HANDLE.set(LogHandle {
        handle: reload_handle,
    }) {
        Ok(_) => {}
        Err(_) => {
            eprintln! {"setup log handler failed\n"};
        }
    };
    tracing_subscriber::registry().with(filter_layer).init();
}

// a handle to get and set the log level
type BoxLayer = tracing_subscriber::fmt::Layer<tracing_subscriber::Registry>;
pub(crate) type FilteredLayer = filter::Filtered<BoxLayer, EnvFilter, Registry>;
pub struct LogHandle {
    handle: reload::Handle<FilteredLayer, Registry>,
}

pub fn set_level(level_str: String) -> Result<String, Error> {
    let level: LevelFilter;
    match level_str.as_str() {
        "debug" => level = LevelFilter::DEBUG,
        "error" => level = LevelFilter::ERROR,
        "info" => level = LevelFilter::INFO,
        "warn" => level = LevelFilter::WARN,
        "trace" => level = LevelFilter::TRACE,
        "off" => level = LevelFilter::OFF,
        _ => {
            return Err(Error::RequestFailure(
                "unable to find newlevel in request".to_string(),
            ))
        }
    }
    if let Some(static_log_handler) = LOG_HANDLE.get() {
        let filter = tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into());
        match static_log_handler.handle.modify(|layer| {
            *layer.filter_mut() = filter;
        }) {
            Ok(_) => {
                let ret_str = format!("set new log level to {}", level);
                tracing::info!(%level, ret_str);
                Ok(ret_str)
            }
            Err(e) => {
                let ret_str = format!("failed to set new level {}: {} ", level, e);
                tracing::info!(%level, ret_str);
                Err(Error::RequestFailure(ret_str))
            }
        }
    } else {
        let ret_str = ("log handler is not initialized").to_string();
        Err(Error::RequestFailure(ret_str))
    }
}

pub fn get_current() -> Result<String, Error> {
    if let Some(static_log_handler) = LOG_HANDLE.get() {
        match static_log_handler
            .handle
            .with_current(|f| format!("{}", f.filter()))
        {
            Ok(current_level) => Ok(current_level),
            Err(e) => Err(Error::RequestFailure(e.to_string())),
        }
    } else {
        let ret_str = ("log handler is not initialized").to_string();
        Err(Error::RequestFailure(ret_str))
    }
}
