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

use std::time::Instant;

use once_cell::sync::Lazy;
use tracing_subscriber::{
    filter,
    filter::{EnvFilter, LevelFilter},
    prelude::*,
    reload, Layer, Registry,
};
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

// pub static mut LOG_HANDLE: Option<&mut LogHandle> = None;
pub static APPLICATION_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);
static mut PRI_LOG_HANDLE: Option<&mut LogHandle> = None;

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
    unsafe {
        PRI_LOG_HANDLE = Some(Box::leak(Box::new(LogHandle(reload_handle))));
    }
    tracing_subscriber::registry().with(filter_layer).init();
}

// a handle to get and set the log level
pub struct LogHandle(reload::Handle<FilteredLayer, Registry>);
type BoxLayer = tracing_subscriber::fmt::Layer<tracing_subscriber::Registry>;
pub(crate) type FilteredLayer = filter::Filtered<BoxLayer, EnvFilter, Registry>;

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
            return Err(Error::InvalidParam(
                "unable to find newlevel in request\n".to_string(),
            ))
        }
    }

    let filter = tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into());
    unsafe {
        match PRI_LOG_HANDLE.as_ref().unwrap().0.modify(|layer| {
            *layer.filter_mut() = filter;
        }) {
            Ok(_) => {
                let ret_str = format!("set new log level to {} \n", level);
                tracing::info!(%level, ret_str);
                Ok(ret_str)
            }
            Err(e) => {
                let ret_str = format!("failed to set new level {}: {} \n", level, e);
                tracing::info!(%level, ret_str);
                Err(Error::InvalidParam(ret_str))
            }
        }
    }
}

pub fn get_current() -> Result<String, Error> {
    unsafe {
        match PRI_LOG_HANDLE
            .as_ref()
            .unwrap()
            .0
            .with_current(|f| format!("{}", f.filter()))
        {
            Ok(current_level) => Ok(current_level),
            Err(e) => Err(Error::InvalidParam(e.to_string())),
        }
    }
}
