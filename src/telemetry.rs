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
    reload,
    reload::Error,
    Layer, Registry,
};
use tracing_subscriber::{fmt, EnvFilter, Layer, Registry};

pub static APPLICATION_START_TIME: Lazy<Instant> = Lazy::new(Instant::now);

#[cfg(feature = "console")]
pub fn setup_logging() {
    Lazy::force(&APPLICATION_START_TIME);
    tracing_subscriber::registry()
        .with(console_subscriber::spawn())
        .with(fmt_layer())
        .init();
}

#[cfg(not(feature = "console"))]
pub fn setup_logging() -> Result<LogHandle, Error> {
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
    tracing_subscriber::registry().with(filter_layer).init();
    Ok(LogHandle::new(reload_handle))
}

#[derive(Clone)]
pub struct LogHandle(reload::Handle<FilteredLayer, Registry>);
type BoxLayer = tracing_subscriber::fmt::Layer<tracing_subscriber::Registry>;
pub(crate) type FilteredLayer = filter::Filtered<BoxLayer, EnvFilter, Registry>;

// a handle to get and set the log level
impl LogHandle {
    pub(crate) fn new(handle: reload::Handle<FilteredLayer, Registry>) -> Self {
        Self(handle)
    }

    pub fn set_level(&self, level_str: String) -> Result<String, Error> {
        let mut level: LevelFilter = LevelFilter::INFO;

        let mut wrong_level = false;
        match level_str.as_str() {
            "debug" => level = LevelFilter::DEBUG,
            "error" => level = LevelFilter::ERROR,
            "info" => level = LevelFilter::INFO,
            "warn" => level = LevelFilter::WARN,
            "trace" => level = LevelFilter::TRACE,
            "off" => level = LevelFilter::OFF,
            //todo how to directly return here
            _ => wrong_level = true,
        }

        if wrong_level == false {
            let filter =
                tracing_subscriber::EnvFilter::from_default_env().add_directive(level.into());
            self.0.modify(|layer| {
                *layer.filter_mut() = filter;
            })?;
            let ret_str = format!("set new log level to {} \n", level);
            tracing::info!(%level, ret_str);
            Ok(ret_str)
        } else {
            let ret_str = format!("the new log level is incorrect {} \n", level_str);
            Ok(ret_str)
        }
    }

    pub fn get_current(&self) -> Result<String, Error> {
        self.0
            .with_current(|f| format!("{}", f.filter()))
            .map_err(Into::into)
    }
}
