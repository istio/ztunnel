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
use tracing::{debug, warn};
use tracing_subscriber::{filter, filter::EnvFilter, fmt, prelude::*, reload, Layer, Registry};

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
    let event_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();
    let (filter_layer, reload_handle) = reload::Layer::new(
        tracing_subscriber::fmt::layer()
            .event_format(format)
            .with_filter(event_filter),
    );
    LOG_HANDLE
        .set(LogHandle {
            handle: reload_handle,
        })
        .map_or_else(|_| warn!("setup log handler failed"), |_| {});
    filter_layer
}

// a handle to get and set the log level
type BoxLayer = tracing_subscriber::fmt::Layer<tracing_subscriber::Registry>;
type FilteredLayer = filter::Filtered<BoxLayer, EnvFilter, Registry>;
struct LogHandle {
    handle: reload::Handle<FilteredLayer, Registry>,
}

pub fn set_mod_level(new_level: String) -> bool {
    if let Some(static_log_handler) = LOG_HANDLE.get() {
        //new_directve = current_directive + new_level
        //it can be duplicate, but no worry, the envfilter's parse() will properly handle it
        let new_directive_str;
        if let Ok(current_directives_str) = static_log_handler
            .handle
            .with_current(|f| format!("{}", f.filter()))
        {
            new_directive_str = format!("{},{}", current_directives_str, new_level);
        } else {
            new_directive_str = new_level;
        }
        debug!("new directive is {}", new_directive_str);

        //create the new envfilter based on the new directives
        let new_filter;
        let res = EnvFilter::try_new(new_directive_str);
        match res {
            Ok(e) => {
                new_filter = e;
            }
            Err(e) => {
                warn!("{}", e.to_string());
                return false;
            }
        }

        //set the new filter
        static_log_handler
            .handle
            .modify(|layer| {
                *layer.filter_mut() = new_filter;
            })
            .map_or(false, |_| true)
    } else {
        warn!("failed to get log handle");
        false
    }
}

pub fn get_current_loglevel() -> Option<String> {
    if let Some(static_log_handler) = LOG_HANDLE.get() {
        static_log_handler
            .handle
            .with_current(|f| format!("{}", f.filter()))
            .ok()
    } else {
        warn!("failed to get log handle");
        None
    }
}
