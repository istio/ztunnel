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
use std::env;

pub mod admin;
pub mod app;
pub mod assertions;
pub mod baggage;
pub mod cert_fetcher;
pub mod config;
pub mod copy;
pub mod dns;
pub mod drain;
pub mod hyper_util;
pub mod identity;
#[cfg(target_os = "linux")]
pub mod inpod;
pub mod metrics;
pub mod proxy;
pub mod proxyfactory;
pub mod rbac;
pub mod readiness;
pub mod signal;
pub mod socket;
pub mod state;
pub mod strng;
pub mod telemetry;
pub mod time;
pub mod tls;
pub mod version;
pub mod xds;

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers;

/// When true, authorization policy logs are emitted at INFO level instead of DEBUG.
pub static AUTHZ_POLICY_INFO_LOGGING: Lazy<bool> =
    Lazy::new(|| env::var("AUTHZ_POLICY_INFO_LOGGING").unwrap_or_default() == "true");

#[allow(dead_code)]
static PQC_ENABLED: Lazy<bool> =
    Lazy::new(|| env::var("COMPLIANCE_POLICY").unwrap_or_default() == "pqc");

#[allow(dead_code)]
static TLS12_ENABLED: Lazy<bool> =
    Lazy::new(|| env::var("TLS12_ENABLED").unwrap_or_default() == "true");

/// Logs a message at INFO level if AUTHZ_POLICY_INFO_LOGGING is set to "true",
/// otherwise logs at DEBUG level.
#[macro_export]
macro_rules! authpol_log {
    ($($arg:tt)+) => {
        if *$crate::AUTHZ_POLICY_INFO_LOGGING {
            tracing::info!($($arg)+);
        } else {
            tracing::debug!($($arg)+);
        }
    };
}
