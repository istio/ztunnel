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

use crate::telemetry;
use once_cell::sync::Lazy;
use std::net::{IpAddr, SocketAddr};
use telemetry::LogHandle;
use tracing_subscriber::reload::Error;

// Ensure that the `tracing` stack is only initialised once using `once_cell`
static TRACING: Lazy<Result<LogHandle, Error>> = Lazy::new(telemetry::setup_logging);

pub fn initialize_telemetry() -> &'static Result<LogHandle, Error> {
    Lazy::force(&TRACING)
}

pub fn with_ip(s: SocketAddr, ip: IpAddr) -> SocketAddr {
    SocketAddr::new(ip, s.port())
}
