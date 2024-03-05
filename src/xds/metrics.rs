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

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use crate::metrics::Recorder;

pub struct Metrics {
    pub connection_terminations: Family<ConnectionTermination, Counter>,
}

#[derive(Clone, Hash, Debug, PartialEq, Eq, EncodeLabelSet)]
pub struct ConnectionTermination {
    pub reason: ConnectionTerminationReason,
}

#[derive(Copy, Clone, Hash, Debug, PartialEq, Eq, EncodeLabelValue)]
pub enum ConnectionTerminationReason {
    ConnectionError,
    Error,
    Reconnect,
    Complete,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let connection_terminations = Family::default();
        registry.register(
            "xds_connection_terminations",
            "The total number of completed connections to xds server (unstable)",
            connection_terminations.clone(),
        );

        Self {
            connection_terminations,
        }
    }
}

impl Recorder<ConnectionTerminationReason, u64> for Metrics {
    fn record(&self, reason: &ConnectionTerminationReason, count: u64) {
        self.connection_terminations
            .get_or_create(&ConnectionTermination { reason: *reason })
            .inc_by(count);
    }
}
