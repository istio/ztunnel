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

use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use crate::metrics::Recorder;

pub(super) struct Metrics {
    pub(super) connection_terminations: Family<ConnectionTermination, Counter>,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub struct ConnectionTermination {
    pub reason: ConnectionTerminationReason,
}

#[derive(Copy, Clone, Hash, PartialEq, Eq, Encode)]
pub enum ConnectionTerminationReason {
    ConnectionError,
    Error,
    Complete,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let connection_terminations = Family::default();
        registry.register(
            "connection_terminations",
            "The total number of completed connections to xds server",
            Box::new(connection_terminations.clone()),
        );

        Self {
            connection_terminations,
        }
    }
}

impl Recorder<ConnectionTerminationReason> for super::Metrics {
    fn record(&self, reason: &ConnectionTerminationReason) {
        self.xds
            .connection_terminations
            .get_or_create(&ConnectionTermination { reason: *reason })
            .inc();
    }
}
