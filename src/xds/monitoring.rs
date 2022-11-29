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

use prometheus_client::{
    encoding::text::Encode, metrics::counter::Counter, metrics::family::Family, registry::Registry,
};

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub struct ConnectionTerminationLabel {
    reason: ConnectionTerminationReason,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub enum ConnectionTerminationReason {
    ConnectionError,
    Error,
}

#[derive(Default, Clone)]
pub struct XdsMetrics {
    connection_terminations: Family<ConnectionTerminationLabel, Counter>,
}

impl XdsMetrics {
    pub fn register(&self, registry: &mut Registry) {
        let sub_registry = registry.sub_registry_with_prefix("xds");
        sub_registry.register(
            "connection_terminations",
            "The total number of connection failures to xds server",
            Box::new(self.connection_terminations.clone()),
        );
    }

    pub(crate) fn inc_connection_terminations(&self, reason: ConnectionTerminationReason) {
        self.connection_terminations
            .get_or_create(&ConnectionTerminationLabel { reason })
            .inc();
    }
}
