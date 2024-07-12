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

use super::service::discovery::v3::DeltaDiscoveryResponse;

pub struct Metrics {
    pub connection_terminations: Family<ConnectionTermination, Counter>,
    pub message_types: Family<TypeUrl, Counter>,
    pub total_messages_size: Counter,
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

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct TypeUrl {
    pub url: String,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let connection_terminations = Family::default();
        registry.register(
            "xds_connection_terminations",
            "The total number of completed connections to xds server (unstable)",
            connection_terminations.clone(),
        );

        let message_types = Family::default();

        registry.register(
            "message_types",
            "Total number of messages received (unstable)",
            message_types.clone(),
        );

        let total_messages_size = Counter::default();

        registry.register(
            "total_messages_size",
            "Total number of bytes received (unstable)",
            total_messages_size.clone(),
        );

        Self {
            connection_terminations,
            message_types,
            total_messages_size,
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

impl Recorder<DeltaDiscoveryResponse, ()> for Metrics {
    fn record(&self, response: &DeltaDiscoveryResponse, _: ()) {
        let type_url = TypeUrl {
            url: response.type_url.clone(),
        };
        self.message_types.get_or_create(&type_url).inc_by(1);

        let mut message_size: usize = 0;
        for resource in &response.resources {
            message_size += resource.resource.as_ref().unwrap().value.len();
        }
        self.total_messages_size.inc_by(message_size as u64);
    }
}
