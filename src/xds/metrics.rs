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
    pub total_messages_size: Family<TypeUrl, Counter>,
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

        let message_count = Family::default();

        registry.register(
            "message_count",
            "Total number of messages received (unstable)",
            message_count.clone(),
        );

        let total_messages_size = Family::default();

        registry.register(
            "total_messages_size",
            "Total number of bytes received (unstable)",
            total_messages_size.clone(),
        );

        Self {
            connection_terminations,
            message_types: message_count,
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
        self.message_types.get_or_create(&type_url).inc();

        let mut total_message_size: u64 = 0;
        for resource in &response.resources {
            total_message_size += resource
                .resource
                .as_ref()
                .map(|v| v.value.len())
                .unwrap_or_default() as u64;
        }
        self.total_messages_size
            .get_or_create(&type_url)
            .inc_by(total_message_size);
    }
}
