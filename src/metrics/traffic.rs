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

use crate::identity::Identity;
use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use crate::metrics::Recorder;

pub(super) struct Metrics {
    pub(super) connection_opens: Family<ConnectionOpen, Counter>,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub enum Reporter {
    source,
    destination,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub enum RequestProtocol {
    tcp,
    http,
}

#[derive(Default, Clone, Hash, PartialEq, Eq, Encode)]
pub enum ResponseFlags {
    #[default]
    none,
}

#[derive(Default, Clone, Hash, PartialEq, Eq, Encode)]
pub enum SecurityPolicy {
    #[default]
    unknown,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub struct ConnectionOpen {
    // TODO: add full set of labels
    pub reporter: Reporter,

    pub source_workload: String,
    pub source_canonical_service: String,
    pub source_canonical_revision: String,
    pub source_workload_namespace: String,
    pub source_principal: Identity,
    pub source_app: String,
    pub source_version: String,
    pub source_cluster: String,

    pub destination_service: String,

    pub destination_workload: String,
    pub destination_canonical_service: String,
    pub destination_canonical_revision: String,
    pub destination_workload_namespace: String,
    pub destination_principal: Identity,
    pub destination_app: String,
    pub destination_version: String,
    pub destination_cluster: String,

    pub request_protocol: RequestProtocol,
    pub response_flags: ResponseFlags,
    pub connection_security_policy: SecurityPolicy,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let connection_opens = Family::default();
        registry.register(
            "connections_opened",
            "The total number of TCP connections opened",
            Box::new(connection_opens.clone()),
        );

        Self { connection_opens }
    }
}

impl Recorder<ConnectionOpen> for super::Metrics {
    fn record(&self, reason: &ConnectionOpen) {
        self.traffic.connection_opens.get_or_create(reason).inc();
    }
}
