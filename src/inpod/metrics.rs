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

use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

#[derive(Clone, Hash, Default, Debug, PartialEq, Eq, EncodeLabelSet)]
struct ProxyLabels {
    uid: String,
}

#[derive(Default)]
pub struct Metrics {
    pub(super) active_proxy_count: Family<(), Gauge>,
    pub(super) pending_proxy_count: Family<(), Gauge>,
    pub(super) proxies_started: Family<(), Counter>,
    pub(super) proxies_stopped: Family<(), Counter>,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let m = Self::default();
        registry.register(
            "active_proxy_count",
            "The total number current workloads with active proxies (unstable)",
            m.active_proxy_count.clone(),
        );
        registry.register(
            "pending_proxy_count",
            "The total number current workloads with pending proxies (unstable)",
            m.pending_proxy_count.clone(),
        );
        registry.register(
            "proxies_started",
            "The total number of proxies that were started (unstable)",
            m.proxies_started.clone(),
        );
        registry.register(
            "proxies_stopped",
            "The total number of proxies that were stopped (unstable)",
            m.proxies_stopped.clone(),
        );
        m
    }
}
