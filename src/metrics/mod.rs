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

use prometheus_client::registry::Registry;

mod meta;
#[allow(non_camel_case_types)]
pub mod traffic;
pub mod xds;

/// Set of Swarm and protocol metrics derived from emitted events.
pub struct Metrics {
    xds: xds::Metrics,
    #[allow(dead_code)]
    meta: meta::Metrics,
    traffic: traffic::Metrics,
}

impl Metrics {
    fn new(registry: &mut Registry) -> Self {
        Self {
            xds: xds::Metrics::new(registry),
            meta: meta::Metrics::new(registry),
            traffic: traffic::Metrics::new(registry),
        }
    }
}

impl From<&mut Registry> for Metrics {
    fn from(registry: &mut Registry) -> Self {
        Metrics::new(registry.sub_registry_with_prefix("istio"))
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::default();
        Metrics::new(registry.sub_registry_with_prefix("istio"))
    }
}

/// Recorder that can record events
pub trait Recorder<E> {
    /// Record the given event.
    fn record(&self, event: &E);
}
