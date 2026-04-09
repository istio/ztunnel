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
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::{Registry, Unit};

use crate::identity::Identity;

#[derive(Clone, Hash, Debug, PartialEq, Eq, EncodeLabelSet)]
pub struct CertExpirationLabels {
    pub identity: Identity,
}

#[derive(Default)]
pub struct Metrics {
    pub cert_expiration_seconds: Family<CertExpirationLabels, Gauge>,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, registry: &mut Registry) {
        registry.register_with_unit(
            "cert_expiration",
            "Seconds until the leaf certificate expires; negative if expired (unstable)",
            Unit::Seconds,
            self.cert_expiration_seconds.clone(),
        );
    }
}
