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
use prometheus_client::registry::Registry;

use crate::version;

pub(super) struct Metrics {}

#[derive(Clone, Hash, Debug, PartialEq, Eq, EncodeLabelSet)]
pub struct IstioBuildLabel {
    component: String,
    tag: String,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let build_gauge: Family<IstioBuildLabel, Gauge> = Default::default();
        registry.register("build", "Istio component build info", build_gauge.clone());

        let git_tag = version::BuildInfo::new().git_tag;
        build_gauge
            .get_or_create(&IstioBuildLabel {
                component: ZTUNNEL,
                tag: git_tag,
            })
            .set(1);

        Self {}
    }
}
