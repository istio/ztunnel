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

use lazy_static::lazy_static;
use prometheus::{register_int_gauge_vec, IntGaugeVec};
lazy_static! {
    static ref ISTIO_BUILD_GAUGE: IntGaugeVec = register_int_gauge_vec!(
        "istio_build",
        "Istio component build info.",
        &["component", "tag"]
    )
    .unwrap();
}

#[cfg(not(feature = "console"))]
pub fn setup_metric() {
    let tag = env!("ZTUNNEL_BUILD_buildTag");
    ISTIO_BUILD_GAUGE
        .with_label_values(&["ztunnel", tag])
        .set(1);
}
