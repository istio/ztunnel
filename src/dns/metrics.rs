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

use hickory_server::server::Request;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};
use std::time::Duration;

use crate::metrics::{DefaultedUnknown, DeferRecorder, Recorder};

use crate::state::workload::Workload;
use crate::strng::RichStrng;

pub struct Metrics {
    pub requests: Family<DnsLabels, Counter>,
    pub forwarded_requests: Family<DnsLabels, Counter>,
    pub forwarded_failures: Family<DnsLabels, Counter>,
    pub forwarded_duration: Family<DnsLabels, Histogram>,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let requests = Family::default();
        registry.register(
            "dns_requests",
            "Total number of DNS requests (unstable)",
            requests.clone(),
        );

        let forwarded_requests = Family::default();
        registry.register(
            "dns_upstream_requests",
            "Total number of DNS requests forwarded to upstream (unstable)",
            forwarded_requests.clone(),
        );

        let forwarded_failures = Family::default();
        registry.register(
            "dns_upstream_failures",
            "Total number of DNS requests that failed to forward upstream (unstable)",
            forwarded_failures.clone(),
        );

        let forwarded_duration = Family::<DnsLabels, Histogram>::new_with_constructor(|| {
            Histogram::new(vec![0.005f64, 0.001, 0.01, 0.1, 1.0, 5.0].into_iter())
        });
        registry.register_with_unit(
            "dns_upstream_request_duration",
            "Total time in seconds Istio takes to get DNS response from upstream (unstable)",
            Unit::Seconds,
            forwarded_duration.clone(),
        );

        Self {
            requests,
            forwarded_requests,
            forwarded_failures,
            forwarded_duration,
        }
    }
}

impl DeferRecorder for Metrics {}

#[derive(Clone, Hash, Debug, PartialEq, Eq, EncodeLabelSet)]
pub struct DnsLabels {
    request_query_type: RichStrng,
    request_protocol: RichStrng,

    // Source workload.
    source_canonical_service: DefaultedUnknown<RichStrng>,
    source_canonical_revision: DefaultedUnknown<RichStrng>,
}

impl DnsLabels {
    pub fn new(r: &Request) -> Self {
        Self {
            request_query_type: r.query().query_type().to_string().to_lowercase().into(),
            request_protocol: r.protocol().to_string().to_lowercase().into(),
            source_canonical_service: Default::default(),
            source_canonical_revision: Default::default(),
        }
    }

    pub fn with_source(mut self, w: &Workload) -> Self {
        self.source_canonical_service = w.canonical_name.clone().into();
        self.source_canonical_revision = w.canonical_revision.clone().into();

        self
    }
}

#[derive(Clone)]
pub struct DnsRequest<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<DnsRequest<'_>, u64> for Metrics {
    fn record(&self, reason: &DnsRequest, count: u64) {
        self.requests
            .get_or_create(&DnsLabels::from(reason))
            .inc_by(count);
    }
}

impl From<&DnsRequest<'_>> for DnsLabels {
    fn from(value: &DnsRequest) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}

#[derive(Clone)]
pub struct ForwardedRequest<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<ForwardedRequest<'_>, u64> for Metrics {
    fn record(&self, reason: &ForwardedRequest, count: u64) {
        self.forwarded_requests
            .get_or_create(&DnsLabels::from(reason))
            .inc_by(count);
    }
}

impl From<&ForwardedRequest<'_>> for DnsLabels {
    fn from(value: &ForwardedRequest) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}

#[derive(Clone)]
pub struct ForwardedFailure<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<ForwardedFailure<'_>, u64> for Metrics {
    fn record(&self, reason: &ForwardedFailure, count: u64) {
        self.forwarded_failures
            .get_or_create(&DnsLabels::from(reason))
            .inc_by(count);
    }
}

impl From<&ForwardedFailure<'_>> for DnsLabels {
    fn from(value: &ForwardedFailure) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}

#[derive(Clone)]
pub struct ForwardedDuration<'a> {
    pub request: &'a Request,
    pub source: Option<&'a Workload>,
}

impl Recorder<ForwardedDuration<'_>, Duration> for Metrics {
    fn record(&self, reason: &ForwardedDuration, duration: Duration) {
        self.forwarded_duration
            .get_or_create(&DnsLabels::from(reason))
            .observe(duration.as_secs_f64());
    }
}

impl From<&ForwardedDuration<'_>> for DnsLabels {
    fn from(value: &ForwardedDuration) -> Self {
        let mut labels = Self::new(value.request);
        if let Some(source) = &value.source {
            labels = labels.with_source(source)
        }
        labels
    }
}
