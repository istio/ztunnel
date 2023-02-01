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

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use std::fmt::Write;

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use crate::identity::Identity;
use crate::metrics::Recorder;
use crate::workload::Workload;

pub(super) struct Metrics {
    pub(super) connection_opens: Family<CommonTrafficLabels, Counter>,
    pub(super) connection_close: Family<CommonTrafficLabels, Counter>,
    pub(super) received_bytes: Family<CommonTrafficLabels, Counter>,
    pub(super) sent_bytes: Family<CommonTrafficLabels, Counter>,
}

#[derive(Clone, Copy, Default, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum Reporter {
    #[default]
    source,
    #[allow(dead_code)]
    destination,
}

#[derive(Clone, Copy, Default, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum RequestProtocol {
    #[default]
    tcp,
    #[allow(dead_code)]
    http,
}

#[derive(Default, Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum ResponseFlags {
    #[default]
    none,
}

impl EncodeLabelValue for ResponseFlags {
    fn encode(&self, writer: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        match self {
            ResponseFlags::none => writer.write_str("-"),
        }
    }
}

#[derive(Default, Copy, Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum SecurityPolicy {
    #[default]
    unknown,
    mutual_tls,
}

#[derive(Default, Hash, PartialEq, Eq, Clone, Debug)]
// DefaultedUnknown is a wrapper around an Option that encodes as "unknown" when missing, rather than ""
struct DefaultedUnknown<T>(Option<T>);

impl From<String> for DefaultedUnknown<String> {
    fn from(t: String) -> Self {
        if t.is_empty() {
            DefaultedUnknown(None)
        } else {
            DefaultedUnknown(Some(t))
        }
    }
}

impl<T> From<Option<T>> for DefaultedUnknown<T> {
    fn from(t: Option<T>) -> Self {
        DefaultedUnknown(t)
    }
}

impl From<Identity> for DefaultedUnknown<Identity> {
    fn from(t: Identity) -> Self {
        DefaultedUnknown(Some(t))
    }
}

impl<T: EncodeLabelValue> EncodeLabelValue for DefaultedUnknown<T> {
    fn encode(&self, writer: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        match self {
            DefaultedUnknown(Some(i)) => i.encode(writer),
            DefaultedUnknown(None) => writer.write_str("unknown"),
        }
    }
}

pub struct ConnectionClose<'a>(&'a ConnectionOpen);

pub struct ReceivedBytes<'a>(&'a ConnectionOpen);

pub struct SentBytes<'a>(&'a ConnectionOpen);

#[derive(Clone)]
pub struct ConnectionOpen {
    pub reporter: Reporter,
    pub source: Workload,
    pub destination: Option<Workload>,
    pub destination_service: Option<String>,
    pub destination_service_namespace: Option<String>,
    pub destination_service_name: Option<String>,
    pub connection_security_policy: SecurityPolicy,
}

impl<'a> From<&'a ConnectionOpen> for ConnectionClose<'a> {
    fn from(c: &'a ConnectionOpen) -> Self {
        ConnectionClose(c)
    }
}

impl<'a> From<&'a ConnectionOpen> for ReceivedBytes<'a> {
    fn from(c: &'a ConnectionOpen) -> Self {
        ReceivedBytes(c)
    }
}

impl<'a> From<&'a ConnectionOpen> for SentBytes<'a> {
    fn from(c: &'a ConnectionOpen) -> Self {
        SentBytes(c)
    }
}

impl CommonTrafficLabels {
    fn new() -> Self {
        Default::default()
    }

    fn with_source(mut self, w: &Workload) -> Self {
        self.source_workload = w.workload_name.clone().into();
        self.source_canonical_service = w.canonical_name.clone().into();
        self.source_canonical_revision = w.canonical_revision.clone().into();
        self.source_workload_namespace = w.namespace.clone().into();
        self.source_principal = w.identity().into();
        self.source_app = w.canonical_name.clone().into();
        self.source_version = w.canonical_revision.clone().into();
        self.source_cluster = "Kubernetes".to_string().into(); // TODO
        self
    }

    fn with_destination(mut self, w: Option<&Workload>) -> Self {
        let Some(w) = w else {
            return self
        };
        self.destination_workload = w.workload_name.clone().into();
        self.destination_canonical_service = w.canonical_name.clone().into();
        self.destination_canonical_revision = w.canonical_revision.clone().into();
        self.destination_workload_namespace = w.namespace.clone().into();
        self.destination_principal = w.identity().into();
        self.destination_app = w.canonical_name.clone().into();
        self.destination_version = w.canonical_revision.clone().into();
        self.destination_cluster = "Kubernetes".to_string().into(); // TODO
        self
    }
}

impl From<ReceivedBytes<'_>> for CommonTrafficLabels {
    fn from(c: ReceivedBytes) -> Self {
        c.0.into()
    }
}

impl From<SentBytes<'_>> for CommonTrafficLabels {
    fn from(c: SentBytes) -> Self {
        c.0.into()
    }
}

impl From<&ConnectionOpen> for CommonTrafficLabels {
    fn from(c: &ConnectionOpen) -> Self {
        CommonTrafficLabels {
            reporter: c.reporter,
            request_protocol: RequestProtocol::tcp,
            response_flags: ResponseFlags::none,
            connection_security_policy: c.connection_security_policy,
            ..CommonTrafficLabels::new()
                .with_source(&c.source)
                .with_destination(c.destination.as_ref())
        }
    }
}

#[derive(Clone, Hash, Default, Debug, PartialEq, Eq, EncodeLabelSet)]
pub(super) struct CommonTrafficLabels {
    reporter: Reporter,

    source_workload: DefaultedUnknown<String>,
    source_canonical_service: DefaultedUnknown<String>,
    source_canonical_revision: DefaultedUnknown<String>,
    source_workload_namespace: DefaultedUnknown<String>,
    source_principal: DefaultedUnknown<Identity>,
    source_app: DefaultedUnknown<String>,
    source_version: DefaultedUnknown<String>,
    source_cluster: DefaultedUnknown<String>,

    // TODO: never set
    destination_service: DefaultedUnknown<String>,
    destination_service_namespace: DefaultedUnknown<String>,
    destination_service_name: DefaultedUnknown<String>,

    destination_workload: DefaultedUnknown<String>,
    destination_canonical_service: DefaultedUnknown<String>,
    destination_canonical_revision: DefaultedUnknown<String>,
    destination_workload_namespace: DefaultedUnknown<String>,
    destination_principal: DefaultedUnknown<Identity>,
    destination_app: DefaultedUnknown<String>,
    destination_version: DefaultedUnknown<String>,
    destination_cluster: DefaultedUnknown<String>,

    request_protocol: RequestProtocol,
    response_flags: ResponseFlags,
    connection_security_policy: SecurityPolicy,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let connection_opens = Family::default();
        registry.register(
            "tcp_connections_opened",
            "The total number of TCP connections opened",
            connection_opens.clone(),
        );
        let connection_close = Family::default();
        registry.register(
            "tcp_connections_closed",
            "The total number of TCP connections closed",
            connection_close.clone(),
        );

        let received_bytes = Family::default();
        registry.register(
            "tcp_received_bytes",
            "The size of total bytes received during request in case of a TCP connection",
            received_bytes.clone(),
        );
        let sent_bytes = Family::default();
        registry.register(
            "tcp_sent_bytes",
            "The size of total bytes sent during response in case of a TCP connection",
            sent_bytes.clone(),
        );

        Self {
            connection_opens,
            connection_close,
            received_bytes,
            sent_bytes,
        }
    }
}

impl Recorder<ConnectionOpen> for super::Metrics {
    fn record_count(&self, reason: &ConnectionOpen, count: u64) {
        self.traffic
            .connection_opens
            .get_or_create(&CommonTrafficLabels::from(reason))
            .inc_by(count);
    }
}

impl Recorder<ConnectionClose<'_>> for super::Metrics {
    fn record_count(&self, reason: &ConnectionClose, count: u64) {
        self.traffic
            .connection_close
            .get_or_create(&CommonTrafficLabels::from(reason.0))
            .inc_by(count);
    }
}

impl Recorder<ReceivedBytes<'_>> for super::Metrics {
    fn record_count(&self, reason: &ReceivedBytes, count: u64) {
        self.traffic
            .received_bytes
            .get_or_create(&CommonTrafficLabels::from(reason.0))
            .inc_by(count);
    }
}

impl Recorder<SentBytes<'_>> for super::Metrics {
    fn record_count(&self, reason: &SentBytes, count: u64) {
        self.traffic
            .sent_bytes
            .get_or_create(&CommonTrafficLabels::from(reason.0))
            .inc_by(count);
    }
}
