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

use std::io::{Error, Write};

use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use crate::identity::Identity;
use crate::metrics::Recorder;
use crate::workload::Workload;

pub(super) struct Metrics {
    pub(super) connection_opens: Family<ConnectionInternal, Counter>,
    pub(super) connection_close: Family<ConnectionInternal, Counter>,
    pub(super) received_bytes: Family<ConnectionInternal, Counter>,
    pub(super) sent_bytes: Family<ConnectionInternal, Counter>,
}

#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, Encode)]
pub enum Reporter {
    #[default]
    source,
    #[allow(dead_code)]
    destination,
}

#[derive(Clone, Copy, Default, Hash, PartialEq, Eq, Encode)]
pub enum RequestProtocol {
    #[default]
    tcp,
    #[allow(dead_code)]
    http,
}

#[derive(Default, Copy, Clone, Hash, PartialEq, Eq)]
pub enum ResponseFlags {
    #[default]
    none,
}

impl Encode for ResponseFlags {
    fn encode(&self, writer: &mut dyn Write) -> Result<(), Error> {
        match self {
            ResponseFlags::none => writer.write_all(b"-"),
        }
    }
}

#[derive(Default, Copy, Clone, Hash, PartialEq, Eq, Encode)]
pub enum SecurityPolicy {
    #[default]
    unknown,
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

impl<T: Encode> Encode for DefaultedUnknown<T> {
    fn encode(&self, writer: &mut dyn Write) -> Result<(), Error> {
        match self {
            DefaultedUnknown(Some(i)) => i.encode(writer),
            DefaultedUnknown(None) => writer.write_all(b"unknown"),
        }
    }
}

pub struct ConnectionClose<'a>(&'a ConnectionOpen);

pub struct ReceivedBytes<'a>(pub &'a ConnectionOpen);

pub struct SentBytes<'a>(pub &'a ConnectionOpen);

#[derive(Clone)]
pub struct ConnectionOpen {
    pub reporter: Reporter,
    pub source: Workload,
    pub destination: Option<Workload>,
    pub destination_service: Option<String>,
    pub connection_security_policy: SecurityPolicy,
}

impl<'a> From<&'a ConnectionOpen> for ConnectionClose<'a> {
    fn from(c: &'a ConnectionOpen) -> Self {
        ConnectionClose(c)
    }
}

impl From<ConnectionClose<'_>> for ConnectionInternal {
    fn from(c: ConnectionClose) -> Self {
        c.0.into()
    }
}

impl From<ReceivedBytes<'_>> for ConnectionInternal {
    fn from(c: ReceivedBytes) -> Self {
        c.0.into()
    }
}

impl From<SentBytes<'_>> for ConnectionInternal {
    fn from(c: SentBytes) -> Self {
        c.0.into()
    }
}

impl From<&ConnectionOpen> for ConnectionInternal {
    fn from(c: &ConnectionOpen) -> Self {
        let mut co = ConnectionInternal {
            reporter: c.reporter,

            source_workload: c.source.workload_name.clone().into(),
            source_canonical_service: c.source.canonical_name.clone().into(),
            source_canonical_revision: c.source.canonical_revision.clone().into(),
            source_workload_namespace: c.source.namespace.clone().into(),
            source_principal: c.source.identity().into(),
            source_app: c.source.canonical_name.clone().into(),
            source_version: c.source.canonical_revision.clone().into(),
            source_cluster: "Kubernetes".to_string().into(), // TODO

            destination_service: c.destination_service.clone().into(),
            request_protocol: RequestProtocol::tcp,
            response_flags: ResponseFlags::none,
            connection_security_policy: c.connection_security_policy,

            ..Default::default()
        };
        if let Some(w) = c.destination.as_ref() {
            co.destination_workload = w.workload_name.clone().into();
            co.destination_canonical_service = w.canonical_name.clone().into();
            co.destination_canonical_revision = w.canonical_revision.clone().into();
            co.destination_workload_namespace = w.namespace.clone().into();
            co.destination_principal = w.identity().into();
            co.destination_app = w.canonical_name.clone().into();
            co.destination_version = w.canonical_revision.clone().into();
            co.destination_cluster = "Kubernetes".to_string().into(); // TODO
        }
        co
    }
}

#[derive(Clone, Hash, Default, PartialEq, Eq, Encode)]
pub(super) struct ConnectionInternal {
    reporter: Reporter,

    source_workload: DefaultedUnknown<String>,
    source_canonical_service: DefaultedUnknown<String>,
    source_canonical_revision: DefaultedUnknown<String>,
    source_workload_namespace: DefaultedUnknown<String>,
    source_principal: DefaultedUnknown<Identity>,
    source_app: DefaultedUnknown<String>,
    source_version: DefaultedUnknown<String>,
    source_cluster: DefaultedUnknown<String>,

    destination_service: DefaultedUnknown<String>,

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
            Box::new(connection_opens.clone()),
        );
        let connection_close = Family::default();
        registry.register(
            "tcp_connections_closed",
            "The total number of TCP connections closed",
            Box::new(connection_close.clone()),
        );

        let received_bytes = Family::default();
        registry.register(
            "tcp_received_bytes",
            "The size of total bytes received during request in case of a TCP connection",
            Box::new(received_bytes.clone()),
        );
        let sent_bytes = Family::default();
        registry.register(
            "tcp_sent_bytes",
            "The size of total bytes sent during response in case of a TCP connection",
            Box::new(sent_bytes.clone()),
        );

        Self {
            connection_opens,
            connection_close,
            received_bytes,
            sent_bytes
        }
    }
}

impl Recorder<ConnectionOpen> for super::Metrics {
    fn record_count(&self, reason: &ConnectionOpen, count: u64) {
        self.traffic
            .connection_opens
            .get_or_create(&ConnectionInternal::from(reason))
            .inc_by(count);
    }
}

impl Recorder<ConnectionClose<'_>> for super::Metrics {
    fn record_count(&self, reason: &ConnectionClose, count: u64) {
        self.traffic
            .connection_close
            .get_or_create(&ConnectionInternal::from(reason.0))
            .inc_by(count);
    }
}

impl Recorder<ReceivedBytes<'_>> for super::Metrics {
    fn record_count(&self, reason: &ReceivedBytes, count: u64) {
        self.traffic
            .received_bytes
            .get_or_create(&ConnectionInternal::from(reason.0))
            .inc_by(count);
    }
}

impl Recorder<SentBytes<'_>> for super::Metrics {
    fn record_count(&self, reason: &SentBytes, count: u64) {
        self.traffic
            .sent_bytes
            .get_or_create(&ConnectionInternal::from(reason.0))
            .inc_by(count);
    }
}
