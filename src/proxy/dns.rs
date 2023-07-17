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

use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use crate::state::ProxyState;

use bytes::Bytes;
use drain::Watch;
use futures::stream::StreamExt;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Response, StatusCode};
// use hyper::{Method, Request, Response, StatusCode};
use itertools::Itertools;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, instrument, trace, trace_span, warn, Instrument};

use super::Error;
use crate::baggage::parse_baggage_header;
use crate::config::Config;
use crate::identity::SecretManager;
use crate::metrics::Recorder;
use crate::proxy;
use crate::proxy::inbound::InboundConnect::{DirectPath, Hbone};
use crate::proxy::metrics::{ConnectionOpen, Metrics, Reporter};
use crate::proxy::{metrics, ProxyInputs, TraceParent, BAGGAGE_HEADER, TRACEPARENT_HEADER};
use crate::rbac::Connection;
use crate::socket::to_canonical;
use crate::state::workload::{address, GatewayAddress, NetworkAddress, Workload};
use crate::state::DemandProxyState;
use crate::tls::TlsError;

use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use crate::dns::SystemForwarder;
use crate::dns::Forwarder;
// use crate::test_helpers::dns::{a_request, n, socket_addr, system_forwarder};
// use trust_dns_server::server::{Protocol};
use std::collections::HashMap;
use tokio::task::JoinHandle;

use trust_dns_client::client::{AsyncClient, ClientHandle};
use trust_dns_client::error::ClientError;
use trust_dns_proto::error::{ProtoError, ProtoErrorKind};
use trust_dns_proto::iocompat::AsyncIoTokioAsStd;
use trust_dns_proto::op::{Edns, Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns_proto::serialize::binary::BinDecodable;
use trust_dns_proto::tcp::TcpClientStream;
use trust_dns_proto::udp::UdpClientStream;
use trust_dns_proto::xfer::{DnsRequest, DnsRequestOptions, DnsResponse};
use trust_dns_proto::DnsHandle;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::server::{Protocol, Request};

struct TaskContext {
    task: tokio::task::JoinHandle<()>,
    finished: bool,
    // time started
    // dns cache ttl?
}

pub(super) struct Dns {
    cfg: Config,
    state: DemandProxyState,
    drain: Watch,
    // metrics: Arc<Metrics>,

    // workload UID to task
    tasks: HashMap<String, TaskContext>,
}

/// Constructs a new [Message] of type [MessageType::Query];
pub fn new_message(name: Name, rr_type: RecordType) -> Message {
    let mut msg = Message::new();
    msg.set_id(123);
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    msg.add_query(Query::query(name, rr_type));
    msg
}

/// Converts the given [Message] into a server-side [Request] with dummy values for
/// the client IP and protocol.
pub fn server_request(msg: &Message, client_addr: SocketAddr, protocol: Protocol) -> Request {
    // Serialize the message.
    let wire_bytes = msg.to_vec().unwrap();

    // Deserialize into a server-side request.
    let msg_request = MessageRequest::from_bytes(&wire_bytes).unwrap();

    Request::new(msg_request, client_addr, protocol)
}

/// Creates a A-record [Request] for the given name.
pub fn a_request(name: Name, client_addr: SocketAddr, protocol: Protocol) -> Request {
    server_request(&new_message(name, RecordType::A), client_addr, protocol)
}

/// A short-hand helper for constructing a [Name].
pub fn n<S: AsRef<str>>(name: S) -> Name {
    Name::from_utf8(name).unwrap()
}

/// Helper for parsing a [SocketAddr] string.
pub fn socket_addr<S: AsRef<str>>(socket_addr: S) -> SocketAddr {
    socket_addr.as_ref().parse().unwrap()
}

impl Dns {
    pub(super) async fn new(mut pi: ProxyInputs, drain: Watch) -> Result<Dns, Error> {
        info!(
            component="dns",
            "dns async client started",
        );
        Ok(Dns {
            cfg: pi.cfg,
            state: pi.state,
            // metrics: pi.metrics,
            drain,
            tasks: HashMap::new(),
        })
    }

    fn get_handle(state: Arc<RwLock<ProxyState>>, dns_workload: Workload) -> JoinHandle<()> {
        return tokio::spawn(async move {

            let hn = dns_workload.async_hostname.clone();

            info!("dns workload async task started for {:?}", &hn);

            let fw = SystemForwarder::new().unwrap();
            let r = fw.resolver();
            // Lookup a host.
            let req = a_request(
                n(&hn),
                socket_addr("1.1.1.1:80"),
                Protocol::Udp,
            );
            // let r = forwarder.resolver();
            let resp = r.lookup(&req).await.unwrap();
            info!("dns workload resp: {:?}", resp);

            tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            info!("dns workload async task done for {}", hn);

            let ips = resp.record_iter().filter_map(|record| {
                if record.rr_type().is_ip_addr() {
                    // TODO: handle ipv6
                    let a = record.data().unwrap().as_a();
                    return Some(a.unwrap().clone());
                }
                None
            }).collect_vec();
            state.write().unwrap().resolved_dns.set_dns(dns_workload.uid, ips);

        });
    }

    pub(super) async fn run(mut self) {
        let accept = async move {
            loop {
                let dns_workloads = self.state.state.read().unwrap().workloads.get_async_dns_workloads();
                // TODO: kill tasks that no longer need to be running

                for dns_workload in dns_workloads.iter() {
                    match self.tasks.get(&dns_workload.uid) {
                        None => {
                            let clone = dns_workload.clone();
                            let handle = Self::get_handle(self.state.state.clone(), clone);
                            let task = TaskContext {
                                task: handle,
                                finished: false,
                            };
                            self.tasks.insert(dns_workload.uid.clone(), task);
                            info!("dns workload async task queued for {:?}. curr tasks {}", dns_workload.async_hostname, self.tasks.len());
                            // let _ = tokio::try_join!(task.task).unwrap();
                        }
                        Some(mut t) => {
                            // TODO: check if task is still running
                            if t.task.is_finished() {
                                // info!("dns workload async task finished {:?}", t.task);
                                // t.finished = true;
                            }
                            trace!("dns workload async task already exists {:?}", t.task);
                        }
                    }
                }
                // important! give existing tasks some time to run
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        };

        tokio::select! {
            res = accept => { res }
            _ = self.drain.signaled() => {
                // info!("async dns draining");
                // self.tasks.get_mut("foo").unwrap().task.abort();
                info!("async dns drained");
            }
        }
    }
}
