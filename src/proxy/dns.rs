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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::Instant;

use crate::config::ProxyMode;
use crate::state::DemandProxyState;

use drain::Watch;
use itertools::Itertools;
use tracing::{info, trace, warn};

use super::Error;
use crate::dns;
use crate::proxy::ProxyInputs;
use crate::state::workload::Workload;

use tokio::task::JoinHandle;

use trust_dns_proto::op::{Message, MessageType, Query};
use trust_dns_proto::rr::{Name, RecordType};
use trust_dns_proto::serialize::binary::BinDecodable;
use trust_dns_server::authority::MessageRequest;
use trust_dns_server::server::{Protocol, Request};

struct TaskContext {
    task: tokio::task::JoinHandle<()>,
    // monotonic task start time
    start: Instant,
    finished: bool,
    // TODO: honor dns cache ttl?
}

// PollingDns roughly maps to STRICT/LOGICAL DNS in envoy to allow ambient support for workload entry
// hostnames that are resolved using async polling from the dataplane.
// This can be important in niche cases, like geographic dns resolution, as documented in
// https://github.com/istio/istio/blob/7bf52db38c91c89a4d56d6a94f402fd9ddaf6465/pilot/pkg/serviceregistry/kube/conversion.go#L151-L155
pub(super) struct PollingDns {
    pi: ProxyInputs,
    drain: Watch,
    // workload UID to task
    tasks: HashMap<String, TaskContext>,
}

// TODO(kdorosh) DRY the copied code following here and generally clean up any latest placeholder test values

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

impl PollingDns {
    pub(super) async fn new(pi: ProxyInputs, drain: Watch) -> Result<PollingDns, Error> {
        info!(component = "dns", "dns async polling client started",);
        Ok(PollingDns {
            pi,
            drain,
            tasks: HashMap::new(),
        })
    }

    fn get_handle(
        proxy_mode: ProxyMode,
        dns_nameservers: Vec<SocketAddr>,
        mut state: DemandProxyState,
        dns_workload: Workload,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let hostname = dns_workload.hostname.clone();
            trace!("dns workload async task started for {:?}", &hostname);

            // TODO(kdorosh): don't make a new forwarder for every request?
            let fw = dns::forwarder_for_mode(proxy_mode, dns_nameservers).unwrap(); // TODO(kdorosh) handle unwrap
            let r = fw.resolver();

            // Lookup a host.
            let req = a_request(
                n(&hostname),
                socket_addr("1.1.1.1:80"), // TODO(kdorosh): don't hardcode this
                Protocol::Udp,
            );
            let resp = r.lookup(&req).await;
            if resp.is_err() {
                warn!(
                    "dns async response for workload {} is: {:?}",
                    &dns_workload.uid, resp
                );
                return;
            } else {
                trace!(
                    "dns async response for workload {} is: {:?}",
                    &dns_workload.uid,
                    resp
                );
            }
            let resp = resp.unwrap();
            let ips = resp
                .record_iter()
                .filter_map(|record| {
                    if record.rr_type().is_ip_addr() {
                        // TODO: handle ipv6
                        return record.data().unwrap().as_a().copied();
                    }
                    None
                })
                .collect_vec();
            state.set_ips_for_workload(dns_workload.uid, ips);
        })
    }

    pub(super) async fn run(mut self) {
        let accept = async move {
            loop {
                // TODO(kdorosh) impl+test polling only if requests were received during last DNS ttl

                let dns_workloads = self
                    .pi
                    .state
                    .state
                    .read()
                    .unwrap()
                    .workloads
                    .get_async_dns_workloads();

                // kill tasks that no longer need to be running
                let current_workload_uids =
                    dns_workloads.iter().map(|w| w.uid.clone()).collect_vec();
                let current_workload_uid_set: HashSet<String> =
                    HashSet::from_iter(current_workload_uids.iter().cloned());
                let mut workload_uid_to_remove_set: HashSet<String> = HashSet::new();
                for (workload_uid, task) in self.tasks.iter() {
                    if !current_workload_uid_set.contains(workload_uid) {
                        trace!(
                            "dns workload async task no longer needed for {}; aborting",
                            workload_uid
                        );
                        task.task.abort();
                        workload_uid_to_remove_set.insert(workload_uid.clone());
                    }
                }
                for workload_uid in workload_uid_to_remove_set.iter() {
                    self.tasks.remove(workload_uid);
                }

                // start new tasks, if needed
                for dns_workload in dns_workloads.iter() {
                    match self.tasks.get_mut(&dns_workload.uid) {
                        None => {
                            let clone = dns_workload.clone();
                            let handle = Self::get_handle(
                                self.pi.cfg.proxy_mode.to_owned(),
                                self.pi.cfg.dns_nameservers.to_owned(),
                                self.pi.state.clone(),
                                clone,
                            );
                            let task = TaskContext {
                                task: handle,
                                start: Instant::now(),
                                finished: false,
                            };
                            self.tasks.insert(dns_workload.uid.clone(), task);
                            trace!(
                                "dns workload async task queued for {:?}. curr tasks {}",
                                dns_workload.hostname,
                                self.tasks.len()
                            );
                        }
                        Some(t) => {
                            if t.task.is_finished() {
                                if !t.finished {
                                    trace!("dns workload async task finished {:?}", t.task);
                                    t.finished = true;
                                }
                                if t.finished
                                    && Instant::now().duration_since(t.start).as_secs() > 5
                                {
                                    // TODO: make this configurable
                                    trace!("dns workload async task finished and queued for re-polling {:?}", t.task);
                                    t.task = Self::get_handle(
                                        self.pi.cfg.proxy_mode.to_owned(),
                                        self.pi.cfg.dns_nameservers.to_owned(),
                                        self.pi.state.clone(),
                                        dns_workload.clone(),
                                    );
                                    t.start = Instant::now();
                                    t.finished = false;
                                }

                                if !t.finished
                                    && Instant::now().duration_since(t.start).as_secs() > 10
                                {
                                    warn!("dns workload async task still running after 10s; killing task and re-polling {:?}", t.task);
                                    t.task.abort();

                                    t.task = Self::get_handle(
                                        self.pi.cfg.proxy_mode.to_owned(),
                                        self.pi.cfg.dns_nameservers.to_owned(),
                                        self.pi.state.clone(),
                                        dns_workload.clone(),
                                    );
                                    t.start = Instant::now();
                                }
                                trace!(
                                    "dns workload async task queued for {:?}",
                                    dns_workload.hostname
                                );
                            }
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
                info!("async dns client drained");
            }
        }
    }
}
