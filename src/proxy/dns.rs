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
use std::net::IpAddr;
use std::time::Instant;

use crate::state::{DemandProxyState, ResolvedDns};

use drain::Watch;
use itertools::Itertools;
use tracing::{info, trace, warn};

use super::Error;
use crate::proxy::ProxyInputs;

use tokio::task::JoinHandle;

use trust_dns_resolver::config::*;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

struct TaskContext {
    task: tokio::task::JoinHandle<()>,
    // monotonic task start time
    start: Instant, // TODO(kdorosh): get this value from resolved DNS
    finished: bool,
    // TODO: honor dns cache ttl?
}

// PollingDns is an implementation of https://github.com/envoyproxy/envoy/issues/20562
// it to allows ambient support for workload entry hostnames that are resolved on-demand
// (upon initial request) and then re-resolved using async polling from the dataplane if
// requests continue to come in.
//
// Dataplane DNS resolution can be important in niche cases, like geographic dns resolution, as documented in
// https://github.com/istio/istio/blob/7bf52db38c91c89a4d56d6a94f402fd9ddaf6465/pilot/pkg/serviceregistry/kube/conversion.go#L151-L155
pub(super) struct PollingDns {
    pi: ProxyInputs,
    drain: Watch,
    // workload UID to task
    tasks: HashMap<String, TaskContext>,
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
        mut state: DemandProxyState,
        dns_resolver_config: ResolverConfig,
        dns_resolver_opts: ResolverOpts,
        hostname: String,
        workload_uid: String,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let hostname = hostname.clone();
            trace!("dns workload async task started for {:?}", &hostname);

            // TODO(kdorosh): handle unwrap
            let r = TokioAsyncResolver::new(dns_resolver_config, dns_resolver_opts, TokioHandle)
                .unwrap();
            let resp = r.lookup_ip(&hostname).await;
            if resp.is_err() {
                warn!(
                    "dns async poller: error response for workload {} is: {:?}",
                    &workload_uid, resp
                );
                return;
            } else {
                trace!(
                    "dns async poller: response for workload {} is: {:?}",
                    &workload_uid,
                    resp
                );
            }
            let resp = resp.unwrap();
            let ips = resp
                .as_lookup()
                .record_iter()
                .filter_map(|record| {
                    if record.rr_type().is_ip_addr() {
                        // TODO: handle ipv6
                        return record.data().unwrap().as_a().copied();
                    }
                    None
                })
                .collect_vec();
            let set = HashSet::from_iter(ips.iter().map(|x| IpAddr::V4(*x)));
            let old = state.get_ips_for_workload(workload_uid.to_owned());
            // TODO(kdorosh) get from DNS record TTL
            let rdns = ResolvedDns::new(
                hostname,
                set,
                old.unwrap_or_default().get_last_queried(),
                std::time::Duration::from_secs(30),
            );
            state.set_ips_for_workload(workload_uid, rdns);
        })
    }

    pub(super) async fn run(mut self) {
        let accept = async move {
            loop {
                // TODO(kdorosh) impl+test polling only if requests were received during last DNS ttl

                let dns_workloads = self.pi.state.get_recent_workloads_queried();

                // kill tasks that no longer need to be running
                let current_workload_uids = dns_workloads
                    .iter()
                    .map(|w| w.workload_uid.clone())
                    .collect_vec();
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
                    let cloned_hostname = dns_workload.hostname.clone();
                    let cloned_uid = dns_workload.workload_uid.clone();
                    match self.tasks.get_mut(&dns_workload.workload_uid) {
                        None => {
                            let handle = Self::get_handle(
                                self.pi.state.clone(),
                                self.pi.cfg.dns_resolver_config.clone(),
                                self.pi.cfg.dns_resolver_opts,
                                cloned_hostname.to_owned(),
                                cloned_uid.to_owned(),
                            );
                            let task = TaskContext {
                                task: handle,
                                start: Instant::now(),
                                finished: false,
                            };
                            self.tasks.insert(cloned_uid.clone(), task);
                            trace!(
                                "dns workload async task queued for {:?}. curr tasks {}",
                                dns_workload.hostname,
                                self.tasks.len()
                            );
                        }
                        Some(t) => {
                            if !t.task.is_finished() {
                                return;
                            }
                            if !t.finished {
                                trace!("dns workload async task finished {:?}", t.task);
                                t.finished = true;
                            }
                            // TODO(kdorosh): dont harcode 1s; time comes from dns ttl
                            if t.finished && Instant::now().duration_since(t.start).as_secs() > 1 {
                                trace!("dns workload async task finished and queued for re-polling {:?}", t.task);
                                t.task = Self::get_handle(
                                    self.pi.state.clone(),
                                    self.pi.cfg.dns_resolver_config.clone(),
                                    self.pi.cfg.dns_resolver_opts,
                                    cloned_hostname,
                                    cloned_uid,
                                );
                                t.start = Instant::now();
                                t.finished = false;
                                return;
                            }
                            if !t.finished && Instant::now().duration_since(t.start).as_secs() > 10
                            {
                                warn!("dns workload async task still running after 10s; killing task and re-polling {:?}", t.task);
                                t.task.abort();

                                t.task = Self::get_handle(
                                    self.pi.state.clone(),
                                    self.pi.cfg.dns_resolver_config.clone(),
                                    self.pi.cfg.dns_resolver_opts,
                                    cloned_hostname,
                                    cloned_uid,
                                );
                                t.start = Instant::now();
                                return;
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
