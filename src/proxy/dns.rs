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
use crate::state::WorkloadDnsInfo;
use tokio::task::JoinHandle;

use trust_dns_resolver::config::*;
use trust_dns_resolver::{TokioAsyncResolver, TokioHandle};

struct TaskContext {
    task: tokio::task::JoinHandle<()>,
    // monotonic task start time
    start: Instant,
    finished: bool,
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
        info!(
            component = "dns",
            "on-demand dns async polling client started",
        );
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
        workload_dns: WorkloadDnsInfo,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let hostname = workload_dns.hostname.clone();
            let workload_uid = workload_dns.workload_uid.clone();
            trace!("dns async poller: task started for {:?}", &hostname);

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
            let old = state.get_ips_for_workload(&workload_uid);
            // TODO(kdorosh) get from DNS record TTL
            let rdns = ResolvedDns::new(
                hostname,
                set,
                Some(Instant::now()),
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

                let dns_workloads = self.pi.state.get_workloads_ready_for_dns_refresh();

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
                            "dns async poller: task no longer needed for {}; aborting",
                            workload_uid
                        );
                        task.task.abort();
                        workload_uid_to_remove_set.insert(workload_uid.clone());
                    }
                }
                for workload_uid in workload_uid_to_remove_set.iter() {
                    self.tasks.remove(workload_uid);
                    self.pi.state.remove_ips_for_workload(workload_uid);
                }

                // start new tasks, if needed
                for workload_dns in dns_workloads.iter() {
                    match self.tasks.get_mut(&workload_dns.workload_uid) {
                        None => {
                            let handle = Self::get_handle(
                                self.pi.state.clone(),
                                self.pi.cfg.dns_resolver_config.clone(),
                                self.pi.cfg.dns_resolver_opts,
                                workload_dns.to_owned(),
                            );
                            let task = TaskContext {
                                task: handle,
                                start: Instant::now(),
                                finished: false,
                            };
                            self.tasks.insert(workload_dns.workload_uid.clone(), task);
                            trace!(
                                "dns async poller: task queued for {:?}. curr tasks {}",
                                workload_dns.hostname,
                                self.tasks.len()
                            );
                        }
                        Some(t) => {
                            if !t.task.is_finished() {
                                return;
                            }
                            if !t.finished {
                                trace!("dns async poller: task finished {:?}", t.task);
                                t.finished = true;
                            }
                            if !t.finished && Instant::now().duration_since(t.start).as_secs() > 10
                            {
                                warn!("dns async poller: task still running after 10s; killing task and re-polling {:?}", t.task);
                                t.task.abort();

                                t.task = Self::get_handle(
                                    self.pi.state.clone(),
                                    self.pi.cfg.dns_resolver_config.clone(),
                                    self.pi.cfg.dns_resolver_opts,
                                    workload_dns.to_owned(),
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
