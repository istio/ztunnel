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

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::net::IpAddr;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{sync, thread};

use anyhow::anyhow;
use netns_rs::NetNs;
use tokio::runtime::{Handle, RuntimeFlavor};
use tracing::{debug, warn, Instrument};

use crate::test_helpers::helpers;

pub struct NamespaceManager {
    prefix: String,
    state: Arc<Mutex<State>>,
}

#[derive(Default, Debug)]
struct Network {
    id: u8,
    node_id: u8,
    node: String,
}

struct NodeNetwork {
    id: u8,
    net: NetNs,
}

#[derive(Default)]
struct State {
    pods: HashMap<String, Network>,
    nodes: HashMap<String, NodeNetwork>,
}

#[derive(Clone)]
pub struct Resolver {
    state: Arc<Mutex<State>>,
}

impl Resolver {
    pub fn resolve(&self, name: &str) -> Option<IpAddr> {
        self.state
            .lock()
            .unwrap()
            .pods
            .get(name)
            .map(|i| id_to_ip(i.node_id, i.id))
    }
}

#[derive(Debug)]
pub struct Namespace {
    id: u8,
    node_id: u8,
    name: String,
    node_name: String,
    netns: NetNs,
}

pub struct Ready(SyncSender<()>);

impl Ready {
    pub fn set_ready(self) {
        let _ = self.0.send(());
    }
}

impl Namespace {
    pub fn ip(&self) -> IpAddr {
        id_to_ip(self.node_id, self.id)
    }

    pub fn interface(&self) -> String {
        format!("veth{}", self.id)
    }

    // A small helper around run_ready that marks as "ready" immediately.
    pub fn run<F, Fut>(self, f: F) -> anyhow::Result<JoinHandle<anyhow::Result<()>>>
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        self.run_ready(|ready| async move {
            ready.set_ready();
            f().await
        })
    }

    /// run_ready runs an (async) closure. As input, a Ready is passed. This must be marked set_ready()
    /// before the closure executes. run_ready() will return once set_ready() is called and run in the background.
    /// Because network namespaces are bound to a thread, this function spins up a new thread for the closure and
    /// spawns a single-threaded tokio runtime.
    /// To await the closure, be sure to call join().
    pub fn run_ready<F, Fut>(self, f: F) -> anyhow::Result<JoinHandle<anyhow::Result<()>>>
    where
        F: FnOnce(Ready) -> Fut + Send + 'static,
        Fut: Future<Output = anyhow::Result<()>>,
    {
        let name = self.name.clone();
        let node_name = self.node_name.clone();
        let (tx, rx) = sync::mpsc::sync_channel::<()>(0);
        // Change network namespaces changes the entire thread, so we want to run each network in its own thread
        let j = thread::spawn(move || {
            self.netns
                .run(|_n| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(f(Ready(tx)).instrument(tracing::info_span!(
                        "run",
                        name = self.name,
                        node = self.node_name
                    )))
                })
                .unwrap()
        });
        debug!(%name, %node_name, "awaiting ready");
        // Await readiness
        if rx.recv().is_err() {
            debug!(%name, %node_name, "failed ready");
            j.join().unwrap()?;
            anyhow::bail!("readiness dropped; used ready.set_ready() instead");
        }
        debug!(%name, %node_name, "ready");
        Ok(j)
    }
}

fn drop_namespace(name: &str) {
    debug!("dropping namespace {name}");
    match NetNs::get(name) {
        // We do not store exclusive NetNs since they are not Clone, so just fetch it...
        Ok(ns) => {
            if let Err(e) = ns.remove() {
                warn!("failed to remove namespace {name}: {e}");
            }
        }
        Err(e) => warn!("failed to find namespace {name}: {e}"),
    }
}

fn id_to_ip(node_id: u8, pod_id: u8) -> IpAddr {
    IpAddr::from([10, 0, node_id, pod_id])
}

// Clear out the namespace on Drop. This gives best effort assurance our test cleans up properly
impl Drop for NamespaceManager {
    fn drop(&mut self) {
        // Drop the root namespace
        drop_namespace(&self.prefix);
        let state = self.state.lock().unwrap();
        for (name, ns) in state.pods.iter() {
            drop_namespace(&format!("{}~{}~{name}", self.prefix, &ns.node));
        }
        for (name, _) in state.nodes.iter() {
            drop_namespace(&format!("{}~{name}", self.prefix));
        }
    }
}

impl NamespaceManager {
    pub fn new(prefix: &str) -> anyhow::Result<Self> {
        if let Ok(h) = Handle::try_current() {
            assert_eq!(
                h.runtime_flavor(),
                RuntimeFlavor::CurrentThread,
                "Namespaces require single threaded"
            );
        }
        let _ns = NetNs::new(prefix)?;
        // Build Self early so we cleanup if later commands fail
        let res = Self {
            prefix: prefix.to_string(),
            state: Default::default(),
        };
        helpers::run_command(&format!(
            "
ip -n {prefix} link add name br0 type bridge
ip -n {prefix} link set dev br0 up
ip -n {prefix} addr add 172.172.0.1/16 dev br0
"
        ))?;
        Ok(res)
    }

    pub fn resolver(&self) -> Resolver {
        Resolver {
            state: self.state.clone(),
        }
    }

    pub fn resolve(&self, name: &str) -> Option<IpAddr> {
        self.resolver().resolve(name)
    }

    pub(super) fn run_in_node(
        &self,
        node: &str,
        f: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.state
            .lock()
            .unwrap()
            .nodes
            .get(node)
            .ok_or_else(|| anyhow!("unknown node"))?
            .net
            .run(|_| f())?
    }

    /// child constructs a new network namespace "inside" the root namespace.
    /// Each namespace gets a unique IP address, and is configured to be able to route to all other namespaces
    /// through the root network namespace.
    pub fn child(&self, node: &str, name: &str) -> anyhow::Result<Namespace> {
        debug!(%node, %name, "building namespace");
        let mut state = self.state.lock().unwrap();
        // Namespaces are never removed, so its safe (for now) to use the size
        // 10.0.0.1 is the node namespace, so skip 0 and 1
        assert!(state.pods.len() < 254, "only 255 networks allowed");
        let id = state.pods.len() as u8 + 2;
        let node_net = format!("{}~{node}", &self.prefix);
        let prefix = &self.prefix;
        if state.pods.contains_key(name) {
            panic!("pod {name} already registered");
        }
        if !state.nodes.contains_key(node) {
            assert!(state.nodes.len() < 16, "only 16 nodes allowed");
            let node_id = state.nodes.len() as u8 + 2;
            // Setup node
            let netns = NetNs::new(&node_net)?;
            state.nodes.insert(
                node.to_string(),
                NodeNetwork {
                    id: node_id,
                    net: netns,
                },
            );
            let veth = format!("veth{node_id}");
            helpers::run_command(&format!(
                "
set -ex
ip -n {prefix} link add {veth} type veth peer name eth0 netns {node_net}
ip -n {prefix} link set dev {veth} up
ip -n {prefix} link set dev {veth} master br0
# Give our node an IP
ip -n {node_net} link set dev eth0 up
ip -n {node_net} addr add 172.172.0.{node_id}/16 dev eth0
# Route everything to the network
ip -n {node_net} route add default via 172.172.0.1
# TODO: cross product routing for
ip -n {node_net} route add 172.172.0.0/17 dev eth0 scope link src 172.172.0.{node_id}
"
            ))?;
            for (node, s) in state.nodes.iter() {
                if s.id == node_id {
                    // ourselves, skip
                    continue;
                }
                let other_id = s.id;
                let other_net = format!("{}~{node}", &self.prefix);
                helpers::run_command(&format!(
                    "
set -ex
# For each other node, give a route to it for all pods in the node
ip -n {node_net} route add 10.0.{other_id}.0/24 via 172.172.0.{other_id} dev eth0
# Also give that node a route to us
ip -n {other_net} route add 10.0.{node_id}.0/24 via 172.172.0.{node_id} dev eth0
"
                ))?;
            }
        }
        let node_id = state.nodes.get(node).unwrap().id;
        let veth = format!("veth{id}");
        let net = format!("{}~{node}~{name}", prefix);
        let netns = NetNs::new(&net)?;
        let ns = Namespace {
            id,
            node_id,
            netns,
            node_name: node.to_string(),
            name: name.to_string(),
        };
        let ip = ns.ip();
        state.pods.insert(
            name.to_string(),
            Network {
                id,
                node_id,
                node: node.to_string(),
            },
        );
        // Give the namespace a veth and configure routing
        // Largely inspired by https://github.com/containernetworking/plugins/blob/main/plugins/main/ptp/ptp.go
        helpers::run_command(&format!(
            "
set -ex
ip -n {node_net} link add {veth} type veth peer name eth0 netns {net}
ip -n {node_net} link set dev {veth} up
ip -n {node_net} addr add 10.0.{node_id}.1 dev {veth}
ip -n {node_net} route add {ip} dev {veth} scope host

ip -n {net} link set dev lo up
ip -n {net} link set dev eth0 up
ip -n {net} addr add {ip}/24 dev eth0
ip -n {net} route add default via 10.0.{node_id}.1
ip -n {net} route add 10.0.{node_id}.1 dev eth0 scope link src {ip}
ip -n {net} route del 10.0.{node_id}.0/24 # remove auto-kernel route
ip -n {net} route add 10.0.{node_id}.0/24 via 10.0.{node_id}.1 src {ip}
ip netns exec {node_net} sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec {node_net} sysctl -w net.ipv4.conf.{veth}.rp_filter=0
"
        ))?;
        Ok(ns)
    }
}
