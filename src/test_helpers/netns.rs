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

use netns_rs::NetNs;
use tokio::runtime::{Handle, RuntimeFlavor};
use tracing::{debug, warn, Instrument};

use crate::test_helpers::helpers;

pub struct NamespaceManager {
    prefix: String,
    root: NetNs,
    namespaces: Arc<Mutex<HashMap<String, u8>>>,
}

#[derive(Clone)]
pub struct Resolver {
    namespaces: Arc<Mutex<HashMap<String, u8>>>,
}

impl Resolver {
    pub fn resolve(&self, name: &str) -> Option<IpAddr> {
        self.namespaces
            .lock()
            .unwrap()
            .get(name)
            .map(|i| id_to_ip(*i))
    }
}

#[derive(Debug)]
pub struct Namespace {
    id: u8,
    name: String,
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
        id_to_ip(self.id)
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
        let (tx, rx) = sync::mpsc::sync_channel::<()>(0);
        // Change network namespaces changes the entire thread, so we want to run each network in its own thread
        let j = thread::spawn(move || {
            self.netns
                .run(|_n| {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(
                        f(Ready(tx)).instrument(tracing::info_span!("run", namespace = self.name)),
                    )
                })
                .unwrap()
        });
        debug!(namespace = name, "awaiting ready");
        // Await readiness
        if rx.recv().is_err() {
            debug!(namespace = name, "failed ready");
            j.join().unwrap()?;
            anyhow::bail!("readiness dropped; used ready.set_ready() instead");
        }
        debug!(namespace = name, "ready");
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

fn id_to_ip(i: u8) -> IpAddr {
    IpAddr::from([10, 0, i, 1])
}

// Clear out the namespace on Drop. This gives best effort assurance our test cleans up properly
impl Drop for NamespaceManager {
    fn drop(&mut self) {
        // Drop the root namespace
        drop_namespace(&self.prefix);
        for (name, _) in self.namespaces.lock().unwrap().iter() {
            drop_namespace(&format!("{}-{name}", self.prefix));
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
        let ns = NetNs::new(prefix)?;
        // Build Self early so we cleanup if later commands fail
        let res = Self {
            prefix: prefix.to_string(),
            root: ns,
            namespaces: Default::default(),
        };
        Ok(res)
    }

    pub(super) fn count(&self) -> u8 {
        self.namespaces.lock().unwrap().len() as u8
    }

    pub fn resolver(&self) -> Resolver {
        Resolver {
            namespaces: self.namespaces.clone(),
        }
    }

    pub fn resolve(&self, name: &str) -> Option<IpAddr> {
        self.resolver().resolve(name)
    }

    pub(super) fn run_in_root_namespace(
        &self,
        f: impl FnOnce() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.root.run(|_| f())?
    }

    /// child constructs a new network namespace "inside" the root namespace.
    /// Each namespace gets a unique IP address, and is configured to be able to route to all other namespaces
    /// through the root network namespace.
    pub fn child(&self, name: &str) -> anyhow::Result<Namespace> {
        let mut namespaces = self.namespaces.lock().unwrap();
        // Namespaces are never removed, so its safe (for now) to use the size
        // 10.0.0.x is the host namespace, so skip 0
        assert!(namespaces.len() < 255, "only 255 networks allowed");
        let id = namespaces.len() as u8 + 1;
        let prefix = &self.prefix;
        let veth = format!("veth{id}");
        let net = format!("{}-{name}", prefix);
        let netns = NetNs::new(&net)?;
        let ns = Namespace {
            id,
            netns,
            name: name.to_string(),
        };
        let ip = ns.ip();
        // Give the namespace a veth and configure routing
        // Largely inspired by https://github.com/containernetworking/plugins/blob/main/plugins/main/ptp/ptp.go
        helpers::run_command(&format!(
            "
ip -n {prefix} link add {veth} type veth peer name eth0 netns {net}
ip -n {prefix} link set dev {veth} up
ip -n {prefix} addr add 10.0.0.1 dev {veth}
ip -n {prefix} route add {ip} dev {veth} scope host

ip -n {net} link set dev lo up
ip -n {net} link set dev eth0 up
ip -n {net} addr add {ip}/16 dev eth0
ip -n {net} route add default via 10.0.0.1
ip -n {net} route add 10.0.0.1 dev eth0 scope link src {ip}
ip -n {net} route del 10.0.0.0/16 # remove auto-kernel route
ip -n {net} route add 10.0.0.0/16 via 10.0.0.1 src {ip}
"
        ))?;
        namespaces.insert(name.to_string(), id);
        Ok(ns)
    }
}
