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
use futures::FutureExt;
use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::io::Write;
use std::net::IpAddr;
use std::process::Command;
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::{sync, thread};

use netns_rs::NetNs;
use tokio::runtime::{Handle, RuntimeFlavor};
use tracing::{debug, info, warn, Instrument};

pub struct NamespaceManager {
    prefix: String,
    namespaces: Arc<Mutex<HashMap<String, u8>>>,
}

#[derive(Debug)]
pub struct Namespace {
    id: u8,
    name: String,
    namespace_name: String,
    netns: NetNs,
}

pub struct Ready(SyncSender<()>);

impl Ready {
    // This is the same as drop(ready) but more explicit
    pub fn set_ready(self) {}
}

impl Namespace {
    pub fn ip(&self) -> IpAddr {
        id_to_ip(self.id)
    }

    pub fn run<F, Fut>(self, f: F) -> anyhow::Result<JoinHandle<anyhow::Result<()>>>
        where
            F: FnOnce(IpAddr) -> Fut + Send + 'static,
            Fut: Future<Output = anyhow::Result<()>> {
        self.run_ready(|ip, ready| async move {
            ready.set_ready();
            f(ip).await
        })
    }

    pub fn run_ready<F, Fut>(self, f: F) -> anyhow::Result<JoinHandle<anyhow::Result<()>>>
    where
        F: FnOnce(IpAddr, Ready) -> Fut + Send + 'static,
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
                        f(id_to_ip(self.id), Ready(tx))
                            .instrument(tracing::info_span!("run", namespace = self.name)),
                    )
                })
                .unwrap()
        });
        debug!(namespace=name, "awaiting ready");
        // Await readiness
        let _ = rx.recv();
        debug!(namespace=name, "ready");
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

impl Drop for NamespaceManager {
    fn drop(&mut self) {
        // Drop the root namespace
        drop_namespace(&self.prefix);
        for (name, _) in self.namespaces.lock().unwrap().iter() {
            drop_namespace( &format!("{}_inner_{name}", self.prefix));
        }
    }
}

impl NamespaceManager {
    // pub async fn run<F, O, Fut>(prefix: &str, f: F) -> anyhow::Result<O>
    // where
    // F: FnOnce(&Self) -> Fut + Send + 'static,
    // Fut: Future<Output = anyhow::Result<O>> + std::panic::UnwindSafe,
    // {
    //     if let Ok(h) = Handle::try_current() {
    //         assert_eq!(
    //             h.runtime_flavor(),
    //             RuntimeFlavor::CurrentThread,
    //             "Namespaces require single threaded"
    //         );
    //     }
    //     let _ = NetNs::new(prefix)?;
    //     let n = Self {
    //         prefix: prefix.to_string(),
    //         namespaces: Default::default(),
    //     };
    //     f(&n)
    // }
    pub fn new(prefix: &str) -> anyhow::Result<Self> {
        if let Ok(h) = Handle::try_current() {
            assert_eq!(
                h.runtime_flavor(),
                RuntimeFlavor::CurrentThread,
                "Namespaces require single threaded"
            );
        }
        let _ = NetNs::new(prefix)?;
        Ok(Self {
            prefix: prefix.to_string(),
            namespaces: Default::default(),
        })
    }

    pub fn resolve(&self, name: &str) -> Option<IpAddr> {
        self.namespaces
            .lock()
            .unwrap()
            .get(name)
            .map(|i| id_to_ip(*i))
    }

    pub fn child(&self, name: &str) -> anyhow::Result<Namespace> {
        let mut namespaces = self.namespaces.lock().unwrap();
        // Namespaces are never removed, so its safe (for now) to use the size
        // 10.0.0.x is the host namespace, so skip 0
        let id = namespaces.len() as u8 + 1;
        assert!(id <= 255, "only 255 networks allowed");
        let prefix = &self.prefix;
        let veth = format!("veth{id}");
        let net = format!("{}_inner_{name}", prefix);
        let netns = NetNs::new(&net)?;
        let ns = Namespace {
            id,
            netns,
            name: name.to_string(),
            namespace_name: net.clone(),
        };
        let ip = ns.ip();
        Self::run_command(&format!(
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

    fn run_command(cmd: &str) -> anyhow::Result<()> {
        debug!("running command {cmd}");
        let output = Command::new("sh").arg("-c").arg(cmd).output()?;
        debug!(
            "complete! code={}, stdout={}, stderr={}",
            output.status,
            std::str::from_utf8(&output.stdout)?,
            std::str::from_utf8(&output.stdout)?
        );
        println!("status: {}", output.status);
        std::io::stdout().write_all(&output.stdout).unwrap();
        std::io::stderr().write_all(&output.stderr).unwrap();
        Ok(())
    }
}
