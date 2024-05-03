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

use crate::rbac::{Authorization, RbacScope};
use std::collections::{HashMap, HashSet};
use tokio::sync::watch;
use crate::strng::Strng;

/// A PolicyStore encapsulates all policy information about workloads in the mesh
#[derive(Default, Debug)]
pub struct PolicyStore {
    /// policies maintains a mapping of ns/name to policy.
    pub(super) by_key: HashMap<Strng, Authorization>,

    /// policies_by_namespace maintains a mapping of namespace (or "" for global) to policy names
    by_namespace: HashMap<Strng, HashSet<Strng>>,

    notifier: PolicyStoreNotify,
}

#[derive(Debug)]
struct PolicyStoreNotify {
    sender: watch::Sender<()>,
}

impl Default for PolicyStoreNotify {
    fn default() -> Self {
        let (tx, _rx) = watch::channel(());
        PolicyStoreNotify { sender: tx }
    }
}

impl PolicyStore {
    pub fn get(&self, key: &Strng) -> Option<&Authorization> {
        self.by_key.get(key)
    }

    pub fn get_by_namespace(&self, namespace: &Strng) -> Vec<Strng> {
        self.by_namespace
            .get(namespace.into())
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    pub fn insert(&mut self, rbac: Authorization) {
        let key: Strng = rbac.to_key().into();
        match rbac.scope {
            RbacScope::Global => {
                self.by_namespace
                    .entry("".into())
                    .or_default()
                    .insert(key.clone());
            }
            RbacScope::Namespace => {
                self.by_namespace
                    .entry(rbac.namespace.into())
                    .or_default()
                    .insert(key.clone());
            }
            RbacScope::WorkloadSelector => {}
        }
        self.by_key.insert(key, rbac);
    }

    pub fn remove(&mut self, name: Strng) {
        let Some(rbac) = self.by_key.remove(&name) else {
            return;
        };
        if let Some(key) = match rbac.scope {
            RbacScope::Global => Some("".into()),
            RbacScope::Namespace => Some(rbac.namespace.into()),
            RbacScope::WorkloadSelector => None,
        } {
            if let Some(pl) = self.by_namespace.get_mut(&key) {
                pl.remove(&name);
                if pl.is_empty() {
                    self.by_namespace.remove(&key);
                }
            }
        }
    }
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.notifier.sender.subscribe()
    }
    pub fn send(&mut self) {
        self.notifier.sender.send_replace(());
    }
    pub fn clear_all_policies(&mut self) {
        self.by_namespace.clear();
        self.by_key.clear();
    }
}
