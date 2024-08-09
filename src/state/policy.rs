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
use crate::strng;
use crate::strng::Strng;
use std::collections::{HashMap, HashSet};
use tokio::sync::watch;

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
            .get(namespace)
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    pub fn insert(&mut self, xds_name: Strng, rbac: Authorization) {
        self.remove(xds_name.clone());
        match rbac.scope {
            RbacScope::Global => {
                self.by_namespace
                    .entry(strng::EMPTY)
                    .or_default()
                    .insert(xds_name.clone());
            }
            RbacScope::Namespace => {
                self.by_namespace
                    .entry(strng::new(&rbac.namespace))
                    .or_default()
                    .insert(xds_name.clone());
            }
            RbacScope::WorkloadSelector => {}
        }
        self.by_key.insert(xds_name.clone(), rbac);
    }

    pub fn remove(&mut self, xds_name: Strng) {
        let Some(rbac) = self.by_key.remove(&xds_name) else {
            return;
        };
        if let Some(key) = match rbac.scope {
            RbacScope::Global => Some(strng::EMPTY),
            RbacScope::Namespace => Some(rbac.namespace),
            RbacScope::WorkloadSelector => None,
        } {
            if let Some(pl) = self.by_namespace.get_mut(&key) {
                pl.remove(&xds_name);
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


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{rbac::{RbacAction, RbacMatch, StringMatch}, test_helpers::xds};

    #[test]
    fn rbac_change_scope() {
        let mut store = PolicyStore::default();
        let namespace = "default";
        let name = "test_policy";
        let mut xds_name = String::with_capacity(1 + namespace.len() + name.len());
        xds_name.push_str(namespace.clone());
        xds_name.push('/');
        xds_name.push_str(name.clone());
        let mut policy = Authorization{
            name: "test_policy".into(),
            namespace: namespace.into(),
            scope: RbacScope::Namespace,
            action: RbacAction::Allow,
            rules: vec![vec![vec![RbacMatch {
                namespaces: vec![StringMatch::Exact("whatever".into())],
                ..Default::default()
            }]]],
        };
        let policy_key = policy.to_key();
        // insert this namespace-scoped policy into policystore then assert it is
        // exists in by_namespace of policystore
        store.insert(xds_name.clone(), policy.clone());
        let namespace_policies = store.get_by_namespace(&namespace.into());
        assert!(namespace_policies.contains(&policy_key));
        // change policy scope to workload and insert it into policystore again, then
        // assert it is not exists in by_namespace of policystore anymore
        policy.scope = RbacScope::WorkloadSelector;
        store.insert(xds_name.clone(), policy.clone());
        let namespace_policies = store.get_by_namespace(&namespace.into());
        assert!(!namespace_policies.contains(&policy_key));
    }

}