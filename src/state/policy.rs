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

/// A PolicyStore encapsulates all policy information about workloads in the mesh
#[derive(serde::Serialize, Default, Debug)]
pub struct PolicyStore {
    /// policies maintains a mapping of ns/name to policy.
    by_key: HashMap<String, Authorization>,

    /// policies_by_namespace maintains a mapping of namespace (or "" for global) to policy names
    by_namespace: HashMap<String, HashSet<String>>,
}

impl PolicyStore {
    pub fn get<T: AsRef<str>>(&self, key: T) -> Option<&Authorization> {
        self.by_key.get(key.as_ref())
    }

    pub fn get_by_namespace<T: AsRef<str>>(&self, namespace: T) -> Vec<String> {
        self.by_namespace
            .get(namespace.as_ref())
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    pub fn insert(&mut self, rbac: Authorization) {
        let key = rbac.to_key();
        match rbac.scope {
            RbacScope::Global => {
                self.by_namespace
                    .entry("".to_string())
                    .or_default()
                    .insert(key.clone());
            }
            RbacScope::Namespace => {
                self.by_namespace
                    .entry(rbac.namespace.clone())
                    .or_default()
                    .insert(key.clone());
            }
            RbacScope::WorkloadSelector => {}
        }
        self.by_key.insert(key, rbac);
    }

    pub fn remove(&mut self, name: String) {
        let Some(rbac) = self.by_key.remove(&name) else {
            return;
        };
        if let Some(key) = match rbac.scope {
            RbacScope::Global => Some("".to_string()),
            RbacScope::Namespace => Some(rbac.namespace),
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
}
