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

use crate::telemetry;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use tracing::info;
mod server;
pub use server::*;

/// Ready tracks whether the process is ready.
#[derive(Clone, Debug, Default)]
pub struct Ready(Arc<Mutex<HashSet<String>>>);

impl Ready {
    pub fn new() -> Ready {
        Ready(Default::default())
    }

    /// register_task allows a caller to add a dependency to be marked "ready".
    pub fn register_task(&self, name: &str) -> BlockReady {
        self.0.lock().unwrap().insert(name.to_string());
        BlockReady {
            parent: self.to_owned(),
            name: name.to_string(),
        }
    }

    pub fn pending(&self) -> HashSet<String> {
        self.0.lock().unwrap().clone()
    }
}

/// BlockReady blocks readiness until it is dropped.
pub struct BlockReady {
    parent: Ready,
    name: String,
}

impl BlockReady {
    pub fn subtask(&self, name: &str) -> BlockReady {
        self.parent.register_task(name)
    }

    /// Atomically replaces this readiness blocker with another blocker.
    pub(crate) fn replace_with(mut self, name: &str) -> BlockReady {
        let new_name = name.to_string();

        let mut pending = self.parent.0.lock().unwrap();
        let removed = pending.remove(&self.name);
        debug_assert!(removed); // It is a bug to somehow remove something twice
        pending.insert(new_name.clone());
        drop(pending);

        self.name = new_name;
        self
    }
}

impl Drop for BlockReady {
    fn drop(&mut self) {
        let mut pending = self.parent.0.lock().unwrap();
        let removed = pending.remove(&self.name);
        debug_assert!(removed); // It is a bug to somehow remove something twice
        let left = pending.len();
        let dur = telemetry::APPLICATION_START_TIME.elapsed();
        if left == 0 {
            info!(
                "Task '{}' complete ({dur:?}), marking server ready",
                self.name
            );
        } else {
            info!(
                "Task '{}' complete ({dur:?}), still awaiting {left} tasks",
                self.name
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacing_task_holds_replacement_until_replacement_is_dropped() {
        let ready = Ready::new();
        let task = ready.register_task("state manager");

        let replacement = task.replace_with("xds monitor dead");

        let pending = ready.pending();
        assert!(
            !pending.contains("state manager"),
            "old readiness blocker should be removed by replacement"
        );
        assert!(
            pending.contains("xds monitor dead"),
            "replacement readiness blocker should remain registered"
        );

        drop(replacement);
        assert!(
            ready.pending().is_empty(),
            "replacement blocker should drop normally"
        );
    }

    #[test]
    fn replacing_task_does_not_leak_original_guard_fields() {
        let ready = Ready::new();
        let task = ready.register_task("state manager");
        assert_eq!(std::sync::Arc::strong_count(&ready.0), 2);

        let replacement = task.replace_with("xds monitor dead");

        assert_eq!(
            std::sync::Arc::strong_count(&ready.0),
            2,
            "replacement should transfer the original guard without leaking its Ready clone"
        );

        drop(replacement);
        assert_eq!(std::sync::Arc::strong_count(&ready.0), 1);
    }
}
