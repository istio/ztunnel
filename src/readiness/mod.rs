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
            parent: self.clone(),
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
