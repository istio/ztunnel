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

use crate::proxy::error;
use crate::rbac::Connection;
use drain;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct ConnectionDrain {
    tx: drain::Signal,
    rx: drain::Watch,
}

impl ConnectionDrain {
    fn new() -> Self {
        let (tx, rx) = drain::channel();
        ConnectionDrain { tx, rx }
    }
}

#[derive(Clone)]
pub struct ConnectionManager {
    drains: Arc<RwLock<HashMap<Connection, ConnectionDrain>>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        ConnectionManager {
            drains: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn track(self, c: &Connection) -> drain::Watch {
        match self.drains.read().await.get(c) {
            Some(cd) => cd.rx.clone(),
            None => {
                let cd = ConnectionDrain::new();
                let rx = cd.rx.clone();
                //TODO: this was racy, another insert may happen between dropping the read lock and attaining this write lock
                // try_insert is the best solution once it's no longer a nightly-only experimental API
                let mut drains = self.drains.write().await;
                if let Some(w) = drains.get(c) {
                    return w.rx.clone();
                }
                drains.insert(c.clone(), cd);
                rx
            }
        }
    }

    pub async fn drain(&self, c: &Connection) {
        match self.drains.clone().write().await.remove(c) {
            Some(cd) => {
                cd.tx.drain().await;
            }
            None => {
                // this is bad, possibly drain called twice
                error!("requested drain on a Connection which wasn't initialized");
            }
        }
    }

    pub async fn connections(&self) -> Vec<Connection> {
        // potentially large copy under read lock, could require optomization
        self.drains.read().await.keys().cloned().collect()
    }

    pub async fn drain_all(self) {
        let mut drains = self.drains.write_owned().await;
        for (_c, cd) in drains.drain() {
            cd.tx.drain().await;
        }
    }
}
