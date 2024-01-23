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

    /// drain drops the internal reference to rx and then signals drain on the tx
    // always inline, this is for convenience so that we don't forget do drop the rx but there's really no reason it needs to grow the stack
    #[inline(always)]
    async fn drain(self) {
        drop(self.rx); // very important, drain cannont complete if there are outstand rx
        self.tx.drain().await;
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
        // consider removing this whole if let since if it's None we need to perform another get inside the write lock to prevnt racy inserts
        if let Some(cd) = self.drains.read().await.get(c) {
            return cd.rx.clone();
        }
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

    pub async fn close(&self, c: &Connection) {
        if let Some(cd) = self.drains.clone().write().await.remove(c) {
            cd.drain().await;
        } else {
            // this is bad, possibly drain called twice
            error!("requested drain on a Connection which wasn't initialized");
        }
    }

    pub async fn connections(&self) -> Vec<Connection> {
        // potentially large copy under read lock, could require optomization
        self.drains.read().await.keys().cloned().collect()
    }

    #[allow(dead_code)]
    pub async fn drain_all(self) {
        let mut drains = self.drains.write_owned().await;
        for (_conn, cd) in drains.drain() {
            cd.drain().await;
        }
    }
}

#[cfg(test)]
mod test {
    use drain::Watch;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::time::Duration;

    use super::ConnectionManager;
    use crate::rbac::Connection;

    #[tokio::test]
    async fn test_connection_manager() {
        // setup a new ConnectionManager
        let connection_manager = ConnectionManager::new();
        // ensure drains is empty
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);

        // track a new connection
        let conn1 = Connection {
            src_identity: None,
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            dst_network: "".to_string(),
            dst: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 2), 8080)),
        };
        let close1 = connection_manager.clone().track(&conn1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(connection_manager.connections().await, vec!(conn1.clone()));

        // setup a second track on the same connection
        let another_conn1 = conn1.clone();
        let another_close1 = connection_manager.clone().track(&another_conn1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(connection_manager.connections().await, vec!(conn1.clone()));

        // track a second connection
        let conn2 = Connection {
            src_identity: None,
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3)),
            dst_network: "".to_string(),
            dst: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 2), 8080)),
        };
        let close2 = connection_manager.clone().track(&conn2).await;
        // ensure drains contains exactly 2 items
        assert_eq!(connection_manager.drains.read().await.len(), 2);
        assert_eq!(connection_manager.connections().await.len(), 2);
        let mut connections = connection_manager.connections().await;
        connections.sort(); // ordering cannot be guaranteed without sorting
        assert_eq!(connections, vec![conn1.clone(), conn2.clone()]);

        // spawn tasks to assert that we close in a timely manner for conn1
        tokio::spawn(async_close_assert(close1));
        tokio::spawn(async_close_assert(another_close1));
        // close conn1
        connection_manager.close(&conn1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(connection_manager.connections().await, vec!(conn2.clone()));

        // spawn a task to assert that we close in a timely manner for conn2
        tokio::spawn(async_close_assert(close2));
        // close conn2
        connection_manager.close(&conn2).await;
        // assert that drains is empty again
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);
    }

    // small helper to assert that the Watches are working in a timely manner
    async fn async_close_assert(c: Watch) {
        let result = tokio::time::timeout(Duration::from_secs(1), c.signaled()).await;
        assert!(result.is_ok());
    }
}
