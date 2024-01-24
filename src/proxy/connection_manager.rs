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
use crate::state::DemandProxyState;
use drain;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::watch;
use tokio::sync::RwLock;
use tracing::info;

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
}

pub async fn policy_watcher(
    state: DemandProxyState,
    mut stop_rx: watch::Receiver<()>,
    connection_manager: ConnectionManager,
    parent_proxy: &str,
) {
    let mut policies_changed = state.read().policies.subscribe();
    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                break;
            }
            _ = policies_changed.changed() => {
                let connections = connection_manager.connections().await;
                for conn in connections {
                    if !state.assert_rbac(&conn).await {
                        connection_manager.close(&conn).await;
                        info!("{parent_proxy} connection {conn} closed because it's no longer allowed after a policy update");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use drain::Watch;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;
    use tokio::sync::watch;
    use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

    use crate::rbac::Connection;
    use crate::state::{DemandProxyState, ProxyState};
    use crate::xds::istio::security::{Action, Authorization, Scope};
    use crate::xds::ProxyStateUpdateMutator;

    use super::ConnectionManager;

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
        tokio::spawn(assert_close(close1));
        tokio::spawn(assert_close(another_close1));
        // close conn1
        connection_manager.close(&conn1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(connection_manager.connections().await, vec!(conn2.clone()));

        // spawn a task to assert that we close in a timely manner for conn2
        tokio::spawn(assert_close(close2));
        // close conn2
        connection_manager.close(&conn2).await;
        // assert that drains is empty again
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);
    }

    #[tokio::test]
    async fn test_policy_watcher_closes() {
        // preamble: setup an environment
        let state = Arc::new(RwLock::new(ProxyState::default()));
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        let connection_manager = ConnectionManager::new();
        let parent_proxy = "test";
        let (stop_tx, stop_rx) = watch::channel(());
        let state_mutator = ProxyStateUpdateMutator::new_no_fetch();

        // clones to move into spawned task
        let ds = dstate.clone();
        let cm = connection_manager.clone();
        // spawn a task which watches policy and asserts that the policy watcher stop correctly
        tokio::spawn(async move {
            let res = tokio::time::timeout(
                Duration::from_secs(1),
                super::policy_watcher(ds, stop_rx, cm, parent_proxy),
            )
            .await;
            assert!(res.is_ok())
        });

        // create a test connection
        let conn1 = Connection {
            src_identity: None,
            src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            dst_network: "".to_string(),
            dst: std::net::SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 2), 8080)),
        };
        // watch the connection
        let close1 = connection_manager.clone().track(&conn1).await;

        // generate policy which denies everything
        let auth = Authorization {
            name: "allow-nothing".to_string(),
            action: Action::Deny as i32,
            scope: Scope::Global as i32,
            namespace: "default".to_string(),
            rules: vec![],
        };

        // spawn an assertion that our connection close is received
        tokio::spawn(assert_close(close1));

        // update our state
        let mut s = state
            .write()
            .expect("test fails if we're unable to get a write lock on state");
        let res = state_mutator.insert_authorization(&mut s, auth);
        // assert that the update was OK
        assert!(res.is_ok());
        // release lock
        drop(s);

        // send the signal which stops policy watcher
        stop_tx.send_replace(());
    }

    // small helper to assert that the Watches are working in a timely manner
    async fn assert_close(c: Watch) {
        let result = tokio::time::timeout(Duration::from_secs(1), c.signaled()).await;
        assert!(result.is_ok())
    }
}
