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

use crate::identity::Identity;
use crate::proxy::error;
use crate::state::DemandProxyState;
use crate::state::ProxyRbacContext;
use drain;
use http_types::convert::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Clone, Copy, Hash, Debug, Eq, PartialEq)]
pub struct ConnectionTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionMetadata {
    #[serde(default)]
    identity: Option<Identity>,
}

struct ConnectionDrain {
    // TODO: this should almost certainly be changed to a type which has counted references exposed.
    // tokio::sync::watch can be subscribed without taking a write lock and exposes references
    // and also a receiver_count method
    tx: drain::Signal,
    rx: drain::Watch,
    count: usize,
}

impl ConnectionDrain {
    fn new() -> Self {
        let (tx, rx) = drain::channel();
        ConnectionDrain { tx, rx, count: 0 }
    }

    /// drain drops the internal reference to rx and then signals drain on the tx
    // always inline, this is for convenience so that we don't forget to drop the rx but there's really no reason it needs to grow the stack
    #[inline(always)]
    async fn drain(self) {
        drop(self.rx); // very important, drain cannont complete if there are outstand rx
        self.tx.drain().await;
    }
}

#[derive(Clone)]
pub struct ConnectionManager {
    drains: Arc<RwLock<HashMap<ProxyRbacContext, ConnectionDrain>>>,
}

impl std::default::Default for ConnectionManager {
    fn default() -> Self {
        ConnectionManager {
            drains: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl ConnectionManager {
    // register a connection with the connection manager
    // this must be done before a connection can be tracked
    // allows policy to be asserted against the connection
    // even no tasks have a receiver channel yet
    pub async fn register(&self, c: &ProxyRbacContext) {
        self.drains
            .write()
            .await
            .entry(c.clone())
            .or_insert(ConnectionDrain::new());
    }

    // get a channel to receive close on for your connection
    // requires that the connection be registered first
    // if you receive None this connection is invalid and should close
    pub async fn track(&self, c: &ProxyRbacContext) -> Option<drain::Watch> {
        match self
            .drains
            .write()
            .await
            .entry(c.to_owned())
            .and_modify(|cd| cd.count += 1)
        {
            std::collections::hash_map::Entry::Occupied(cd) => {
                let rx = cd.get().rx.clone();
                Some(rx)
            }
            std::collections::hash_map::Entry::Vacant(_) => None,
        }
    }

    // releases tracking on a connection
    // uses a counter to determine if there are other tracked connections or not so it may retain the tx/rx channels when necessary
    pub async fn release(&self, c: &ProxyRbacContext) {
        let mut drains = self.drains.write().await;
        if let Some((k, mut v)) = drains.remove_entry(c) {
            if v.count > 1 {
                // something else is tracking this connection, decrement count but retain
                v.count -= 1;
                drains.insert(k, v);
            }
        }
    }

    // signal all connections listening to this channel to take action (typically terminate traffic)
    async fn close(&self, c: &ProxyRbacContext) {
        if let Some(cd) = self.drains.write().await.remove(c) {
            cd.drain().await;
        } else {
            // this is bad, possibly drain called twice
            error!("requested drain on a Connection which wasn't initialized");
        }
    }

    //  get a list of all connections being tracked
    async fn connections(&self) -> Vec<ProxyRbacContext> {
        // potentially large copy under read lock, could require optomization
        self.drains.read().await.keys().cloned().collect()
    }

    /// fetch looks up a tuple and returns the connection metadata
    // TODO: we should key on tuple so we can more efficiently lookup
    pub async fn fetch(&self, ctu: &ConnectionTuple) -> Option<ConnectionMetadata> {
        let cm = self.drains.read().await;
        cm.iter()
            .map(|(c, _)| &c.conn)
            // TODO: we are ignoring source port here
            .find(|c| ctu.dst == c.dst && ctu.src.ip() == c.src_ip)
            .map(|c| ConnectionMetadata {
                identity: c.src_identity.clone(),
            })
    }
}

pub struct PolicyWatcher {
    state: DemandProxyState,
    stop: drain::Watch,
    connection_manager: ConnectionManager,
}

impl PolicyWatcher {
    pub fn new(
        state: DemandProxyState,
        stop: drain::Watch,
        connection_manager: ConnectionManager,
    ) -> Self {
        PolicyWatcher {
            state,
            stop,
            connection_manager,
        }
    }

    pub async fn run(self) {
        let mut policies_changed = self.state.read().policies.subscribe();
        loop {
            tokio::select! {
                _ = self.stop.clone().signaled() => {
                    break;
                }
                _ = policies_changed.changed() => {
                    let connections = self.connection_manager.connections().await;
                    for conn in connections {
                        if !self.state.assert_rbac(&conn).await {
                            self.connection_manager.close(&conn).await;
                            info!("connection {conn} closed because it's no longer allowed after a policy update");
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use drain::Watch;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    use crate::rbac::Connection;
    use crate::state::{DemandProxyState, ProxyState};
    use crate::xds::istio::security::{Action, Authorization, Scope};
    use crate::xds::ProxyStateUpdateMutator;

    use super::{ConnectionManager, PolicyWatcher};

    #[tokio::test]
    async fn test_connection_manager_close() {
        // setup a new ConnectionManager
        let connection_manager = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);

        // track a new connection
        let rbac_ctx1 = crate::state::ProxyRbacContext {
            conn: Connection {
                src_identity: None,
                src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                dst_network: "".to_string(),
                dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 2),
                    8080,
                )),
            },
            dest_workload_info: None,
        };

        // assert that tracking an unregistered connection is None
        let close1 = connection_manager.track(&rbac_ctx1).await;
        assert!(close1.is_none());
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);

        connection_manager.register(&rbac_ctx1).await;
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(
            connection_manager.connections().await,
            vec!(rbac_ctx1.clone())
        );

        let close1 = connection_manager
            .track(&rbac_ctx1)
            .await
            .expect("should not be None");

        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(
            connection_manager.connections().await,
            vec!(rbac_ctx1.clone())
        );

        // setup a second track on the same connection
        let another_conn1 = rbac_ctx1.clone();
        let another_close1 = connection_manager
            .track(&another_conn1)
            .await
            .expect("should not be None");

        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(
            connection_manager.connections().await,
            vec!(rbac_ctx1.clone())
        );

        // track a second connection
        let rbac_ctx2 = crate::state::ProxyRbacContext {
            conn: Connection {
                src_identity: None,
                src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3)),
                dst_network: "".to_string(),
                dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 2),
                    8080,
                )),
            },
            dest_workload_info: None,
        };

        connection_manager.register(&rbac_ctx2).await;
        let close2 = connection_manager
            .track(&rbac_ctx2)
            .await
            .expect("should not be None");

        // ensure drains contains exactly 2 items
        assert_eq!(connection_manager.drains.read().await.len(), 2);
        assert_eq!(connection_manager.connections().await.len(), 2);
        let mut connections = connection_manager.connections().await;
        connections.sort(); // ordering cannot be guaranteed without sorting
        assert_eq!(connections, vec![rbac_ctx1.clone(), rbac_ctx2.clone()]);

        // spawn tasks to assert that we close in a timely manner for rbac_ctx1
        tokio::spawn(assert_close(close1));
        tokio::spawn(assert_close(another_close1));
        // close rbac_ctx1
        connection_manager.close(&rbac_ctx1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(
            connection_manager.connections().await,
            vec!(rbac_ctx2.clone())
        );

        // spawn a task to assert that we close in a timely manner for rbac_ctx2
        tokio::spawn(assert_close(close2));
        // close rbac_ctx2
        connection_manager.close(&rbac_ctx2).await;
        // assert that drains is empty again
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);
    }

    #[tokio::test]
    async fn test_connection_manager_release() {
        // setup a new ConnectionManager
        let connection_manager = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);

        // create a new connection
        let conn1 = crate::state::ProxyRbacContext {
            conn: Connection {
                src_identity: None,
                src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                dst_network: "".to_string(),
                dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 2),
                    8080,
                )),
            },
            dest_workload_info: None,
        };
        // create a second connection
        let conn2 = crate::state::ProxyRbacContext {
            conn: Connection {
                src_identity: None,
                src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 3)),
                dst_network: "".to_string(),
                dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 2),
                    8080,
                )),
            },
            dest_workload_info: None,
        };
        let another_conn1 = conn1.clone();

        connection_manager.register(&conn1).await;

        // watch the connections
        let close1 = connection_manager
            .track(&conn1)
            .await
            .expect("should not be None");
        let another_close1 = connection_manager
            .track(&another_conn1)
            .await
            .expect("should not be None");
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(connection_manager.connections().await, vec!(conn1.clone()));

        // release conn1's clone
        drop(another_close1);
        connection_manager.release(&another_conn1).await;
        // ensure drains still contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(connection_manager.connections().await, vec!(conn1.clone()));

        connection_manager.register(&conn2).await;
        // track conn2
        let close2 = connection_manager
            .track(&conn2)
            .await
            .expect("should not be None");
        // ensure drains contains exactly 2 items
        assert_eq!(connection_manager.drains.read().await.len(), 2);
        assert_eq!(connection_manager.connections().await.len(), 2);
        let mut connections = connection_manager.connections().await;
        connections.sort(); // ordering cannot be guaranteed without sorting
        assert_eq!(connections, vec![conn1.clone(), conn2.clone()]);

        // release conn1
        drop(close1);
        connection_manager.release(&conn1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(connection_manager.connections().await, vec!(conn2.clone()));

        // clone conn2 and track it
        let another_conn2 = conn2.clone();
        let another_close2 = connection_manager
            .track(&another_conn2)
            .await
            .expect("should not be None");
        drop(close2);
        // release tracking on conn2
        connection_manager.release(&conn2).await;
        // ensure drains still contains exactly 1 item
        assert_eq!(connection_manager.drains.read().await.len(), 1);
        assert_eq!(connection_manager.connections().await.len(), 1);
        assert_eq!(
            connection_manager.connections().await,
            vec!(another_conn2.clone())
        );

        // release tracking on conn2's clone
        drop(another_close2);
        connection_manager.release(&another_conn2).await;
        // ensure drains contains exactly 0 items
        assert_eq!(connection_manager.drains.read().await.len(), 0);
        assert_eq!(connection_manager.connections().await.len(), 0);
    }

    #[tokio::test]
    async fn test_policy_watcher_lifecycle() {
        // preamble: setup an environment
        let state = Arc::new(RwLock::new(ProxyState::default()));
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        let connection_manager = ConnectionManager::default();
        let (tx, stop) = drain::channel();
        let state_mutator = ProxyStateUpdateMutator::new_no_fetch();

        // clones to move into spawned task
        let ds = dstate.clone();
        let cm = connection_manager.clone();
        let pw = PolicyWatcher::new(ds, stop, cm);
        // spawn a task which watches policy and asserts that the policy watcher stop correctly
        tokio::spawn(async move {
            let res = tokio::time::timeout(Duration::from_secs(1), pw.run()).await;
            assert!(res.is_ok())
        });

        // create a test connection
        let conn1 = crate::state::ProxyRbacContext {
            conn: Connection {
                src_identity: None,
                src_ip: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
                dst_network: "".to_string(),
                dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::new(192, 168, 0, 2),
                    8080,
                )),
            },
            dest_workload_info: None,
        };
        // watch the connection
        connection_manager.register(&conn1).await;
        let close1 = connection_manager
            .track(&conn1)
            .await
            .expect("should not be None");

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

        // this block will scope our guard appropriately
        {
            // update our state
            let mut s = state
                .write()
                .expect("test fails if we're unable to get a write lock on state");
            let res = state_mutator.insert_authorization(&mut s, auth);
            // assert that the update was OK
            assert!(res.is_ok());
        } // release lock

        // send the signal which stops policy watcher
        tx.drain().await;
    }

    // small helper to assert that the Watches are working in a timely manner
    async fn assert_close(c: Watch) {
        let result = tokio::time::timeout(Duration::from_secs(1), c.signaled()).await;
        assert!(result.is_ok())
    }
}
