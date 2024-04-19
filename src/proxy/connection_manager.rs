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

use crate::proxy::{error, Error};

use crate::state::DemandProxyState;
use crate::state::ProxyRbacContext;
use drain;
use serde::{Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::fmt::Formatter;
use std::future::Future;
use std::net::SocketAddr;

use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, info};

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
    drains: Arc<RwLock<HashMap<InboundConnection, ConnectionDrain>>>,
    outbound_connections: Arc<RwLock<HashSet<OutboundConnection>>>,
}

impl std::fmt::Debug for ConnectionManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionManager").finish()
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        ConnectionManager {
            drains: Arc::new(RwLock::new(HashMap::new())),
            outbound_connections: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

pub struct ConnectionGuard {
    cm: ConnectionManager,
    conn: InboundConnection,
    watch: Option<drain::Watch>,
}

impl ConnectionGuard {
    pub async fn handle_connection(
        mut self,
        send: impl Future<Output = Result<(u64, u64), Error>> + Sized,
    ) -> Result<(u64, u64), Error> {
        let watch = self.watch.take().expect("watch cannot be taken twice");
        tokio::select! {
            res = send => {
                self.cm.release(&self.conn);
                res
            }
            _signaled = watch.signaled() => Err(Error::AuthorizationPolicyLateRejection)
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if self.watch.is_some() {
            debug!("rbac context {:?} auto-dropped", &self.conn);
            self.cm.release(&self.conn)
        }
    }
}

pub struct OutboundConnectionGuard {
    cm: ConnectionManager,
    conn: OutboundConnection,
}

impl Drop for OutboundConnectionGuard {
    fn drop(&mut self) {
        self.cm.release_outbound(&self.conn)
    }
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutboundConnection {
    pub src: SocketAddr,
    pub original_dst: SocketAddr,
    pub actual_dst: SocketAddr,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConnectionDump {
    pub src: SocketAddr,
    pub original_dst: Option<String>,
    pub actual_dst: SocketAddr,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConnection {
    #[serde(flatten)]
    pub ctx: ProxyRbacContext,
    pub dest_service: Option<String>,
}

impl ConnectionManager {
    pub fn track_outbound(
        &self,
        src: SocketAddr,
        original_dst: SocketAddr,
        actual_dst: SocketAddr,
    ) -> OutboundConnectionGuard {
        let c = OutboundConnection {
            src,
            original_dst,
            actual_dst,
        };

        self.outbound_connections
            .write()
            .expect("mutex")
            .insert(c.clone());

        OutboundConnectionGuard {
            cm: self.clone(),
            conn: c,
        }
    }

    pub async fn assert_rbac(
        &self,
        state: &DemandProxyState,
        ctx: &ProxyRbacContext,
        dest_service: Option<String>,
    ) -> Result<ConnectionGuard, Error> {
        // Register before our initial assert. This prevents a race if policy changes between assert() and
        // track()
        let conn = InboundConnection {
            ctx: ctx.clone(),
            dest_service,
        };
        self.register(&conn);
        if !state.assert_rbac(ctx).await {
            return Err(Error::AuthorizationPolicyRejection);
        }
        let Some(watch) = self.track(&conn) else {
            return Err(Error::AuthorizationPolicyRejection);
        };
        Ok(ConnectionGuard {
            cm: self.clone(),
            conn,
            watch: Some(watch),
        })
    }
    // register a connection with the connection manager
    // this must be done before a connection can be tracked
    // allows policy to be asserted against the connection
    // even no tasks have a receiver channel yet
    fn register(&self, c: &InboundConnection) {
        self.drains
            .write()
            .expect("mutex")
            .entry(c.clone())
            .or_insert(ConnectionDrain::new());
    }

    // get a channel to receive close on for your connection
    // requires that the connection be registered first
    // if you receive None this connection is invalid and should close
    fn track(&self, c: &InboundConnection) -> Option<drain::Watch> {
        match self
            .drains
            .write()
            .expect("mutex")
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
    fn release(&self, c: &InboundConnection) {
        let mut drains = self.drains.write().expect("mutex");
        if let Some((k, mut v)) = drains.remove_entry(c) {
            if v.count > 1 {
                // something else is tracking this connection, decrement count but retain
                v.count -= 1;
                drains.insert(k, v);
            }
        }
    }

    fn release_outbound(&self, c: &OutboundConnection) {
        self.outbound_connections.write().expect("mutex").remove(c);
    }

    // signal all connections listening to this channel to take action (typically terminate traffic)
    async fn close(&self, c: &InboundConnection) {
        let drain = { self.drains.write().expect("mutex").remove(c) };
        if let Some(cd) = drain {
            cd.drain().await;
        } else {
            // this is bad, possibly drain called twice
            error!("requested drain on a Connection which wasn't initialized");
        }
    }

    //  get a list of all connections being tracked
    pub fn connections(&self) -> Vec<InboundConnection> {
        // potentially large copy under read lock, could require optimization
        self.drains.read().expect("mutex").keys().cloned().collect()
    }
}

#[derive(serde::Serialize)]
struct ConnectionManagerDump {
    inbound: Vec<InboundConnectionDump>,
    outbound: Vec<OutboundConnection>,
}

impl Serialize for ConnectionManager {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let inbound: Vec<_> = self
            .drains
            .read()
            .expect("mutex")
            .keys()
            .cloned()
            .map(|c| InboundConnectionDump {
                src: c.ctx.conn.src,
                original_dst: c.dest_service,
                actual_dst: c.ctx.conn.dst,
            })
            .collect();
        let outbound: Vec<_> = self
            .outbound_connections
            .read()
            .expect("mutex")
            .iter()
            .cloned()
            .collect();
        let dump = ConnectionManagerDump { inbound, outbound };
        dump.serialize(serializer)
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
                    let connections = self.connection_manager.connections();
                    for conn in connections {
                        if !self.state.assert_rbac(&conn.ctx).await {
                            self.connection_manager.close(&conn).await;
                            info!("connection {} closed because it's no longer allowed after a policy update", conn.ctx);
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

    use super::{ConnectionManager, InboundConnection, PolicyWatcher};

    #[tokio::test]
    async fn test_connection_manager_close() {
        // setup a new ConnectionManager
        let connection_manager = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(connection_manager.drains.read().unwrap().len(), 0);
        assert_eq!(connection_manager.connections().len(), 0);

        // track a new connection
        let rbac_ctx1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".to_string(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload_info: None,
            },
            dest_service: None,
        };

        // assert that tracking an unregistered connection is None
        let close1 = connection_manager.track(&rbac_ctx1);
        assert!(close1.is_none());
        assert_eq!(connection_manager.drains.read().unwrap().len(), 0);
        assert_eq!(connection_manager.connections().len(), 0);

        connection_manager.register(&rbac_ctx1);
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(connection_manager.connections(), vec!(rbac_ctx1.clone()));

        let close1 = connection_manager
            .track(&rbac_ctx1)
            .expect("should not be None");

        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(connection_manager.connections(), vec!(rbac_ctx1.clone()));

        // setup a second track on the same connection
        let another_conn1 = rbac_ctx1.clone();
        let another_close1 = connection_manager
            .track(&another_conn1)
            .expect("should not be None");

        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(connection_manager.connections(), vec!(rbac_ctx1.clone()));

        // track a second connection
        let rbac_ctx2 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 3).into(),
                        80,
                    ),
                    dst_network: "".to_string(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload_info: None,
            },
            dest_service: None,
        };

        connection_manager.register(&rbac_ctx2);
        let close2 = connection_manager
            .track(&rbac_ctx2)
            .expect("should not be None");

        // ensure drains contains exactly 2 items
        assert_eq!(connection_manager.drains.read().unwrap().len(), 2);
        assert_eq!(connection_manager.connections().len(), 2);
        let mut connections = connection_manager.connections();
        connections.sort(); // ordering cannot be guaranteed without sorting
        assert_eq!(connections, vec![rbac_ctx1.clone(), rbac_ctx2.clone()]);

        // spawn tasks to assert that we close in a timely manner for rbac_ctx1
        tokio::spawn(assert_close(close1));
        tokio::spawn(assert_close(another_close1));
        // close rbac_ctx1
        connection_manager.close(&rbac_ctx1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(connection_manager.connections(), vec!(rbac_ctx2.clone()));

        // spawn a task to assert that we close in a timely manner for rbac_ctx2
        tokio::spawn(assert_close(close2));
        // close rbac_ctx2
        connection_manager.close(&rbac_ctx2).await;
        // assert that drains is empty again
        assert_eq!(connection_manager.drains.read().unwrap().len(), 0);
        assert_eq!(connection_manager.connections().len(), 0);
    }

    #[tokio::test]
    async fn test_connection_manager_release() {
        // setup a new ConnectionManager
        let connection_manager = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(connection_manager.drains.read().unwrap().len(), 0);
        assert_eq!(connection_manager.connections().len(), 0);

        // create a new connection
        let conn1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".to_string(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload_info: None,
            },
            dest_service: None,
        };

        // create a second connection
        let conn2 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 3).into(),
                        80,
                    ),
                    dst_network: "".to_string(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload_info: None,
            },
            dest_service: None,
        };
        let another_conn1 = conn1.clone();

        connection_manager.register(&conn1);

        // watch the connections
        let close1 = connection_manager
            .track(&conn1)
            .expect("should not be None");
        let another_close1 = connection_manager
            .track(&another_conn1)
            .expect("should not be None");
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(connection_manager.connections(), vec!(conn1.clone()));

        // release conn1's clone
        drop(another_close1);
        connection_manager.release(&another_conn1);
        // ensure drains still contains exactly 1 item
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(connection_manager.connections(), vec!(conn1.clone()));

        connection_manager.register(&conn2);
        // track conn2
        let close2 = connection_manager
            .track(&conn2)
            .expect("should not be None");
        // ensure drains contains exactly 2 items
        assert_eq!(connection_manager.drains.read().unwrap().len(), 2);
        assert_eq!(connection_manager.connections().len(), 2);
        let mut connections = connection_manager.connections();
        connections.sort(); // ordering cannot be guaranteed without sorting
        assert_eq!(connections, vec![conn1.clone(), conn2.clone()]);

        // release conn1
        drop(close1);
        connection_manager.release(&conn1);
        // ensure drains contains exactly 1 item
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(connection_manager.connections(), vec!(conn2.clone()));

        // clone conn2 and track it
        let another_conn2 = conn2.clone();
        let another_close2 = connection_manager
            .track(&another_conn2)
            .expect("should not be None");
        drop(close2);
        // release tracking on conn2
        connection_manager.release(&conn2);
        // ensure drains still contains exactly 1 item
        assert_eq!(connection_manager.drains.read().unwrap().len(), 1);
        assert_eq!(connection_manager.connections().len(), 1);
        assert_eq!(
            connection_manager.connections(),
            vec!(another_conn2.clone())
        );

        // release tracking on conn2's clone
        drop(another_close2);
        connection_manager.release(&another_conn2);
        // ensure drains contains exactly 0 items
        assert_eq!(connection_manager.drains.read().unwrap().len(), 0);
        assert_eq!(connection_manager.connections().len(), 0);
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
        let conn1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".to_string(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload_info: None,
            },
            dest_service: None,
        };
        // watch the connection
        connection_manager.register(&conn1);
        let close1 = connection_manager
            .track(&conn1)
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
