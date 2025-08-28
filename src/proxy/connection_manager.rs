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

use crate::proxy::Error;

use crate::state::DemandProxyState;
use crate::state::ProxyRbacContext;
use serde::{Serialize, Serializer};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::Formatter;
use std::net::SocketAddr;

use crate::drain;
use crate::drain::{DrainTrigger, DrainWatcher};
use crate::state::workload::{InboundProtocol, OutboundProtocol};
use std::sync::Arc;
use std::sync::RwLock;
use tracing::{debug, error, info, warn};

struct ConnectionDrain {
    // TODO: this should almost certainly be changed to a type which has counted references exposed.
    // tokio::sync::watch can be subscribed without taking a write lock and exposes references
    // and also a receiver_count method
    tx: DrainTrigger,
    rx: DrainWatcher,
    count: usize,
}

impl ConnectionDrain {
    fn new() -> Self {
        let (tx, rx) = drain::new();
        ConnectionDrain { tx, rx, count: 1 }
    }

    /// drain drops the internal reference to rx and then signals drain on the tx
    // always inline, this is for convenience so that we don't forget to drop the rx but there's really no reason it needs to grow the stack
    #[inline(always)]
    async fn drain(self) {
        drop(self.rx); // very important, drain cannot complete if there are outstand rx
        self.tx
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
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
    watch: Option<DrainWatcher>,
}

// For reasons that I don't fully understand, this uses an obscene amount of stack space when written as a normal function,
// amounting to ~1kb overhead per connection.
// Inlining it removes this entirely, and the macro ensures we do it consistently across the various areas we use it.
#[macro_export]
macro_rules! handle_connection {
    ($connguard:expr, $future:expr) => {{
        let watch = $connguard.watcher();
        tokio::select! {
            res = $future => {
                $connguard.release();
                res
            }
            _signaled = watch.wait_for_drain() => Err(Error::AuthorizationPolicyLateRejection)
        }
    }};
}

impl ConnectionGuard {
    pub fn watcher(&mut self) -> drain::DrainWatcher {
        self.watch.take().expect("watch cannot be taken twice")
    }
    pub fn release(self) {
        self.cm.release(&self.conn);
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
    pub protocol: OutboundProtocol,
}

#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundConnectionDump {
    pub src: SocketAddr,
    pub original_dst: Option<String>,
    pub actual_dst: SocketAddr,
    pub protocol: InboundProtocol,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, serde::Serialize)]
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
        protocol: OutboundProtocol,
    ) -> OutboundConnectionGuard {
        let c = OutboundConnection {
            src,
            original_dst,
            actual_dst,
            protocol,
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
        let Some(watch) = self.register(&conn) else {
            warn!("failed to track {conn:?}");
            debug_assert!(false, "failed to track {conn:?}");
            return Err(Error::ConnectionTrackingFailed);
        };
        if let Err(err) = state.assert_rbac(ctx).await {
            self.release(&conn);
            return Err(Error::AuthorizationPolicyRejection(err));
        }
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
    fn register(&self, c: &InboundConnection) -> Option<DrainWatcher> {
        match self.drains.write().expect("mutex").entry(c.clone()) {
            Entry::Occupied(mut cd) => {
                cd.get_mut().count += 1;
                let rx = cd.get().rx.clone();
                Some(rx)
            }
            Entry::Vacant(entry) => {
                let drain = ConnectionDrain::new();
                let rx = drain.rx.clone();
                entry.insert(drain);
                Some(rx)
            }
        }
    }

    // releases tracking on a connection
    // uses a counter to determine if there are other tracked connections or not so it may retain the tx/rx channels when necessary
    pub fn release(&self, c: &InboundConnection) {
        let mut drains = self.drains.write().expect("mutex");
        if let Some((k, mut v)) = drains.remove_entry(c)
            && v.count > 1
        {
            // something else is tracking this connection, decrement count but retain
            v.count -= 1;
            drains.insert(k, v);
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
                protocol: if c.ctx.conn.src_identity.is_some() {
                    InboundProtocol::HBONE
                } else {
                    InboundProtocol::TCP
                },
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
    stop: DrainWatcher,
    connection_manager: ConnectionManager,
}

impl PolicyWatcher {
    pub fn new(
        state: DemandProxyState,
        stop: DrainWatcher,
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
                _ = self.stop.clone().wait_for_drain() => {
                    break;
                }
                _ = policies_changed.changed() => {
                    let connections = self.connection_manager.connections();
                    for conn in connections {
                        if self.state.assert_rbac(&conn.ctx).await.is_err() {
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
    use crate::drain;
    use crate::drain::DrainWatcher;
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use prometheus_client::registry::Registry;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    use crate::rbac::Connection;
    use crate::state::{DemandProxyState, ProxyState};
    use crate::test_helpers::test_default_workload;
    use crate::xds::ProxyStateUpdateMutator;
    use crate::xds::istio::security::{Action, Authorization, Scope};

    use super::{ConnectionGuard, ConnectionManager, InboundConnection, PolicyWatcher};

    #[tokio::test]
    async fn test_connection_manager_close() {
        // setup a new ConnectionManager
        let cm = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);

        let register = |cm: &ConnectionManager, c: &InboundConnection| {
            let cm = cm.clone();
            let c = c.clone();

            let watch = cm.register(&c).unwrap();
            ConnectionGuard {
                cm,
                conn: c,
                watch: Some(watch),
            }
        };

        // track a new connection
        let rbac_ctx1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };

        // ensure drains contains exactly 1 item
        let mut close1 = register(&cm, &rbac_ctx1);
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx1.clone()));

        // setup a second track on the same connection
        let mut another_close1 = register(&cm, &rbac_ctx1);

        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx1.clone()));

        // track a second connection
        let rbac_ctx2 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 3).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };

        let mut close2 = register(&cm, &rbac_ctx2);
        // ensure drains contains exactly 2 items
        assert_eq!(cm.drains.read().unwrap().len(), 2);
        assert_eq!(cm.connections().len(), 2);
        let mut connections = cm.connections();
        // ordering cannot be guaranteed without sorting
        connections.sort_by(|a, b| a.ctx.conn.cmp(&b.ctx.conn));
        assert_eq!(connections, vec![rbac_ctx1.clone(), rbac_ctx2.clone()]);

        // spawn tasks to assert that we close in a timely manner for rbac_ctx1
        tokio::spawn(assert_close(close1.watch.take().unwrap()));
        tokio::spawn(assert_close(another_close1.watch.take().unwrap()));
        // close rbac_ctx1
        cm.close(&rbac_ctx1).await;
        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(rbac_ctx2.clone()));

        // spawn a task to assert that we close in a timely manner for rbac_ctx2
        tokio::spawn(assert_close(close2.watch.take().unwrap()));
        // close rbac_ctx2
        cm.close(&rbac_ctx2).await;
        // assert that drains is empty again
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);
    }

    #[tokio::test]
    async fn test_connection_manager_release() {
        // setup a new ConnectionManager
        let cm = ConnectionManager::default();
        // ensure drains is empty
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);

        let register = |cm: &ConnectionManager, c: &InboundConnection| {
            let cm = cm.clone();
            let c = c.clone();

            let watch = cm.register(&c).unwrap();
            ConnectionGuard {
                cm,
                conn: c,
                watch: Some(watch),
            }
        };

        // create a new connection
        let conn1 = InboundConnection {
            ctx: crate::state::ProxyRbacContext {
                conn: Connection {
                    src_identity: None,
                    src: std::net::SocketAddr::new(
                        std::net::Ipv4Addr::new(192, 168, 0, 1).into(),
                        80,
                    ),
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
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
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };
        let another_conn1 = conn1.clone();

        let close1 = register(&cm, &conn1);
        let another_close1 = register(&cm, &another_conn1);

        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn1.clone()));

        // release conn1's clone
        drop(another_close1);
        // ensure drains still contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn1.clone()));

        let close2 = register(&cm, &conn2);
        // ensure drains contains exactly 2 items
        assert_eq!(cm.drains.read().unwrap().len(), 2);
        assert_eq!(cm.connections().len(), 2);
        let mut connections = cm.connections();
        // ordering cannot be guaranteed without sorting
        connections.sort_by(|a, b| a.ctx.conn.cmp(&b.ctx.conn));
        assert_eq!(connections, vec![conn1.clone(), conn2.clone()]);

        // release conn1
        drop(close1);
        // ensure drains contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(conn2.clone()));

        // clone conn2 and track it
        let another_conn2 = conn2.clone();
        let another_close2 = register(&cm, &another_conn2);
        // release tracking on conn2
        drop(close2);
        // ensure drains still contains exactly 1 item
        assert_eq!(cm.drains.read().unwrap().len(), 1);
        assert_eq!(cm.connections().len(), 1);
        assert_eq!(cm.connections(), vec!(another_conn2.clone()));

        // release tracking on conn2's clone
        drop(another_close2);
        // ensure drains contains exactly 0 items
        assert_eq!(cm.drains.read().unwrap().len(), 0);
        assert_eq!(cm.connections().len(), 0);
    }

    #[tokio::test]
    async fn test_policy_watcher_lifecycle() {
        // preamble: setup an environment
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let dstate = DemandProxyState::new(
            state.clone(),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );
        let connection_manager = ConnectionManager::default();
        let (tx, stop) = drain::new();
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
                    dst_network: "".into(),
                    dst: std::net::SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(192, 168, 0, 2),
                        8080,
                    )),
                },
                dest_workload: Arc::new(test_default_workload()),
            },
            dest_service: None,
        };
        // watch the connection
        let close1 = connection_manager
            .register(&conn1)
            .expect("should not be None");

        // generate policy which denies everything
        let auth_name = "allow-nothing";
        let auth_namespace = "default";
        let auth = Authorization {
            name: auth_name.into(),
            action: Action::Deny as i32,
            scope: Scope::Global as i32,
            namespace: auth_namespace.into(),
            rules: vec![],
        };
        let mut auth_xds_name = String::with_capacity(1 + auth_namespace.len() + auth_name.len());
        auth_xds_name.push_str(auth_namespace);
        auth_xds_name.push('/');
        auth_xds_name.push_str(auth_name);

        // spawn an assertion that our connection close is received
        tokio::spawn(assert_close(close1));

        // this block will scope our guard appropriately
        {
            // update our state
            let mut s = state
                .write()
                .expect("test fails if we're unable to get a write lock on state");
            let res =
                state_mutator.insert_authorization(&mut s, auth_xds_name.clone().into(), auth);
            // assert that the update was OK
            assert!(res.is_ok());
        } // release lock

        // send the signal which stops policy watcher
        tx.start_drain_and_wait(drain::DrainMode::Immediate).await;
    }

    // small helper to assert that the Watches are working in a timely manner
    async fn assert_close(c: DrainWatcher) {
        let result = tokio::time::timeout(Duration::from_secs(1), c.wait_for_drain()).await;
        assert!(result.is_ok())
    }
}
