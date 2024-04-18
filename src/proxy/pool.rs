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

use super::{Error, SocketFactory};
use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper::http::{Request, Response};
use std::time::Duration;

use std::collections::hash_map::DefaultHasher;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, AtomicU16, Ordering};
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task;

use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error};

use crate::config;
use crate::identity::{Identity, SecretManager};

use std::collections::HashMap;

use pingora_pool;

static GLOBAL_CONN_COUNT: AtomicI32 = AtomicI32::new(0);

// A relatively nonstandard HTTP/2 connection pool designed to allow multiplexing proxied workload connections
// over a (smaller) number of HTTP/2 mTLS tunnels.
//
// The following invariants apply to this pool:
// - Every workload (inpod mode) gets its own connpool.
// - Every unique src/dest key gets their own dedicated connections inside the pool.
// - Every unique src/dest key gets 1-n dedicated connections, where N is (currently) unbounded but practically limited
//   by flow control throttling.
#[derive(Clone)]
pub struct WorkloadHBONEPool {
    // this is effectively just a convenience data type - a rwlocked hashmap with keying and LRU drops
    // and has no actual hyper/http/connection logic.
    cfg: config::Config,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    cert_manager: Arc<SecretManager>,
    state: Arc<PoolState>,
    pool_watcher: watch::Receiver<bool>,
    max_streamcount: u16,
}

struct PoolState {
    pool_notifier: watch::Sender<bool>, // This is already impl clone? rustc complains that it isn't, tho
    timeout_tx: watch::Sender<bool>, // This is already impl clone? rustc complains that it isn't, tho
    timeout_rx: watch::Receiver<bool>,
    // this is effectively just a convenience data type - a rwlocked hashmap with keying and LRU drops
    // and has no actual hyper/http/connection logic.
    connected_pool: Arc<pingora_pool::ConnectionPool<ConnClient>>,
    // this must be a readlockable list-of-locks, so we can lock per-key, not globally, and avoid holding up all conn attempts
    established_conn_writelock: RwLock<HashMap<u64, Option<Mutex<()>>>>,
    close_pollers: futures::stream::FuturesUnordered<task::JoinHandle<()>>,
    pool_unused_release_timeout: Duration,
}

impl PoolState {
    // This simply puts the connection back into the inner pool,
    // and sets up a timed popper, which will resolve
    // - when this reference is popped back out of the inner pool (doing nothing)
    // - when this reference is evicted from the inner pool (doing nothing)
    // - when the timeout_idler is drained (will pop)
    // - when the timeout is hit (will pop)
    //
    // Idle poppers are safe to invoke if the conn they are popping is already gone
    // from the inner queue, so we will start one for every insert, let them run or terminate on their own,
    // and poll them to completion on shutdown.
    //
    // Note that "idle" in the context of this pool means "no one has asked for it or dropped it in X time, so prune it".
    //
    // Pruning the idle connection from the pool does not close it - it simply ensures the pool stops holding a ref.
    // hyper self-closes client conns when all refs are dropped and streamcount is 0, so pool consumers must
    // drop their checked out conns and/or terminate their streams as well.
    //
    // Note that this simply removes the client ref from this pool - if other things hold client/streamrefs refs,
    // they must also drop those before the underlying connection is fully closed.
    fn checkin_conn(&self, conn: ConnClient, pool_key: pingora_pool::ConnectionMeta) {
        let (evict, pickup) = self.connected_pool.put(&pool_key, conn);
        let rx = self.timeout_rx.clone();
        let pool_ref = self.connected_pool.clone();
        let pool_key_ref = pool_key.clone();
        let release_timeout = self.pool_unused_release_timeout;
        self.close_pollers.push(tokio::spawn(async move {
            pool_ref
                .idle_timeout(&pool_key_ref, release_timeout, evict, rx, pickup)
                .await;
            debug!(
                "connection {:#?} was removed/checked out/timed out of the pool",
                pool_key_ref
            )
        }));
        let _ = self.pool_notifier.send(true);
    }

    async fn first_checkout_conn_from_pool(
        &self,
        workload_key: &WorkloadKey,
        pool_key: &pingora_pool::ConnectionMeta,
    ) -> Option<ConnClient> {
        debug!("first checkout READLOCK");
        let map_read_lock = self.established_conn_writelock.read().await;
        match map_read_lock.get(&pool_key.key) {
            Some(exist_conn_lock) => {
                debug!("first checkout INNER WRITELOCK");
                let _conn_lock = exist_conn_lock.as_ref().unwrap().lock().await;

                debug!(
                    "getting conn for key {:#?} and hash {:#?}",
                    workload_key, pool_key.key
                );
                self.connected_pool.get(&pool_key.key).and_then(|e_conn| {
                    debug!("got existing conn for key {:#?}", workload_key);
                    if e_conn.at_max_streamcount() {
                        debug!(
                            "got conn for key {:#?}, but streamcount is maxed",
                            workload_key
                        );
                        None
                    } else {
                        self.checkin_conn(e_conn.clone(), pool_key.clone());
                        Some(e_conn)
                    }
                })
            }
            None => None,
        }
    }
}

impl Drop for PoolState {
    fn drop(&mut self) {
        debug!("poolstate dropping, cancelling all outstanding pool eviction timeout spawns");
        let _ = self.timeout_tx.send(true);
    }
}

impl WorkloadHBONEPool {
    // Creates a new pool instance, which should be owned by a single proxied workload.
    // The pool will watch the provided drain signal and drain itself when notified.
    // Callers should then be safe to drop() the pool instance.
    pub fn new(
        cfg: crate::config::Config,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        cert_manager: Arc<SecretManager>,
    ) -> WorkloadHBONEPool {
        let (timeout_tx, timeout_rx) = watch::channel(false);
        let (timeout_send, timeout_recv) = watch::channel(false);
        let max_count = cfg.pool_max_streams_per_conn;
        let pool_duration = cfg.pool_unused_release_timeout;
        debug!("constructing pool with {:#?} streams per conn", max_count);
        Self {
            state: Arc::new(PoolState {
                pool_notifier: timeout_tx,
                timeout_tx: timeout_send,
                timeout_rx: timeout_recv,
                // the number here is simply the number of unique src/dest keys
                // the pool is expected to track before the inner hashmap resizes.
                connected_pool: Arc::new(pingora_pool::ConnectionPool::new(500)),
                established_conn_writelock: RwLock::new(HashMap::new()),
                close_pollers: futures::stream::FuturesUnordered::new(),
                pool_unused_release_timeout: pool_duration,
            }),
            cfg,
            socket_factory,
            cert_manager,
            pool_watcher: timeout_rx,
            max_streamcount: max_count,
        }
    }

    // Obtain a pooled connection. Will prefer to retrieve an existing conn from the pool, but
    // if none exist, or the existing conn is maxed out on streamcount, will spawn a new one,
    // even if it is to the same dest+port.
    //
    // If many `connects` request a connection to the same dest at once, all will wait until exactly
    // one connection is created, before deciding if they should create more or just use that one.
    pub async fn connect(&mut self, workload_key: WorkloadKey) -> Result<ConnClient, Error> {
        debug!("pool connect START");
        // TODO BML this may not be collision resistant/slow. It should be resistant enough for workloads tho.
        let mut s = DefaultHasher::new();
        workload_key.hash(&mut s);
        let hash_key = s.finish();
        let pool_key = pingora_pool::ConnectionMeta::new(
            hash_key,
            GLOBAL_CONN_COUNT.fetch_add(1, Ordering::Relaxed),
        );

        debug!("pool connect GET EXISTING");
        // First, see if we can naively just check out a connection.
        // This should be the common case, except for the first establishment of a new connection/key.
        // This will be done under outer readlock (nonexclusive)/inner keyed writelock (exclusive).
        //
        // It is important that the *initial* check here is authoritative, hence the locks, as
        // we must know if this is a connection for a key *nobody* has tried to start yet,
        // or if other things have already established conns for this key.
        //
        // This is so we can backpressure correctly if 1000 tasks all demand a new connection
        // to the same key at once, and not eagerly open 1000 tunnel connections.
        let existing_conn = self
            .state
            .first_checkout_conn_from_pool(&workload_key, &pool_key)
            .await;

        debug!("pool connect GOT EXISTING");
        if existing_conn.is_some() {
            debug!("using existing conn, connect future will be dropped on the floor");
            Ok(existing_conn.unwrap())
        } else {
            // We couldn't get a conn. This means either nobody has tried to establish any conns for this key yet,
            // or they have, but no conns are currently available
            // (because someone else has checked all of them out and not put any back yet)
            //
            // So, we wil writelock the outer lock to see if an inner lock entry exists for our key.
            //
            // critical block - this writelocks the entire pool for all tasks/threads
            // as we check to see if anyone has ever inserted a sharded mutex for this key.
            //
            // If not, we insert one.
            //
            // We want to hold this for as short as possible a time, and drop it
            // before we hold it over an await.
            //
            // this is is the ONLY block where we should hold a writelock on the whole mutex map
            // for the rest, a readlock (nonexclusive) is sufficient.
            {
                debug!("pool connect MAP OUTER WRITELOCK START");
                let mut map_write_lock = self.state.established_conn_writelock.write().await;
                debug!("pool connect MAP OUTER WRITELOCK END");
                match map_write_lock.get(&hash_key) {
                    Some(_) => {
                        debug!("already have conn for key {:#?}", hash_key);
                    }
                    None => {
                        debug!("inserting conn mutex for key {:#?}", hash_key);
                        map_write_lock.insert(hash_key, Some(Mutex::new(())));
                    }
                };
                drop(map_write_lock); // strictly redundant
            }

            // If we get here, it means the following are true:
            // 1. We have a guaranteed sharded mutex in the outer map for our current key.
            // 2. We can now, under readlock(nonexclusive) in the outer map, attempt to
            // take the inner writelock for our specific key (exclusive).
            //
            // This unblocks other tasks spawning connections against other keys, but blocks other
            // tasks spawning connections against THIS key - which is what we want.

            // NOTE: This inner, key-specific mutex is a tokio::async::Mutex, and not a stdlib sync mutex.
            // these differ from the stdlib sync mutex in that they are (slightly) slower
            // (they effectively sleep the current task) and they can be held over an await.
            // The tokio docs (rightly) advise you to not use these,
            // because holding a lock over an await is a great way to create deadlocks if the await you
            // hold it over does not resolve.
            //
            // HOWEVER. Here we know this connection will either establish or timeout
            // and we WANT other tasks to go back to sleep if there is an outstanding lock.
            // So the downsides are actually useful (we WANT task contention -
            // to block other parallel tasks from trying to spawn a connection if we are already doing so)
            //
            // BEGIN take outer readlock
            debug!("pool connect MAP OUTER READLOCK START");
            let map_read_lock = self.state.established_conn_writelock.read().await;
            debug!("pool connect MAP OUTER READLOCK END");
            let exist_conn_lock = map_read_lock.get(&hash_key).unwrap();
            // BEGIN take inner writelock
            debug!("pool connect MAP INNER WRITELOCK START");
            let found_conn = match exist_conn_lock.as_ref().unwrap().try_lock() {
                Ok(_guard) => {
                    // If we get here, it means the following are true:
                    // 1. We did not get a connection for our key.
                    // 2. We have the exclusive inner writelock to create a new connection for our key.
                    //
                    // So, carry on doing that.
                    debug!("appears we need a new conn, retaining connlock");
                    debug!("nothing else is creating a conn, make one");
                    let pool_conn = self.spawn_new_pool_conn(workload_key.clone()).await;
                    let client = ConnClient{
                        sender: pool_conn?,
                        stream_count: Arc::new(AtomicU16::new(0)),
                        stream_count_max: self.max_streamcount,
                        wl_key: workload_key.clone(),
                    };

                    debug!(
                        "starting new conn for key {:#?} with pk {:#?}",
                        workload_key, pool_key
                    );
                    debug!("dropping lock");
                    Some(client)
                    // END take inner writelock
                }
                Err(_) => {
                    debug!("something else is creating a conn, wait for it");
                    // If we get here, it means the following are true:
                    // 1. At one point, there was a preexisting conn in the pool for this key.
                    // 2. When we checked, we got nothing for that key.
                    // 3. We could not get the exclusive inner writelock to add a new one for this key.
                    // 4. Someone else got the exclusive inner writelock, and is adding a new one for this key.
                    //
                    // So, loop and wait for the pool_watcher to tell us a new conn was enpooled,
                    // so we can pull it out and check it.
                    loop {
                        match self.pool_watcher.changed().await {
                            Ok(_) => {
                                debug!(
                                    "notified a new conn was enpooled, checking for hash {:#?}",
                                    hash_key
                                );
                                // The sharded mutex for this connkey is already locked - someone else must be making a conn
                                // if they are, try to wait for it, but bail if we find one and it's got a maxed streamcount.
                                let existing_conn = self.state.connected_pool.get(&hash_key);
                                match existing_conn {
                                    None => {
                                        debug!("got nothing");
                                        continue;
                                    }
                                    Some(e_conn) => {
                                        debug!("found existing conn after waiting");
                                        // We found a conn, but it's already maxed out.
                                        // Return None and create another.
                                        if e_conn.at_max_streamcount() {
                                            debug!("found existing conn for key {:#?}, but streamcount is maxed", workload_key);
                                            break None;
                                        }
                                        debug!("pool connect LOOP END");
                                        break Some(e_conn);
                                    }
                                }
                            }
                            Err(_) => {
                                // END take outer readlock
                                return Err(Error::WorkloadHBONEPoolDraining);
                            }
                        }
                    }
                }
            };

            // If we get here, it means the following are true:
            // 1. At one point, there was a preexisting conn in the pool for this key.
            // 2. When we checked, we got nothing for that key.
            // 3. We could not get the exclusive inner writelock to add a new one
            // 4. Someone else got the exclusive inner writelock, and is adding a new one
            // 5. We waited until we got that connection for our key, that someone else added.
            //
            // So now we are down to 2 options:
            //
            // 1. We got an existing connection, it's usable, we use it.
            // 2. We got an existing connection, it's not usable, we start another.
            //
            // Note that for (2) we do not really need to take the inner writelock again for this key -
            // if we checked out a conn inserted by someone else that we cannot use,
            // everyone else will implicitly be waiting for us to check one back in,
            // since they are in their own loops.
            match found_conn {
                // After waiting, we found an available conn we can use, so no need to start another.
                // Clone the underlying client, return a copy, and put the other back in the pool.
                Some(f_conn) => {
                    self.state.checkin_conn(f_conn.clone(), pool_key.clone());
                    Ok(f_conn)
                }

                // After waiting, we found an available conn, but for whatever reason couldn't use it.
                // (streamcount maxed, etc)
                // Start a new one, clone the underlying client, return a copy, and put the other back in the pool.
                None => {
                    debug!("spawning new conn for key {:#?} to replace", workload_key);
                    let pool_conn = self.spawn_new_pool_conn(workload_key.clone()).await;
                    let r_conn = ConnClient{
                        sender: pool_conn?,
                        stream_count: Arc::new(AtomicU16::new(0)),
                        stream_count_max: self.max_streamcount,
                        wl_key: workload_key.clone(),
                    };
                    self.state.checkin_conn(r_conn.clone(), pool_key.clone());
                    Ok(r_conn)
                }
            }
            // END take outer readlock
        }.and_then(|conn| {
            // Finally, we either have a conn or an error.
            // Just for safety's sake, since we are using a hash thanks to pingora supporting arbitrary Eq, Hash
            // types, do a deep equality test before returning the conn, returning an error if the conn's key does
            // not equal the provided key
            //
            // this is a final safety check for collisions, we will throw up our hands and refuse to return the conn
            match conn.is_for_workload(workload_key) {
                Ok(()) => {
                    Ok(conn)
                }
                Err(e) => {
                    Err(e)
                }
            }
        })
    }

    async fn spawn_new_pool_conn(
        &self,
        key: WorkloadKey,
    ) -> Result<http2::SendRequest<Empty<Bytes>>, Error> {
        let clone_key = key.clone();
        let mut c_builder = http2::Builder::new(crate::hyper_util::TokioExecutor);
        let builder = c_builder
            .initial_stream_window_size(self.cfg.window_size)
            .max_frame_size(self.cfg.frame_size)
            .initial_connection_window_size(self.cfg.connection_window_size);

        let local = self
            .cfg
            .enable_original_source
            .unwrap_or_default()
            .then_some(key.src);
        let cert = self.cert_manager.fetch_certificate(&key.src_id).await?;
        let connector = cert.outbound_connector(key.dst_id)?;
        let tcp_stream =
            super::freebind_connect(local, key.dst, self.socket_factory.as_ref()).await?;
        tcp_stream.set_nodelay(true)?; // TODO: this is backwards of expectations
        let tls_stream = connector.connect(tcp_stream).await?;
        let (request_sender, connection) = builder
            .handshake(::hyper_util::rt::TokioIo::new(tls_stream))
            .await
            .map_err(Error::HttpHandshake)?;

        // spawn a task to poll the connection and drive the HTTP state
        // if we got a drain for that connection, respect it in a race
        // it is important to have a drain here, or this connection will never terminate
        let mut driver_drain = self.state.timeout_rx.clone();
        tokio::spawn(async move {
            debug!("starting a connection driver for {:?}", clone_key);
            tokio::select! {
                    _ = driver_drain.changed() => {
                        debug!("draining outer HBONE connection {:?}", clone_key);
                    }
                    res = connection=> {
                        match res {
                            Err(e) => {
                                error!("Error in HBONE connection handshake: {:?}", e);
                            }
                            Ok(_) => {
                                debug!("done with HBONE connection handshake: {:?}", res);
                            }
                        }
                    }
            }
        });

        Ok(request_sender)
    }
}

#[derive(Debug, Clone)]
// A sort of faux-client, that represents a single checked-out 'request sender' which might
// send requests over some underlying stream using some underlying http/2 client
pub struct ConnClient {
    sender: http2::SendRequest<Empty<Bytes>>,
    stream_count: Arc<AtomicU16>, // the current streamcount for this client conn.
    stream_count_max: u16,        // the max streamcount associated with this client.
    // A WL key may have many clients, but every client has no more than one WL key
    wl_key: WorkloadKey, // the WL key associated with this client.
}

impl ConnClient {
    pub fn at_max_streamcount(&self) -> bool {
        let curr_count = self.stream_count.load(Ordering::Relaxed);
        debug!("checking streamcount: {curr_count}");
        if curr_count >= self.stream_count_max {
            return true;
        }
        false
    }

    pub fn send_request(
        &mut self,
        req: Request<Empty<Bytes>>,
    ) -> impl Future<Output = hyper::Result<Response<Incoming>>> {
        // TODO should we enforce streamcount per-sent-request? This would be slow.
        self.stream_count.fetch_add(1, Ordering::Relaxed);
        self.sender.send_request(req)
    }

    pub fn is_for_workload(&self, wl_key: WorkloadKey) -> Result<(), crate::proxy::Error> {
        if !(self.wl_key == wl_key) {
            Err(crate::proxy::Error::Generic(
                "fetched connection does not match workload key!".into(),
            ))
        } else {
            Ok(())
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct WorkloadKey {
    pub src_id: Identity,
    pub dst_id: Vec<Identity>,
    // In theory we can just use src,dst,node. However, the dst has a check that
    // the L3 destination IP matches the HBONE IP. This could be loosened to just assert they are the same identity maybe.
    pub dst: SocketAddr,
    // Because we spoof the source IP, we need to key on this as well. Note: for in-pod its already per-pod
    // pools anyways.
    pub src: IpAddr,
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::time::Instant;

    use crate::identity;

    use drain::Watch;
    use futures_util::StreamExt;
    use hyper::body::Incoming;

    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::task::{self};

    #[cfg(tokio_unstable)]
    use tracing::Instrument;

    use ztunnel::test_helpers::*;

    use super::*;

    #[tokio::test]
    async fn test_pool_reuses_conn_for_same_key() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let (server_addr, server_handle) = spawn_server(server_drain).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 6,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));

        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 2).await;
        let client2 = spawn_client(pool.clone(), key1.clone(), server_addr, 2).await;
        let client3 = spawn_client(pool.clone(), key1, server_addr, 2).await;

        assert!(client1.is_ok());
        assert!(client2.is_ok());
        assert!(client3.is_ok());

        server_drain_signal.drain().await;
        drop(pool);
        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 1, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok());
        assert!(client3.is_ok());
    }

    #[tokio::test]
    async fn test_pool_does_not_reuse_conn_for_diff_key() {
        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain).await;

        // crate::telemetry::setup_logging();

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 10,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let key2 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 3]),
            dst: server_addr,
        };

        let client1 = spawn_client(pool.clone(), key1, server_addr, 2).await;
        let client2 = spawn_client(pool.clone(), key2, server_addr, 2).await;

        server_drain_signal.drain().await;
        drop(pool);
        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok()); // expect this to panic - we used a new key
    }

    #[tokio::test]
    async fn test_pool_respects_per_conn_stream_limit() {
        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 3,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 4).await;
        let client2 = spawn_client(pool.clone(), key1, server_addr, 2).await;

        server_drain_signal.drain().await;
        drop(pool);

        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok()); // expect this to panic - same key, but stream limit of 3
    }

    #[tokio::test]
    async fn test_pool_handles_many_conns_per_key() {
        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 2,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));

        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 4).await;
        let client2 = spawn_client(pool.clone(), key1.clone(), server_addr, 4).await;

        drop(pool);
        server_drain_signal.drain().await;

        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok());
    }

    #[tokio::test]
    async fn test_pool_100_clients_streamexhaust() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 50,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);
        server_drain_signal.drain().await;
        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 3, "actual conncount was {real_conncount}");
    }

    #[tokio::test]
    async fn test_pool_100_clients_singleconn() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 1000,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);

        server_drain_signal.drain().await;
        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 1, "actual conncount was {real_conncount}");
    }

    #[tokio::test]
    async fn test_pool_100_clients_100_srcs() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 100,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let client_count = 100;
        let mut count = 0u8;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;

            let key1 = WorkloadKey {
                src_id: Identity::default(),
                dst_id: vec![Identity::default()],
                src: IpAddr::from([127, 0, 0, count]),
                dst: server_addr,
            };
            // key1.src = IpAddr::from([127, 0, 0, count]);

            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }

        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);

        server_drain_signal.drain().await;
        let real_conncount = server_handle.await.unwrap();
        assert!(
            real_conncount == 100,
            "actual conncount was {real_conncount}"
        );
    }

    #[tokio::test]
    async fn test_pool_1000_clients_3_srcs() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 1000,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr);

        let mut key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 1]),
            dst: server_addr,
        };

        let client_count = 100;
        let mut count = 0u32;
        let mut tasks = futures::stream::FuturesUnordered::new();
        loop {
            count += 1;
            if count % 2 == 0 {
                debug!("using key 2");
                key1.src = IpAddr::from([127, 0, 0, 4]);
            } else if count % 3 == 0 {
                debug!("using key 3");
                key1.src = IpAddr::from([127, 0, 0, 6]);
            } else {
                debug!("using key 1");
                key1.src = IpAddr::from([127, 0, 0, 2]);
            }

            tasks.push(spawn_client(pool.clone(), key1.clone(), server_addr, 100));

            if count == client_count {
                break;
            }
        }
        while let Some(Err(res)) = tasks.next().await {
            assert!(!res.is_panic(), "CLIENT PANICKED!");
            continue;
        }

        drop(pool);

        server_drain_signal.drain().await;
        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 3, "actual conncount was {real_conncount}");
    }

    fn spawn_client(
        mut pool: WorkloadHBONEPool,
        key: WorkloadKey,
        remote_addr: SocketAddr,
        req_count: u32,
    ) -> task::JoinHandle<()> {
        tokio::spawn(async move {
            let req = || {
                hyper::Request::builder()
                    .uri(format!("{remote_addr}"))
                    .method(hyper::Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(Empty::<Bytes>::new())
                    .unwrap()
            };

            let start = Instant::now();

            let mut c1 = pool
                .connect(key.clone())
                // needs tokio_unstable, but useful
                // .instrument(tracing::debug_span!("client_tid", tid=%tokio::task::id()))
                .await
                .unwrap();
            debug!(
                "client spent {}ms waiting for conn",
                start.elapsed().as_millis()
            );

            let mut count = 0u32;
            loop {
                count += 1;
                let res = c1.send_request(req()).await;

                if res.is_err() {
                    panic!("SEND ERR: {:#?} sendcount {count}", res);
                } else if res.unwrap().status() != 200 {
                    panic!("CLIENT RETURNED ERROR")
                }

                if count >= req_count {
                    debug!("CLIENT DONE");
                    break;
                }
            }
        })
    }

    async fn spawn_server(stop: Watch) -> (SocketAddr, task::JoinHandle<u32>) {
        // We'll bind to 127.0.0.1:3000
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let test_cfg = test_config();
        async fn hello_world(req: Request<Incoming>) -> Result<Response<Empty<Bytes>>, Infallible> {
            debug!("hello world: received request");
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let (mut ri, mut wi) =
                            tokio::io::split(hyper_util::rt::TokioIo::new(upgraded));
                        // Signal we are the waypoint so tests can validate this
                        wi.write_all(b"waypoint\n").await.unwrap();
                        tcp::handle_stream(tcp::Mode::ReadWrite, &mut ri, &mut wi).await;
                    }
                    Err(e) => panic!("No upgrade {e}"),
                }
            });
            Ok::<_, Infallible>(Response::new(http_body_util::Empty::<Bytes>::new()))
        }

        let conn_count: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        // let _drop_conn_count: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));

        // We create a TcpListener and bind it to 127.0.0.1:3000
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();

        let certs = crate::tls::mock::generate_test_certs(
            &Identity::default().into(),
            Duration::from_secs(0),
            Duration::from_secs(100),
        );
        let acceptor = crate::tls::mock::MockServerCertProvider::new(certs);
        let mut tls_stream = crate::hyper_util::tls_server(acceptor, listener);

        let srv_handle = tokio::spawn(async move {
            // We start a loop to continuously accept incoming connections
            // and also count them
            let movable_count = conn_count.clone();
            let accept = async move {
                loop {
                    let stream = tls_stream.next().await.unwrap();
                    movable_count.fetch_add(1, Ordering::Relaxed);
                    debug!("bump serverconn");

                    // Spawn a tokio task to serve multiple connections concurrently
                    tokio::task::spawn(async move {
                        // Finally, we bind the incoming connection to our `hello` service
                        if let Err(err) = crate::hyper_util::http2_server()
                            .initial_stream_window_size(test_cfg.window_size)
                            .initial_connection_window_size(test_cfg.connection_window_size)
                            .max_frame_size(test_cfg.frame_size)
                            // 64KB max; default is 16MB driven from Golang's defaults
                            // Since we know we are going to recieve a bounded set of headers, more is overkill.
                            .max_header_list_size(65536)
                            .serve_connection(
                                hyper_util::rt::TokioIo::new(stream),
                                service_fn(hello_world),
                            )
                            .await
                        {
                            println!("Error serving connection: {:?}", err);
                        }
                    });
                }
            };
            tokio::select! {
                _ = accept => {}
                _ = stop.signaled() => {
                    debug!("GOT STOP SERVER");
                }
            };

            conn_count.load(Ordering::Relaxed)
        });

        (bound_addr, srv_handle)
    }
}
