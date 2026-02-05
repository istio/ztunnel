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

#![warn(clippy::cast_lossless)]
use super::{Error, SocketFactory};
use super::{LocalWorkloadInformation, h2};
use std::time::Duration;

use std::collections::hash_map::DefaultHasher;

use std::hash::{Hash, Hasher};

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use tokio::sync::watch;

use tokio::sync::Mutex;
use tracing::{Instrument, debug, trace};

use crate::baggage::Baggage;
use crate::config;

use flurry;

use crate::proxy::h2::H2Stream;
use crate::proxy::h2::client::{H2ConnectClient, WorkloadKey};
use pingora_pool;
use tokio::io;

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
    state: Arc<PoolState>,
    pool_watcher: watch::Receiver<bool>,
}

// PoolState is effectively the gnarly inner state stuff that needs thread/task sync, and should be wrapped in a Mutex.
struct PoolState {
    pool_notifier: watch::Sender<bool>, // This is already impl clone? rustc complains that it isn't, tho
    timeout_tx: watch::Sender<bool>, // This is already impl clone? rustc complains that it isn't, tho
    // this is effectively just a convenience data type - a rwlocked hashmap with keying and LRU drops
    // and has no actual hyper/http/connection logic.
    connected_pool: Arc<pingora_pool::ConnectionPool<H2ConnectClient>>,
    // this must be an atomic/concurrent-safe list-of-locks, so we can lock per-key, not globally, and avoid holding up all conn attempts
    established_conn_writelock: flurry::HashMap<u64, Option<Arc<Mutex<()>>>>,
    pool_unused_release_timeout: Duration,
    // This is merely a counter to track the overall number of conns this pool spawns
    // to ensure we get unique poolkeys-per-new-conn, it is not a limit
    pool_global_conn_count: AtomicI32,
    spawner: ConnSpawner,
}

struct ConnSpawner {
    cfg: Arc<config::Config>,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    local_workload: Arc<LocalWorkloadInformation>,
    timeout_rx: watch::Receiver<bool>,
}

// Does nothing but spawn new conns when asked
impl ConnSpawner {
    async fn new_pool_conn(&self, key: WorkloadKey) -> Result<H2ConnectClient, Error> {
        debug!("spawning new pool conn for {}", key);

        let cert = self.local_workload.fetch_certificate().await?;
        let connector = cert.outbound_connector(key.dst_id.clone())?;
        let tcp_stream = super::freebind_connect(None, key.dst, self.socket_factory.as_ref())
            .await
            .map_err(|e: io::Error| match e.kind() {
                io::ErrorKind::TimedOut => Error::MaybeHBONENetworkPolicyError(e),
                _ => e.into(),
            })?;

        let tls_stream = connector.connect(tcp_stream).await?;
        trace!("connector connected, handshaking");
        let sender = h2::client::spawn_connection(
            self.cfg.clone(),
            tls_stream,
            self.timeout_rx.clone(),
            key,
        )
        .await?;
        Ok(sender)
    }
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
    // and poll them to completion on shutdown - any duplicates from repeated checkouts/checkins of the same conn
    // will simply resolve as a no-op in order.
    //
    // Note that "idle" in the context of this pool means "no one has asked for it or dropped it in X time, so prune it".
    //
    // Pruning the idle connection from the pool does not close it - it simply ensures the pool stops holding a ref.
    // hyper self-closes client conns when all refs are dropped and streamcount is 0, so pool consumers must
    // drop their checked out conns and/or terminate their streams as well.
    //
    // Note that this simply removes the client ref from this pool - if other things hold client/streamrefs refs,
    // they must also drop those before the underlying connection is fully closed.
    fn maybe_checkin_conn(&self, conn: H2ConnectClient, pool_key: pingora_pool::ConnectionMeta) {
        if conn.will_be_at_max_streamcount() {
            debug!(
                "checked out connection for {:?} is now at max streamcount; removing from pool",
                pool_key
            );
            return;
        }
        let (evict, pickup) = self.connected_pool.put(&pool_key, conn);
        let rx = self.spawner.timeout_rx.clone();
        let pool_ref = self.connected_pool.clone();
        let pool_key_ref = pool_key.clone();
        let release_timeout = self.pool_unused_release_timeout;
        tokio::spawn(
            async move {
                debug!("starting an idle timeout for connection {:?}", pool_key_ref);
                pool_ref
                    .idle_timeout(&pool_key_ref, release_timeout, evict, rx, pickup)
                    .await;
                debug!(
                    "connection {:?} was removed/checked out/timed out of the pool",
                    pool_key_ref
                )
            }
            .in_current_span(),
        );
        let _ = self.pool_notifier.send(true);
    }

    // Since we are using a hash key to do lookup on the inner pingora pool, do a get guard
    // to make sure what we pull out actually deep-equals the workload_key, to avoid *sigh* crossing the streams.
    fn guarded_get(
        &self,
        hash_key: &u64,
        workload_key: &WorkloadKey,
    ) -> Result<Option<H2ConnectClient>, Error> {
        match self.connected_pool.get(hash_key) {
            None => Ok(None),
            Some(conn) => match Self::enforce_key_integrity(conn, workload_key) {
                Err(e) => Err(e),
                Ok(conn) => Ok(Some(conn)),
            },
        }
    }

    // Just for safety's sake, since we are using a hash thanks to pingora NOT supporting arbitrary Eq, Hash
    // types, do a deep equality test before returning the conn, returning an error if the conn's key does
    // not equal the provided key
    //
    // this is a final safety check for collisions, we will throw up our hands and refuse to return the conn
    fn enforce_key_integrity(
        conn: H2ConnectClient,
        expected_key: &WorkloadKey,
    ) -> Result<H2ConnectClient, Error> {
        match conn.is_for_workload(expected_key) {
            Ok(()) => Ok(conn),
            Err(e) => Err(e),
        }
    }

    // 1. Tries to get a writelock.
    // 2. If successful, hold it, spawn a new connection, check it in, return a clone of it.
    // 3. If not successful, return nothing.
    //
    // This is useful if we want to race someone else to the writelock to spawn a connection,
    // and expect the losers to queue up and wait for the (singular) winner of the writelock
    //
    // This function should ALWAYS return a connection if it wins the writelock for the provided key.
    // This function should NEVER return a connection if it does not win the writelock for the provided key.
    // This function should ALWAYS propagate Error results to the caller
    //
    // It is important that the *initial* check here is authoritative, hence the locks, as
    // we must know if this is a connection for a key *nobody* has tried to start yet
    // (i.e. no writelock for our key in the outer map)
    // or if other things have already established conns for this key (writelock for our key in the outer map).
    //
    // This is so we can backpressure correctly if 1000 tasks all demand a new connection
    // to the same key at once, and not eagerly open 1000 tunnel connections.
    async fn start_conn_if_win_writelock(
        &self,
        workload_key: &WorkloadKey,
        pool_key: &pingora_pool::ConnectionMeta,
    ) -> Result<Option<H2ConnectClient>, Error> {
        let inner_conn_lock = {
            trace!("getting keyed lock out of lockmap");
            let guard = self.established_conn_writelock.guard();

            let exist_conn_lock = self
                .established_conn_writelock
                .get(&pool_key.key, &guard)
                .unwrap();
            trace!("got keyed lock out of lockmap");
            exist_conn_lock.as_ref().unwrap().clone()
        };

        trace!("attempting to win connlock for {}", workload_key);

        let inner_lock = inner_conn_lock.try_lock();
        match inner_lock {
            Ok(_guard) => {
                // BEGIN take inner writelock
                debug!("nothing else is creating a conn and we won the lock, make one");
                let client = self.spawner.new_pool_conn(workload_key.clone()).await?;

                debug!(
                    "checking in new conn for {} with pk {:?}",
                    workload_key, pool_key
                );
                self.maybe_checkin_conn(client.clone(), pool_key.clone());
                Ok(Some(client))
                // END take inner writelock
            }
            Err(_) => {
                debug!(
                    "did not win connlock for {}, something else has it",
                    workload_key
                );
                Ok(None)
            }
        }
    }

    // Does an initial, naive check to see if we have a writelock inserted into the map for this key
    //
    // If we do, take the writelock for that key, clone (or create) a connection, check it back in,
    // and return a cloned ref, then drop the writelock.
    //
    // Otherwise, return None.
    //
    // This function should ALWAYS return a connection if a writelock exists for the provided key.
    // This function should NEVER return a connection if no writelock exists for the provided key.
    // This function should ALWAYS propagate Error results to the caller
    //
    // It is important that the *initial* check here is authoritative, hence the locks, as
    // we must know if this is a connection for a key *nobody* has tried to start yet
    // (i.e. no writelock for our key in the outer map)
    // or if other things have already established conns for this key (writelock for our key in the outer map).
    //
    // This is so we can backpressure correctly if 1000 tasks all demand a new connection
    // to the same key at once, and not eagerly open 1000 tunnel connections.
    async fn checkout_conn_under_writelock(
        &self,
        workload_key: &WorkloadKey,
        pool_key: &pingora_pool::ConnectionMeta,
    ) -> Result<Option<H2ConnectClient>, Error> {
        let found_conn = {
            trace!("pool connect outer map - take guard");
            let guard = self.established_conn_writelock.guard();

            trace!("pool connect outer map - check for keyed mutex");
            let exist_conn_lock = self.established_conn_writelock.get(&pool_key.key, &guard);
            exist_conn_lock.and_then(|e_conn_lock| e_conn_lock.clone())
        };
        let Some(exist_conn_lock) = found_conn else {
            return Ok(None);
        };
        debug!(
            "checkout - found mutex for pool key {:?}, waiting for writelock",
            pool_key
        );
        let _conn_lock = exist_conn_lock.as_ref().lock().await;

        trace!(
            "checkout - got writelock for conn with key {} and hash {:?}",
            workload_key, pool_key.key
        );
        let returned_connection = loop {
            match self.guarded_get(&pool_key.key, workload_key)? {
                Some(mut existing) => {
                    if !existing.ready_to_use() {
                        // We checked this out, and will not check it back in
                        // Loop again to find another/make a new one
                        debug!(
                            "checked out broken connection for {}, dropping it",
                            workload_key
                        );
                        continue;
                    }
                    debug!("re-using connection for {}", workload_key);
                    break existing;
                }
                None => {
                    debug!("new connection needed for {}", workload_key);
                    break self.spawner.new_pool_conn(workload_key.clone()).await?;
                }
            };
        };

        // For any connection, we will check in a copy and return the other unless its already maxed out
        // TODO: in the future, we can keep track of these and start to use them once they finish some streams.
        self.maybe_checkin_conn(returned_connection.clone(), pool_key.clone());
        Ok(Some(returned_connection))
    }
}

// When the Arc-wrapped PoolState is finally dropped, trigger the drain,
// which will terminate all connection driver spawns, as well as cancel all outstanding eviction timeout spawns
impl Drop for PoolState {
    fn drop(&mut self) {
        debug!(
            "poolstate dropping, stopping all connection drivers and cancelling all outstanding eviction timeout spawns"
        );
        let _ = self.timeout_tx.send(true);
    }
}

impl WorkloadHBONEPool {
    // Creates a new pool instance, which should be owned by a single proxied workload.
    // The pool will watch the provided drain signal and drain itself when notified.
    // Callers should then be safe to drop() the pool instance.
    pub fn new(
        cfg: Arc<crate::config::Config>,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        local_workload: Arc<LocalWorkloadInformation>,
    ) -> WorkloadHBONEPool {
        let (timeout_tx, timeout_rx) = watch::channel(false);
        let (timeout_send, timeout_recv) = watch::channel(false);
        let pool_duration = cfg.pool_unused_release_timeout;

        let spawner = ConnSpawner {
            cfg,
            socket_factory,
            local_workload,
            timeout_rx: timeout_recv.clone(),
        };

        Self {
            state: Arc::new(PoolState {
                pool_notifier: timeout_tx,
                timeout_tx: timeout_send,
                // timeout_rx: timeout_recv,
                // the number here is simply the number of unique src/dest keys
                // the pool is expected to track before the inner hashmap resizes.
                connected_pool: Arc::new(pingora_pool::ConnectionPool::new(500)),
                established_conn_writelock: flurry::HashMap::new(),
                pool_unused_release_timeout: pool_duration,
                pool_global_conn_count: AtomicI32::new(0),
                spawner,
            }),
            pool_watcher: timeout_rx,
        }
    }

    pub async fn send_request_pooled(
        &mut self,
        workload_key: &WorkloadKey,
        request: http::Request<()>,
    ) -> Result<(H2Stream, Option<Baggage>), Error> {
        let mut connection = self.connect(workload_key).await?;

        connection.send_request(request).await
    }

    // Obtain a pooled connection. Will prefer to retrieve an existing conn from the pool, but
    // if none exist, or the existing conn is maxed out on streamcount, will spawn a new one,
    // even if it is to the same dest+port.
    //
    // If many `connects` request a connection to the same dest at once, all will wait until exactly
    // one connection is created, before deciding if they should create more or just use that one.
    async fn connect(&mut self, workload_key: &WorkloadKey) -> Result<H2ConnectClient, Error> {
        trace!("pool connect START");
        // TODO BML this may not be collision resistant, or a fast hash. It should be resistant enough for workloads tho.
        // We are doing a deep-equals check at the end to mitigate any collisions, will see about bumping Pingora
        let mut s = DefaultHasher::new();
        workload_key.hash(&mut s);
        let hash_key = s.finish();
        let pool_key = pingora_pool::ConnectionMeta::new(
            hash_key,
            self.state
                .pool_global_conn_count
                .fetch_add(1, Ordering::SeqCst),
        );
        // First, see if we can naively take an inner lock for our specific key, and get a connection.
        // This should be the common case, except for the first establishment of a new connection/key.
        // This will be done under outer readlock (nonexclusive)/inner keyed writelock (exclusive).
        let existing_conn = self
            .state
            .checkout_conn_under_writelock(workload_key, &pool_key)
            .await?;

        // Early return, no need to do anything else
        if let Some(e) = existing_conn {
            debug!("initial attempt - found existing conn, done");
            return Ok(e);
        }

        // We couldn't get a writelock for this key. This means nobody has tried to establish any conns for this key yet,
        // So, we will take a nonexclusive readlock on the outer lockmap, and attempt to insert one.
        //
        // (if multiple threads try to insert one, only one will succeed.)
        {
            debug!(
                "didn't find a connection for key {:?}, making sure lockmap has entry",
                hash_key
            );
            let guard = self.state.established_conn_writelock.guard();
            match self.state.established_conn_writelock.try_insert(
                hash_key,
                Some(Arc::new(Mutex::new(()))),
                &guard,
            ) {
                Ok(_) => {
                    debug!("inserting conn mutex for key {:?} into lockmap", hash_key);
                }
                Err(_) => {
                    debug!("already have conn for key {:?} in lockmap", hash_key);
                }
            }
        }

        // If we get here, it means the following are true:
        // 1. We have a guaranteed sharded mutex in the outer map for our current key
        // 2. We can now, under readlock(nonexclusive) in the outer map, attempt to
        // take the inner writelock for our specific key (exclusive).
        //
        // This doesn't block other tasks spawning connections against other keys, but DOES block other
        // tasks spawning connections against THIS key - which is what we want.

        // NOTE: The inner, key-specific mutex is a tokio::async::Mutex, and not a stdlib sync mutex.
        // these differ from the stdlib sync mutex in that they are (slightly) slower
        // (they effectively sleep the current task) and they can be held over an await.
        // The tokio docs (rightly) advise you to not use these,
        // because holding a lock over an await is a great way to create deadlocks if the await you
        // hold it over does not resolve.
        //
        // HOWEVER. Here we know this connection will either establish or timeout (or fail with error)
        // and we WANT other tasks to go back to sleep if a task is already trying to create a new connection for this key.
        //
        // So the downsides are actually useful (we WANT task contention -
        // to block other parallel tasks from trying to spawn a connection for this key if we are already doing so)
        trace!("fallback attempt - trying win win connlock");
        let res = match self
            .state
            .start_conn_if_win_writelock(workload_key, &pool_key)
            .await?
        {
            Some(client) => client,
            None => {
                debug!("we didn't win the lock, something else is creating a conn, wait for it");
                // If we get here, it means the following are true:
                // 1. We have a writelock in the outer map for this key (either we inserted, or someone beat us to it - but it's there)
                // 2. We could not get the exclusive inner writelock to add a new conn for this key.
                // 3. Someone else got the exclusive inner writelock, and is adding a new conn for this key.
                //
                // So, loop and wait for the pool_watcher to tell us a new conn was enpooled,
                // so we can pull it out and check it.
                loop {
                    match self.pool_watcher.changed().await {
                        Ok(_) => {
                            trace!(
                                "notified a new conn was enpooled, checking for hash {:?}",
                                hash_key
                            );
                            // Notifier fired, try and get a conn out for our key.
                            let existing_conn = self
                                .state
                                .checkout_conn_under_writelock(workload_key, &pool_key)
                                .await?;
                            match existing_conn {
                                None => {
                                    trace!(
                                        "woke up on pool notification, but didn't find a conn for {:?} yet",
                                        hash_key
                                    );
                                    continue;
                                }
                                Some(e_conn) => {
                                    debug!("found existing conn after waiting");
                                    break e_conn;
                                }
                            }
                        }
                        Err(_) => {
                            return Err(Error::WorkloadHBONEPoolDraining);
                        }
                    }
                }
            }
        };
        Ok(res)
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;
    use std::net::IpAddr;
    use std::net::SocketAddr;
    use std::time::Instant;

    use crate::{drain, identity, proxy};

    use futures_util::{StreamExt, future};
    use hyper::body::Incoming;

    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use prometheus_client::registry::Registry;
    use std::sync::RwLock;
    use std::sync::atomic::AtomicU32;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
    use tokio::sync::oneshot;

    use tracing::{Instrument, error};

    use crate::test_helpers::helpers::initialize_telemetry;

    use crate::identity::Identity;

    use self::h2::TokioH2Stream;

    use super::*;
    use crate::drain::DrainWatcher;
    use crate::state::workload;
    use crate::state::{DemandProxyState, ProxyState, WorkloadInfo};
    use crate::test_helpers::test_default_workload;
    use ztunnel::test_helpers::*;

    macro_rules! assert_opens_drops {
        ($srv:expr_2021, $open:expr_2021, $drops:expr_2021) => {
            assert_eq!(
                $srv.conn_counter.load(Ordering::Relaxed),
                $open,
                "total connections opened, wanted {}",
                $open
            );
            #[allow(clippy::reversed_empty_ranges)]
            for want in 0..$drops {
                tokio::time::timeout(Duration::from_secs(2), $srv.drop_rx.recv())
                    .await
                    .expect(&format!(
                        "wanted {} drops, but timed out after getting {}",
                        $drops, want
                    ))
                    .expect("wanted drop");
            }
            assert!(
                $srv.drop_rx.is_empty(),
                "after {} drops, we shouldn't have more, but got {}",
                $drops,
                $srv.drop_rx.len()
            )
        };
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connections_reused() {
        let (pool, mut srv) = setup_test(3).await;

        let key = key(&srv, 2);

        // Pool allows 3. When we spawn 2 concurrently, we should open a single connection and keep it alive
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 2).await;
        assert_opens_drops!(srv, 1, 0);

        // Since the last two closed, we are free to re-use the same connection
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 2).await;
        assert_opens_drops!(srv, 1, 0);

        // Once we drop the pool, we should drop the connections as well
        drop(pool);
        assert_opens_drops!(srv, 1, 1);
    }

    /// This is really a test for TokioH2Stream, but its nicer here because we have access to
    /// streams.
    /// Most important, we make sure there are no panics.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_buffering() {
        let (mut pool, srv) = setup_test(3).await;

        let key = key(&srv, 2);
        let req = || {
            http::Request::builder()
                .uri(srv.addr.to_string())
                .method(http::Method::CONNECT)
                .version(http::Version::HTTP_2)
                .body(())
                .unwrap()
        };

        let (c, _baggage) = pool.send_request_pooled(&key.clone(), req()).await.unwrap();
        let mut c = TokioH2Stream::new(c);
        c.write_all(b"abcde").await.unwrap();
        let mut b = [0u8; 100];
        // Properly buffer reads and don't error
        assert_eq!(c.read(&mut b).await.unwrap(), 8);
        assert_eq!(&b[..8], b"poolsrv\n"); // this is added by itself
        assert_eq!(c.read(&mut b[..1]).await.unwrap(), 1);
        assert_eq!(&b[..1], b"a");
        assert_eq!(c.read(&mut b[..1]).await.unwrap(), 1);
        assert_eq!(&b[..1], b"b");
        assert_eq!(c.read(&mut b[..1]).await.unwrap(), 1);
        assert_eq!(&b[..1], b"c");
        assert_eq!(c.read(&mut b).await.unwrap(), 2); // there are only two bytes left
        assert_eq!(&b[..2], b"de");

        // Once we drop the pool, we should still retained the buffered data,
        // but then we should error.
        c.write_all(b"abcde").await.unwrap();
        assert_eq!(c.read(&mut b[..3]).await.unwrap(), 3);
        assert_eq!(&b[..3], b"abc");
        drop(pool);
        assert_eq!(c.read(&mut b[..2]).await.unwrap(), 2);
        assert_eq!(&b[..2], b"de");
        assert!(c.read(&mut b).await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unique_keys_have_unique_connections() {
        let (pool, mut srv) = setup_test(3).await;

        let key1 = key(&srv, 1);
        let key2 = key(&srv, 2);

        test_client(pool.clone(), key1, srv.addr).await;
        test_client(pool.clone(), key2, srv.addr).await;
        assert_opens_drops!(srv, 2, 0);
        // Once we drop the pool, we should drop the connections as well
        drop(pool);
        assert_opens_drops!(srv, 2, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connection_limits() {
        let (pool, mut srv) = setup_test(2).await;

        let key = key(&srv, 1);

        // Pool allows 2. When we spawn 4 concurrently, so we need 2 connections
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 4).await;
        assert_opens_drops!(srv, 2, 2);

        // This should require 3 connections (2 already opened, 1 new). However, due to an inefficiency
        // in our pool, we don't properly reuse streams that hit the max.
        // The first batch of 4 will start a connection for the first 2 connections, and each max out so they
        // are not returned to the pool.
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 5).await;
        assert_opens_drops!(srv, 5, 2);

        // Once we drop the pool, we should drop the rest of the connections as well (3 new ones, and the one already checked above)
        drop(pool);
        assert_opens_drops!(srv, 5, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_goaway() {
        let (pool, mut srv) = setup_test(2).await;

        let key = key(&srv, 1);

        // Establish one connection, it will be pooled
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 1).await;
        assert_opens_drops!(srv, 1, 0);

        // Trigger server GOAWAY. Wait for the server to finish
        srv.goaway_tx.send(()).unwrap();
        assert_opens_drops!(srv, 1, 1);

        // Open a new connection. We should create a new one, since the last one is busted
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 1).await;
        assert_opens_drops!(srv, 2, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn single_pool() {
        // Test an edge case of a pool size of 1. Probably users shouldn't have pool size 1, and if
        // they do, we should just disable the pool. For now, we don't do that, so make sure it works.
        let (pool, mut srv) = setup_test(1).await;

        let key = key(&srv, 1);

        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 2).await;
        assert_opens_drops!(srv, 2, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stress_test_single_source() {
        let (pool, mut srv) = setup_test(101).await;

        let key = key(&srv, 1);

        // Spin up 100 requests, they should all work
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 100).await;
        assert_opens_drops!(srv, 1, 0);

        // Once we drop the pool, we should drop the connections as well
        drop(pool);
        assert_opens_drops!(srv, 1, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stress_test_multiple_source() {
        let (pool, mut srv) = setup_test(100).await;

        // Spin up 100 requests each from their own source, they should all work
        let mut tasks = vec![];
        for count in 0..100 {
            let key = key(&srv, count);
            tasks.push(test_client(pool.clone(), key.clone(), srv.addr));
        }
        future::join_all(tasks).await;

        drop(pool);
        assert_opens_drops!(srv, 100, 100);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stress_test_many_client_many_sources() {
        let (pool, mut srv) = setup_test(100).await;

        // Spin up 300 requests each from 3 different sources, they should all work
        let mut tasks = vec![];
        for count in 0..300u16 {
            let key = key(&srv, (count % 3) as u8);
            tasks.push(test_client(pool.clone(), key.clone(), srv.addr));
        }
        future::join_all(tasks).await;
        drop(pool);
        assert_opens_drops!(srv, 3, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_eviction() {
        let (pool, mut srv) = setup_test_with_idle(3, Duration::from_millis(100)).await;

        let key = key(&srv, 1);

        // Pool allows 3. When we spawn 2 concurrently, we should open a single connection and keep it alive
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 2).await;
        // After 100ms, we should drop everything
        assert_opens_drops!(srv, 1, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idle_eviction_with_persistent() {
        let (pool, mut srv) = setup_test_with_idle(4, Duration::from_millis(100)).await;

        let key = key(&srv, 1);
        let (client_stop_signal, client_stop) = drain::new();
        // Spin up 1 connection
        spawn_persistent_client(pool.clone(), key.clone(), srv.addr, client_stop).await;
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 2).await;
        // We shouldn't drop anything yet
        assert_opens_drops!(srv, 1, 0);
        // This should spill over into a new connection, which should drop
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 4).await;
        assert_opens_drops!(srv, 2, 1);

        // Trigger the persistent client to stop, we should evict that connection as well
        client_stop_signal
            .start_drain_and_wait(drain::DrainMode::Immediate)
            .await;
        assert_opens_drops!(srv, 2, 1);
    }

    async fn spawn_clients_concurrently(
        mut pool: WorkloadHBONEPool,
        key: WorkloadKey,
        remote_addr: SocketAddr,
        req_count: u32,
    ) {
        let (shutdown_send, _shutdown_recv) = tokio::sync::broadcast::channel::<()>(1);

        let mut tasks = vec![];
        for req_num in 0..req_count {
            let req = || {
                hyper::Request::builder()
                    .uri(format!("{remote_addr}"))
                    .method(hyper::Method::CONNECT)
                    .version(hyper::Version::HTTP_2)
                    .body(())
                    .unwrap()
            };

            let start = Instant::now();

            let c1 = pool
                .send_request_pooled(&key.clone(), req())
                .instrument(tracing::debug_span!("client", request = req_num))
                .await
                .expect("connect should succeed");
            debug!(
                "client spent {}ms waiting for conn",
                start.elapsed().as_millis()
            );
            let mut shutdown_recv = shutdown_send.subscribe();
            tasks.push(tokio::spawn(async move {
                let _ = shutdown_recv.recv().await;
                drop(c1);
                debug!("dropped stream");
            }));
        }
        drop(shutdown_send);
        future::join_all(tasks).await;
    }

    async fn test_client(mut pool: WorkloadHBONEPool, key: WorkloadKey, remote_addr: SocketAddr) {
        let req = || {
            hyper::Request::builder()
                .uri(format!("{remote_addr}"))
                .method(hyper::Method::CONNECT)
                .version(hyper::Version::HTTP_2)
                .body(())
                .unwrap()
        };

        let start = Instant::now();

        let _c1 = pool
            .send_request_pooled(&key.clone(), req())
            .await
            .expect("connect should succeed");
        debug!(
            "client spent {}ms waiting for conn",
            start.elapsed().as_millis()
        );
    }

    async fn spawn_persistent_client(
        mut pool: WorkloadHBONEPool,
        key: WorkloadKey,
        remote_addr: SocketAddr,
        stop: DrainWatcher,
    ) {
        let req = || {
            http::Request::builder()
                .uri(format!("{remote_addr}"))
                .method(http::Method::CONNECT)
                .version(http::Version::HTTP_2)
                .body(())
                .unwrap()
        };

        let start = Instant::now();

        let c1 = pool.send_request_pooled(&key.clone(), req()).await.unwrap();
        debug!(
            "client spent {}ms waiting for conn",
            start.elapsed().as_millis()
        );
        tokio::spawn(async move {
            let _ = stop.wait_for_drain().await;
            debug!("persistent client stop");
            // Close our connection
            drop(c1);
        });
    }

    async fn spawn_server(
        conn_count: Arc<AtomicU32>,
        drop_tx: UnboundedSender<()>,
        goaway: oneshot::Receiver<()>,
    ) -> SocketAddr {
        use http_body_util::Empty;
        // We'll bind to 127.0.0.1:3000
        let addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let test_cfg = test_config();
        async fn hello_world(
            req: Request<Incoming>,
        ) -> Result<Response<Empty<bytes::Bytes>>, Infallible> {
            debug!("hello world: received request");
            tokio::task::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        let mut io = hyper_util::rt::TokioIo::new(upgraded);
                        io.write_all(b"poolsrv\n").await.unwrap();
                        tcp::handle_stream(tcp::Mode::ReadWrite, &mut io).await;
                    }
                    Err(e) => panic!("No upgrade {e}"),
                }
                debug!("hello world: completed request");
            });
            Ok::<_, Infallible>(Response::new(http_body_util::Empty::<bytes::Bytes>::new()))
        }

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

        let mut goaway = Some(goaway);
        tokio::spawn(async move {
            // We start a loop to continuously accept incoming connections
            // and also count them
            let conn_count = conn_count.clone();
            let drop_tx = drop_tx.clone();
            let accept = async move {
                loop {
                    let goaway_rx = goaway.take();
                    let stream = tls_stream.next().await.unwrap();
                    conn_count.fetch_add(1, Ordering::SeqCst);
                    debug!("server stream started");
                    let drop_tx = drop_tx.clone();

                    let server = crate::hyper_util::http2_server()
                        .initial_stream_window_size(test_cfg.window_size)
                        .initial_connection_window_size(test_cfg.connection_window_size)
                        .max_frame_size(test_cfg.frame_size)
                        .max_header_list_size(65536)
                        .serve_connection(
                            hyper_util::rt::TokioIo::new(stream),
                            service_fn(hello_world),
                        );

                    // Spawn a tokio task to serve multiple connections concurrently
                    tokio::task::spawn(async move {
                        let recv = async move {
                            match goaway_rx {
                                Some(rx) => {
                                    let _ = rx.await;
                                }
                                None => futures_util::future::pending::<()>().await,
                            };
                        };
                        let res = match futures_util::future::select(Box::pin(recv), server).await {
                            futures_util::future::Either::Left((_shutdown, mut server)) => {
                                debug!("server drain starting... {_shutdown:?}");
                                let drain = std::pin::Pin::new(&mut server);
                                drain.graceful_shutdown();
                                let _res = server.await;
                                debug!("server drain done");
                                Ok(())
                            }
                            // Serving finished, just return the result.
                            futures_util::future::Either::Right((res, _shutdown)) => {
                                debug!("inbound serve done {:?}", res);
                                res
                            }
                        };
                        if let Err(err) = res {
                            error!("server failed: {err:?}");
                        }
                        let _ = drop_tx.send(());
                    });
                }
            };
            accept.await;
        });

        bound_addr
    }

    async fn setup_test(max_conns: u16) -> (WorkloadHBONEPool, TestServer) {
        setup_test_with_idle(max_conns, Duration::from_secs(100)).await
    }

    async fn setup_test_with_idle(
        max_conns: u16,
        idle: Duration,
    ) -> (WorkloadHBONEPool, TestServer) {
        initialize_telemetry();
        let conn_counter: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let (drop_tx, drop_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (goaway_tx, goaway_rx) = oneshot::channel::<()>();
        let addr = spawn_server(conn_counter.clone(), drop_tx, goaway_rx).await;

        let cfg = crate::config::Config {
            pool_max_streams_per_conn: max_conns,
            pool_unused_release_timeout: idle,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory::default());

        let mut state = ProxyState::new(None);
        let wl = Arc::new(workload::Workload {
            uid: "uid".into(),
            name: "source-workload".into(),
            namespace: "ns".into(),
            service_account: "default".into(),
            ..test_default_workload()
        });
        state.workloads.insert(wl.clone());
        let mut registry = Registry::default();
        let metrics = Arc::new(crate::proxy::Metrics::new(&mut registry));
        let mock_proxy_state = DemandProxyState::new(
            Arc::new(RwLock::new(state)),
            None,
            ResolverConfig::default(),
            ResolverOpts::default(),
            metrics,
        );
        let local_workload = Arc::new(proxy::LocalWorkloadInformation::new(
            Arc::new(WorkloadInfo {
                name: wl.name.to_string(),
                namespace: wl.namespace.to_string(),
                service_account: wl.service_account.to_string(),
            }),
            mock_proxy_state,
            identity::mock::new_secret_manager(Duration::from_secs(10)),
            Arc::new(cfg.clone()),
        ));
        let pool = WorkloadHBONEPool::new(Arc::new(cfg), sock_fact, local_workload);
        let server = TestServer {
            conn_counter,
            drop_rx,
            goaway_tx,
            addr,
        };
        (pool, server)
    }

    struct TestServer {
        conn_counter: Arc<AtomicU32>,
        drop_rx: UnboundedReceiver<()>,
        goaway_tx: oneshot::Sender<()>,
        addr: SocketAddr,
    }

    fn key(srv: &TestServer, ip: u8) -> WorkloadKey {
        WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, ip]),
            dst: srv.addr,
        }
    }
}
