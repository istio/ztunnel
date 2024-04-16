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
use drain::Watch;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::client::conn::http2;
use hyper::http::{Request, Response};

use std::collections::hash_map::DefaultHasher;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI32, AtomicU16, Ordering};
use std::sync::Arc;

use tokio::sync::watch;
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
    pool_notifier: watch::Sender<bool>,
    pool_watcher: watch::Receiver<bool>,
    max_streamcount: u16,
    // this is effectively just a convenience data type - a rwlocked hashmap with keying and LRU drops
    // and has no actual hyper/http/connection logic.
    connected_pool: Arc<pingora_pool::ConnectionPool<Client>>,
    cfg: config::Config,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    cert_manager: Arc<SecretManager>,
    drainer: Watch,
    // this must be a readlockable list-of-locks, so we can lock per-key, not globally, and avoid holding up all conn attempts
    established_conn_writelock: Arc<RwLock<HashMap<u64, Option<Mutex<()>>>>>,
}

impl WorkloadHBONEPool {
    pub fn new(
        cfg: crate::config::Config,
        socket_factory: Arc<dyn SocketFactory + Send + Sync>,
        cert_manager: Arc<SecretManager>,
        drainer: Watch, //when signaled, will stop driving all conns in the pool, effectively draining the pool.
    ) -> WorkloadHBONEPool {
        let (tx, rx) = watch::channel(false);
        debug!(
            "constructing pool with {:#?} streams per conn",
            cfg.pool_max_streams_per_conn
        );
        Self {
            pool_notifier: tx,
            pool_watcher: rx,
            max_streamcount: cfg.pool_max_streams_per_conn,
            // the number here is simply the number of unique src/dest keys
            // the pool is expected to track before the inner hashmap resizes.
            connected_pool: Arc::new(pingora_pool::ConnectionPool::new(50000)),
            cfg,
            socket_factory,
            cert_manager,
            drainer,
            established_conn_writelock: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn connect(&mut self, key: WorkloadKey) -> Result<Client, Error> {
        // TODO BML this may not be collision resistant
        // it may also be slow as shit
        let mut s = DefaultHasher::new();
        key.hash(&mut s);
        let hash_key = s.finish();
        let pool_key = pingora_pool::ConnectionMeta::new(
            hash_key,
            GLOBAL_CONN_COUNT.fetch_add(1, Ordering::Relaxed),
        );

        let existing_conn = self
            .first_checkout_conn_from_pool(&key, hash_key, &pool_key)
            .await;

        if existing_conn.is_some() {
            debug!("using existing conn, connect future will be dropped on the floor");
            Ok(existing_conn.unwrap())
        } else {
            // critical block - this writelocks the entire pool for all tasks/threads
            // as we check to see if anyone has inserted a sharded mutex for this key.
            // So we want to hold this for as short as possible a time, and drop it
            // before we hold it over an await.
            //
            // this is is the only block where we should hold a writelock on the whole mutex map
            {
                let mut map_write_lock = self.established_conn_writelock.write().await;
                match map_write_lock.get(&hash_key) {
                    Some(_) => {
                        debug!("already have conn for key {:#?}", hash_key);
                    }
                    None => {
                        debug!("inserting conn mutex for key {:#?}", hash_key);
                        map_write_lock.insert(hash_key, Some(Mutex::new(())));
                    }
                };
                drop(map_write_lock);
            }

            // Now we know _someone_ won the race to insert a conn mutex, we don't need a writelock
            // on the outer map anymore - so we can just readlock the outer map,
            // and get the inner mutex for this connkey that we care about.
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
            let map_read_lock = self.established_conn_writelock.read().await;
            let exist_conn_lock = map_read_lock.get(&hash_key).unwrap();
            let found_conn = match exist_conn_lock.as_ref().unwrap().try_lock() {
                Ok(_guard) => {
                    // if we get here, either we won the connlock race and can create one,
                    // or someone else won, but the streamcount for the one they added is already hit,
                    // so we should start and insert another.
                    debug!("appears we need a new conn, retaining connlock");
                    debug!("nothing else is creating a conn, make one");
                    let pool_conn = self.spawn_new_pool_conn(key.clone()).await;
                    let client = Client(
                        pool_conn?,
                        Arc::new(AtomicU16::new(0)),
                        self.max_streamcount,
                    );

                    debug!(
                        "starting new conn for key {:#?} with pk {:#?}",
                        key, pool_key
                    );
                    debug!("dropping lock");
                    Some(client)
                }
                Err(_) => {
                    // The sharded mutex for this connkey is already locked - someone else must be making a conn
                    // if they are, try to wait for it, but bail if we find one and it's got a maxed streamcount.
                    debug!("something else is creating a conn, wait for it");
                    // let waiter = self.pool_watcher.changed();
                    // tokio::pin!(waiter);

                    loop {
                        match self.pool_watcher.changed().await {
                            Ok(_) => {
                                debug!(
                                    "notified a new conn was enpooled, checking for hash {:#?}",
                                    hash_key
                                );

                                let existing_conn = self.connected_pool.get(&hash_key); // .and_then(|e_conn| {

                                //         debug!("while waiting for new conn, got existing conn for key {:#?}", key);
                                // });
                                match existing_conn {
                                    None => {
                                        debug!("got nothin");
                                        continue;
                                    }
                                    Some(e_conn) => {
                                        debug!("found existing conn after waiting");
                                        if e_conn.at_max_streamcount() {
                                            debug!("found existing conn for key {:#?}, but streamcount is maxed", key);
                                            break None;
                                        }
                                        break Some(e_conn);
                                    }
                                }
                            }
                            Err(_) => {
                                break None
                            }
                        }
                    }
                }
            };

            match found_conn {
                Some(f_conn) => {
                    self.connected_pool.put(&pool_key, f_conn.clone());
                    let _ = self.pool_notifier.send(true);
                    Ok(f_conn)
                }

                None => {
                    debug!("spawning new conn for key {:#?} to replace", key);
                    let pool_conn = self.spawn_new_pool_conn(key.clone()).await;
                    let r_conn = Client(
                        pool_conn?,
                        Arc::new(AtomicU16::new(0)),
                        self.max_streamcount,
                    );
                    self.connected_pool.put(&pool_key, r_conn.clone());
                    let _ = self.pool_notifier.send(true);
                    Ok(r_conn)
                }
            }
        }
    }
    async fn first_checkout_conn_from_pool(
        &self,
        key: &WorkloadKey,
        hash_key: u64,
        pool_key: &pingora_pool::ConnectionMeta,
    ) -> Option<Client> {
        let map_read_lock = self.established_conn_writelock.read().await;
        match map_read_lock.get(&hash_key) {
            Some(exist_conn_lock) => {
                let _conn_lock = exist_conn_lock.as_ref().unwrap().lock().await;

                debug!("getting conn for key {:#?} and hash {:#?}", key, hash_key);
                self.connected_pool.get(&hash_key).and_then(|e_conn| {
                    debug!("got existing conn for key {:#?}", key);
                    if e_conn.at_max_streamcount() {
                        debug!("got conn for key {:#?}, but streamcount is maxed", key);
                        None
                    } else {
                        self.connected_pool.put(pool_key, e_conn.clone());
                        let _ = self.pool_notifier.send(true);
                        Some(e_conn)
                    }
                })
            }
            None => None,
        }
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
        let driver_drain = self.drainer.clone();
        tokio::spawn(async move {
            debug!("starting a connection driver for {:?}", clone_key);
            tokio::select! {
                    _ = driver_drain.signaled() => {
                        debug!("draining outer HBONE connection");
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
pub struct Client(http2::SendRequest<Empty<Bytes>>, Arc<AtomicU16>, u16);

impl Client {
    pub fn at_max_streamcount(&self) -> bool {
        let curr_count = self.1.load(Ordering::Relaxed);
        debug!("checking streamcount: {curr_count}");
        if curr_count >= self.2 {
            return true;
        }
        false
    }

    pub fn send_request(
        &mut self,
        req: Request<Empty<Bytes>>,
    ) -> impl Future<Output = hyper::Result<Response<Incoming>>> {
        // TODO should we enforce streamcount per-sent-request? This would be slow.
        self.1.fetch_add(1, Ordering::Relaxed);
        self.0.send_request(req)
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
    use tracing::{error, info, Instrument};

    use ztunnel::test_helpers::*;

    use super::*;

    #[tokio::test]
    async fn test_pool_reuses_conn_for_same_key() {
        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();

        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 6,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));

        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 2).await;
        let client2 = spawn_client(pool.clone(), key1.clone(), server_addr, 2).await;
        let client3 = spawn_client(pool.clone(), key1, server_addr, 2).await;

        drop(pool);
        server_drain_signal.drain().await;
        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 1, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok());
        assert!(client3.is_ok());
    }

    #[tokio::test]
    async fn test_pool_does_not_reuse_conn_for_diff_key() {
        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        // crate::telemetry::setup_logging();

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 10,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

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

        drop(pool);
        server_drain_signal.drain().await;
        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok()); // expect this to panic - we used a new key
    }

    #[tokio::test]
    async fn test_pool_respects_per_conn_stream_limit() {
        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 3,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

        let key1 = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            src: IpAddr::from([127, 0, 0, 2]),
            dst: server_addr,
        };
        let client1 = spawn_client(pool.clone(), key1.clone(), server_addr, 4).await;
        let client2 = spawn_client(pool.clone(), key1, server_addr, 2).await;

        drop(pool);
        server_drain_signal.drain().await;

        let real_conncount = server_handle.await.unwrap();
        assert!(real_conncount == 2, "actual conncount was {real_conncount}");

        assert!(client1.is_ok());
        assert!(client2.is_ok()); // expect this to panic - same key, but stream limit of 3
    }

    #[tokio::test]
    async fn test_pool_handles_many_conns_per_key() {
        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 2,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));

        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

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
        crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 50,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

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
        let _cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        };

        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 1000,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

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
        let _cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        };

        // crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 100,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

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
        let _cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        };

        crate::telemetry::setup_logging();

        let (server_drain_signal, server_drain) = drain::channel();
        let (server_addr, server_handle) = spawn_server(server_drain.clone()).await;

        let cfg = crate::config::Config {
            local_node: Some("local-node".to_string()),
            pool_max_streams_per_conn: 100,
            ..crate::config::parse_config().unwrap()
        };
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory);
        let cert_mgr = identity::mock::new_secret_manager(Duration::from_secs(10));
        let pool = WorkloadHBONEPool::new(cfg.clone(), sock_fact, cert_mgr, server_drain);

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
                    Err(e) => error!("No upgrade {e}"),
                }
            });
            Ok::<_, Infallible>(Response::new(http_body_util::Empty::<Bytes>::new()))
        }

        let conn_count: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));
        let _drop_conn_count: Arc<AtomicU32> = Arc::new(AtomicU32::new(0));

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
