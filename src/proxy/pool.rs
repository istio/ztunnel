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

use std::hash::{Hash, Hasher};
use std::ops::{Deref, DerefMut};

use std::sync::Arc;
use std::sync::Mutex;
#[cfg(any(test, feature = "testing"))]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use rand::Rng;
use tokio::sync::Notify;
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;

use tracing::{Instrument, debug, trace};

use crate::baggage::Baggage;
use crate::config;

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
}

// PoolState is effectively the gnarly inner state stuff that needs thread/task sync.
struct PoolState {
    timeout_tx: watch::Sender<bool>,
    timeout_rx: watch::Receiver<bool>,
    connect_drain_tx: watch::Sender<bool>,
    connect_drain_rx: watch::Receiver<bool>,
    // this is effectively just a convenience data type - a rwlocked hashmap with keying and LRU drops
    // and has no actual hyper/http/connection logic.
    connected_pool: Arc<pingora_pool::ConnectionPool<PooledConnection>>,
    entries: flurry::HashMap<u64, Arc<PoolEntry>>,
    pool_unused_release_timeout: Duration,
    // This is merely a counter to track the overall number of conns this pool spawns
    // to ensure we get unique poolkeys-per-new-conn, it is not a limit
    pool_global_conn_count: AtomicI32,
    factory: Arc<dyn ConnectionFactory>,
    draining: AtomicBool,
    #[cfg(any(test, feature = "testing"))]
    synchronization_wakeups: AtomicU64,
    #[cfg(any(test, feature = "testing"))]
    unrelated_wakeups: AtomicU64,
}

struct PoolEntry {
    key: WorkloadKey,
    hash_key: u64,
    inner: Mutex<EntryInner>,
    notify: Notify,
    pooled: AtomicUsize,
}

struct EntryInner {
    state: EntryState,
    transition: u64,
    mapped: bool,
    users: usize,
    waiters: usize,
    connections: usize,
}

#[derive(Clone, Copy)]
enum EntryState {
    Empty,
    Connecting {
        failures: u8,
    },
    Backoff {
        until: Instant,
        attempts: u8,
        transition: u64,
    },
}

enum EntryAction {
    Create,
    Wait(WaiterGuard),
    Backoff(Instant, WaiterGuard),
}

struct EntryHandle {
    pool: std::sync::Weak<PoolState>,
    entry: Arc<PoolEntry>,
}

impl Drop for EntryHandle {
    fn drop(&mut self) {
        if self.entry.remove_user()
            && let Some(pool) = self.pool.upgrade()
        {
            pool.cleanup_entry(&self.entry);
        }
    }
}

struct WaiterGuard {
    entry: Arc<PoolEntry>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.entry.remove_waiter();
    }
}

struct CreationGuard {
    entry: Arc<PoolEntry>,
    active: bool,
}

struct ConnectionCheckoutGuard {
    pool: std::sync::Weak<PoolState>,
    connection: Option<PooledConnection>,
}

impl Drop for CreationGuard {
    fn drop(&mut self) {
        if self.active {
            self.entry.mark_cancelled();
        }
    }
}

impl CreationGuard {
    fn complete(&mut self) {
        self.active = false;
    }
}

impl ConnectionCheckoutGuard {
    fn new(pool: &Arc<PoolState>, connection: PooledConnection) -> Self {
        Self {
            pool: Arc::downgrade(pool),
            connection: Some(connection),
        }
    }

    fn connection(&self) -> &PooledConnection {
        self.connection
            .as_ref()
            .expect("checked-out connection must be present")
    }

    fn connection_mut(&mut self) -> &mut PooledConnection {
        self.connection
            .as_mut()
            .expect("checked-out connection must be present")
    }

    fn into_connection(mut self) -> PooledConnection {
        self.connection
            .take()
            .expect("checked-out connection must be present")
    }
}

impl Drop for ConnectionCheckoutGuard {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take()
            && let Some(pool) = self.pool.upgrade()
        {
            pool.recover_capacity(connection);
        }
    }
}

struct ConnSpawner {
    cfg: Arc<config::Config>,
    socket_factory: Arc<dyn SocketFactory + Send + Sync>,
    local_workload: Arc<LocalWorkloadInformation>,
    timeout_rx: watch::Receiver<bool>,
    crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
    metrics: Arc<crate::proxy::Metrics>,
}

#[async_trait::async_trait]
trait ConnectionFactory: Send + Sync {
    async fn new_pool_conn(&self, key: WorkloadKey) -> Result<H2ConnectClient, Error>;
}

#[cfg(test)]
struct BlockingConnectionFactory {
    started: Arc<Notify>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl ConnectionFactory for BlockingConnectionFactory {
    async fn new_pool_conn(&self, _key: WorkloadKey) -> Result<H2ConnectClient, Error> {
        self.started.notify_one();
        std::future::pending().await
    }
}

#[derive(Clone)]
struct PooledConnection {
    client: H2ConnectClient,
    meta: pingora_pool::ConnectionMeta,
    entry: Arc<PoolEntry>,
    idle_reset: Arc<IdleReset>,
}

struct IdlePeriod {
    generation: u64,
    deadline: Instant,
    evict: Arc<Notify>,
    pickup: oneshot::Receiver<bool>,
}

struct IdleReset {
    inner: Mutex<IdleResetInner>,
    notify: Notify,
    #[cfg(test)]
    waiting_without_period: Notify,
    #[cfg(test)]
    pause_checkout_after_pickup: AtomicBool,
    #[cfg(test)]
    checkout_picked_up: Notify,
}

struct IdleResetInner {
    active: bool,
    in_pool: bool,
    generation: u64,
    latest: Option<IdlePeriod>,
}

impl Deref for PooledConnection {
    type Target = H2ConnectClient;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

impl IdleReset {
    fn new() -> Self {
        Self {
            inner: Mutex::new(IdleResetInner {
                active: true,
                in_pool: false,
                generation: 0,
                latest: None,
            }),
            notify: Notify::new(),
            #[cfg(test)]
            waiting_without_period: Notify::new(),
            #[cfg(test)]
            pause_checkout_after_pickup: AtomicBool::new(false),
            #[cfg(test)]
            checkout_picked_up: Notify::new(),
        }
    }

    fn take_latest(&self) -> Option<IdlePeriod> {
        self.inner.lock().unwrap().latest.take()
    }

    fn is_active(&self) -> bool {
        self.inner.lock().unwrap().active
    }

    #[cfg(test)]
    fn pause_checkout_after_pickup(&self) {
        if self.pause_checkout_after_pickup.load(Ordering::Acquire) {
            self.checkout_picked_up.notify_waiters();
            while self.pause_checkout_after_pickup.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
        }
    }
}

impl PoolEntry {
    fn new(key: WorkloadKey, hash_key: u64) -> Self {
        Self {
            key,
            hash_key,
            inner: Mutex::new(EntryInner {
                state: EntryState::Empty,
                transition: 0,
                mapped: true,
                users: 0,
                waiters: 0,
                connections: 0,
            }),
            notify: Notify::new(),
            pooled: AtomicUsize::new(0),
        }
    }

    fn add_user(&self) {
        let mut inner = self.inner.lock().unwrap();
        debug_assert!(inner.mapped);
        inner.users += 1;
    }

    fn try_add_user(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if !inner.mapped {
            return false;
        }
        inner.users += 1;
        true
    }

    fn remove_user(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        debug_assert!(inner.users > 0);
        inner.users -= 1;
        Self::is_idle_inner(&inner)
    }

    fn add_connection(&self) {
        self.inner.lock().unwrap().connections += 1;
    }

    fn remove_connection(&self) {
        let mut inner = self.inner.lock().unwrap();
        debug_assert!(inner.connections > 0);
        inner.connections -= 1;
    }

    fn add_pooled(&self) {
        self.pooled.fetch_add(1, Ordering::Release);
    }

    fn remove_pooled(&self) {
        let previous = self
            .pooled
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |pooled| {
                pooled.checked_sub(1)
            });
        debug_assert!(previous.is_ok(), "pooled connection count underflow");
    }

    fn remove_waiter(&self) {
        let mut inner = self.inner.lock().unwrap();
        debug_assert!(inner.waiters > 0);
        inner.waiters -= 1;
    }

    fn wait_action(self: &Arc<Self>) -> EntryAction {
        let mut inner = self.inner.lock().unwrap();
        self.wait_action_locked(&mut inner)
    }

    fn wait_action_locked(self: &Arc<Self>, inner: &mut EntryInner) -> EntryAction {
        inner.waiters += 1;
        EntryAction::Wait(WaiterGuard {
            entry: self.clone(),
        })
    }

    fn next_action(self: &Arc<Self>) -> EntryAction {
        if self.pooled.load(Ordering::Acquire) > 0 {
            return self.wait_action();
        }
        let mut inner = self.inner.lock().unwrap();
        if self.pooled.load(Ordering::Acquire) > 0 {
            return self.wait_action_locked(&mut inner);
        }
        match inner.state {
            EntryState::Empty => {
                inner.transition = inner.transition.wrapping_add(1);
                inner.state = EntryState::Connecting { failures: 0 };
                EntryAction::Create
            }
            EntryState::Connecting { .. } => self.wait_action_locked(&mut inner),
            EntryState::Backoff { until, .. } if until <= Instant::now() => {
                let EntryState::Backoff { attempts, .. } = inner.state else {
                    unreachable!()
                };
                inner.transition = inner.transition.wrapping_add(1);
                inner.state = EntryState::Connecting { failures: attempts };
                EntryAction::Create
            }
            EntryState::Backoff { until, .. } => {
                inner.waiters += 1;
                EntryAction::Backoff(
                    until,
                    WaiterGuard {
                        entry: self.clone(),
                    },
                )
            }
        }
    }

    fn mark_success(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.transition = inner.transition.wrapping_add(1);
        inner.state = EntryState::Empty;
        drop(inner);
        self.notify.notify_one();
    }

    fn mark_failure(&self) -> (Instant, u64) {
        let mut inner = self.inner.lock().unwrap();
        let failures = match inner.state {
            EntryState::Connecting { failures } => failures,
            _ => 0,
        };
        let attempts = failures.saturating_add(1);
        let exponent = u32::from(attempts.saturating_sub(1).min(6));
        let base_ms = 25u64.saturating_mul(1u64 << exponent).min(1_000);
        let jitter_ms = rand::rng().random_range(0..=base_ms / 2);
        let until = Instant::now() + Duration::from_millis(base_ms + jitter_ms);
        inner.transition = inner.transition.wrapping_add(1);
        let transition = inner.transition;
        inner.state = EntryState::Backoff {
            until,
            attempts,
            transition,
        };
        drop(inner);
        self.notify.notify_waiters();
        (until, transition)
    }

    fn expire_backoff(&self, expected_transition: u64) {
        let mut inner = self.inner.lock().unwrap();
        if matches!(
            inner.state,
            EntryState::Backoff { transition, .. } if transition == expected_transition
        ) {
            inner.transition = inner.transition.wrapping_add(1);
            inner.state = EntryState::Empty;
            drop(inner);
            self.notify.notify_waiters();
        }
    }

    fn mark_cancelled(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.transition = inner.transition.wrapping_add(1);
        inner.state = EntryState::Empty;
        drop(inner);
        self.notify.notify_waiters();
    }

    fn try_tombstone_if_idle(&self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        if !inner.mapped || !Self::is_idle_inner(&inner) {
            return false;
        }
        inner.mapped = false;
        true
    }

    fn is_idle_inner(inner: &EntryInner) -> bool {
        inner.users == 0
            && inner.waiters == 0
            && inner.connections == 0
            && matches!(inner.state, EntryState::Empty)
    }
}

#[async_trait::async_trait]
impl ConnectionFactory for ConnSpawner {
    // Does nothing but spawn new conns when asked.
    async fn new_pool_conn(&self, key: WorkloadKey) -> Result<H2ConnectClient, Error> {
        self.connect(key).await
    }
}

impl ConnSpawner {
    async fn connect(&self, key: WorkloadKey) -> Result<H2ConnectClient, Error> {
        debug!("spawning new pool conn for {}", key);

        let cert = self.local_workload.fetch_certificate().await?;
        let connector = cert.outbound_connector(key.dst_id.clone(), self.crl_manager.clone())?;
        let tcp_stream = super::freebind_connect(None, key.dst, self.socket_factory.as_ref())
            .await
            .map_err(|e: io::Error| match e.kind() {
                io::ErrorKind::TimedOut => Error::MaybeHBONENetworkPolicyError(e),
                _ => e.into(),
            })?;

        let tls_stream = connector.connect(tcp_stream).await.inspect_err(|e| {
            if crate::tls::io_error_is_cert_revoked(e) {
                self.metrics
                    .record_crl_rejection(crate::proxy::metrics::Reporter::source);
            }
        })?;
        trace!("connector connected, handshaking");
        // Enforce CRL revocation on this tunnel for its whole lifetime
        let revocation = self.crl_manager.as_ref().map(|crl_manager| {
            let (_, ssl) = tls_stream.get_ref();
            let peer_identity = {
                let x509_cert = crate::tls::certificate_from_connection(ssl);
                crate::tls::identity(&x509_cert)
            };
            crl_manager.register(crate::tls::revocation::ConnRegistration::from_conn(
                ssl,
                peer_identity,
                cert.root_store(),
                webpki::KeyUsage::server_auth(),
                crate::proxy::metrics::Reporter::source,
            ))
        });
        let sender = h2::client::spawn_connection(
            self.cfg.clone(),
            tls_stream,
            self.timeout_rx.clone(),
            key,
            revocation,
        )
        .await?;
        Ok(sender)
    }
}

impl PoolState {
    fn hash_key(workload_key: &WorkloadKey) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        workload_key.hash(&mut hasher);
        hasher.finish()
    }

    #[cfg(any(test, feature = "testing"))]
    fn record_synchronization_wakeup(&self, entry: &PoolEntry, workload_key: &WorkloadKey) {
        self.synchronization_wakeups.fetch_add(1, Ordering::Relaxed);
        if &entry.key != workload_key {
            self.unrelated_wakeups.fetch_add(1, Ordering::Relaxed);
        }
    }

    // Note that "idle" in the context of this pool means "no one has asked for it or dropped it in X time, so prune it".
    //
    // Each actual H2 connection owns one idle monitor task. Repeated checkout/check-in cycles reset
    // that task with a new generation instead of spawning another task. The generation prevents an
    // expiration selected concurrently with a newer check-in from removing the newer idle period.
    fn maybe_checkin_conn(
        self: &Arc<Self>,
        conn: &PooledConnection,
        capacity_recovered: bool,
    ) -> bool {
        if self.draining.load(Ordering::Acquire) {
            return false;
        }
        if capacity_recovered {
            if !conn.has_stream_capacity() {
                return false;
            }
        } else if conn.will_be_at_max_streamcount() {
            debug!(
                "checked out connection for {:?} is now at max streamcount; removing from pool",
                conn.meta
            );
            return false;
        }

        let mut idle = conn.idle_reset.inner.lock().unwrap();
        if !idle.active || idle.in_pool {
            return false;
        }
        idle.generation = idle.generation.wrapping_add(1);
        let generation = idle.generation;
        let meta = conn.meta.clone();
        conn.entry.add_pooled();
        let (evict, pickup) = self.connected_pool.put(&meta, conn.clone());
        idle.in_pool = true;
        idle.latest = Some(IdlePeriod {
            generation,
            deadline: Instant::now() + self.pool_unused_release_timeout,
            evict,
            pickup,
        });
        drop(idle);
        conn.entry.notify.notify_one();
        conn.idle_reset.notify.notify_one();
        true
    }

    fn recover_capacity(self: &Arc<Self>, mut conn: PooledConnection) {
        if conn.ready_to_use() {
            self.maybe_checkin_conn(&conn, true);
        } else {
            let mut idle = conn.idle_reset.inner.lock().unwrap();
            idle.active = false;
            idle.latest = None;
            if idle.in_pool {
                self.connected_pool.pop_closed(&conn.meta);
                conn.entry.remove_pooled();
            }
            idle.in_pool = false;
            drop(idle);
            conn.idle_reset.notify.notify_one();
            conn.entry.notify.notify_waiters();
        }
    }

    fn entry_for_key(self: &Arc<Self>, workload_key: &WorkloadKey) -> Result<EntryHandle, Error> {
        let hash_key = Self::hash_key(workload_key);
        loop {
            let guard = self.entries.guard();
            if let Some(entry) = self.entries.get(&hash_key, &guard).cloned() {
                if entry.key != *workload_key {
                    return Err(Error::Generic(
                        "connection pool hash collision for workload key".into(),
                    ));
                }
                if entry.try_add_user() {
                    return Ok(EntryHandle {
                        pool: Arc::downgrade(self),
                        entry,
                    });
                }
                self.cleanup_entry(&entry);
                std::hint::spin_loop();
                continue;
            }

            let entry = Arc::new(PoolEntry::new(workload_key.clone(), hash_key));
            entry.add_user();
            match self.entries.try_insert(hash_key, entry.clone(), &guard) {
                Ok(_) => {
                    return Ok(EntryHandle {
                        pool: Arc::downgrade(self),
                        entry,
                    });
                }
                Err(error) => {
                    let current = error.current.clone();
                    if current.key != *workload_key {
                        return Err(Error::Generic(
                            "connection pool hash collision for workload key".into(),
                        ));
                    }
                    if current.try_add_user() {
                        return Ok(EntryHandle {
                            pool: Arc::downgrade(self),
                            entry: current,
                        });
                    }
                    self.cleanup_entry(&current);
                    std::hint::spin_loop();
                }
            }
        }
    }

    fn cleanup_entry(&self, expected: &Arc<PoolEntry>) {
        if !expected.try_tombstone_if_idle() {
            return;
        }

        let guard = self.entries.guard();
        let Some(entry) = self.entries.get(&expected.hash_key, &guard) else {
            return;
        };
        if Arc::ptr_eq(entry, expected) {
            trace!("removing unused pool entry for {}", expected.key);
            self.entries.remove(&expected.hash_key, &guard);
        }
    }

    fn begin_creation(&self, entry: &Arc<PoolEntry>) -> CreationGuard {
        CreationGuard {
            entry: entry.clone(),
            active: true,
        }
    }

    fn publish_success(
        self: &Arc<Self>,
        workload_key: &WorkloadKey,
        entry: &Arc<PoolEntry>,
        conn: H2ConnectClient,
    ) -> PooledConnection {
        let meta = pingora_pool::ConnectionMeta::new(
            entry.hash_key,
            self.pool_global_conn_count.fetch_add(1, Ordering::Relaxed),
        );
        let idle_reset = Arc::new(IdleReset::new());
        let pooled = PooledConnection {
            client: conn,
            meta,
            entry: entry.clone(),
            idle_reset: idle_reset.clone(),
        };
        entry.add_connection();
        self.maybe_checkin_conn(&pooled, false);
        tokio::spawn(
            IdleMonitor {
                pool: Arc::downgrade(self),
                entry: entry.clone(),
                meta: pooled.meta.clone(),
                idle_reset,
                connected_pool: self.connected_pool.clone(),
                timeout_rx: self.timeout_rx.clone(),
            }
            .run()
            .in_current_span(),
        );
        debug!(
            "published connection {:?} for {}",
            pooled.meta, workload_key
        );
        entry.mark_success();
        pooled
    }

    fn publish_failure(self: &Arc<Self>, workload_key: &WorkloadKey, entry: &Arc<PoolEntry>) {
        debug!("connection creation failed for {}", workload_key);
        let (until, transition) = entry.mark_failure();
        let pool = Arc::downgrade(self);
        let entry = entry.clone();
        let mut connect_drain_rx = self.connect_drain_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep_until(until) => {
                    entry.expire_backoff(transition);
                }
                _ = connect_drain_rx.changed() => {
                    entry.mark_cancelled();
                }
            }
            if let Some(pool) = pool.upgrade() {
                pool.cleanup_entry(&entry);
            }
        });
    }

    // Since we are using a hash key to do lookup on the inner pingora pool, do a get guard
    // to make sure what we pull out actually deep-equals the workload_key, to avoid *sigh* crossing the streams.
    fn guarded_get(
        &self,
        hash_key: u64,
        workload_key: &WorkloadKey,
    ) -> Result<Option<PooledConnection>, Error> {
        match self.connected_pool.get(&hash_key) {
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
        conn: PooledConnection,
        expected_key: &WorkloadKey,
    ) -> Result<PooledConnection, Error> {
        match conn.is_for_workload(expected_key) {
            Ok(()) => Ok(conn),
            Err(e) => Err(e),
        }
    }

    fn checkout_existing_conn(
        self: &Arc<Self>,
        entry: &PoolEntry,
        workload_key: &WorkloadKey,
    ) -> Result<Option<PooledConnection>, Error> {
        loop {
            match self.guarded_get(entry.hash_key, workload_key)? {
                Some(mut existing) => {
                    let idle_reset = existing.idle_reset.clone();
                    #[cfg(test)]
                    idle_reset.pause_checkout_after_pickup();
                    let mut idle = idle_reset.inner.lock().unwrap();
                    if !idle.in_pool {
                        continue;
                    }
                    idle.in_pool = false;
                    idle.generation = idle.generation.wrapping_add(1);
                    idle.latest = None;
                    if !idle.active || !existing.ready_to_use() {
                        debug!(
                            "checked out broken connection for {}, dropping it",
                            workload_key
                        );
                        idle.active = false;
                        existing.entry.remove_pooled();
                        drop(idle);
                        idle_reset.notify.notify_one();
                        existing.entry.notify.notify_waiters();
                        continue;
                    }
                    let reinserted = if !existing.will_be_at_max_streamcount() && idle.active {
                        idle.generation = idle.generation.wrapping_add(1);
                        let generation = idle.generation;
                        let meta = existing.meta.clone();
                        let (evict, pickup) = self.connected_pool.put(&meta, existing.clone());
                        idle.in_pool = true;
                        idle.latest = Some(IdlePeriod {
                            generation,
                            deadline: Instant::now() + self.pool_unused_release_timeout,
                            evict,
                            pickup,
                        });
                        true
                    } else {
                        existing.entry.remove_pooled();
                        false
                    };
                    drop(idle);
                    idle_reset.notify.notify_one();
                    if reinserted {
                        existing.entry.notify.notify_one();
                    } else {
                        existing.entry.notify.notify_waiters();
                    }
                    debug!("re-using connection for {}", workload_key);
                    return Ok(Some(existing));
                }
                None => return Ok(None),
            }
        }
    }

    fn stop_connecting(&self) {
        if self.draining.swap(true, Ordering::AcqRel) {
            return;
        }
        debug!("draining HBONE connection pool");
        let _ = self.connect_drain_tx.send(true);
        let entries = self
            .entries
            .iter(&self.entries.guard())
            .map(|entry| entry.1)
            .cloned()
            .collect::<Vec<_>>();
        for entry in entries {
            entry.mark_cancelled();
        }
    }

    fn shutdown(&self) {
        self.stop_connecting();
        let _ = self.timeout_tx.send(true);
    }
}

struct IdleMonitor {
    pool: std::sync::Weak<PoolState>,
    entry: Arc<PoolEntry>,
    meta: pingora_pool::ConnectionMeta,
    idle_reset: Arc<IdleReset>,
    connected_pool: Arc<pingora_pool::ConnectionPool<PooledConnection>>,
    timeout_rx: watch::Receiver<bool>,
}

impl IdleMonitor {
    async fn run(mut self) {
        let mut current: Option<IdlePeriod> = None;
        loop {
            let Some(mut idle) = current.take() else {
                let reset = self.idle_reset.notify.notified();
                tokio::pin!(reset);
                reset.as_mut().enable();
                if let Some(period) = self.idle_reset.take_latest() {
                    current = Some(period);
                    continue;
                }
                if !self.idle_reset.is_active() {
                    break;
                }
                #[cfg(test)]
                self.idle_reset.waiting_without_period.notify_waiters();
                tokio::select! {
                    _ = &mut reset => {
                        if !self.idle_reset.is_active() {
                            break;
                        }
                        current = self.idle_reset.take_latest();
                    }
                    drain = self.timeout_rx.changed() => {
                        if drain.is_err() || *self.timeout_rx.borrow() {
                            self.close(true);
                            break;
                        }
                    }
                }
                continue;
            };

            let expiration = tokio::time::sleep_until(idle.deadline);
            tokio::pin!(expiration);
            tokio::select! {
                biased;
                _ = self.idle_reset.notify.notified() => {
                    if !self.idle_reset.is_active() {
                        break;
                    }
                    current = self.idle_reset.take_latest();
                }
                drain = self.timeout_rx.changed() => {
                    if drain.is_err() || *self.timeout_rx.borrow() {
                        self.close(true);
                        break;
                    }
                    current = Some(idle);
                }
                _ = &mut idle.pickup => {
                    trace!("connection {:?} checked out before idle expiration", self.meta);
                }
                _ = idle.evict.notified() => {
                    trace!("connection {:?} evicted before idle expiration", self.meta);
                    self.close(false);
                    break;
                }
                _ = &mut expiration => {
                    let mut reset = self.idle_reset.inner.lock().unwrap();
                    if reset.active
                        && reset.in_pool
                        && reset.generation == idle.generation
                    {
                        debug!("connection {:?} reached its idle expiration", self.meta);
                        reset.active = false;
                        reset.in_pool = false;
                        reset.latest = None;
                        self.connected_pool.pop_closed(&self.meta);
                        self.entry.remove_pooled();
                        drop(reset);
                        self.entry.notify.notify_waiters();
                        break;
                    }
                }
            }
        }

        self.entry.remove_connection();
        if let Some(pool) = self.pool.upgrade() {
            pool.cleanup_entry(&self.entry);
        }
    }

    fn close(&self, remove_from_pool: bool) {
        let mut reset = self.idle_reset.inner.lock().unwrap();
        reset.active = false;
        reset.latest = None;
        if reset.in_pool {
            if remove_from_pool {
                self.connected_pool.pop_closed(&self.meta);
            }
            self.entry.remove_pooled();
            self.entry.notify.notify_waiters();
        }
        reset.in_pool = false;
    }
}

// When the Arc-wrapped PoolState is finally dropped, trigger the drain,
// which will terminate all connection driver spawns, as well as cancel all outstanding eviction timeout spawns
impl Drop for PoolState {
    fn drop(&mut self) {
        debug!(
            "poolstate dropping, stopping all connection drivers and cancelling all outstanding eviction timeout spawns"
        );
        self.shutdown();
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
        crl_manager: Option<Arc<crate::tls::crl::CrlManager>>,
        metrics: Arc<crate::proxy::Metrics>,
    ) -> WorkloadHBONEPool {
        let (timeout_tx, timeout_rx) = watch::channel(false);
        let (connect_drain_tx, connect_drain_rx) = watch::channel(false);
        let pool_duration = cfg.pool_unused_release_timeout;

        let spawner = ConnSpawner {
            cfg,
            socket_factory,
            local_workload,
            timeout_rx: timeout_rx.clone(),
            crl_manager,
            metrics,
        };

        Self {
            state: Arc::new(PoolState {
                timeout_tx,
                timeout_rx,
                connect_drain_tx,
                connect_drain_rx,
                connected_pool: Arc::new(pingora_pool::ConnectionPool::new(500)),
                entries: flurry::HashMap::new(),
                pool_unused_release_timeout: pool_duration,
                pool_global_conn_count: AtomicI32::new(0),
                factory: Arc::new(spawner),
                draining: AtomicBool::new(false),
                #[cfg(any(test, feature = "testing"))]
                synchronization_wakeups: AtomicU64::new(0),
                #[cfg(any(test, feature = "testing"))]
                unrelated_wakeups: AtomicU64::new(0),
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn blocking_for_test(idle: Duration) -> (Self, Arc<Notify>) {
        let started = Arc::new(Notify::new());
        let factory = Arc::new(BlockingConnectionFactory {
            started: started.clone(),
        });
        let (timeout_tx, timeout_rx) = watch::channel(false);
        let (connect_drain_tx, connect_drain_rx) = watch::channel(false);
        let pool = Self {
            state: Arc::new(PoolState {
                timeout_tx,
                timeout_rx,
                connect_drain_tx,
                connect_drain_rx,
                connected_pool: Arc::new(pingora_pool::ConnectionPool::new(500)),
                entries: flurry::HashMap::new(),
                pool_unused_release_timeout: idle,
                pool_global_conn_count: AtomicI32::new(0),
                factory,
                draining: AtomicBool::new(false),
                synchronization_wakeups: AtomicU64::new(0),
                unrelated_wakeups: AtomicU64::new(0),
            }),
        };
        (pool, started)
    }

    #[cfg(test)]
    pub(crate) fn shutdown(&self) {
        self.state.shutdown();
    }

    pub(crate) fn watch_drain(&self, drain: crate::drain::DrainWatcher) {
        let pool = self.clone();
        tokio::spawn(
            async move {
                let release = drain.wait_for_drain().await;
                match release.mode() {
                    crate::drain::DrainMode::Graceful => pool.state.stop_connecting(),
                    crate::drain::DrainMode::Immediate => pool.state.shutdown(),
                }
                drop(release);
            }
            .in_current_span(),
        );
    }

    pub async fn send_request_pooled(
        &mut self,
        workload_key: &WorkloadKey,
        request: http::Request<()>,
    ) -> Result<(H2Stream, Option<Baggage>, Option<watch::Receiver<bool>>), Error> {
        let connection = self.connect(workload_key).await?;
        let mut checkout = ConnectionCheckoutGuard::new(&self.state, connection);

        // Surface the tunnel's revocation signal so the caller can attribute a revoked teardown.
        let revoked = checkout.connection().revoked_receiver();
        let (mut stream, baggage) = checkout.connection_mut().send_request(request).await?;
        let connection = checkout.into_connection();
        let pool = Arc::downgrade(&self.state);
        stream.set_on_close(move || {
            if let Some(pool) = pool.upgrade() {
                pool.recover_capacity(connection);
            }
        });
        Ok((stream, baggage, revoked))
    }

    // Obtain a pooled connection. Will prefer to retrieve an existing conn from the pool, but
    // if none exist, or the existing conn is maxed out on streamcount, will spawn a new one,
    // even if it is to the same dest+port.
    //
    // If many `connects` request a connection to the same dest at once, all will wait until exactly
    // one connection is created, before deciding if they should create more or just use that one.
    async fn connect(&mut self, workload_key: &WorkloadKey) -> Result<PooledConnection, Error> {
        trace!("pool connect START");
        if self.state.draining.load(Ordering::Acquire) {
            return Err(Error::WorkloadHBONEPoolDraining);
        }
        let entry = self.state.entry_for_key(workload_key)?;
        let existing_conn = self
            .state
            .checkout_existing_conn(&entry.entry, workload_key)?;
        if let Some(existing) = existing_conn {
            debug!("initial attempt - found existing conn, done");
            return Ok(existing);
        }

        let mut connect_drain_rx = self.state.connect_drain_rx.clone();
        loop {
            if self.state.draining.load(Ordering::Acquire) || *connect_drain_rx.borrow() {
                return Err(Error::WorkloadHBONEPoolDraining);
            }

            let notified = entry.entry.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if let Some(existing) = self
                .state
                .checkout_existing_conn(&entry.entry, workload_key)?
            {
                debug!("found existing connection after registering waiter");
                return Ok(existing);
            }
            let action = entry.entry.next_action();

            match action {
                EntryAction::Create => {
                    let mut guard = self.state.begin_creation(&entry.entry);
                    debug!("becoming connection creator for {}", workload_key);
                    let creation = self.state.factory.new_pool_conn(workload_key.clone());
                    tokio::pin!(creation);
                    let result = tokio::select! {
                        biased;
                        changed = connect_drain_rx.changed() => {
                            let _ = changed;
                            return Err(Error::WorkloadHBONEPoolDraining);
                        }
                        result = &mut creation => result,
                    };
                    match result {
                        Ok(conn) => {
                            let client =
                                self.state.publish_success(workload_key, &entry.entry, conn);
                            guard.complete();
                            return Ok(client);
                        }
                        Err(err) => {
                            self.state.publish_failure(workload_key, &entry.entry);
                            guard.complete();
                            return Err(err);
                        }
                    }
                }
                EntryAction::Wait(_waiter) => {
                    debug!("waiting for a pool entry update for {}", workload_key);
                    tokio::select! {
                        biased;
                        changed = connect_drain_rx.changed() => {
                            let _ = changed;
                            return Err(Error::WorkloadHBONEPoolDraining);
                        }
                        _ = &mut notified => {}
                    }
                    #[cfg(any(test, feature = "testing"))]
                    self.state
                        .record_synchronization_wakeup(&entry.entry, workload_key);
                    if let Some(existing) = self
                        .state
                        .checkout_existing_conn(&entry.entry, workload_key)?
                    {
                        return Ok(existing);
                    }
                }
                EntryAction::Backoff(until, _waiter) => {
                    debug!("waiting for connection backoff for {}", workload_key);
                    let _notified = tokio::select! {
                        biased;
                        changed = connect_drain_rx.changed() => {
                            let _ = changed;
                            return Err(Error::WorkloadHBONEPoolDraining);
                        }
                        _ = &mut notified => true,
                        _ = tokio::time::sleep_until(until) => false,
                    };
                    #[cfg(any(test, feature = "testing"))]
                    if _notified {
                        self.state
                            .record_synchronization_wakeup(&entry.entry, workload_key);
                        if let Some(existing) = self
                            .state
                            .checkout_existing_conn(&entry.entry, workload_key)?
                        {
                            return Ok(existing);
                        }
                    }
                }
            }
        }
    }
}

#[cfg(feature = "testing")]
pub mod benchmarks {
    use super::{
        ConnectionFactory, PoolState, WorkloadHBONEPool,
        h2::client::{H2ConnectClient, WorkloadKey},
    };
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::watch;

    const BENCHMARK_IDLE_TIMEOUT: Duration = Duration::from_millis(10);

    struct BenchmarkFactory {
        clients: Arc<HashMap<WorkloadKey, H2ConnectClient>>,
        factory_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ConnectionFactory for BenchmarkFactory {
        async fn new_pool_conn(&self, key: WorkloadKey) -> Result<H2ConnectClient, super::Error> {
            self.factory_calls.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
            self.clients
                .get(&key)
                .cloned()
                .ok_or_else(|| std::io::Error::other("missing benchmark connection").into())
        }
    }

    pub struct ProductionPoolFixture {
        clients: Arc<HashMap<WorkloadKey, H2ConnectClient>>,
        keys: Arc<Vec<WorkloadKey>>,
    }

    impl ProductionPoolFixture {
        pub async fn new(destinations: usize) -> Self {
            Self::with_max_streams(destinations, u16::MAX).await
        }

        pub async fn with_max_streams(destinations: usize, max_streams: u16) -> Self {
            let keys = (0..destinations)
                .map(|index| WorkloadKey {
                    src_id: crate::identity::Identity::default(),
                    dst_id: vec![crate::identity::Identity::default()],
                    dst: SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::LOCALHOST),
                        10_000 + u16::try_from(index).unwrap(),
                    ),
                    src: IpAddr::V4(Ipv4Addr::LOCALHOST),
                })
                .collect::<Vec<_>>();
            let mut clients = HashMap::with_capacity(keys.len());
            for key in &keys {
                clients.insert(
                    key.clone(),
                    H2ConnectClient::benchmark_client(key.clone(), max_streams).await,
                );
            }
            Self {
                clients: Arc::new(clients),
                keys: Arc::new(keys),
            }
        }

        pub fn pool(&self) -> ProductionPool {
            let factory = Arc::new(BenchmarkFactory {
                clients: self.clients.clone(),
                factory_calls: AtomicUsize::new(0),
            });
            let (timeout_tx, timeout_rx) = watch::channel(false);
            let (connect_drain_tx, connect_drain_rx) = watch::channel(false);
            ProductionPool {
                pool: WorkloadHBONEPool {
                    state: Arc::new(PoolState {
                        timeout_tx,
                        timeout_rx,
                        connect_drain_tx,
                        connect_drain_rx,
                        connected_pool: Arc::new(pingora_pool::ConnectionPool::new(500)),
                        entries: flurry::HashMap::new(),
                        pool_unused_release_timeout: BENCHMARK_IDLE_TIMEOUT,
                        pool_global_conn_count: super::AtomicI32::new(0),
                        factory: factory.clone(),
                        draining: super::AtomicBool::new(false),
                        synchronization_wakeups: AtomicU64::new(0),
                        unrelated_wakeups: AtomicU64::new(0),
                    }),
                },
                keys: self.keys.clone(),
                factory,
            }
        }
    }

    pub struct ProductionPool {
        pool: WorkloadHBONEPool,
        keys: Arc<Vec<WorkloadKey>>,
        factory: Arc<BenchmarkFactory>,
    }

    impl ProductionPool {
        pub async fn checkout(&self, key: usize) {
            let mut pool = self.pool.clone();
            pool.connect(&self.keys[key]).await.unwrap();
        }

        pub async fn open_stream(&self, key: usize) -> crate::proxy::h2::H2Stream {
            let mut pool = self.pool.clone();
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://benchmark.invalid")
                .body(())
                .unwrap();
            pool.send_request_pooled(&self.keys[key], request)
                .await
                .unwrap()
                .0
        }

        pub fn factory_calls(&self) -> usize {
            self.factory.factory_calls.load(Ordering::Relaxed)
        }

        pub fn wakeups(&self) -> u64 {
            self.pool
                .state
                .synchronization_wakeups
                .load(Ordering::Relaxed)
        }

        pub fn unrelated_wakeups(&self) -> u64 {
            self.pool.state.unrelated_wakeups.load(Ordering::Relaxed)
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
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
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::sync::atomic::AtomicU32;
    use std::sync::{Barrier, RwLock};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
    use tokio::sync::{Semaphore, oneshot};

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

    struct MockConnectionFactory {
        clients: HashMap<WorkloadKey, H2ConnectClient>,
        calls: Mutex<HashMap<WorkloadKey, usize>>,
        failures: Mutex<HashMap<WorkloadKey, usize>>,
        blocked_key: Option<WorkloadKey>,
        release_first: Arc<Semaphore>,
    }

    impl MockConnectionFactory {
        fn new(clients: HashMap<WorkloadKey, H2ConnectClient>) -> Self {
            Self {
                clients,
                calls: Mutex::new(HashMap::new()),
                failures: Mutex::new(HashMap::new()),
                blocked_key: None,
                release_first: Arc::new(Semaphore::new(0)),
            }
        }

        fn blocking_first(mut self, key: WorkloadKey) -> Self {
            self.blocked_key = Some(key);
            self
        }

        fn fail_first(self, key: WorkloadKey, failures: usize) -> Self {
            self.failures.lock().unwrap().insert(key, failures);
            self
        }

        fn calls_for(&self, key: &WorkloadKey) -> usize {
            self.calls.lock().unwrap().get(key).copied().unwrap_or(0)
        }

        fn release_first(&self) {
            self.release_first.add_permits(1);
        }
    }

    #[async_trait::async_trait]
    impl ConnectionFactory for MockConnectionFactory {
        async fn new_pool_conn(&self, key: WorkloadKey) -> Result<H2ConnectClient, Error> {
            let call = {
                let mut calls = self.calls.lock().unwrap();
                let calls = calls.entry(key.clone()).or_default();
                *calls += 1;
                *calls
            };

            if self.blocked_key.as_ref() == Some(&key) && call == 1 {
                self.release_first
                    .acquire()
                    .await
                    .expect("test semaphore should remain open")
                    .forget();
            }

            let should_fail = {
                let mut failures = self.failures.lock().unwrap();
                match failures.get_mut(&key) {
                    Some(remaining) if *remaining > 0 => {
                        *remaining -= 1;
                        true
                    }
                    _ => false,
                }
            };
            if should_fail {
                return Err(io::Error::other("mock connection failure").into());
            }

            self.clients
                .get(&key)
                .cloned()
                .ok_or_else(|| io::Error::other("missing mock connection").into())
        }
    }

    fn pool_with_factory(idle: Duration, factory: Arc<dyn ConnectionFactory>) -> WorkloadHBONEPool {
        let (timeout_tx, timeout_rx) = watch::channel(false);
        let (connect_drain_tx, connect_drain_rx) = watch::channel(false);
        WorkloadHBONEPool {
            state: Arc::new(PoolState {
                timeout_tx,
                timeout_rx,
                connect_drain_tx,
                connect_drain_rx,
                connected_pool: Arc::new(pingora_pool::ConnectionPool::new(500)),
                entries: flurry::HashMap::new(),
                pool_unused_release_timeout: idle,
                pool_global_conn_count: AtomicI32::new(0),
                factory,
                draining: AtomicBool::new(false),
                synchronization_wakeups: AtomicU64::new(0),
                unrelated_wakeups: AtomicU64::new(0),
            }),
        }
    }

    async fn wait_for_factory_calls(
        factory: &MockConnectionFactory,
        key: &WorkloadKey,
        expected: usize,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while factory.calls_for(key) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("factory call count should advance");
    }

    async fn prebuilt_clients(
        source_pool: &WorkloadHBONEPool,
        keys: &[WorkloadKey],
    ) -> HashMap<WorkloadKey, H2ConnectClient> {
        let mut clients = HashMap::new();
        for key in keys {
            let client = source_pool
                .state
                .factory
                .new_pool_conn(key.clone())
                .await
                .expect("prebuilt connection should succeed");
            clients.insert(key.clone(), client);
        }
        clients
    }

    #[test]
    fn pool_entry_registration_is_atomic_with_cleanup() {
        let workload_key = WorkloadKey {
            src_id: Identity::default(),
            dst_id: vec![Identity::default()],
            dst: "127.0.0.1:15008".parse().unwrap(),
            src: "127.0.0.1".parse().unwrap(),
        };
        for _ in 0..1_000 {
            let entry = Arc::new(PoolEntry::new(workload_key.clone(), 1));
            let barrier = Arc::new(Barrier::new(3));
            let register = {
                let entry = entry.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    entry.try_add_user()
                })
            };
            let cleanup = {
                let entry = entry.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    entry.try_tombstone_if_idle()
                })
            };
            barrier.wait();
            let registered = register.join().unwrap();
            let tombstoned = cleanup.join().unwrap();
            assert_ne!(
                registered, tombstoned,
                "registration and cleanup must be mutually exclusive"
            );
            if registered {
                entry.remove_user();
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_same_destination_single_flight() {
        let (source_pool, srv) = setup_test(200).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory =
            Arc::new(MockConnectionFactory::new(clients).blocking_first(workload_key.clone()));
        let pool = pool_with_factory(Duration::from_secs(100), factory.clone());

        let tasks = (0..100)
            .map(|_| {
                let mut pool = pool.clone();
                let workload_key = workload_key.clone();
                tokio::spawn(async move { pool.connect(&workload_key).await })
            })
            .collect::<Vec<_>>();

        wait_for_factory_calls(&factory, &workload_key, 1).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert_eq!(factory.calls_for(&workload_key), 1);
        factory.release_first();

        let connections = tokio::time::timeout(Duration::from_secs(2), future::join_all(tasks))
            .await
            .expect("same-key waiters should not hang");
        assert!(
            connections
                .into_iter()
                .all(|result| result.unwrap().is_ok())
        );
        assert_eq!(factory.calls_for(&workload_key), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_different_destinations_progress_independently() {
        let (source_pool, srv) = setup_test(10).await;
        let key_a = key(&srv, 1);
        let key_b = key(&srv, 2);
        let clients = prebuilt_clients(&source_pool, &[key_a.clone(), key_b.clone()]).await;
        let factory = Arc::new(MockConnectionFactory::new(clients).blocking_first(key_a.clone()));
        let pool = pool_with_factory(Duration::from_secs(100), factory.clone());

        let mut pool_a = pool.clone();
        let task_a = {
            let key_a = key_a.clone();
            tokio::spawn(async move { pool_a.connect(&key_a).await })
        };
        wait_for_factory_calls(&factory, &key_a, 1).await;
        let mut waiter_pool_a = pool.clone();
        let waiter_key_a = key_a.clone();
        let waiter_a = tokio::spawn(async move { waiter_pool_a.connect(&waiter_key_a).await });
        tokio::task::yield_now().await;

        let mut pool_b = pool.clone();
        let connection_b = tokio::time::timeout(Duration::from_secs(1), pool_b.connect(&key_b))
            .await
            .expect("key B must not wait for key A")
            .expect("key B connection should succeed");
        assert_eq!(factory.calls_for(&key_b), 1);
        assert!(!task_a.is_finished());
        assert!(!waiter_a.is_finished());
        assert_eq!(
            factory.calls_for(&key_a),
            1,
            "publishing key B must not wake or advance key A"
        );

        factory.release_first();
        task_a.await.unwrap().unwrap();
        waiter_a.await.unwrap().unwrap();
        drop(connection_b);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_creator_cancellation_releases_waiters() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory =
            Arc::new(MockConnectionFactory::new(clients).blocking_first(workload_key.clone()));
        let pool = pool_with_factory(Duration::from_secs(100), factory.clone());

        let mut creator_pool = pool.clone();
        let creator_key = workload_key.clone();
        let creator = tokio::spawn(async move { creator_pool.connect(&creator_key).await });
        wait_for_factory_calls(&factory, &workload_key, 1).await;

        let mut waiter_pool = pool.clone();
        let waiter_key = workload_key.clone();
        let waiter = tokio::spawn(async move { waiter_pool.connect(&waiter_key).await });
        creator.abort();
        assert!(matches!(creator.await, Err(error) if error.is_cancelled()));

        wait_for_factory_calls(&factory, &workload_key, 2).await;
        tokio::time::timeout(Duration::from_secs(2), waiter)
            .await
            .expect("cancelled creator should release waiter")
            .unwrap()
            .unwrap();
        assert_eq!(factory.calls_for(&workload_key), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_connection_failure_releases_waiters() {
        let (source_pool, srv) = setup_test(20).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory =
            Arc::new(MockConnectionFactory::new(clients).fail_first(workload_key.clone(), 1));
        let pool = pool_with_factory(Duration::from_secs(100), factory.clone());

        let tasks = (0..20)
            .map(|_| {
                let mut pool = pool.clone();
                let workload_key = workload_key.clone();
                tokio::spawn(async move { pool.connect(&workload_key).await })
            })
            .collect::<Vec<_>>();

        let results = tokio::time::timeout(Duration::from_secs(2), future::join_all(tasks))
            .await
            .expect("failure waiters should not hang");
        let (successes, failures): (Vec<_>, Vec<_>) = results
            .into_iter()
            .map(Result::unwrap)
            .partition(Result::is_ok);
        assert_eq!(failures.len(), 1);
        assert_eq!(successes.len(), 19);
        assert_eq!(factory.calls_for(&workload_key), 2);

        let mut retry_pool = pool.clone();
        retry_pool.connect(&workload_key).await.unwrap();
        assert_eq!(factory.calls_for(&workload_key), 2);
    }

    #[tokio::test]
    async fn pool_lone_failure_backoff_expires_and_cleans_entry() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory =
            Arc::new(MockConnectionFactory::new(clients).fail_first(workload_key.clone(), 1));
        let mut pool = pool_with_factory(Duration::from_secs(100), factory);
        tokio::time::pause();

        assert!(pool.connect(&workload_key).await.is_err());
        let guard = pool.state.entries.guard();
        assert!(
            pool.state
                .entries
                .contains_key(&PoolState::hash_key(&workload_key), &guard)
        );
        drop(guard);

        tokio::time::advance(Duration::from_secs(2)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            pool.state.entries.is_empty(),
            "expired backoff without users must release its entry"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_shutdown_releases_creator_and_waiters() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory =
            Arc::new(MockConnectionFactory::new(clients).blocking_first(workload_key.clone()));
        let pool = pool_with_factory(Duration::from_secs(100), factory.clone());

        let mut creator_pool = pool.clone();
        let creator_key = workload_key.clone();
        let creator = tokio::spawn(async move { creator_pool.connect(&creator_key).await });
        wait_for_factory_calls(&factory, &workload_key, 1).await;

        let mut waiter_pool = pool.clone();
        let waiter_key = workload_key.clone();
        let waiter = tokio::spawn(async move { waiter_pool.connect(&waiter_key).await });
        tokio::task::yield_now().await;
        pool.shutdown();

        for task in [creator, waiter] {
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("pool shutdown must release connection tasks")
                .unwrap();
            assert!(matches!(result, Err(Error::WorkloadHBONEPoolDraining)));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_graceful_drain_releases_creator_and_waiters() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory =
            Arc::new(MockConnectionFactory::new(clients).blocking_first(workload_key.clone()));
        let pool = pool_with_factory(Duration::from_secs(100), factory.clone());
        let (drain_tx, drain_rx) = drain::new();
        pool.watch_drain(drain_rx);

        let mut creator_pool = pool.clone();
        let creator_key = workload_key.clone();
        let creator = tokio::spawn(async move { creator_pool.connect(&creator_key).await });
        wait_for_factory_calls(&factory, &workload_key, 1).await;

        let mut waiter_pool = pool.clone();
        let waiter_key = workload_key.clone();
        let waiter = tokio::spawn(async move { waiter_pool.connect(&waiter_key).await });
        tokio::task::yield_now().await;

        drain_tx
            .start_drain_and_wait(crate::drain::DrainMode::Graceful)
            .await;
        for task in [creator, waiter] {
            let result = tokio::time::timeout(Duration::from_secs(2), task)
                .await
                .expect("graceful drain must release connection tasks")
                .unwrap();
            assert!(matches!(result, Err(Error::WorkloadHBONEPoolDraining)));
        }
        assert!(
            !*pool.state.timeout_rx.borrow(),
            "graceful drain must not stop active H2 connection drivers"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn graceful_drain_keeps_active_hbone_stream_usable() {
        let (mut pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let request = http::Request::builder()
            .uri(srv.addr.to_string())
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap();
        let (stream, _, _) = pool
            .send_request_pooled(&workload_key, request)
            .await
            .unwrap();
        let mut stream = TokioH2Stream::new(stream);
        let mut greeting = [0; 8];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, b"poolsrv\n");

        let (drain_tx, drain_rx) = drain::new();
        pool.watch_drain(drain_rx.clone());
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stream_result_tx, stream_result_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            crate::drain::run_with_drain(
                "pool-graceful-drain-test".to_string(),
                drain_rx,
                Duration::from_secs(1),
                async move |drain, _force_shutdown| {
                    tokio::spawn(async move {
                        let _ = ready_tx.send(());
                        let release = drain.clone().wait_for_drain().await;
                        stream.write_all(b"still-open").await.unwrap();
                        let mut echoed = [0; 10];
                        stream.read_exact(&mut echoed).await.unwrap();
                        let _ = stream_result_tx.send(echoed);
                        drop(release);
                        drop(drain);
                    });
                    futures_util::future::pending::<()>().await;
                },
            )
            .await;
        });
        ready_rx.await.unwrap();
        let draining =
            tokio::spawn(drain_tx.start_drain_and_wait(crate::drain::DrainMode::Graceful));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !pool.state.draining.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pool should observe graceful drain");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream_result_rx)
                .await
                .expect("active stream should remain usable during graceful drain")
                .unwrap(),
            *b"still-open"
        );
        worker.await.unwrap();
        draining.await.unwrap();
    }

    #[tokio::test]
    async fn pool_idle_expiration_is_generation_safe() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory = Arc::new(MockConnectionFactory::new(clients));
        let mut pool = pool_with_factory(Duration::from_millis(100), factory.clone());
        tokio::time::pause();

        drop(pool.connect(&workload_key).await.unwrap());
        assert_eq!(factory.calls_for(&workload_key), 1);
        tokio::time::advance(Duration::from_millis(75)).await;

        drop(pool.connect(&workload_key).await.unwrap());
        tokio::time::advance(Duration::from_millis(50)).await;
        drop(pool.connect(&workload_key).await.unwrap());
        assert_eq!(
            factory.calls_for(&workload_key),
            1,
            "stale expiration must not remove a newer idle generation"
        );

        let guard = pool.state.entries.guard();
        let entry = pool
            .state
            .entries
            .get(&PoolState::hash_key(&workload_key), &guard)
            .cloned()
            .unwrap();
        drop(guard);
        assert_eq!(entry.inner.lock().unwrap().connections, 1);

        tokio::time::advance(Duration::from_millis(101)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            pool.state.entries.is_empty(),
            "expired connection should release its unused destination entry"
        );

        drop(pool.connect(&workload_key).await.unwrap());
        assert_eq!(factory.calls_for(&workload_key), 2);
    }

    #[tokio::test]
    async fn pool_idle_monitor_observes_reinsert_after_pickup() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory = Arc::new(MockConnectionFactory::new(clients));
        let mut pool = pool_with_factory(Duration::from_millis(100), factory);
        tokio::time::pause();

        let connection = pool.connect(&workload_key).await.unwrap();
        let idle_reset = connection.idle_reset.clone();
        drop(connection);
        tokio::time::timeout(Duration::from_secs(1), async {
            while idle_reset.inner.lock().unwrap().latest.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle monitor should consume the initial idle period");

        let waiting = idle_reset.waiting_without_period.notified();
        tokio::pin!(waiting);
        waiting.as_mut().enable();
        let picked_up = idle_reset.checkout_picked_up.notified();
        tokio::pin!(picked_up);
        picked_up.as_mut().enable();
        idle_reset
            .pause_checkout_after_pickup
            .store(true, Ordering::Release);
        let state = pool.state.clone();
        let entry = {
            let guard = state.entries.guard();
            state
                .entries
                .get(&PoolState::hash_key(&workload_key), &guard)
                .cloned()
                .unwrap()
        };
        let checkout_key = workload_key.clone();
        let checkout_entry = entry.clone();
        let checkout = tokio::task::spawn_blocking(move || {
            state.checkout_existing_conn(&checkout_entry, &checkout_key)
        });
        picked_up.await;
        waiting.await;

        idle_reset
            .pause_checkout_after_pickup
            .store(false, Ordering::Release);
        drop(checkout.await.unwrap().unwrap().unwrap());
        tokio::time::advance(Duration::from_millis(101)).await;
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            pool.state.entries.is_empty(),
            "reinserted connection should retain an active idle expiration"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pool_checkout_does_not_double_release_expired_residency() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory = Arc::new(MockConnectionFactory::new(clients));
        let mut pool = pool_with_factory(Duration::from_secs(100), factory);

        let connection = pool.connect(&workload_key).await.unwrap();
        let idle_reset = connection.idle_reset.clone();
        let entry = connection.entry.clone();
        tokio::time::timeout(Duration::from_secs(1), async {
            while idle_reset.inner.lock().unwrap().latest.is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle monitor should consume the initial idle period");

        let picked_up = idle_reset.checkout_picked_up.notified();
        tokio::pin!(picked_up);
        picked_up.as_mut().enable();
        idle_reset
            .pause_checkout_after_pickup
            .store(true, Ordering::Release);
        let state = pool.state.clone();
        let checkout_key = workload_key.clone();
        let checkout_entry = entry.clone();
        let checkout = tokio::task::spawn_blocking(move || {
            state.checkout_existing_conn(&checkout_entry, &checkout_key)
        });
        picked_up.await;

        {
            let mut idle = idle_reset.inner.lock().unwrap();
            assert!(idle.in_pool);
            idle.active = false;
            idle.in_pool = false;
            idle.latest = None;
        }
        entry.remove_pooled();
        idle_reset
            .pause_checkout_after_pickup
            .store(false, Ordering::Release);
        assert!(checkout.await.unwrap().unwrap().is_none());
        assert_eq!(entry.pooled.load(Ordering::Acquire), 0);

        idle_reset.notify.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while entry.inner.lock().unwrap().connections > 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("expired checkout race should release its idle monitor");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_request_creation_releases_connection_capacity() {
        let (source_pool, srv) = setup_test(10).await;
        let workload_key = key(&srv, 1);
        let (client, request_seen, release_response) =
            H2ConnectClient::test_client_with_blocked_response(workload_key.clone(), 1).await;
        let factory = Arc::new(MockConnectionFactory::new(HashMap::from([(
            workload_key.clone(),
            client,
        )])));
        let pool = pool_with_factory(Duration::from_millis(20), factory.clone());
        let request = http::Request::builder()
            .uri("https://cancelled-request.test")
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap();

        let request_task = {
            let mut pool = pool.clone();
            let workload_key = workload_key.clone();
            tokio::spawn(async move { pool.send_request_pooled(&workload_key, request).await })
        };
        request_seen.await.unwrap();
        request_task.abort();
        assert!(matches!(
            request_task.await,
            Err(error) if error.is_cancelled()
        ));
        drop(release_response);
        tokio::time::sleep(Duration::from_millis(10)).await;

        let retry_request = http::Request::builder()
            .uri("https://reused-request.test")
            .method(http::Method::CONNECT)
            .version(http::Version::HTTP_2)
            .body(())
            .unwrap();
        let mut retry_pool = pool.clone();
        let stream = tokio::time::timeout(
            Duration::from_secs(1),
            retry_pool.send_request_pooled(&workload_key, retry_request),
        )
        .await
        .expect("cancelled request must not strand connection capacity")
        .unwrap();
        assert_eq!(
            factory.calls_for(&workload_key),
            1,
            "the existing H2 connection should be reused after cancellation"
        );
        drop(stream);

        tokio::time::timeout(Duration::from_secs(1), async {
            while !pool.state.entries.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reused connection and entry should expire cleanly");
        drop(source_pool);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_idle_reset_keeps_one_pending_record() {
        let (source_pool, srv) = setup_test(100).await;
        let workload_key = key(&srv, 1);
        let clients = prebuilt_clients(&source_pool, std::slice::from_ref(&workload_key)).await;
        let factory = Arc::new(MockConnectionFactory::new(clients));
        let mut pool = pool_with_factory(Duration::from_secs(100), factory);

        let first = pool.connect(&workload_key).await.unwrap();
        let idle_reset = first.idle_reset.clone();
        drop(first);
        for _ in 0..1_000 {
            drop(pool.connect(&workload_key).await.unwrap());
        }

        let idle = idle_reset.inner.lock().unwrap();
        assert!(idle.active);
        assert!(idle.in_pool);
        assert!(
            idle.generation >= 1_000,
            "all resets should update the single replacement slot"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pool_randomized_lifecycle_stress_preserves_entry_invariants() {
        let (source_pool, srv) = setup_test(100).await;
        let keys = (1..=8).map(|source| key(&srv, source)).collect::<Vec<_>>();
        let clients = prebuilt_clients(&source_pool, &keys).await;
        let mut mock_factory = MockConnectionFactory::new(clients);
        for workload_key in &keys {
            mock_factory = mock_factory.fail_first(workload_key.clone(), 5);
        }
        let factory = Arc::new(mock_factory);
        let pool = pool_with_factory(Duration::from_millis(20), factory.clone());
        let mut rng = StdRng::seed_from_u64(0x5eed);
        for _ in 0..20 {
            let mut tasks = Vec::with_capacity(1_000);
            for _ in 0..1_000 {
                let workload_key = keys[rng.random_range(0..keys.len())].clone();
                let cancel = rng.random_ratio(1, 17);
                let delay_before = rng.random_range(0..=3);
                let delay_after = rng.random_range(0..=3);
                let task = {
                    let mut pool = pool.clone();
                    tokio::spawn(async move {
                        if delay_before > 0 {
                            tokio::time::sleep(Duration::from_millis(delay_before)).await;
                        }
                        let result = pool.connect(&workload_key).await;
                        if delay_after > 0 {
                            tokio::time::sleep(Duration::from_millis(delay_after)).await;
                        }
                        result
                    })
                };
                if cancel {
                    task.abort();
                }
                tasks.push(task);
            }
            let results = tokio::time::timeout(Duration::from_secs(5), future::join_all(tasks))
                .await
                .expect("stress batch should not hang");
            assert!(results.into_iter().all(|result| match result {
                Ok(Ok(_)) | Ok(Err(_)) => true,
                Err(error) => error.is_cancelled(),
            }));
            if rng.random_bool(0.5) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            } else {
                tokio::task::yield_now().await;
            }
        }
        let guard = pool.state.entries.guard();
        for (_, entry) in pool.state.entries.iter(&guard) {
            let inner = entry.inner.lock().unwrap();
            assert!(!matches!(inner.state, EntryState::Connecting { .. }));
            assert_eq!(inner.waiters, 0);
        }
        drop(guard);

        pool.shutdown();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if pool.state.entries.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("idle stress entries should be cleaned up");
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

        let (c, _baggage, _) = pool.send_request_pooled(&key.clone(), req()).await.unwrap();
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
    async fn saturated_connections_are_reused_after_capacity_returns() {
        let (pool, mut srv) = setup_test(2).await;

        let key = key(&srv, 1);

        // Pool allows 2. When we spawn 4 concurrently, we need 2 connections.
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 4).await;
        assert_opens_drops!(srv, 2, 0);

        // Both saturated connections become reusable after stream capacity returns, so only one
        // additional connection is needed for five concurrent requests.
        spawn_clients_concurrently(pool.clone(), key.clone(), srv.addr, 5).await;
        assert_opens_drops!(srv, 3, 0);

        // Once we drop the pool, all three reusable connections should close.
        drop(pool);
        assert_opens_drops!(srv, 3, 3);
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
        assert_opens_drops!(srv, 2, 0);
        drop(pool);
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
        ));
        let pool = WorkloadHBONEPool::new(
            Arc::new(cfg),
            sock_fact,
            local_workload,
            None,
            Arc::new(crate::proxy::Metrics::new(&mut Registry::default())),
        );
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
