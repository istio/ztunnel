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

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Formatter, Write};
use std::hash::{Hash, RandomState};
use std::str::FromStr;
use std::sync::Arc;

use crate::config::ProxyMode;
use async_trait::async_trait;

use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use tokio::sync::{Mutex, mpsc, watch};
use tokio::time::{Duration, Instant, sleep_until};

use crate::{strng, tls};

use super::CaClient;
use super::Error::{self, Spiffe};

use crate::state::WorkloadInfo;
use crate::strng::Strng;
use backoff::{ExponentialBackoff, backoff::Backoff};
use keyed_priority_queue::KeyedPriorityQueue;

const CERT_REFRESH_FAILURE_RETRY_DELAY_MAX_INTERVAL: Duration = Duration::from_secs(150);

/// Default trust domain to use if not otherwise specified.
pub const DEFAULT_TRUST_DOMAIN: &str = "cluster.local";

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum Identity {
    Spiffe {
        trust_domain: Strng,
        namespace: Strng,
        service_account: Strng,
    },
}

impl EncodeLabelValue for Identity {
    fn encode(&self, writer: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        writer.write_str(&self.to_string())
    }
}

impl serde::Serialize for Identity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl FromStr for Identity {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const URI_PREFIX: &str = "spiffe://";
        const SERVICE_ACCOUNT: &str = "sa";
        const NAMESPACE: &str = "ns";
        if !s.starts_with(URI_PREFIX) {
            return Err(Spiffe(s.to_string()));
        }
        let split: Vec<_> = s[URI_PREFIX.len()..].split('/').collect();
        if split.len() != 5 {
            return Err(Spiffe(s.to_string()));
        }
        if split[1] != NAMESPACE || split[3] != SERVICE_ACCOUNT {
            return Err(Spiffe(s.to_string()));
        }
        Ok(Identity::Spiffe {
            trust_domain: split[0].into(),
            namespace: split[2].into(),
            service_account: split[4].into(),
        })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Identity::Spiffe {
                trust_domain,
                namespace,
                service_account,
            } => write!(
                f,
                "spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"
            ),
        }
    }
}

impl Identity {
    pub fn from_parts(td: Strng, ns: Strng, sa: Strng) -> Identity {
        Identity::Spiffe {
            trust_domain: td,
            namespace: ns,
            service_account: sa,
        }
    }

    pub fn to_strng(self: &Identity) -> Strng {
        match self {
            Identity::Spiffe {
                trust_domain,
                namespace,
                service_account,
            } => strng::format!("spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}"),
        }
    }

    pub fn trust_domain(&self) -> Strng {
        match self {
            Identity::Spiffe { trust_domain, .. } => trust_domain.clone(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Default for Identity {
    fn default() -> Self {
        const SERVICE_ACCOUNT: &str = "ztunnel";
        const NAMESPACE: &str = "istio-system";
        Identity::Spiffe {
            trust_domain: DEFAULT_TRUST_DOMAIN.into(),
            namespace: NAMESPACE.into(),
            service_account: SERVICE_ACCOUNT.into(),
        }
    }
}

#[async_trait]
pub trait CaClientTrait: Send + Sync {
    async fn fetch_certificate(
        &self,
        req: &CertRequest,
    ) -> Result<tls::WorkloadCertificate, Error>;
}

/// A request to mint an SVID for a workload.
///
/// `identity` is always present (the SPIFFE ID being requested). `workload`
/// and `workload_uid` are optional, supplying per-pod context that providers
/// like the SPIFFE Broker need for attestation. The Istio CA provider ignores
/// the extra fields; providers added later require them.
#[derive(Debug, Clone)]
pub struct CertRequest {
    pub identity: Identity,
    pub workload: Option<Arc<WorkloadInfo>>,
    /// The Kubernetes pod UID (as delivered over ZDS from the CNI) for the
    /// requesting workload. Used by the SPIFFE Broker `KubernetesObject`
    /// attestor to build a `KubernetesObjectReference.uid`. `None` for
    /// providers that do not need it (e.g. Istio CA) or in tests.
    pub workload_uid: Option<Strng>,
}

impl CertRequest {
    /// Construct a request with only a SPIFFE identity. Used by providers
    /// (Istio CA) that do not need per-workload attestation context.
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            workload: None,
            workload_uid: None,
        }
    }
}

impl From<Identity> for CertRequest {
    fn from(identity: Identity) -> Self {
        Self::new(identity)
    }
}

impl From<&Identity> for CertRequest {
    fn from(identity: &Identity) -> Self {
        Self::new(identity.clone())
    }
}

/// Internal cache key for [`SecretManager`]. Determines whether SVIDs are
/// shared across workloads with the same identity (Istio CA semantics) or
/// kept per-workload (SPIFFE Broker semantics).
///
/// The Istio CA path always uses [`CacheKey::Identity`] which collapses all
/// pods sharing a SPIFFE ID to the same cache entry, preserving the original
/// behaviour. The Broker path uses [`CacheKey::Workload`] so two pods sharing
/// a service account each receive their own attested SVID.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum CacheKey {
    Identity(Identity),
    Workload { id: Identity, uid: Strng },
}

impl CacheKey {
    pub fn identity(&self) -> &Identity {
        match self {
            CacheKey::Identity(id) => id,
            CacheKey::Workload { id, .. } => id,
        }
    }

    /// Returns the Kubernetes pod UID for per-workload keys, or `None` for
    /// identity-only keys (Istio CA semantics).
    pub fn uid(&self) -> Option<&Strng> {
        match self {
            CacheKey::Identity(_) => None,
            CacheKey::Workload { uid, .. } => Some(uid),
        }
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CacheKey::Identity(id) => write!(f, "{id}"),
            CacheKey::Workload { id, uid } => write!(f, "{id} (uid={uid})"),
        }
    }
}

impl From<Identity> for CacheKey {
    fn from(id: Identity) -> Self {
        CacheKey::Identity(id)
    }
}

impl From<&Identity> for CacheKey {
    fn from(id: &Identity) -> Self {
        CacheKey::Identity(id.clone())
    }
}

#[derive(PartialOrd, PartialEq, Eq, Ord, Debug, Copy, Clone)]
pub enum Priority {
    // Needs to be in the order of the lowest priority.
    Background,
    Warmup,
    RealTime,
}

// Arguably this type is overloaded - it's used both for internal bookkeeping and reporting state
// to /config_dump (collect_certs). It may be the case we'll wont to fork off a similar copy in the
// future.
#[derive(Debug)]
pub enum CertState {
    // Should happen only on the first request for an Identity.
    Initializing(Priority),
    Available(Arc<tls::WorkloadCertificate>),
    // The last attempt to fetch the certificate has failed and there is no previous certificate
    // available.
    //
    // In the future it may also mean that the last available certificate has expired. Note that
    // this shouldn't change the semantics, strictly speaking - there always is a chance that the
    // certificate will expire before it is used by the caller.
    Unavailable(Error),
}

// Represents a watch::channel storing the certificate state. Contains None only during the first
// request to the CaClient.
struct CertChannel {
    // The initial value must be the last seen value, otherwise fetch_certificate may wait for the
    // certificate to refresh instead of returning a cached one. Since the Receiver is never used
    // directly (it is cloned out of here before reading) this never changes.
    rx: watch::Receiver<CertState>,
    // This struct is referenced by SecretManager, it contains both channel ends: the receiver
    // (used on the SecretManager side) and the sender (used by the background refreshing task).
    // While this makes the code simpler, do note that it makes it impossible to use sender closure
    // as an indication of the background task failing.
    tx: watch::Sender<CertState>,
    // Optional per-workload attestation context. Recorded at insertion time and reused on every
    // refresh so providers that need workload information (SPIFFE Broker) can rebuild a complete
    // `CertRequest`. Always `None` for Istio CA entries.
    workload: Option<Arc<WorkloadInfo>>,
}

#[derive(Eq, PartialEq)]
struct PendingPriority(Priority, Instant);

impl Ord for PendingPriority {
    // Lexicographical comparison but reverse the second component (Instant).
    fn cmp(&self, other: &Self) -> Ordering {
        match self.0.cmp(&other.0) {
            Ordering::Equal => other.1.cmp(&self.1),
            ne => ne,
        }
    }
}

impl PartialOrd for PendingPriority {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// Implements the actual logic behind SecretManager.
struct Worker {
    client: Box<dyn CaClientTrait>,
    // For now, certificates contain SystemTime so we need to convert it to Instant. Using Converter
    // allows us to work on Instants without referring to the current SystemTime, which allows for
    // time control in unit tests.
    //
    // TODO: Change tls::Certs to use Instant instead of SystemTime.
    time_conv: crate::time::Converter,
    // Maps each cache key to its certificate state. The variant determines whether two workloads
    // sharing a SPIFFE identity share or split cache entries (see [`CacheKey`]).
    certs: Mutex<HashMap<CacheKey, CertChannel>>,
    // How many concurrent fetch_certificate calls can be pending at a time.
    concurrency: u16,
}

impl Worker {
    fn new(
        client: Box<dyn CaClientTrait>,
        requests: mpsc::Receiver<Request>,
        cfg: SecretManagerConfig,
    ) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        if cfg.concurrency == 0 {
            panic!("concurrency cannot be 0, operations would block forever");
        }
        let worker = Arc::new(Self {
            client,
            time_conv: cfg.time_conv,
            concurrency: cfg.concurrency,
            certs: Default::default(),
        });

        // Process requests in the background. The task will terminate on its own when the
        // identities channel is dropped.
        let w = worker.clone();
        (worker, tokio::spawn(async move { w.run(requests).await }))
    }

    async fn has_id(&self, key: &CacheKey) -> bool {
        self.certs.lock().await.contains_key(key)
    }

    // Manages certificate updates. Since all the work is done in a single task, the code is
    // lock-free. This is OK as the code is I/O bound so we don't need the extra parallelism.
    async fn run(&self, mut requests: mpsc::Receiver<Request>) {
        use futures::StreamExt;
        use futures::stream::FuturesUnordered;

        #[derive(Eq, PartialEq)]
        enum Fetch {
            Processing,
            Forgetting,
        }

        // A set of futures refreshing the certificates. Each future completes with the cache key
        // for which it was invoked and a resulting certificate or error.
        let mut fetches = FuturesUnordered::new();
        // The set of cache keys for which there are pending fetches. Elements of `fetches` and
        // `processing` correspond to each other.
        let mut processing: HashMap<CacheKey, Fetch> = HashMap::new();
        // Cache keys for which we will need to refresh certificates in the future, ordered by the
        // priority and time at which the refresh needs to happen.
        //
        // Note that while the sorting criteria may seem too simple, it is in fact correct due to
        // the specifics of values inserted. Only Background priority items are ever inserted into
        // the future, for all other priorities Instant::now() is used as the scheduled time of the
        // refresh. In other words, at any point in time, there are no high-priority
        // (not Background) items scheduled to run in the future.
        let mut pending: KeyedPriorityQueue<CacheKey, PendingPriority> = KeyedPriorityQueue::new();
        // The set of pending cache keys with backoffs (i.e. pending requests that have already
        // failed at least once). Basically, each cert fetch attempt gets its own backoff.
        // This avoids delays where a fetch for one workload needlessly stalls the refetch of
        // another workload. Kept separate from the `pending` KeyedPriorityKey for convenience.
        let mut pending_backoffs_by_id: HashMap<CacheKey, ExponentialBackoff> = HashMap::new();

        'main: loop {
            let next = pending.peek().map(|(_, PendingPriority(_, ts))| *ts);
            tokio::select! {
                // Handle requests from SecretManager. Those are generally split between the
                // client-side processing (operations on the `certs` map) and the worker-side
                // processing (receiving the relevant request and taking action on it). The order
                // of processing of requests here may not match with the order the `certs` map was
                // processed by clients: it is possible for concurrent calls fetch_certificate
                // (id) and forget_certificate(id) to result in id not being present in the `certs`
                // map, but the Fetch and Forget requests arriving in the reverse order in the
                // worker here.
                //
                // For that reason, we check the `certs` map (via the has_id call) before processing
                // each request to decide if it's still relevant. After the check we are free to
                // not worry about ordering and proceed with handling the request - a contradicting
                // call made later by the client would result in another request being delivered to
                // the worker.
                res = requests.recv() => match res {
                    Some(Request::Fetch(key, pri)) => {
                        if !self.has_id(&key).await {
                            // Nobody interested in the key anymore, do nothing.
                            continue 'main;
                        }
                        match processing.get(&key) {
                            None => {
                                push_increase(&mut pending, key, PendingPriority(pri, Instant::now()));
                            },
                            Some(Fetch::Forgetting) => {
                                // Once the associated future completes, the result will be dropped
                                // instead of communicated back to the `certs` map and queued for
                                // refresh.
                                processing.insert(key, Fetch::Processing);
                            },
                            Some(Fetch::Processing) => (),
                        }
                    },
                    Some(Request::Forget(key)) => {
                        if self.has_id(&key).await {
                            // After the forget was queued, there was another request to start
                            // managing the key. Do nothing.
                            continue 'main;
                        }
                        match processing.get(&key) {
                            None => {
                                pending.remove(&key);
                            },
                            Some(Fetch::Processing) => {
                                processing.insert(key, Fetch::Forgetting);
                            },
                            Some(Fetch::Forgetting) => (),
                        }
                    },
                    None => break 'main,
                },

                // Handle fetch results.
                Some((key, res)) = fetches.next() => {
                    // Explicit binding to help inference: FuturesUnordered's element type
                    // is otherwise inferred too late within the select! macro expansion.
                    let key: CacheKey = key;
                    let id_for_trace = key.identity().clone();
                    tracing::trace!(id=%id_for_trace, "fetch complete");
                    match processing.remove(&key) {
                        Some(Fetch::Processing) => (),
                        Some(Fetch::Forgetting) => continue 'main,
                        None => unreachable!("processing should represent all fetches"),
                    }
                    let (state, refresh_at) = match res {
                        Err(err) => {
                            // Check if we should retain the existing valid certificate
                            let existing_cert_info = self.get_existing_cert_info(&key).await;

                            // Use the next backoff to determine when to retry the fetch and default
                            // to the constant value if the backoff has been reset. In the case of
                            // None we'll use the max_interval to retry the fetch. The max_interval
                            // is set to 150 seconds, otherwise next_backoff will increment the backoff
                            // value based on the current_interval, the multiplier and the randomization_factor
                            // defined earlier. In the case that we hit the max_interval, the 150 second wait
                            // time will continue for a cert until the backoff is reset by a successful fetch.
                            //
                            // The exact formula for how next backoff is calculated, per the backoff crate
                            // documentation (https://docs.rs/backoff/0.4.0/backoff/#enums), is as follows:
                            //
                            // randomized interval =
                            //     retry_interval * (random value in range [1 - randomization_factor, 1 + randomization_factor])
                            //
                            // Note that we are using a backoff-per-unique-key. This is to prevent issues
                            // when a cert cannot be fetched for one workload, but that should not stall
                            // retries for other workloads.

                            let mut keyed_backoff = match pending_backoffs_by_id.remove(&key) {
                                Some(backoff) => {
                                    backoff
                                },
                                None => {
                                    // The backoff strategy used for retrying operations. Sets the initial values for the backoff.
                                    // The values are chosen to be reasonable for the CA client to be able to recover from transient
                                    // errors.
                                    ExponentialBackoff {
                                        initial_interval: Duration::from_millis(500),
                                        current_interval: Duration::from_secs(1),
                                        // The maximum interval is set to 150 seconds, which is the maximum time the backoff will
                                        // wait to retry a cert again.
                                        max_interval: CERT_REFRESH_FAILURE_RETRY_DELAY_MAX_INTERVAL,
                                        multiplier: 2.0,
                                        randomization_factor: 0.2,
                                        ..Default::default()
                                    }
                                }
                            };
                            let retry_delay = keyed_backoff.next_backoff().unwrap_or(CERT_REFRESH_FAILURE_RETRY_DELAY_MAX_INTERVAL);
                            // Store the per-key backoff, we're gonna retry.
                            pending_backoffs_by_id.insert(key.clone(), keyed_backoff);
                            let refresh_at = Instant::now() + retry_delay;

                            match existing_cert_info {
                                // we do have a valid existing certificate, schedule retry
                                Some((valid_cert, cert_expiry_instant)) => {
                                    let effective_refresh_at = std::cmp::min(refresh_at, cert_expiry_instant);
                                    tracing::info!(id=%id_for_trace, "certificate renewal failed ({err}); retaining existing valid certificate until {:?}; next retry at {:?}", cert_expiry_instant, effective_refresh_at);
                                    (CertState::Available(valid_cert), effective_refresh_at)
                                },
                                // we don't have a valid existing certificate
                                None => {
                                    tracing::warn!(id=%id_for_trace, "certificate fetch failed ({err}) and no valid existing certificate; will retry in {retry_delay:?} (backoff capped at {CERT_REFRESH_FAILURE_RETRY_DELAY_MAX_INTERVAL:?})");
                                    (CertState::Unavailable(err), refresh_at)
                                }
                            }
                        },
                        Ok(certs) => {
                             tracing::debug!(id=%id_for_trace, "certificate fetch succeeded");
                            // Reset (pop and drop) the backoff on success.
                            pending_backoffs_by_id.remove(&key);
                            let certs: tls::WorkloadCertificate = certs; // Type annotation.
                            let refresh_at = self.time_conv.system_time_to_instant(certs.refresh_at());
                            let refresh_at = if let Some(t) = refresh_at {
                                t.into()
                            } else {
                                // Malformed certificate (not_after is way too much into the
                                // past or the future). Queue another refresh soon.
                                //
                                // TODO: This is a bit inconsistent since we still return the
                                // certificate to the caller successfully. Basically the
                                // behavior is silly, but simple and avoid panics in time math.
                                // We'll try to get rid of the SystemTime <-> Instant
                                // conversion here, so for now leaving the code as is.
                                Instant::now()
                            };
                            (CertState::Available(Arc::new(certs)), refresh_at)
                        },
                    };
                    if self.update_certs(&key, state).await {
                        push_increase(&mut pending, key, PendingPriority(Priority::Background, refresh_at));
                    }
                },
                // Initiate the next fetch.
                true = maybe_sleep_until(next), if fetches.len() < self.concurrency as usize => {
                    let (key, _) = pending.pop().expect("pending should always have an element at this point");
                    processing.insert(key.clone(), Fetch::Processing);
                    // Look up any per-workload context recorded at insertion time so providers
                    // that need it (e.g. SPIFFE Broker) can build a complete CertRequest.
                    let workload = {
                        let certs = self.certs.lock().await;
                        match certs.get(&key) {
                            Some(c) => c.workload.clone(),
                            None => None,
                        }
                    };
                    // Workload UID lives on the CacheKey itself; carrying it on
                    // CertRequest lets the KubernetesObject attestor build a
                    // KubernetesObjectReference.uid without re-plumbing.
                    let workload_uid = key.uid().cloned();
                    fetches.push(async move {
                        let req = CertRequest {
                            identity: key.identity().clone(),
                            workload,
                            workload_uid,
                        };
                        let res: Result<tls::WorkloadCertificate, Error> =
                            self.client.fetch_certificate(&req).await;
                        (key, res)
                    });
                },
            };
        }
        // SecretManager dropped, drain remaining requests and terminate background processing.
        while fetches.next().await.is_some() {}
    }

    // Returns whether the cache entry is still managed.
    async fn update_certs(&self, key: &CacheKey, certs: CertState) -> bool {
        // Both errors (lack of entry in the `certs` map and a send error) are handled the same way
        // (by returning false): either (a) there was no entry in the `certs` map due to a
        // forget_certificate call some time ago or (b) a forget_certificate call was made and
        // finished just after the lock was released (but before certs was sent)
        match self.certs.lock().await.get(key) {
            Some(state) => {
                state.tx.send(certs).expect("state.rx cannot be gone");
                true
            }
            None => false,
        }
    }

    /// Returns existing valid certificate and its expiry time, or None if unavailable/expired
    async fn get_existing_cert_info(
        &self,
        key: &CacheKey,
    ) -> Option<(Arc<tls::WorkloadCertificate>, Instant)> {
        let id = key.identity();
        if let Some(cert_channel) = self.certs.lock().await.get(key) {
            match &*cert_channel.rx.borrow() {
                CertState::Available(cert) => {
                    let now = self
                        .time_conv
                        .instant_to_system_time(std::time::Instant::now());
                    if let Some(now) = now {
                        let cert_expiry = cert.cert.expiration().not_after;

                        if now < cert_expiry {
                            if let Some(expiry_instant) =
                                self.time_conv.system_time_to_instant(cert_expiry)
                            {
                                tracing::debug!(%id, "existing certificate valid until {:?}", cert_expiry);
                                return Some((cert.clone(), expiry_instant.into()));
                            }
                        } else {
                            tracing::debug!(%id, "existing certificate expired at {:?}", cert_expiry);
                        }
                    }
                }
                _ => {
                    tracing::debug!(%id, "no valid certificate available to retain");
                }
            }
        }
        None
    }
}

// tokio::select evaluates each pattern before checking the (optional) associated condition. Work
// around that by returning false to fail the pattern match when sleep is not viable.
async fn maybe_sleep_until(till: Option<Instant>) -> bool {
    match till {
        Some(till) => {
            sleep_until(till).await;
            true
        }
        None => false,
    }
}

pub enum Request {
    Fetch(CacheKey, Priority),
    Forget(CacheKey),
}

pub struct SecretManagerConfig {
    time_conv: crate::time::Converter,
    concurrency: u16,
}

// push_increase pushes an item onto the queue if its not present, otherwise updates the priority to the
// max of (current, new).
fn push_increase<TKey: Hash + Eq, TPriority: Ord>(
    kp: &mut KeyedPriorityQueue<TKey, TPriority, RandomState>,
    key: TKey,
    priority: TPriority,
) {
    if kp.get_priority(&key).is_none_or(|p| priority > *p) {
        kp.push(key, priority);
    }
}

/// SecretManager provides a wrapper around a CaClient with caching.
#[derive(Clone)]
pub struct SecretManager {
    worker: Arc<Worker>,
    // Channel to which certificate requests are sent to. The Identity for which request is being
    // sent for must have a corresponding entry in the worker's certs map (which is where the
    // result can be read from).
    requests: mpsc::Sender<Request>,
}

impl fmt::Debug for SecretManager {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretManager").finish()
    }
}

impl SecretManager {
    pub async fn new(cfg: Arc<crate::config::Config>) -> Result<Self, Error> {
        match &cfg.ca_provider {
            crate::config::CaProvider::IstioCa => Self::new_istio_ca(cfg).await,
            #[cfg(target_os = "linux")]
            crate::config::CaProvider::SpiffeBroker(broker_cfg) => {
                Self::new_spiffe_broker(broker_cfg).await
            }
            // `validate_config` rejects `SpiffeBroker` on non-Linux at
            // startup, so the variant is statically unreachable here even
            // though the enum still carries it.
            #[cfg(not(target_os = "linux"))]
            crate::config::CaProvider::SpiffeBroker(_) => unreachable!(
                "SpiffeBroker CA provider is rejected on non-Linux by validate_config"
            ),
        }
    }

    async fn new_istio_ca(cfg: Arc<crate::config::Config>) -> Result<Self, Error> {
        let caclient = CaClient::new(
            cfg.ca_address
                .clone()
                .expect("ca_address must be set to use CA"),
            cfg.alt_ca_hostname.clone(),
            cfg.ca_root_cert.clone(),
            cfg.auth.clone(),
            cfg.proxy_mode == ProxyMode::Shared,
            cfg.secret_ttl.as_secs().try_into().unwrap_or(60 * 60 * 24),
            cfg.ca_headers.vec.clone(),
        )
        .await?;
        Ok(Self::new_with_client(caclient))
    }

    /// Build a `SecretManager` backed by the SPIFFE Broker provider.
    ///
    /// Bootstrap sequence:
    /// 1. Open the SPIFFE Workload API socket (plain UDS, no mTLS — auth'd
    ///    server-side by `SO_PEERCRED` + workload attestation) and fetch
    ///    ztunnel's own SVID via [`SvidSource::bootstrap`]. A detached
    ///    background task keeps that SVID fresh as it rotates.
    /// 2. Open an mTLS-wrapped UDS channel to the SPIFFE Broker, using the
    ///    bootstrapped SVID as both the client certificate and the trust
    ///    root for the broker's server cert.
    /// 3. Share that channel between
    ///    (a) a [`SpiffeBrokerClient`] that mints per-workload SVIDs on
    ///    demand via `SubscribeToX509SVID`, and
    ///    (b) a long-lived background subscriber that keeps a process-wide
    ///    federated trust-bundle cache fresh via
    ///    `SubscribeToX509Bundles`.
    ///
    /// Linux-only: the broker stack depends on inpod-only data structures and
    /// is rejected outside inpod by `config::validate_config`.
    #[cfg(target_os = "linux")]
    async fn new_spiffe_broker(
        broker_cfg: &crate::config::SpiffeBrokerConfig,
    ) -> Result<Self, Error> {
        use crate::config::BrokerAttestation;
        use crate::identity::broker::attestor::{KubernetesObjectAttestor, WorkloadAttestor};
        use crate::identity::broker::bundles::{TrustBundleStore, spawn_bundle_subscriber};
        use crate::identity::broker::channel::UdsGrpcChannel;
        use crate::identity::broker::client::SpiffeBrokerClient;

        let attestor: Arc<dyn WorkloadAttestor> = match broker_cfg.attestation {
            BrokerAttestation::KubernetesObject => Arc::new(KubernetesObjectAttestor),
        };

        // Step 1: bootstrap ztunnel's SVID from the Workload API.
        //
        // On a freshly started node the SPIRE agent's Workload API socket may
        // not exist yet, or ztunnel's own registration entry may not have
        // propagated, so the first attempts can fail transiently. Rather than
        // returning an error here (which turns a routine startup race into a
        // CrashLoopBackOff), retry with a capped backoff. ztunnel has no
        // liveness probe and its readiness server has not started yet, so while
        // we wait the pod simply reports NotReady and recovers automatically
        // once SPIRE is reachable.
        let svid_source = Self::bootstrap_svid_with_retry(broker_cfg).await;

        // Step 2: open the mTLS-wrapped broker channel.
        let channel = UdsGrpcChannel::new_mtls(broker_cfg.socket_path.clone(), svid_source)?;

        let bundle_store = TrustBundleStore::new();
        // Detached for the lifetime of the SecretManager (process-scoped).
        // The task reconnects on failure with capped backoff.
        spawn_bundle_subscriber(channel.clone(), Arc::clone(&bundle_store));
        let client = SpiffeBrokerClient::with_channel(
            attestor,
            channel,
            bundle_store,
            broker_cfg.timeout,
        );
        Ok(Self::new_with_client(client))
    }

    /// Bootstrap ztunnel's own SVID from the SPIFFE Workload API, retrying
    /// with a capped exponential backoff until it succeeds.
    ///
    /// At node startup the SPIRE agent (and thus its Workload API socket) may
    /// come up after ztunnel, and ztunnel's own registration entry may take a
    /// moment to propagate. Both make the first bootstrap attempts fail with
    /// transient transport/timeout/mismatch errors. Retrying in-process keeps
    /// the pod alive (it reports NotReady until ready) instead of exiting and
    /// entering CrashLoopBackOff.
    #[cfg(target_os = "linux")]
    async fn bootstrap_svid_with_retry(
        broker_cfg: &crate::config::SpiffeBrokerConfig,
    ) -> Arc<crate::identity::broker::svid_source::SvidSource> {
        use crate::identity::broker::svid_source::SvidSource;

        const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
        const MAX_BACKOFF: Duration = Duration::from_secs(30);

        let mut backoff = INITIAL_BACKOFF;
        let mut attempt: u64 = 0;
        loop {
            attempt += 1;
            match SvidSource::bootstrap(
                broker_cfg.workload_api_socket.clone(),
                broker_cfg.workload_api_spiffe_id.clone(),
            )
            .await
            {
                Ok(source) => return source,
                Err(err) => {
                    tracing::warn!(
                        attempt,
                        retry_in = ?backoff,
                        "failed to bootstrap ztunnel SVID from the SPIFFE Workload API ({err}); \
                         the SPIRE agent socket may not be ready yet. Will retry; the pod stays \
                         NotReady until this succeeds"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = std::cmp::min(backoff.saturating_mul(2), MAX_BACKOFF);
                }
            }
        }
    }

    pub fn new_with_client<C: 'static + CaClientTrait>(client: C) -> Self {
        Self::new_internal(
            Box::new(client),
            SecretManagerConfig {
                time_conv: crate::time::Converter::new(),
                concurrency: 8,
            },
        )
        .0
    }

    fn new_internal(
        client: Box<dyn CaClientTrait>,
        cfg: SecretManagerConfig,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(10);
        let (worker, handle) = Worker::new(client, rx, cfg);
        (
            Self {
                worker,
                requests: tx,
            },
            handle,
        )
    }

    async fn post(&self, req: Request) {
        if let Err(e) = self.requests.send(req).await {
            unreachable!("SecretManager worker died: {e}");
        }
    }

    async fn start_fetch(
        &self,
        id: &Identity,
        pri: Priority,
    ) -> Result<watch::Receiver<CertState>, Error> {
        // Public API entry-point: SVIDs are keyed by Identity only (no per-workload split).
        // This preserves the original Istio CA cache discipline where pods sharing a SPIFFE
        // identity share the same SVID.
        self.start_fetch_with_key(CacheKey::Identity(id.clone()), None, pri)
            .await
    }

    async fn start_fetch_with_key(
        &self,
        key: CacheKey,
        workload: Option<Arc<WorkloadInfo>>,
        pri: Priority,
    ) -> Result<watch::Receiver<CertState>, Error> {
        let mut certs = self.worker.certs.lock().await;
        match certs.get(&key) {
            // Key found in cache and is already being refreshed. Bump the priority if needed.
            Some(st) => {
                let rx = st.rx.clone();
                drop(certs);

                if let Some(existing_pri) = init_pri(&rx)
                    && pri > existing_pri
                {
                    self.post(Request::Fetch(key, pri)).await;
                }
                Ok(rx)
            }
            // New key, start managing it and return the newly created channel.
            None => {
                let (tx, rx) = watch::channel(CertState::Initializing(pri));
                certs.insert(
                    key.clone(),
                    CertChannel {
                        rx: rx.clone(),
                        tx,
                        workload,
                    },
                );
                drop(certs);
                // Notify the background worker to start refreshing the certificate.
                self.post(Request::Fetch(key, pri)).await;
                Ok(rx)
            }
        }
    }

    async fn wait(
        &self,
        mut rx: watch::Receiver<CertState>,
    ) -> Result<Arc<tls::WorkloadCertificate>, Error> {
        loop {
            tokio::select! {
                // Wait for the initial value if not ready yet.
                res = rx.changed() => match res {
                    Ok(()) => match *rx.borrow() {
                        CertState::Unavailable(ref err) => return Err(err.to_owned()),
                        CertState::Available(ref certs) => return Ok(certs.to_owned()),
                        // Another call bumped up the priority, but still fetching the first
                        // certificate.
                        CertState::Initializing(_) => (),
                    },
                    Err(_) => return Err(Error::Forgotten),
                },
                // Ideally we'd detect it by rx.changed() failing above, but making sure that senders
                // are owned by the background worker (and so drop on panic/other error) complicates
                // the code.
                _ = self.requests.closed() => unreachable!("SecretManager worker died: requests channel is closed"),
            }
        }
    }

    pub async fn fetch_certificate_pri(
        &self,
        id: &Identity,
        pri: Priority,
    ) -> Result<Arc<tls::WorkloadCertificate>, Error> {
        // This method is intentionally left simple, since unit tests are based on start_fetch
        // and wait. Any changes should go to one of those two methods, and if that proves
        // impossible - unit testing strategy may need to be rethinked.
        self.wait(self.start_fetch(id, pri).await?).await
    }

    pub async fn fetch_certificate(
        &self,
        id: &Identity,
    ) -> Result<Arc<tls::WorkloadCertificate>, Error> {
        self.fetch_certificate_pri(id, Priority::RealTime).await
    }

    /// Fetch (or wait for) the SVID for `id`, supplying the per-workload
    /// context that the SPIFFE Broker provider's attestor needs.
    ///
    /// `workload`, `uid`, and `netns` are recorded on the cache entry and
    /// forwarded into the [`CertRequest`] handed to the underlying
    /// `CaClientTrait`. The cache key is `CacheKey::Workload { id, uid }`
    /// so two pods sharing a SPIFFE identity each get their own attested
    /// SVID, rather than racing for a shared one.
    ///
    /// Callers should only use this method when the configured provider is
    /// the SPIFFE Broker; the Istio CA path should keep using
    /// [`Self::fetch_certificate`] so SVIDs continue to be deduped across
    /// pods that share an identity.
    pub async fn fetch_workload_certificate(
        &self,
        id: &Identity,
        workload: Arc<WorkloadInfo>,
        uid: Strng,
    ) -> Result<Arc<tls::WorkloadCertificate>, Error> {
        let key = CacheKey::Workload {
            id: id.clone(),
            uid,
        };
        let rx = self
            .start_fetch_with_key(key, Some(workload), Priority::RealTime)
            .await?;
        self.wait(rx).await
    }

    pub async fn forget_certificate(&self, id: &Identity) {
        // TODO: consider keeping the cert around for a minute or so to avoid churn
        // We would ideally drop any pending or new requests to rotate.
        let key = CacheKey::Identity(id.clone());
        if self.worker.certs.lock().await.remove(&key).is_some() {
            self.post(Request::Forget(key)).await;
        }
    }

    // TODO(qfel): It would be much nicer to have something like map_certs returning an iterator,
    // but due to locking that would require a self-referential type.
    pub async fn collect_certs<R>(&self, f: impl Fn(&Identity, &CertState) -> R) -> Vec<R> {
        let mut ret = Vec::new();
        for (key, chan) in self.worker.certs.lock().await.iter() {
            ret.push(f(key.identity(), &chan.rx.borrow()));
        }
        ret
    }
}

// Matches CertState::Initializing(pri) from a Receiver, wrapped in a function to make borrow
// lifetimes more manageable.
fn init_pri(rx: &watch::Receiver<CertState>) -> Option<Priority> {
    match *rx.borrow() {
        CertState::Initializing(pri) => Some(pri),
        _ => None,
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod mock {
    use std::{
        sync::Arc,
        time::{Duration, SystemTime},
    };

    use crate::identity::caclient::mock::{self, CaClient as MockCaClient};

    use super::SecretManager;

    pub struct Config {
        pub cert_lifetime: Duration,
        pub fetch_latency: Duration,
        pub epoch: Option<SystemTime>,
    }

    pub fn new_secret_manager(cert_lifetime: Duration) -> Arc<SecretManager> {
        new_secret_manager_cfg(Config {
            cert_lifetime,
            fetch_latency: Duration::ZERO,
            epoch: None,
        })
    }

    // Like `new_secret_manager` but also returns a clone of the underlying mock
    // CaClient so tests can inspect what was requested (e.g. whether each fetch
    // carried WorkloadInfo). MockCaClient is cheap to clone (Arc-backed).
    pub fn new_secret_manager_with_client(
        cert_lifetime: Duration,
    ) -> (Arc<SecretManager>, MockCaClient) {
        let time_conv = crate::time::Converter::new_at(SystemTime::now());
        let client = MockCaClient::new(mock::ClientConfig {
            cert_lifetime,
            fetch_latency: Duration::ZERO,
            time_conv: time_conv.clone(),
        });
        let sm = Arc::new(
            SecretManager::new_internal(
                Box::new(client.clone()),
                super::SecretManagerConfig {
                    time_conv,
                    concurrency: 2,
                },
            )
            .0,
        );
        (sm, client)
    }

    // There is no need to return Arc, but most callers want one so it simplifies the code - and we
    // don't care about the extra overhead in tests.
    pub fn new_secret_manager_cfg(cfg: Config) -> Arc<SecretManager> {
        let time_conv = crate::time::Converter::new_at(cfg.epoch.unwrap_or_else(SystemTime::now));
        let client = MockCaClient::new(mock::ClientConfig {
            cert_lifetime: cfg.cert_lifetime,
            fetch_latency: cfg.fetch_latency,
            time_conv: time_conv.clone(),
        });
        Arc::new(
            SecretManager::new_internal(
                Box::new(client),
                super::SecretManagerConfig {
                    time_conv,
                    concurrency: 2,
                },
            )
            .0,
        )
    }

    impl SecretManager {
        pub async fn cache_len(&self) -> usize {
            self.worker.certs.lock().await.len()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use matches::assert_matches;

    use crate::identity::caclient::mock::CaClient as MockCaClient;
    use crate::identity::{self, *};
    use crate::strng;

    use super::{mock, *};

    async fn stress_many_ids(sm: Arc<SecretManager>, iterations: u32) {
        for i in 0..iterations {
            let id = identity::Identity::Spiffe {
                trust_domain: "cluster.local".into(),
                namespace: "istio-system".into(),
                service_account: strng::format!("ztunnel{i}"),
            };
            sm.fetch_certificate(&id)
                .await
                .expect("Didn't get a cert as expected.");
        }
    }

    async fn stress_single_id(sm: Arc<SecretManager>, id: Identity, dur: Duration) {
        let start_time = time::Instant::now();
        loop {
            let current_time = time::Instant::now();
            if current_time - start_time > dur {
                break;
            }
            sm.fetch_certificate(&id)
                .await
                .expect("Didn't get a cert as expected.");
            tokio::time::sleep(Duration::from_micros(500)).await;
        }
    }

    async fn verify_cert_updates(sm: Arc<SecretManager>, id: Identity) {
        let current_cert = sm
            .fetch_certificate(&id)
            .await
            .expect("Didn't get a cert as expected.");
        // We should loop until we get a new cert provisioned
        loop {
            let new_cert = sm
                .fetch_certificate(&id)
                .await
                .expect("Didn't get a cert as expected.");

            if current_cert.cert.serial() != new_cert.cert.serial() {
                let new = new_cert.cert.expiration().not_before;
                let old = current_cert.cert.expiration().not_before;
                assert!(old < new, "new cert should be newer");
                return;
            }
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_stress_caching() {
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let secret_manager = mock::new_secret_manager(Duration::from_millis(50));

        for _n in 0..8 {
            tasks.push(tokio::spawn(stress_many_ids(secret_manager.clone(), 100)));
        }
        let results = futures::future::join_all(tasks).await;
        for result in results.iter() {
            assert!(result.is_ok());
        }
        assert_eq!(100, secret_manager.cache_len().await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_cache_refresh() {
        let test_dur = Duration::from_millis(200);

        let id: Identity = Default::default();

        // Certs added to the cache should be refreshed every 25 millis
        let cert_lifetime = Duration::from_millis(50);
        let secret_manager = mock::new_secret_manager(cert_lifetime);

        // Start spamming fetches for that cert.
        for _n in 0..3 {
            tokio::spawn(stress_single_id(
                secret_manager.clone(),
                id.clone(),
                test_dur,
            ));
        }

        tokio::time::timeout(
            Duration::from_secs(2),
            verify_cert_updates(secret_manager.clone(), id.clone()),
        )
        .await
        .unwrap();
    }

    // Regression test for the SPIFFE Broker (workload-keyed) path: a cert
    // fetched via `fetch_workload_certificate` must keep rotating in the
    // background, and every fetch — initial and each refresh — must carry
    // WorkloadInfo. The broker's KubernetesObject attestor requires it on
    // every call, so dropping it on refresh would stall rotation and let the
    // SVID expire.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_workload_keyed_cert_rotation_carries_workload() {
        use crate::state::WorkloadInfo;

        // Short lifetime so the background refresh (at half-life) fires quickly.
        let cert_lifetime = Duration::from_millis(50);
        let (sm, client) = mock::new_secret_manager_with_client(cert_lifetime);

        let id = Identity::Spiffe {
            trust_domain: "cluster.local".into(),
            namespace: "ztunnel-broker-test".into(),
            service_account: "probe".into(),
        };
        let workload = Arc::new(WorkloadInfo::new(
            "probe-a".to_string(),
            "ztunnel-broker-test".to_string(),
            "probe".to_string(),
        ));
        let uid: crate::strng::Strng = "pod-uid-1".into();

        let first = sm
            .fetch_workload_certificate(&id, workload.clone(), uid.clone())
            .await
            .expect("initial workload cert");

        // Wait until the background refresh rotates the cert (serial changes).
        // The repeated fetches here hit the cached entry and do not trigger new
        // fetches themselves, so any rotation observed comes from the background
        // refresh task.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let cur = sm
                    .fetch_workload_certificate(&id, workload.clone(), uid.clone())
                    .await
                    .expect("workload cert");
                if cur.cert.serial() != first.cert.serial() {
                    let new = cur.cert.expiration().not_before;
                    let old = first.cert.expiration().not_before;
                    assert!(old < new, "rotated cert should be newer");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("workload cert should rotate within the timeout");

        // Every fetch (initial + each background refresh) must have carried
        // WorkloadInfo; otherwise the broker attestor would reject the request.
        let presence = client.workload_present().await;
        assert!(
            presence.len() >= 2,
            "expected at least one background refresh, got fetches: {presence:?}"
        );
        assert!(
            presence.iter().all(|&p| p),
            "every fetch must carry workload context: {presence:?}"
        );
    }

    fn collect_strings<T: IntoIterator>(xs: T) -> Vec<String>
    where
        T::Item: ToString,
    {
        xs.into_iter().map(|x| x.to_string()).collect()
    }

    const NANOSEC: Duration = Duration::from_nanos(1);
    const MILLISEC: Duration = Duration::from_millis(1);
    const SEC: Duration = Duration::from_secs(1);
    const CERT_HALFLIFE: Duration = Duration::from_secs(50);

    // Represents common test case setup.
    struct Test {
        secret_manager: Arc<SecretManager>,
        caclient: MockCaClient,
        worker: tokio::task::JoinHandle<()>,
    }

    impl Test {
        // Deconstructs the Test into the background worker handle. This drops the
        // underlying SecretManager so that the underlying worker should terminate soon after this
        // call.
        fn into_worker(self) -> tokio::task::JoinHandle<()> {
            self.worker
        }

        // Consume the SecretManager and wait for the background worker to finish.
        async fn tear_down(self) {
            self.into_worker().await.unwrap();
        }
    }

    fn setup(concurrency: u16) -> Test {
        // Tests that use this function rely on Tokio's test time pause and auto-advance. It gets a
        // bit tricky so a few things to remember:
        //  - When *all* futures are blocked waiting for a specific time, the runtime will
        //    auto-advance the timer to ~that time.
        //  - Tokio's time functions have millisecond granularity, so sleeping 1ns results in a 1ms
        //    clock skip.
        //  - In practice, sleep calls add some number of microseconds and then round down to the
        //    nearest millisecond. That means eg. sleep(1ms) will advance the timer by 2ms while
        //    sleep(600us) will advance the timer by only 1ms.
        let time_conv = crate::time::Converter::new();
        let caclient = MockCaClient::new(caclient::mock::ClientConfig {
            time_conv: time_conv.clone(),
            fetch_latency: SEC,
            cert_lifetime: 2 * CERT_HALFLIFE,
        });
        let (secret_manager, worker) = SecretManager::new_internal(
            Box::new(caclient.clone()),
            SecretManagerConfig {
                time_conv,
                concurrency,
            },
        );
        Test {
            worker,
            caclient,
            secret_manager: Arc::new(secret_manager),
        }
    }

    fn identity(name: &str) -> Identity {
        Identity::Spiffe {
            trust_domain: "test".into(),
            namespace: "test".into(),
            service_account: name.into(),
        }
    }

    fn identity_n(name: &str, n: u8) -> Identity {
        Identity::Spiffe {
            trust_domain: "test".into(),
            namespace: "test".into(),
            service_account: strng::format!("{name}{n}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_priority() {
        let test = setup(1);

        let requests = vec![
            (identity("id1"), Priority::Background),
            (identity("id2"), Priority::Background),
            (identity("id3"), Priority::Warmup),
            (identity("id4"), Priority::RealTime),
        ];
        let expected = vec![
            identity("id1"),
            identity("id4"),
            identity("id3"),
            identity("id2"),
        ];

        // Capture the start time of the test
        let start = Instant::now();
        let mut tasks = Vec::new();
        for (id, pri) in requests {
            // Force the background worker to proceed as far as possible without sleeping
            // (which happens in CaClient). This is technically not needed before the first
            // SecretManager call but putting it here makes for simpler computation later on.
            tokio::time::sleep(NANOSEC).await;
            let sm = test.secret_manager.clone();
            let rx = sm.start_fetch(&id, pri).await.unwrap();
            tasks.push(tokio::spawn(async move { sm.wait(rx).await }));
            // Now the request has either started (for the first request) or is queued in the
            // background worker.
        }
        // Process all pending requests.
        for result in futures::future::join_all(tasks).await {
            assert_matches!(result, Ok(Ok(_)));
        }

        // Ensure all requests have been issued in the expected order.
        assert_eq!(
            collect_strings(test.caclient.fetches().await),
            collect_strings(&expected),
        );

        test.caclient.clear_fetches().await;
        // Certificates should start refreshing at start + CERT_HALFLIFE, so just before that there
        // should be no new CaClient calls.
        tokio::time::sleep_until(start + CERT_HALFLIFE - MILLISEC).await;
        assert!(test.caclient.fetches().await.is_empty());

        // Each certificate request is delayed by 1ms, and each CaClient call takes 1s. So CaClient
        // calls complete at 1s1ms, 2s2ms, and so on. Wait till the last CaClient call completion +
        // CERT_HALFLIFE to ensure all background refreshes have been issues, and then an extra
        // second to ensure the last one has completed.
        let num_ids = expected.len() as u32;
        tokio::time::sleep_until(start + CERT_HALFLIFE + num_ids * (SEC + MILLISEC) + SEC).await;
        assert_eq!(
            collect_strings(test.caclient.fetches().await),
            collect_strings(&expected),
        );

        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_warmup_new() {
        let test = setup(1);

        // Capture the start time of the test
        let mut tasks = Vec::new();
        for i in 1..5 {
            let sm = test.secret_manager.clone();
            tasks.push(tokio::spawn(async move {
                sm.fetch_certificate_pri(&identity_n("warmup-", i), Priority::Warmup)
                    .await
                    .unwrap();
            }));
        }
        // Ensure all requests are executing/queued in the background worker.
        tokio::time::sleep(NANOSEC).await;
        test.secret_manager
            .fetch_certificate_pri(&identity("realtime"), Priority::RealTime)
            .await
            .unwrap();
        assert_eq!(
            collect_strings(test.caclient.fetches().await),
            collect_strings(vec![identity("warmup-1"), identity("realtime")]),
        );

        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_warmup_existing() {
        let test = setup(1);

        let mut fetches = Vec::new();
        for i in 1..5 {
            let sm = test.secret_manager.clone();
            fetches.push(tokio::spawn(async move {
                sm.fetch_certificate_pri(&identity_n("warmup-", i), Priority::Warmup)
                    .await
            }));
            // Make sure that fetch order is well-defined (each fetch has a different timestamp).
            // Also ensures that upon exit of the loop, the first fetch is already being processed
            // while the remaining ones have proceeded as far as they could and are now blocked
            // waiting on available workers.
            tokio::time::sleep(MILLISEC).await;
        }
        test.secret_manager
            .fetch_certificate_pri(&identity("warmup-4"), Priority::RealTime)
            .await
            .unwrap();

        assert_eq!(
            collect_strings(test.caclient.fetches().await),
            collect_strings(vec![identity("warmup-1"), identity("warmup-4")]),
        );

        for result in futures::future::join_all(fetches).await {
            assert_matches!(result, Ok(Ok(_)));
        }
        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_duplicate_requests() {
        let test = setup(1);
        let id = identity("id1");
        let mut rxs = Vec::new();
        for _ in 1..5 {
            let rx = test
                .secret_manager
                .start_fetch(&id, Priority::RealTime)
                .await
                .unwrap();
            rxs.push(rx);
        }
        let mut rxs_iter = rxs.into_iter();
        let want = test
            .secret_manager
            .wait(rxs_iter.next().unwrap())
            .await
            .unwrap();
        for rx in rxs_iter {
            let got = test.secret_manager.wait(rx).await.unwrap();
            assert!(Arc::ptr_eq(&want, &got));
        }
        assert_eq!(test.caclient.fetches().await.len(), 1);

        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_concurrency() {
        let start = Instant::now();
        let test = setup(4);
        let mut futs = Vec::new();
        for i in 0..4 {
            let id = identity_n("id-", i);
            futs.push(async {
                let id2: Identity = id;
                test.secret_manager
                    .fetch_certificate_pri(&id2, Priority::RealTime)
                    .await
            });
        }
        for result in futures::future::join_all(futs).await {
            assert_matches!(result, Ok(_));
        }
        assert_eq!(Instant::now().duration_since(start), SEC);
        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unused_cleanup() {
        setup(1).tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_forget_pending() {
        let test = setup(1);
        let start = Instant::now();
        let sm = test.secret_manager.clone();

        let fetch = tokio::spawn(async move { sm.fetch_certificate(&identity("test")).await });
        // Proceed the fetch till it blocks waiting for the worker.
        tokio::time::sleep_until(start + NANOSEC).await;
        test.secret_manager
            .forget_certificate(&identity("test"))
            .await;

        assert_eq!(test.secret_manager.cache_len().await, 0);
        assert_matches!(fetch.await.unwrap(), Err(Error::Forgotten));
        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_forget() {
        let test = setup(1);
        let _start = Instant::now();
        let sm = test.secret_manager.clone();

        let fetch = tokio::spawn(async move { sm.fetch_certificate(&identity("test")).await });
        let _ = fetch.await.unwrap();
        assert_eq!(test.secret_manager.cache_len().await, 1);
        test.secret_manager
            .forget_certificate(&identity("test"))
            .await;

        assert_eq!(test.secret_manager.cache_len().await, 0);
        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_backoff_resets_on_successful_fetch_after_failure() {
        let mut test = setup(1);
        let id = identity("test");
        let sm = test.secret_manager.clone();
        test.caclient.set_error(true).await;
        assert!(sm.fetch_certificate(&id).await.is_err());
        test.caclient.set_error(false).await;
        assert!(sm.fetch_certificate(&id).await.is_err());
        tokio::time::sleep(SEC * 3).await;
        assert!(sm.fetch_certificate(&id).await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn test_get_existing_cert_info_basic() {
        let test = setup(1);
        let id = identity("basic-test");
        let info = test
            .secret_manager
            .worker
            .get_existing_cert_info(&CacheKey::Identity(id))
            .await;
        assert!(info.is_none());

        // cleanup
        test.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_certificate_retention_on_refresh_failure() {
        let mut test = setup(1);
        let id = identity("retention-test");
        let start = Instant::now();

        // get initial certificate
        let initial_cert = test.secret_manager.fetch_certificate(&id).await.unwrap();
        let initial_serial = initial_cert.cert.serial().clone();
        let initial_fetch_count = test.caclient.fetches().await.len();

        // simulate ca errors
        test.caclient.set_error(true).await;
        assert!(
            test.caclient
                .fetch_certificate(&CertRequest::new(id.clone()))
                .await
                .is_err()
        );

        // wait for background refresh
        tokio::time::sleep_until(start + CERT_HALFLIFE + SEC).await;

        // verify background refresh was attempted and valid certs were retained
        let post_refresh_fetch_count = test.caclient.fetches().await.len();
        let current_cert = test.secret_manager.fetch_certificate(&id).await.unwrap();
        let current_serial = current_cert.cert.serial().clone();

        assert!(post_refresh_fetch_count > initial_fetch_count);
        assert_eq!(initial_serial, current_serial);

        test.tear_down().await;
    }

    #[test]
    fn identity_from_string() {
        assert_eq!(
            Identity::from_str("spiffe://cluster.local/ns/namespace/sa/service-account").ok(),
            Some(Identity::Spiffe {
                trust_domain: "cluster.local".into(),
                namespace: "namespace".into(),
                service_account: "service-account".into(),
            })
        );
        assert_eq!(
            Identity::from_str("spiffe://td/ns/ns/sa/sa").ok(),
            Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "ns".into(),
                service_account: "sa".into(),
            })
        );
        assert_eq!(
            Identity::from_str("spiffe://td.with.dots/ns/ns.with.dots/sa/sa.with.dots").ok(),
            Some(Identity::Spiffe {
                trust_domain: "td.with.dots".into(),
                namespace: "ns.with.dots".into(),
                service_account: "sa.with.dots".into(),
            })
        );
        assert_eq!(
            Identity::from_str("spiffe://td/ns//sa/").ok(),
            Some(Identity::Spiffe {
                trust_domain: "td".into(),
                namespace: "".into(),
                service_account: "".into()
            })
        );
        assert_matches!(Identity::from_str("td/ns/ns/sa/sa"), Err(_));
        assert_matches!(Identity::from_str("spiffe://td/ns/ns/sa"), Err(_));
        assert_matches!(Identity::from_str("spiffe://td/ns/ns/sa/sa/"), Err(_));
        assert_matches!(Identity::from_str("spiffe://td/ns/ns/foobar/sa/"), Err(_));
    }
}
