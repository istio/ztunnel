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
use std::str::FromStr;
use std::sync::Arc;

use crate::config::ProxyMode;
use async_trait::async_trait;

use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{sleep_until, Duration, Instant};

use crate::tls;

use super::CaClient;
use super::Error::{self, Spiffe};

const CERT_REFRESH_FAILURE_RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub enum Identity {
    Spiffe {
        trust_domain: String,
        namespace: String,
        service_account: String,
    },
}

impl EncodeLabelValue for Identity {
    fn encode(&self, writer: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        writer.write_str(&self.to_string())
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
            trust_domain: split[0].to_string(),
            namespace: split[2].to_string(),
            service_account: split[4].to_string(),
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

impl Default for Identity {
    fn default() -> Self {
        const TRUST_DOMAIN: &str = "cluster.local";
        const SERVICE_ACCOUNT: &str = "ztunnel";
        const NAMESPACE: &str = "istio-system";
        Identity::Spiffe {
            trust_domain: TRUST_DOMAIN.to_string(),
            namespace: NAMESPACE.to_string(),
            service_account: SERVICE_ACCOUNT.to_string(),
        }
    }
}

#[async_trait]
pub trait CaClientTrait: Send + Sync {
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::WorkloadCertificate, Error>;
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
    // Maps Identity to the certificate state.
    certs: Mutex<HashMap<Identity, CertChannel>>,
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

    async fn has_id(&self, id: &Identity) -> bool {
        self.certs.lock().await.contains_key(id)
    }

    // Manages certificate updates. Since all the work is done in a single task, the code is
    // lock-free. This is OK as the code is I/O bound so we don't need the extra parallelism.
    async fn run(&self, mut requests: mpsc::Receiver<Request>) {
        use futures::stream::FuturesUnordered;
        use futures::StreamExt;
        use priority_queue::PriorityQueue;

        #[derive(Eq, PartialEq)]
        enum Fetch {
            Processing,
            Forgetting,
        }

        // A set of futures refreshing the certificates. Each future completes with the identity for
        // which it was invoked and a resulting certificate or error.
        let mut fetches = FuturesUnordered::new();
        // The set of identities for which there are pending fetches. Elements of `fetches` and
        // `processing` correspond to each other.
        let mut processing: HashMap<Identity, Fetch> = HashMap::new();
        // Identities for which we will need to refresh certificates in the future, ordered by the
        // priority and time at which the refresh needs to happen.
        //
        // Note that while the sorting criteria may seem too simple, it is in fact correct due to
        // the specifics of values inserted. Only Background priority items are ever inserted into
        // the future, for all other priorities Instant::now() is used as the scheduled time of the
        // refresh. In other words, at any point in time, there are no high-priority
        // (not Background) items scheduled to run in the future.
        let mut pending: PriorityQueue<Identity, PendingPriority> = PriorityQueue::new();

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
                    Some(Request::Fetch(id, pri)) => {
                        if !self.has_id(&id).await {
                            // Nobody interested in the Identity anymore, do nothing.
                            continue 'main;
                        }
                        match processing.get(&id) {
                            None => {
                                pending.push_increase(id, PendingPriority(pri, Instant::now()));
                            },
                            Some(Fetch::Forgetting) => {
                                // Once the associated future completes, the result will be dropped
                                // instead of communicated back to the `certs` map and queued for
                                // refresh.
                                processing.insert(id, Fetch::Processing);
                            },
                            Some(Fetch::Processing) => (),
                        }
                    },
                    Some(Request::Forget(id)) => {
                        if self.has_id(&id).await {
                            // After the forget was queued, there was another request to start
                            // managing the Identity. Do nothing.
                            continue 'main;
                        }
                        match processing.get(&id) {
                            None => {
                                pending.remove(&id);
                            },
                            Some(Fetch::Processing) => {
                                processing.insert(id, Fetch::Forgetting);
                            },
                            Some(Fetch::Forgetting) => (),
                        }
                    },
                    None => break 'main,
                },

                // Handle fetch results.
                Some((id, res)) = fetches.next() => {
                    match processing.remove(&id) {
                        Some(Fetch::Processing) => (),
                        Some(Fetch::Forgetting) => continue 'main,
                        None => unreachable!("processing should represent all fetches"),
                    }
                    let (state, refresh_at) = match res {
                        Err(err) => {
                            let refresh_at = Instant::now() + CERT_REFRESH_FAILURE_RETRY_DELAY;
                            (CertState::Unavailable(err), refresh_at)
                        },
                        Ok(certs) => {
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
                    if self.update_certs(&id, state).await {
                        pending.push_increase(id, PendingPriority(Priority::Background, refresh_at));
                    }
                },
                // Initiate the next fetch.
                true = maybe_sleep_until(next), if fetches.len() < self.concurrency as usize => {
                    let (id, _) = pending.pop().unwrap();
                    processing.insert(id.to_owned(), Fetch::Processing);
                    fetches.push(async move {
                        let res = self.client.fetch_certificate(&id).await;
                        (id, res)
                    });
                },
            };
        }
        // SecretManager dropped, drain remaining requests and terminate background processing.
        while fetches.next().await.is_some() {}
    }

    // Returns whether the Identity is still managed.
    async fn update_certs(&self, id: &Identity, certs: CertState) -> bool {
        // Both errors (lack of entry in the `certs` map and a send error) are handled the same way
        // (by returning false): either (a) there was no entry in the `certs` map due to a
        // forget_certificate call some time ago or (b) a forget_certificate call was made and
        // finished just after the lock was released (but before certs was sent)
        match self.certs.lock().await.get(id) {
            Some(state) => {
                state.tx.send(certs).expect("state.rx cannot be gone");
                true
            }
            None => false,
        }
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

enum Request {
    Fetch(Identity, Priority),
    Forget(Identity),
}

pub struct SecretManagerConfig {
    time_conv: crate::time::Converter,
    concurrency: u16,
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
    pub async fn new(cfg: crate::config::Config) -> Result<Self, Error> {
        let caclient = CaClient::new(
            cfg.ca_address.unwrap(),
            Box::new(tls::ControlPlaneAuthentication::RootCert(
                cfg.ca_root_cert.clone(),
            )),
            cfg.auth,
            cfg.proxy_mode == ProxyMode::Shared,
            cfg.secret_ttl.as_secs().try_into().unwrap_or(60 * 60 * 24),
        )
        .await?;
        Ok(Self::new_with_client(caclient))
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
        let mut certs = self.worker.certs.lock().await;
        match certs.get(id) {
            // Identity found in cache and is already being refreshed. Bump the priority if needed.
            Some(st) => {
                let rx = st.rx.clone();
                drop(certs);

                if let Some(existing_pri) = init_pri(&rx) {
                    if pri > existing_pri {
                        self.post(Request::Fetch(id.clone(), pri)).await;
                    }
                }
                Ok(rx)
            }
            // New identity, start managing it and return the newly created channel.
            None => {
                let (tx, rx) = watch::channel(CertState::Initializing(pri));
                certs.insert(id.to_owned(), CertChannel { rx: rx.clone(), tx });
                drop(certs);
                // Notify the background worker to start refreshing the certificate.
                self.post(Request::Fetch(id.to_owned(), pri)).await;
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

    pub async fn forget_certificate(&self, id: &Identity) {
        if self.worker.certs.lock().await.remove(id).is_some() {
            self.post(Request::Forget(id.clone())).await;
        }
    }

    // TODO(qfel): It would be much nicer to have something like map_certs returning an iterator,
    // but due to locking that would require a self-referential type.
    pub async fn collect_certs<R>(&self, f: impl Fn(&Identity, &CertState) -> R) -> Vec<R> {
        let mut ret = Vec::new();
        for (id, chan) in self.worker.certs.lock().await.iter() {
            ret.push(f(id, &chan.rx.borrow()));
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

    use super::{mock, *};

    async fn stress_many_ids(sm: Arc<SecretManager>, iterations: u32) {
        for i in 0..iterations {
            let id = identity::Identity::Spiffe {
                trust_domain: "cluster.local".to_string(),
                namespace: "istio-system".to_string(),
                service_account: format!("ztunnel{i}"),
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

    async fn verify_cert_updates(
        sm: Arc<SecretManager>,
        id: Identity,
        dur: Duration,
        cert_lifetime: Duration,
    ) {
        let start_time = time::Instant::now();
        let expected_update_interval = cert_lifetime.as_millis() / 2;
        let mut total_updates = 0;
        let mut current_cert = sm
            .fetch_certificate(&id)
            .await
            .expect("Didn't get a cert as expected.");
        loop {
            let new_cert = sm
                .fetch_certificate(&id)
                .await
                .expect("Didn't get a cert as expected.");

            if current_cert.cert.serial() != new_cert.cert.serial() {
                total_updates += 1;
                current_cert = new_cert;
            }
            if time::Instant::now() - start_time > dur {
                break;
            }
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
        assert_eq!(total_updates, dur.as_millis() / expected_update_interval);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_cache_refresh() {
        let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let test_dur = Duration::from_millis(200);

        let id: Identity = Default::default();

        // Certs added to the cache should be refreshed every 80 millis
        let cert_lifetime = Duration::from_millis(160);
        let secret_manager = mock::new_secret_manager(cert_lifetime);

        // Spawn task that verifies cert updates.
        tasks.push(tokio::spawn(verify_cert_updates(
            secret_manager.clone(),
            id.clone(),
            test_dur,
            cert_lifetime,
        )));

        // Start spamming fetches for that cert.
        for _n in 0..7 {
            tasks.push(tokio::spawn(stress_single_id(
                secret_manager.clone(),
                id.clone(),
                test_dur,
            )));
        }

        let results = futures::future::join_all(tasks).await;
        for result in results.iter() {
            assert!(result.is_ok());
        }
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
            trust_domain: "test".to_string(),
            namespace: "test".to_string(),
            service_account: name.to_string(),
        }
    }

    fn identity_n(name: &str, n: u8) -> Identity {
        Identity::Spiffe {
            trust_domain: "test".to_string(),
            namespace: "test".to_string(),
            service_account: format!("{name}{n}"),
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

        assert_matches!(fetch.await.unwrap(), Err(Error::Forgotten));
        test.tear_down().await;
    }

    #[test]
    fn identity_from_string() {
        assert_eq!(
            Identity::from_str("spiffe://cluster.local/ns/namespace/sa/service-account").ok(),
            Some(Identity::Spiffe {
                trust_domain: "cluster.local".to_string(),
                namespace: "namespace".to_string(),
                service_account: "service-account".to_string(),
            })
        );
        assert_eq!(
            Identity::from_str("spiffe://td/ns/ns/sa/sa").ok(),
            Some(Identity::Spiffe {
                trust_domain: "td".to_string(),
                namespace: "ns".to_string(),
                service_account: "sa".to_string(),
            })
        );
        assert_eq!(
            Identity::from_str("spiffe://td.with.dots/ns/ns.with.dots/sa/sa.with.dots").ok(),
            Some(Identity::Spiffe {
                trust_domain: "td.with.dots".to_string(),
                namespace: "ns.with.dots".to_string(),
                service_account: "sa.with.dots".to_string(),
            })
        );
        assert_eq!(
            Identity::from_str("spiffe://td/ns//sa/").ok(),
            Some(Identity::Spiffe {
                trust_domain: "td".to_string(),
                namespace: "".to_string(),
                service_account: "".to_string()
            })
        );
        assert_matches!(Identity::from_str("td/ns/ns/sa/sa"), Err(_));
        assert_matches!(Identity::from_str("spiffe://td/ns/ns/sa"), Err(_));
        assert_matches!(Identity::from_str("spiffe://td/ns/ns/sa/sa/"), Err(_));
        assert_matches!(Identity::from_str("spiffe://td/ns/ns/foobar/sa/"), Err(_));
    }
}
