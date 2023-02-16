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
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fmt::Write;
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use prometheus_client::encoding::{EncodeLabelValue, LabelValueEncoder};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::time::{sleep_until, Duration, Instant};

use crate::tls;

use super::Error::{self, Spiffe};
use super::{CaClient, CertificateProvider};

const CERT_REFRESH_FAILURE_RETRY_DELAY: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
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

#[derive(PartialOrd, PartialEq, Eq, Ord, Debug)]
pub enum Priority {
    // Needs to be in the order of the lowest priority.
    Background,
    Warmup,
    RealTime,
}

enum CertState {
    // Should happen only on the first request for an Identity.
    Initializing,
    Available(tls::Certs),
    // The last attempt to fetch the certificate has failed and there is no previous certificate
    // available.
    //
    // In the future it may also mean that the last available certificate has expired. Note that
    // this shouldn't change the semantics, strictly speaking - there always is a chance that the
    // certificate will expire before it is used by the caller.
    Unavailable(Error),
}

// Represents a watch::channel storing the certificate state. Contains None only during the first
// request to the CertificateProvider.
struct CertChannel {
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
struct Worker<C: CertificateProvider> {
    client: C,
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

impl<C: CertificateProvider> Worker<C> {
    fn new(
        client: C,
        requests: mpsc::Receiver<(Identity, Priority)>,
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

    // Manages certificate updates. Since all the work is done in a single task, the code is
    // lock-free. This is OK as the code is I/O bound so we don't need the extra parallelism.
    async fn run(&self, mut requests: mpsc::Receiver<(Identity, Priority)>) {
        use futures::stream::FuturesUnordered;
        use futures::StreamExt;
        use priority_queue::PriorityQueue;

        // A set of futures refreshing the certificates. Each future completes with the identity for
        // which it was invoked and a resulting certificate or error.
        let mut workers = FuturesUnordered::new();
        // The set of identities for which there are pending requests. Elements of workers and
        // processing correspond to each other.
        let mut processing = HashSet::new();
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
                res = requests.recv() => match res {
                    Some((id, pri)) => {
                        if !processing.contains(&id) {
                            pending.push_increase(id, PendingPriority(pri, Instant::now()));
                        }
                    },
                    None => {
                        break 'main
                    },
                },
                Some(res) = workers.next() => match res {
                    Err(_) => break 'main,
                    Ok((id, certs)) => {
                        processing.remove(&id);
                        let refresh_at = match certs {
                            None => Instant::now() + CERT_REFRESH_FAILURE_RETRY_DELAY,
                            Some(certs) => {
                                let certs: tls::Certs = certs; // Type annotation.
                                if let Some(t) = self.time_conv.system_time_to_instant(certs.refresh_at()) {
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
                                    Instant::now() + CERT_REFRESH_FAILURE_RETRY_DELAY
                                }
                            },
                        };
                        // TODO: Add some jitter.
                        pending.push_increase(id, PendingPriority(Priority::Background, refresh_at));
                    },
                },
                true = maybe_sleep_until(next), if workers.len() < self.concurrency as usize => {
                    let (id, _) = pending.pop().unwrap();
                    processing.insert(id.clone());
                    workers.push(self.refresh(id.clone()));
                },
            };
        }
        // SecretManager dropped, drain remaining requests and terminate background processing.
        while workers.next().await.is_some() {}
    }

    async fn refresh(
        &self,
        id: Identity,
    ) -> Result<(Identity, Option<tls::Certs>), watch::error::SendError<CertState>> {
        let (state, res) = match self.client.fetch_certificate(&id).await {
            Ok(certs) => (CertState::Available(certs.clone()), Some(certs)),
            Err(err) => (CertState::Unavailable(err), None),
        };
        match self.update_certs(&id, state).await {
            Err(e) => Err(e),
            Ok(()) => Ok((id, res)),
        }
    }

    // Fails if nobody is listening, ie. the SecretManager is no more. Should trigger background
    // processing shutdown in such case.
    async fn update_certs(
        &self,
        id: &Identity,
        certs: CertState,
    ) -> Result<(), watch::error::SendError<CertState>> {
        let all_certs = self.certs.lock().await;
        let state = all_certs.get(id).unwrap();
        state.tx.send(certs)
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

pub struct SecretManagerConfig {
    time_conv: crate::time::Converter,
    concurrency: u16,
}

/// SecretManager provides a wrapper around a CertificateProvider with caching.
/// It is designed to be cheap to clone.
#[derive(Clone)]
pub struct SecretManager<C: CertificateProvider> {
    worker: Arc<Worker<C>>,
    // Channel to which certificate requests are sent to. The Identity for which request is being
    // sent for must have a corresponding entry in the worker's certs map (which is where the
    // result can be read from).
    requests: mpsc::Sender<(Identity, Priority)>,
}

impl<T: CertificateProvider> SecretManager<T> {
    pub fn new_with_client(client: T) -> Self {
        Self::new_internal(
            client,
            SecretManagerConfig {
                time_conv: crate::time::Converter::new(),
                concurrency: 8,
            },
        )
        .0
    }

    fn new_internal(client: T, cfg: SecretManagerConfig) -> (Self, tokio::task::JoinHandle<()>) {
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

    async fn start_fetch(
        &self,
        id: &Identity,
        pri: Priority,
    ) -> Result<watch::Receiver<CertState>, Error> {
        let mut certs = self.worker.certs.lock().await;
        match certs.get(id) {
            // Identity found in cache and is already being refreshed.
            Some(st) => Ok(st.rx.clone()),
            // New identity, start managing it and return the newly created channel.
            None => {
                let (tx, rx) = watch::channel(CertState::Initializing);
                certs.insert(id.clone(), CertChannel { rx: rx.clone(), tx });
                drop(certs);
                // Notify the background worker to start refreshing the certificate.
                match self.requests.send((id.clone(), pri)).await {
                    // Note that this should not happen, the background worker is expected to be
                    // running.
                    //
                    // TODO: Better error propagation.
                    Err(_) => Err(Error::EmptyResponse(id.clone())),
                    Ok(()) => Ok(rx),
                }
            }
        }
    }

    async fn wait(
        &self,
        id: &Identity,
        mut rx: watch::Receiver<CertState>,
    ) -> Result<tls::Certs, Error> {
        tokio::select! {
            // Wait for the initial value if not ready yet.
            res = rx.changed() => match res {
                Err(_) => Err(Error::EmptyResponse(id.clone())),
                Ok(()) => match *rx.borrow() {
                    CertState::Unavailable(ref err) => Err(err.clone()),
                    CertState::Available(ref certs) => Ok(certs.clone()),
                    CertState::Initializing => unreachable!("Only the initial state can be Initializing, but the state has changed"),
                },
            },
            // Fail if the background worker died. Ideally we'd detect it by rx.changed() failing
            // above, but making sure that senders are owned by the background worker (and so drop
            // on panic/other error) complicates the code.
            _ = self.requests.closed() => Err(Error::EmptyResponse(id.clone())),
        }
    }

    pub async fn fetch_certificate_pri(
        &self,
        id: &Identity,
        pri: Priority,
    ) -> Result<tls::Certs, Error> {
        // This method is intentionally left simple, since since unit tests are based on start_fetch
        // and wait. Any changes should go to one of those two methods, and if that proves
        // impossible - unit testing strategy may need to be rethinked.
        self.wait(id, self.start_fetch(id, pri).await?).await
    }
}

#[async_trait]
impl<T: CertificateProvider + Clone> CertificateProvider for SecretManager<T> {
    async fn fetch_certificate(&self, id: &Identity) -> Result<tls::Certs, Error> {
        self.fetch_certificate_pri(id, Priority::RealTime).await
    }
}

impl SecretManager<CaClient> {
    pub fn new(cfg: crate::config::Config) -> Result<Self, Error> {
        let caclient = CaClient::new(cfg.ca_address.unwrap(), cfg.ca_root_cert.clone(), cfg.auth)?;
        Ok(Self::new_with_client(caclient))
    }
}

pub mod mock {
    use std::time::Duration;

    use crate::identity::caclient::mock::{self, CaClient as MockCaClient};

    use super::SecretManager;

    pub fn new_secret_manager(cert_lifetime: Duration) -> SecretManager<MockCaClient> {
        let time_conv = crate::time::Converter::new();
        let client = MockCaClient::new(mock::ClientConfig {
            cert_lifetime,
            time_conv: time_conv.clone(),
            ..Default::default()
        });
        SecretManager::new_internal(
            client,
            super::SecretManagerConfig {
                time_conv,
                concurrency: 2,
            },
        )
        .0
    }

    impl SecretManager<MockCaClient> {
        pub async fn cache_len(&self) -> usize {
            self.worker.certs.lock().await.len()
        }

        pub fn client(&self) -> &MockCaClient {
            &self.worker.client
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time;

    use matches::assert_matches;

    use crate::identity::{self, *};

    use super::{mock, *};

    async fn stress_many_ids(sm: SecretManager<caclient::mock::CaClient>, iterations: u32) {
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

    async fn stress_single_id(
        sm: SecretManager<caclient::mock::CaClient>,
        id: Identity,
        dur: Duration,
    ) {
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
        sm: SecretManager<caclient::mock::CaClient>,
        id: Identity,
        dur: Duration,
    ) {
        let start_time = time::Instant::now();
        let expected_update_interval = sm.worker.client.cert_lifetime().as_millis() / 2;
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

            if current_cert != new_cert {
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
        let secret_manager = mock::new_secret_manager(Duration::from_millis(160));

        // Spawn task that verifies cert updates.
        tasks.push(tokio::spawn(verify_cert_updates(
            secret_manager.clone(),
            id.clone(),
            test_dur,
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

    fn collect_strings<T: Iterator>(xs: T) -> Vec<String>
    where
        T::Item: ToString,
    {
        xs.map(|x| x.to_string()).collect()
    }

    const NANOSEC: Duration = Duration::from_nanos(1);
    const MILLISEC: Duration = Duration::from_millis(1);
    const SEC: Duration = Duration::from_secs(1);
    const CERT_HALFLIFE: Duration = Duration::from_secs(50);

    // Wraps SecretManager to retain the background worker handle, so that it can be waited on at
    // the end of the test.
    struct TestSecretManager {
        secret_manager: SecretManager<caclient::mock::CaClient>,
        worker: tokio::task::JoinHandle<()>,
    }

    impl TestSecretManager {
        // Deconstructs the TestSecretManager into the background worker handle. This drops the
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

    // For an easy access to the underlying SecretManager.
    impl std::ops::Deref for TestSecretManager {
        type Target = SecretManager<caclient::mock::CaClient>;

        fn deref(&self) -> &Self::Target {
            &self.secret_manager
        }
    }

    fn setup(concurrency: u16) -> TestSecretManager {
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
        let client = caclient::mock::CaClient::new(caclient::mock::ClientConfig {
            time_conv: time_conv.clone(),
            fetch_latency: SEC,
            cert_lifetime: 2 * CERT_HALFLIFE,
        });

        let (secret_manager, worker) = SecretManager::new_internal(
            client,
            SecretManagerConfig {
                time_conv,
                concurrency,
            },
        );
        TestSecretManager {
            secret_manager,
            worker,
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
        let secret_manager = setup(1);

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
            let sm = secret_manager.clone();
            let rx = sm.start_fetch(&id, pri).await.unwrap();
            tasks.push(tokio::spawn(async move { sm.wait(&id, rx).await }));
            // Now the request has either started (for the first request) or is queued in the
            // background worker.
        }
        // Process all pending requests.
        for result in futures::future::join_all(tasks).await {
            assert_matches!(result, Ok(Ok(_)));
        }

        let client = secret_manager.client();
        // Ensure all requests have been issued in the expected order.
        assert_eq!(
            collect_strings(client.fetches().await.iter()),
            collect_strings(expected.iter()),
        );

        client.clear_fetches().await;
        // Certificates should start refreshing at start + CERT_HALFLIFE, so just before that there
        // should be no new CaClient calls.
        tokio::time::sleep_until(start + CERT_HALFLIFE - MILLISEC).await;
        assert!(client.fetches().await.is_empty());

        // Each certificate request is delayed by 1ms, and each CaClient call takes 1s. So CaClient
        // calls complete at 1s1ms, 2s2ms, and so on. Wait till the last CaClient call completion +
        // CERT_HALFLIFE to ensure all background refreshes have been issues, and then an extra
        // second to ensure the last one has completed.
        let num_ids = expected.len() as u32;
        tokio::time::sleep_until(start + CERT_HALFLIFE + num_ids * (SEC + MILLISEC) + SEC).await;
        assert_eq!(
            collect_strings(client.fetches().await.iter()),
            collect_strings(expected.iter()),
        );

        secret_manager.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_warmup() {
        let secret_manager = setup(1);

        // Capture the start time of the test
        let start = Instant::now();
        let mut tasks = Vec::new();
        for i in 1..21 {
            let sm = secret_manager.clone();
            tasks.push(tokio::spawn(async move {
                sm.fetch_certificate_pri(&identity_n("warmup-", i), Priority::Warmup)
                    .await
                    .unwrap();
            }));
        }
        // Ensure all requests are executing/queued in the background worker.
        tokio::time::sleep(NANOSEC).await; // Expect this to advance the timer by exactly 1ms.
        secret_manager
            .fetch_certificate_pri(&identity("realtime"), Priority::RealTime)
            .await
            .unwrap();
        assert!(Instant::now().duration_since(start) <= 2 * SEC);

        secret_manager.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_duplicate_requests() {
        let secret_manager = setup(1);
        let id = identity("id1");
        let mut rxs = Vec::new();
        for _ in 1..5 {
            let rx = secret_manager
                .start_fetch(&id, Priority::RealTime)
                .await
                .unwrap();
            rxs.push(rx);
        }
        let mut rxs_iter = rxs.into_iter();
        let want = secret_manager
            .wait(&id, rxs_iter.next().unwrap())
            .await
            .unwrap();
        for rx in rxs_iter {
            let got = secret_manager.wait(&id, rx).await.unwrap();
            assert_eq!(got, want);
        }
        assert_eq!(secret_manager.client().fetches().await.len(), 1);

        secret_manager.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_concurrency() {
        let start = Instant::now();
        let secret_manager = setup(4);
        let mut futs = Vec::new();
        for i in 0..4 {
            let id = identity_n("id-", i);
            futs.push(async {
                let id = id; // Move instead of borrowing.
                secret_manager
                    .fetch_certificate_pri(&id, Priority::RealTime)
                    .await
            });
        }
        for result in futures::future::join_all(futs).await {
            result.unwrap();
        }
        assert_eq!(Instant::now().duration_since(start), SEC);
        secret_manager.tear_down().await;
    }

    #[tokio::test(start_paused = true)]
    async fn test_unused_cleanup() {
        setup(1).tear_down().await;
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
