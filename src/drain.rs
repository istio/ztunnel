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

use std::future::Future;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct DrainTrigger(drain_internal::Signal);

impl DrainTrigger {
    /// start_drain_and_wait initiates a draining sequence. The future will not complete until the drain
    /// is complete (all outstanding DrainWatchers are dropped).
    pub async fn start_drain_and_wait(self) {
        self.0.drain().await
    }
}

#[derive(Clone, Debug)]
pub struct DrainWatcher(drain_internal::Watch);

impl DrainWatcher {
    /// wait_for_drain will return once a drain has been initiated.
    /// The drain will not complete until the returned DrainBlocker is dropped
    pub async fn wait_for_drain(self) -> DrainBlocker {
        DrainBlocker(self.0.signaled().await)
    }
}

#[allow(dead_code)]
/// DrainBlocker provides a token that must be dropped to unblock the drain.
pub struct DrainBlocker(drain_internal::ReleaseShutdown);

/// New constructs a new pair for draining
/// * DrainTrigger can be used to start a draining sequence and wait for it to complete.
/// * DrainWatcher should be held by anything that wants to participate in the draining. This can be cloned,
///   and a drain will not complete until all outstanding DrainWatchers are dropped.
pub fn new() -> (DrainTrigger, DrainWatcher) {
    let (tx, rx) = drain_internal::channel();
    (DrainTrigger(tx), DrainWatcher(rx))
}

/// run_with_drain provides a wrapper to run a future with graceful shutdown/draining support.
/// A caller should construct a future with takes two arguments:
/// * drain: while holding onto this, the future is marked as active, which will block the server from shutting down.
///   Additionally, it can be watched (with drain.signaled()) to see when to start a graceful shutdown.
/// * force_shutdown: when this is triggered, the future must forcefully shutdown any ongoing work ASAP.
///   This means the graceful drain exceeded the hard deadline, and all work must terminate now.
///   This is only required for spawned() tasks; otherwise, the future is dropped entirely, canceling all work.
pub async fn run_with_drain<F, Fut, O>(
    component: String,
    drain: DrainWatcher,
    deadline: Duration,
    make_future: F,
) where
    F: FnOnce(DrainWatcher, watch::Receiver<()>) -> Fut,
    Fut: Future<Output = O>,
    O: Send + 'static,
{
    let (sub_drain_signal, sub_drain) = new();
    let (trigger_force_shutdown, force_shutdown) = watch::channel(());
    // Stop accepting once we drain.
    // We will then allow connections up to `deadline` to terminate on their own.
    // After that, they will be forcefully terminated.
    let fut = make_future(sub_drain, force_shutdown);
    tokio::select! {
        _res = fut => {}
        res = drain.wait_for_drain() => {
            debug!(component, "drain started, waiting {:?} for any connections to complete", deadline);
            if tokio::time::timeout(deadline, sub_drain_signal.start_drain_and_wait()).await.is_err() {
                // Not all connections completed within time, we will force shut them down
                warn!(component, "drain duration expired with pending connections, forcefully shutting down");
            }
            // Trigger force shutdown. In theory, this is only needed in the timeout case. However,
            // it doesn't hurt to always trigger it.
            let _ = trigger_force_shutdown.send(());

            info!(component, "drain complete");
            drop(res);
        }
    };
}
