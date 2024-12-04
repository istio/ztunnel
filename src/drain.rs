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

pub use internal::DrainMode;
pub use internal::ReleaseShutdown as DrainBlocker;
pub use internal::Signal as DrainTrigger;
pub use internal::Watch as DrainWatcher;

/// New constructs a new pair for draining
/// * DrainTrigger can be used to start a draining sequence and wait for it to complete.
/// * DrainWatcher should be held by anything that wants to participate in the draining. This can be cloned,
///   and a drain will not complete until all outstanding DrainWatchers are dropped.
pub fn new() -> (DrainTrigger, DrainWatcher) {
    let (tx, rx) = internal::channel();
    (tx, rx)
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
            if res.mode() == DrainMode::Graceful {
                debug!(component, "drain started, waiting {:?} for any connections to complete", deadline);
                if tokio::time::timeout(deadline, sub_drain_signal.start_drain_and_wait(DrainMode::Graceful)).await.is_err() {
                    // Not all connections completed within time, we will force shut them down
                    warn!(component, "drain duration expired with pending connections, forcefully shutting down");
                }
            } else {
                debug!(component, "terminating");
            }
            // Trigger force shutdown. In theory, this is only needed in the timeout case. However,
            // it doesn't hurt to always trigger it.
            let _ = trigger_force_shutdown.send(());

            info!(component, "shutdown complete");
            drop(res);
        }
    };
}

mod internal {
    use tokio::sync::{mpsc, watch};

    /// Creates a drain channel.
    ///
    /// The `Signal` is used to start a drain, and the `Watch` will be notified
    /// when a drain is signaled.
    pub fn channel() -> (Signal, Watch) {
        let (signal_tx, signal_rx) = watch::channel(None);
        let (drained_tx, drained_rx) = mpsc::channel(1);

        let signal = Signal {
            drained_rx,
            signal_tx,
        };
        let watch = Watch {
            drained_tx,
            signal_rx,
        };
        (signal, watch)
    }

    enum Never {}

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum DrainMode {
        Immediate,
        Graceful,
    }

    /// Send a drain command to all watchers.
    pub struct Signal {
        drained_rx: mpsc::Receiver<Never>,
        signal_tx: watch::Sender<Option<DrainMode>>,
    }

    /// Watch for a drain command.
    ///
    /// All `Watch` instances must be dropped for a `Signal::signal` call to
    /// complete.
    #[derive(Clone)]
    pub struct Watch {
        drained_tx: mpsc::Sender<Never>,
        signal_rx: watch::Receiver<Option<DrainMode>>,
    }

    #[must_use = "ReleaseShutdown should be dropped explicitly to release the runtime"]
    #[derive(Clone)]
    #[allow(dead_code)]
    pub struct ReleaseShutdown(mpsc::Sender<Never>, DrainMode);

    impl ReleaseShutdown {
        pub fn mode(&self) -> DrainMode {
            self.1
        }
    }

    impl Signal {
        /// Waits for all [`Watch`] instances to be dropped.
        pub async fn closed(&mut self) {
            self.signal_tx.closed().await;
        }

        /// Asynchronously signals all watchers to begin draining gracefully and waits for all
        /// handles to be dropped.
        pub async fn start_drain_and_wait(mut self, mode: DrainMode) {
            // Update the state of the signal watch so that all watchers are observe
            // the change.
            let _ = self.signal_tx.send(Some(mode));

            // Wait for all watchers to release their drain handle.
            match self.drained_rx.recv().await {
                None => {}
                Some(n) => match n {},
            }
        }
    }

    impl Watch {
        /// Returns a `ReleaseShutdown` handle after the drain has been signaled. The
        /// handle must be dropped when a shutdown action has been completed to
        /// unblock graceful shutdown.
        pub async fn wait_for_drain(mut self) -> ReleaseShutdown {
            // This future completes once `Signal::signal` has been invoked so that
            // the channel's state is updated.
            let mode = self
                .signal_rx
                .wait_for(Option::is_some)
                .await
                .map(|mode| mode.expect("already asserted it is_some"))
                // If we got an error, then the signal was dropped entirely. Presumably this means a graceful shutdown is not required.
                .unwrap_or(DrainMode::Immediate);

            // Return a handle that holds the drain channel, so that the signal task
            // is only notified when all handles have been dropped.
            ReleaseShutdown(self.drained_tx, mode)
        }
    }

    impl std::fmt::Debug for Signal {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Signal").finish_non_exhaustive()
        }
    }

    impl std::fmt::Debug for Watch {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Watch").finish_non_exhaustive()
        }
    }

    impl std::fmt::Debug for ReleaseShutdown {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ReleaseShutdown").finish_non_exhaustive()
        }
    }
}
