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

// #[async_trait::async_trait]
// pub trait Shutdown {
//     async fn shutdown();
// }

use tokio::sync::mpsc;

pub struct Shutdown {
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
    signals: imp::Signals,
}

impl Shutdown {
    /// Registers signal handlers immediately so signals before `wait` are not lost.
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        Shutdown {
            shutdown_tx,
            shutdown_rx,
            signals: imp::Signals::new(),
        }
    }

    /// Trigger returns a ShutdownTrigger which can be used to trigger a shutdown immediately
    pub fn trigger(&self) -> ShutdownTrigger {
        ShutdownTrigger {
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }

    /// Wait completes when the shutdown as been triggered
    pub async fn wait(mut self) {
        imp::shutdown(self.signals, &mut self.shutdown_rx).await
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct ShutdownTrigger {
    shutdown_tx: mpsc::Sender<()>,
}

impl ShutdownTrigger {
    pub async fn shutdown_now(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }
}

#[cfg(unix)]
mod imp {
    use std::process;
    use tokio::signal::unix::{Signal, SignalKind, signal};
    use tokio::sync::mpsc::Receiver;
    use tracing::info;

    pub(super) struct Signals {
        sigint: Signal,
        sigterm: Signal,
    }

    impl Signals {
        pub(super) fn new() -> Self {
            Signals {
                sigint: signal(SignalKind::interrupt()).expect("Failed to register signal handler"),
                sigterm: signal(SignalKind::terminate())
                    .expect("Failed to register signal handler"),
            }
        }
    }

    pub(super) async fn shutdown(signals: Signals, receiver: &mut Receiver<()>) {
        let Signals {
            mut sigint,
            mut sigterm,
        } = signals;
        tokio::select! {
            _ = sigint.recv() => {
                info!("received signal SIGINT, starting shutdown");
                tokio::spawn(async move{
                    sigint.recv().await;
                    info!("Double Ctrl+C, exit immediately");
                    process::exit(0);
                });
            }
            _ = sigterm.recv() => {
                info!("received signal SIGTERM, starting shutdown");
            }
            _ = receiver.recv() => { info!("received explicit shutdown signal")}
        };
    }
}

#[cfg(not(unix))]
mod imp {
    use tokio::signal::windows::{CtrlC, ctrl_c};
    use tokio::sync::mpsc::Receiver;
    use tracing::info;

    pub(super) struct Signals {
        ctrl_c: CtrlC,
    }

    impl Signals {
        pub(super) fn new() -> Self {
            Signals {
                ctrl_c: ctrl_c().expect("Failed to register signal handler"),
            }
        }
    }

    // This isn't quite right, but close enough for windows...
    pub(super) async fn shutdown(mut signals: Signals, receiver: &mut Receiver<()>) {
        tokio::select! {
            _ = signals.ctrl_c.recv() => { info!("received signal, starting shutdown") }
            _ = receiver.recv() => { info!("received explicit shutdown signal")}
        };
    }
}
