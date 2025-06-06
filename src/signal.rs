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

use tokio::sync::mpsc;

pub struct Shutdown {
    shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
}

impl Shutdown {
    pub fn new() -> Self {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        Shutdown {
            shutdown_tx,
            shutdown_rx,
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
        imp::shutdown(&mut self.shutdown_rx).await
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
    use tokio::signal::unix::{SignalKind, signal};
    use tokio::sync::mpsc::Receiver;
    use tracing::info;

    pub(super) async fn shutdown(receiver: &mut Receiver<()>) {
        tokio::select! {
            _ = watch_signal(SignalKind::interrupt(), "SIGINT") => {
                tokio::spawn(async move{
                    watch_signal(SignalKind::interrupt(), "SIGINT").await;
                    info!("Double Ctrl+C, exit immediately");
                    process::exit(0);
                });
            }
            _ = watch_signal(SignalKind::terminate(), "SIGTERM") => {}
            _ = receiver.recv() => { info!("received explicit shutdown signal")}
        };
    }

    async fn watch_signal(kind: SignalKind, name: &'static str) {
        signal(kind)
            .expect("Failed to register signal handler")
            .recv()
            .await;
        info!("received signal {}, starting shutdown", name);
    }
}

#[cfg(not(unix))]
mod imp {
    use tokio::sync::mpsc::Receiver;
    use tracing::info;

    pub(super) async fn shutdown(receiver: &mut Receiver<()>) {
        tokio::select! {
            _ = watch_signal() => {}
            _ = receiver.recv() => { info!("received explicit shutdown signal")}
        };
    }

    // This isn't quite right, but close enough for windows...
    async fn watch_signal() {
        tokio::signal::windows::ctrl_c()
            .expect("Failed to register signal handler")
            .recv()
            .await;
        info!("received signal, starting shutdown");
    }
}
