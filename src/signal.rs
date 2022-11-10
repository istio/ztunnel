// #[async_trait::async_trait]
// pub trait Shutdown {
//     async fn shutdown();
// }

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

pub struct ShutdownTrigger {
    shutdown_tx: mpsc::Sender<()>,
}

impl ShutdownTrigger {
    pub async fn shutdown_now(&self) {
        self.shutdown_tx.send(()).await.unwrap();
    }
}

#[cfg(unix)]
mod imp {
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::sync::mpsc::Receiver;
    use tracing::info;

    pub(super) async fn shutdown(receiver: &mut Receiver<()>) {
        tokio::select! {
            _ = watch_signal(SignalKind::interrupt(), "SIGINT") => {}
            _ = watch_signal(SignalKind::terminate(), "SIGTERM") => {}
            _ = receiver.recv() => { info!("received explicit shutdown signal")}
        };
    }

    async fn watch_signal(kind: SignalKind, name: &'static str) {
        signal(kind)
            .expect("Failed to register signal handler")
            .recv()
            .await;
        info!("received signal {}, starting shutdown", name,);
    }
}

#[cfg(not(unix))]
mod imp {
    use tokio::sync::mpsc::Receiver;

    pub(super) async fn shutdown(receiver: Receiver<()>) {
        // This isn't quite right, but close enough for windows...
        tokio::signal::windows::ctrl_c()
            .expect("Failed to register signal handler")
            .recv()
            .await;
    }
}
