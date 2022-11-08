/// Returns a `Future` that completes when the proxy should start to shutdown.
pub async fn shutdown() {
    imp::shutdown().await
}

#[cfg(unix)]
mod imp {
    use tokio::signal::unix::{signal, SignalKind};
    use tracing::info;

    pub(super) async fn shutdown() {
        tokio::select! {
            () = watch_signal(SignalKind::interrupt(), "SIGINT") => {}
            () = watch_signal(SignalKind::terminate(), "SIGTERM") => {}
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
    pub(super) async fn shutdown() {
        // This isn't quite right, but close enough for windows...
        tokio::signal::windows::ctrl_c()
            .expect("Failed to register signal handler")
            .recv()
            .await;
    }
}
