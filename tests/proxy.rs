use helpers::*;
use once_cell::sync::Lazy;
use ztunnel::*;
mod helpers;

#[tokio::test]
async fn test_lifecycle() {
    Lazy::force(&TRACING);
    let config = config::Config {
        ..Default::default()
    };
    let shutdown = signal::Shutdown::new();

    shutdown.trigger().shutdown_now().await;
    tokio::spawn(async move {
        app::spawn(signal::Shutdown::new(), config)
            .await
            .expect("app shuts down")
    });
}
