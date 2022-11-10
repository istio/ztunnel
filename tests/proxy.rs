use helpers::*;
use once_cell::sync::Lazy;
use std::time::Duration;
use tokio::time;
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

    time::timeout(Duration::from_secs(1), app::spawn(shutdown, config))
        .await
        .expect("app shuts down")
        .expect("app exits without error")
}
