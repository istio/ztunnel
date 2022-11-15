use helpers::*;
use hyper::{Body, Client, Method, Request};
use once_cell::sync::Lazy;
use std::thread;
use std::time::Duration;
use tokio::time;
use tracing::warn;
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

#[tokio::test]
async fn test_quit_lifecycle() {
    // need to wait for the previous test release the port resource
    thread::sleep(Duration::from_secs(1));
    Lazy::force(&TRACING);
    let config = config::Config {
        ..Default::default()
    };

    let shutdown = signal::Shutdown::new();
    time::timeout(Duration::from_secs(1), app::spawn(shutdown, config))
        .await
        .ok();

    thread::sleep(Duration::from_secs(1));

    let req = Request::builder()
        .method(Method::POST)
        .uri("http://localhost:15021/quitquitquit")
        .header("content-type", "application/json")
        .body(Body::default())
        .unwrap();
    let client = Client::new();
    let resp = client.request(req).await;
    match resp {
        Ok(resbody) => assert_eq!(resbody.status(), hyper::StatusCode::OK),
        Err(ref e) => warn!("request get error info: {}", e),
    };
}
