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
