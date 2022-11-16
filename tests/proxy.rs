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

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use std::time::Duration;
use hyper::{Body, Client, Method, Request};
use once_cell::sync::Lazy;
use tokio::time;
use tracing::info;

use helpers::*;
use ztunnel::*;

mod helpers;

fn test_config() -> config::Config {
    config::Config {
        inbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        admin_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        outbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_lifecycle() {
    Lazy::force(&TRACING);
    let shutdown = signal::Shutdown::new();

    shutdown.trigger().shutdown_now().await;

    time::timeout(Duration::from_secs(1), app::spawn(shutdown, test_config()))
        .await
        .expect("app shuts down")
        .expect("app exits without error")
}

#[tokio::test]
async fn test_quit_lifecycle() {
    Lazy::force(&TRACING);

    let shutdown = signal::Shutdown::new();
    let app = app::build(shutdown, test_config()).await.unwrap();
    let addr = app.admin_address;
    info!("address {addr}");
    let (app, _shutdown) = tokio::join!(
        time::timeout(Duration::from_secs(1), app.spawn()),
        admin_shutdown(addr)
    );
    app.expect("app shuts down")
        .expect("app exits without error");
}

#[track_caller]
async fn admin_shutdown(addr: SocketAddr) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{}/quitquitquit", addr))
        .header("content-type", "application/json")
        .body(Body::default())
        .unwrap();
    let client = Client::new();
    let resp = client.request(req).await;
    assert_eq!(resp.unwrap().status(), hyper::StatusCode::OK);
}
