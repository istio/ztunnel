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

use hyper::{Body, Client, Method, Request, Response};
use once_cell::sync::Lazy;
use std::future::Future;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::time;

use helpers::*;
use ztunnel::*;

mod helpers;

fn test_config() -> config::Config {
    config::Config {
        socks5_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        inbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        admin_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        outbound_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        inbound_plaintext_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_shutdown_lifecycle() {
    Lazy::force(&TRACING);

    let app = app::build(test_config()).await.unwrap();

    let shutdown = app.shutdown.trigger().clone();
    let (app, _shutdown) = tokio::join!(
        time::timeout(Duration::from_secs(1), app.spawn()),
        shutdown.shutdown_now()
    );
    app.expect("app shuts down")
        .expect("app exits without error")
}

#[tokio::test]
async fn test_quit_lifecycle() {
    Lazy::force(&TRACING);

    let app = app::build(test_config()).await.unwrap();
    let addr = app.admin_address;

    let (app, _shutdown) = tokio::join!(
        time::timeout(Duration::from_secs(1), app.spawn()),
        admin_shutdown(addr)
    );
    app.expect("app shuts down")
        .expect("app exits without error");
}

struct TestApp {
    admin_address: SocketAddr,
}

async fn with_app<F, Fut, FO>(cfg: config::Config, f: F)
where
    F: Fn(TestApp) -> Fut,
    Fut: Future<Output = FO>,
{
    Lazy::force(&TRACING);

    let app = app::build(cfg).await.unwrap();
    let shutdown = app.shutdown.trigger().clone();

    let ta = TestApp {
        admin_address: app.admin_address,
    };
    let run_and_shutdown = async {
        f(ta).await;
        shutdown.shutdown_now().await;
    };
    let (app, _shutdown) = tokio::join!(app.spawn(), run_and_shutdown);
    app.expect("app exits without error");
}

#[tokio::test]
async fn test_healthz() {
    with_app(test_config(), |app| async move {
        let resp = app.admin_request("healthz/ready").await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    })
    .await;
}

impl TestApp {
    async fn admin_request(&self, path: &str) -> Response<Body> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://localhost:{}/{path}", self.admin_address.port()))
            .header("content-type", "application/json")
            .body(Body::default())
            .unwrap();
        let client = Client::new();
        client.request(req).await.expect("admin request")
    }
}

/// admin_shutdown triggers a shutdown - from the admin server
async fn admin_shutdown(addr: SocketAddr) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://localhost:{}/quitquitquit", addr.port()))
        .header("content-type", "application/json")
        .body(Body::default())
        .unwrap();
    let client = Client::new();
    let resp = client.request(req).await.expect("admin shutdown request");
    assert_eq!(resp.status(), hyper::StatusCode::OK);
}
