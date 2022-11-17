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

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tokio::time;

use ztunnel::test_helpers::app as testapp;
use ztunnel::test_helpers::*;

use ztunnel::*;

fn test_config() -> config::Config {
    config::Config {
        xds_address: None,
        local_xds_path: Some("examples/localhost.yaml".to_string()),
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
    helpers::initialize_telemetry();

    let app = ztunnel::app::build(test_config()).await.unwrap();

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
    helpers::initialize_telemetry();

    let app = ztunnel::app::build(test_config()).await.unwrap();
    let addr = app.admin_address;

    let (app, _shutdown) = tokio::join!(
        time::timeout(Duration::from_secs(1), app.spawn()),
        admin_shutdown(addr)
    );
    app.expect("app shuts down")
        .expect("app exits without error");
}

#[tokio::test]
async fn test_healthz() {
    testapp::with_app(test_config(), |app| async move {
        let resp = app.admin_request("healthz/ready").await;
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    })
    .await;
}

#[tokio::test]
async fn test_request() {
    // Test a round trip outbound call (via socks5)
    let echo = echo::TestServer::new().await;
    let echo_addr = echo.address();
    tokio::spawn(echo.run());
    testapp::with_app(test_config(), |app| async move {
        // We send to 127.0.0.2, configured with TCP
        // TODO: also test HBONE (127.0.0.1); this is blocked on a fake CA.
        let dst = helpers::with_ip(echo_addr, "127.0.0.2".parse().unwrap());
        let mut stream = app.socks5_connect(dst).await;

        const BODY: &[u8] = "hello world".as_bytes();
        stream.write_all(BODY).await.unwrap();

        // Echo server should reply back with the same data
        let mut buf: [u8; BODY.len()] = [0; BODY.len()];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(BODY, buf);
    })
    .await;
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
