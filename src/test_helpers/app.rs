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

use anyhow::anyhow;
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use itertools::Itertools;
use prometheus_parse::Scrape;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

use crate::app::Bound;
use crate::identity::SecretManager;
use crate::test_helpers::localhost_error_message;
use crate::*;

use super::helpers::*;

#[derive(Clone)]
pub struct TestApp {
    pub admin_address: SocketAddr,
    pub metrics_address: SocketAddr,
    pub readiness_address: SocketAddr,
    pub proxy_addresses: proxy::Addresses,
    pub tcp_dns_proxy_address: Option<SocketAddr>,
    pub udp_dns_proxy_address: Option<SocketAddr>,
    pub cert_manager: Arc<SecretManager>,

    pub namespace: Option<super::netns::Namespace>,
}

impl From<(&Bound, Arc<SecretManager>)> for TestApp {
    fn from((app, cert_manager): (&Bound, Arc<SecretManager>)) -> Self {
        Self {
            admin_address: app.admin_address,
            metrics_address: app.metrics_address,
            proxy_addresses: app.proxy_addresses.unwrap(),
            readiness_address: app.readiness_address,
            tcp_dns_proxy_address: app.tcp_dns_proxy_address,
            udp_dns_proxy_address: app.udp_dns_proxy_address,
            cert_manager,
            namespace: None,
        }
    }
}

pub async fn with_app<F, Fut, FO>(cfg: config::Config, f: F)
where
    F: Fn(TestApp) -> Fut,
    Fut: Future<Output = FO>,
{
    initialize_telemetry();
    let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
    let app = app::build_with_cert(cfg, cert_manager.clone())
        .await
        .unwrap();
    let shutdown = app.shutdown.trigger().clone();

    let ta = TestApp::from((&app, cert_manager));
    let run_and_shutdown = async {
        ta.ready().await;
        f(ta).await;
        shutdown.shutdown_now().await;
    };
    let (app, _shutdown) = tokio::join!(app.wait_termination(), run_and_shutdown);
    app.expect("app exits without error");
}

impl TestApp {
    pub async fn admin_request(&self, path: &str) -> anyhow::Result<Response<Incoming>> {
        let port = self.admin_address.port();
        let path = path.to_string();

        let get_resp = move || async move {
            let req = Request::builder()
                .method(Method::GET)
                .uri(format!("http://localhost:{}/{path}", port))
                .header("content-type", "application/json")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let client = hyper_util::pooling_client();
            Ok(client.request(req).await?)
        };

        match self.namespace {
            Some(ref ns) => ns.clone().run(get_resp)?.join().unwrap(),
            None => get_resp().await,
        }
    }

    pub async fn metrics(&self) -> anyhow::Result<ParsedMetrics> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/metrics", self.metrics_address))
            .header("content-type", "application/json")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let client = hyper_util::pooling_client();
        let body = client.request(req).await?.into_body();
        let body = body.collect().await?.to_bytes();
        let iter = std::str::from_utf8(&body)?
            .lines()
            .map(|x| Ok::<_, io::Error>(x.to_string()));
        let scrape = prometheus_parse::Scrape::parse(iter).unwrap();
        Ok(ParsedMetrics { scrape })
    }

    #[cfg(target_os = "linux")]
    pub async fn inpod_state(&self) -> anyhow::Result<HashMap<String, inpod::admin::ProxyState>> {
        let body = self.admin_request("workloadmanager").await?;
        let body = body.collect().await?.to_bytes();
        let result: HashMap<String, inpod::admin::ProxyState> = serde_json::from_slice(&body)?;
        Ok(result)
    }

    pub async fn readiness_request(&self) -> anyhow::Result<()> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!(
                "http://localhost:{}/healthz/ready",
                self.readiness_address.port()
            ))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let client = hyper_util::pooling_client();
        let resp = client
            .request(req)
            .await
            .expect("error sending ready healthcheck request");
        match resp.status() {
            hyper::StatusCode::OK => Ok(()),
            other => Err(anyhow::anyhow!(
                "non-200 status code from readiness request: received {}",
                other
            )),
        }
    }

    pub async fn ready(&self) {
        let mut last_err: anyhow::Result<()> = Ok(());
        for _ in 0..200 {
            last_err = self.readiness_request().await;
            if last_err.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("failed to get ready (last: {last_err:?})");
    }

    pub async fn socks5_connect(&self, addr: SocketAddr, source: IpAddr) -> TcpStream {
        // Always use IPv4 address. In theory, we can resolve `localhost` to pick to support any machine
        // However, we need to make sure the WorkloadStore knows about both families then.
        let socks_addr = with_ip(
            self.proxy_addresses.socks5,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        // Set source IP to TEST_WORKLOAD_SOURCE
        let socket = TcpSocket::new_v4().unwrap();
        socket
            .bind(SocketAddr::from((source, 0)))
            .map_err(|e| anyhow!("{:?}. {}", e, localhost_error_message()))
            .unwrap();

        let stream = socket.connect(socks_addr).await.unwrap();
        stream.set_nodelay(true).unwrap();
        socks5_connect(stream, addr).await.unwrap()
    }

    pub async fn dns_request(
        &self,
        hostname: &str,
        udp: bool,
        ipv6: bool,
    ) -> hickory_proto::xfer::DnsResponse {
        let addr = if udp {
            self.udp_dns_proxy_address.unwrap()
        } else {
            self.tcp_dns_proxy_address.unwrap()
        };
        dns_request(addr, hostname, udp, ipv6).await
    }
}

pub async fn dns_request(
    addr: SocketAddr,
    hostname: &str,
    udp: bool,
    ipv6: bool,
) -> hickory_proto::xfer::DnsResponse {
    use crate::test_helpers::dns::n;
    use crate::test_helpers::dns::send_request;
    use crate::test_helpers::dns::{new_tcp_client, new_udp_client};
    use hickory_proto::rr::RecordType;

    let mut client = if udp {
        new_udp_client(addr).await
    } else {
        new_tcp_client(addr).await
    };

    let query_type = if ipv6 {
        RecordType::AAAA
    } else {
        RecordType::A
    };

    send_request(&mut client, n(hostname), query_type).await
}

pub async fn socks5_connect(mut stream: TcpStream, addr: SocketAddr) -> anyhow::Result<TcpStream> {
    let addr_type = if addr.ip().is_ipv4() { 0x01u8 } else { 0x04u8 };
    stream
        .write_all(&[
            0x05u8, // socks5
            0x1u8,  // 1 auth method
            0x0u8,  // unauthenticated auth method
        ])
        .await?;
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await?;

    let mut cmd = vec![
        0x05u8, // socks5
        0x1u8,  // establish tcp stream
        0x0u8,  // RSV
        addr_type,
    ];
    match socket::to_canonical(addr).ip() {
        IpAddr::V6(ip) => cmd.extend_from_slice(&ip.octets()),
        IpAddr::V4(ip) => cmd.extend_from_slice(&ip.octets()),
    };
    cmd.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&cmd).await?;

    // We don't care about response but need to clear out the stream
    let mut resp = [0u8; 10];
    stream.read_exact(&mut resp).await?;

    Ok(stream)
}

#[derive(Debug)]
pub struct ParsedMetrics {
    scrape: Scrape,
}

impl ParsedMetrics {
    pub fn query(
        &self,
        metric: &str,
        labels: &HashMap<String, String>,
    ) -> Option<Vec<&prometheus_parse::Sample>> {
        if !self
            .scrape
            .docs
            .contains_key(metric.strip_suffix("_total").unwrap_or(metric))
        {
            return None;
        }
        Some(
            self.scrape
                .samples
                .iter()
                .filter(|s| s.metric == metric)
                .filter(|s| superset_of(s.labels.deref(), labels))
                .collect(),
        )
    }

    pub fn query_sum(&self, metric: &str, labels: &HashMap<String, String>) -> u64 {
        let res = self.query(metric, labels);
        res.map(|streams| {
            streams
                .into_iter()
                .map(|sample| {
                    match sample.value {
                        prometheus_parse::Value::Counter(f) => f,
                        // TODO(https://github.com/ccakes/prometheus-parse-rs/issues/5) remove this
                        prometheus_parse::Value::Untyped(f) => f,
                        _ => panic!("query_sum({metric}) must be a counter"),
                    }
                })
                .map(|f| f as u64)
                .sum()
        })
        .unwrap_or(0)
    }
    pub fn metric_info(&self) -> HashMap<String, String> {
        self.scrape.docs.clone()
    }
    pub fn dump(&self) -> String {
        self.scrape
            .samples
            .iter()
            .map(|s| format!("{s:?}"))
            .join("\n")
    }
}

fn superset_of(base: &HashMap<String, String>, check: &HashMap<String, String>) -> bool {
    for (k, v) in check {
        if base.get(k) != Some(v) {
            return false;
        }
    }
    true
}
