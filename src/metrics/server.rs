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

use ::hyper_util::service::TowerToHyperService;
use bytes::Bytes;
use std::sync::Mutex;
use std::time::Duration;
use std::{net::SocketAddr, sync::Arc};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;

use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

use crate::config::Config;
use crate::drain::DrainWatcher;
use crate::hyper_util;
use crate::metrics::evict::Evictable;

pub struct Server {
    s: hyper_util::Server<Mutex<Registry>>,
    // If set, idle connection series are evicted on each scrape.
    evict: Vec<Arc<dyn Evictable>>,
    evict_ttl: Duration,
}

impl Server {
    pub async fn new(
        config: Arc<Config>,
        drain_rx: DrainWatcher,
        registry: Registry,
    ) -> anyhow::Result<Self> {
        hyper_util::Server::<Mutex<Registry>>::bind(
            "stats",
            config.stats_addr,
            drain_rx,
            Mutex::new(registry),
        )
        .await
        .map(|s| Server {
            s,
            evict: vec![],
            evict_ttl: config.metrics_eviction_ttl,
        })
    }

    /// Evict idle connection metrics whenever metrics are scraped.
    pub fn with_eviction(mut self, metrics: Arc<dyn Evictable>) -> Self {
        self.evict.push(metrics);
        self
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        let evict: Arc<[Arc<dyn Evictable>]> = self.evict.into();
        let evict_ttl = self.evict_ttl;
        self.s.spawn_service(move |registry: Arc<Mutex<Registry>>| {
            let evict = evict.clone();
            let service = ServiceBuilder::new()
                .layer(CompressionLayer::new())
                .service_fn(move |req: Request<Incoming>| {
                    let registry = registry.clone();
                    let evict = evict.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(match req.uri().path() {
                            "/metrics" | "/stats/prometheus" => {
                                handle_metrics(registry, evict, evict_ttl, req).await
                            }
                            _ => hyper_util::empty_response(hyper::StatusCode::NOT_FOUND),
                        })
                    }
                });
            TowerToHyperService::new(service)
        })
    }
}

async fn handle_metrics(
    reg: Arc<Mutex<Registry>>,
    evict: Arc<[Arc<dyn Evictable>]>,
    evict_ttl: Duration,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let mut buf = String::new();
    {
        let reg = reg.lock().expect("mutex");
        if let Err(err) = encode(&mut buf, &reg) {
            return Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(err.to_string().into())
                .expect("builder with known status code should not fail");
        }
    }

    // Evict only after a successful encode, so every series is exported at least once after its
    // last activity, even if the scrape interval is longer than the TTL. The registry lock is
    // released; the families take their own locks.
    for m in evict.iter() {
        m.evict_idle(evict_ttl);
    }

    let response_content_type = content_type(&req);

    Response::builder()
        .status(hyper::StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, response_content_type)
        .body(buf.into())
        .expect("builder with known status code should not fail")
}

#[derive(Default)]
enum ContentType {
    #[default]
    PlainText,
    OpenMetrics,
}

impl From<ContentType> for &str {
    fn from(c: ContentType) -> Self {
        match c {
            ContentType::PlainText => "text/plain; charset=utf-8",
            ContentType::OpenMetrics => "application/openmetrics-text;charset=utf-8;version=1.0.0",
        }
    }
}

#[inline(always)]
fn content_type<T>(req: &Request<T>) -> &str {
    req.headers()
        .get_all(http::header::ACCEPT)
        .iter()
        .flat_map(|entry| entry.to_str().ok())
        // get_all can return multiple in one line still
        .flat_map(|entry| entry.split(",").map(|entry| entry.to_lowercase()))
        .find_map(|v| match v.split(";").collect::<Vec<_>>().first() {
            Some(&"application/openmetrics-text") => Some(ContentType::OpenMetrics),
            _ => None,
        })
        .unwrap_or_default()
        .into()
}

#[cfg(test)]
mod test {
    #[test]
    fn test_content_type() {
        let plain_text_req = http::Request::new("I want some plain text");
        assert_eq!(
            super::content_type(&plain_text_req),
            "text/plain; charset=utf-8"
        );

        let openmetrics_req = http::Request::builder()
            .header("X-Custom-Beep", "boop")
            .header("Accept", "application/json")
            .header("Accept", "application/openmetrics-text; other stuff")
            .body("I would like openmetrics")
            .unwrap();
        assert_eq!(
            super::content_type(&openmetrics_req),
            "application/openmetrics-text;charset=utf-8;version=1.0.0"
        );

        let mixed_req = http::Request::builder()
          .header("X-Custom-Beep", "boop")
          .header("Accept", "application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;encoding=delimited;q=0.6,application/openmetrics-text;version=1.0.0;escaping=allow-utf-8;q=0.5,application/openmetrics-text;version=0.0.1;q=0.4,text/plain;version=1.0.0;escaping=allow-utf-8;q=0.3,text/plain;version=0.0.4;q=0.2,*/*;q=0.1")
          .body("I would like openmetrics")
          .unwrap();
        assert_eq!(
            super::content_type(&mixed_req),
            "application/openmetrics-text;charset=utf-8;version=1.0.0"
        );

        let unsupported_req_accept = http::Request::builder()
            .header("Accept", "application/json")
            .body("I would like some json")
            .unwrap();
        // asking for something we don't support, fall back to plaintext
        assert_eq!(
            super::content_type(&unsupported_req_accept),
            "text/plain; charset=utf-8"
        )
    }
}
