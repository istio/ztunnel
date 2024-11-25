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

use bytes::Bytes;
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};

use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

use crate::config::Config;
use crate::drain::DrainWatcher;
use crate::hyper_util;

pub struct Server {
    s: hyper_util::Server<Mutex<Registry>>,
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
        .map(|s| Server { s })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        self.s.spawn(|registry, req| async move {
            match req.uri().path() {
                "/metrics" | "/stats/prometheus" => Ok(handle_metrics(registry, req).await),
                _ => Ok(hyper_util::empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

async fn handle_metrics(
    reg: Arc<Mutex<Registry>>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let mut buf = String::new();
    let reg = reg.lock().expect("mutex");
    if let Err(err) = encode(&mut buf, &reg) {
        return Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .body(err.to_string().into())
            .expect("builder with known status code should not fail");
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
        .find_map(|v| {
            match v
                .to_str()
                .unwrap_or_default()
                .to_lowercase()
                .split(";")
                .collect::<Vec<_>>()
                .first()
            {
                Some(&"application/openmetrics-text") => Some(ContentType::OpenMetrics),
                _ => None,
            }
        })
        .unwrap_or_default()
        .into()
}

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
