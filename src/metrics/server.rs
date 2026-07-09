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
use futures_util::StreamExt;
use std::convert::Infallible;
use std::io::Write;
use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};

use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, StreamBody};
use hyper::body::Incoming;
use hyper::{Request, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;
use tokio::io::duplex;
use tokio_util::io::{ReaderStream, SyncIoBridge};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;

use crate::config::Config;
use crate::drain::DrainWatcher;
use crate::hyper_util;

struct FmtToIoWriter<'a, W: std::io::Write> {
    inner: &'a mut W,
}

impl<'a, W: std::io::Write> std::fmt::Write for FmtToIoWriter<'a, W> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.inner
            .write_all(s.as_bytes())
            .map_err(|_| std::fmt::Error)
    }
}

pub struct Server {
    s: hyper_util::Server,
    registry: Mutex<Registry>,
}

impl Server {
    pub async fn new(
        config: Arc<Config>,
        drain_rx: DrainWatcher,
        registry: Registry,
    ) -> anyhow::Result<Self> {
        hyper_util::Server::bind("stats", config.stats_addr, drain_rx)
            .await
            .map(|s| Server {
                s,
                registry: Mutex::new(registry),
            })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        let state = Arc::new(self.registry);
        let service = ServiceBuilder::new()
            .layer(CompressionLayer::new())
            .service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move {
                    match req.uri().path() {
                        "/metrics" | "/stats/prometheus" => Ok(handle_metrics(state, req).await),
                        _ => Response::builder()
                            .status(hyper::StatusCode::NOT_FOUND)
                            .body(Empty::new().boxed()),
                    }
                }
            });

        self.s.spawn(service)
    }
}

async fn handle_metrics(
    reg: Arc<Mutex<Registry>>,
    req: Request<Incoming>,
) -> Response<BoxBody<Bytes, Infallible>> {
    let (writer, reader) = duplex(4096);

    tokio::task::spawn_blocking(move || {
        let mut sync_writer = SyncIoBridge::new(writer);
        let reg = reg.lock().expect("mutex");
        let mut fmt_target = FmtToIoWriter {
            inner: &mut sync_writer,
        };
        let _ = encode(&mut fmt_target, &reg);
        let _ = sync_writer.flush();
    });

    let raw_stream = ReaderStream::new(reader);
    let framed_stream = raw_stream.map(|result| {
        let bytes = result.unwrap_or_else(|_| Bytes::new());
        Ok::<_, Infallible>(Frame::data(bytes))
    });

    let response_content_type = content_type(&req);

    Response::builder()
        .status(hyper::StatusCode::OK)
        .header(hyper::header::CONTENT_TYPE, response_content_type)
        .body(BoxBody::new(StreamBody::new(framed_stream)))
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
