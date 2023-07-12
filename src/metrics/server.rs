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

use drain::Watch;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

use crate::config::Config;
use crate::hyper_util;

pub struct Server {
    s: hyper_util::Server<Mutex<Registry>>,
}

impl Server {
    pub async fn new(config: Config, drain_rx: Watch, registry: Registry) -> anyhow::Result<Self> {
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
    _req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let mut buf = String::new();
    let reg = reg.lock().unwrap();
    encode(&mut buf, &reg).unwrap();

    Response::builder()
        .status(hyper::StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/openmetrics-text;charset=utf-8;version=1.0.0",
        )
        .body(buf.into())
        .unwrap()
}
