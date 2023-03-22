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

use std::sync::Mutex;
use std::{net::SocketAddr, sync::Arc};

use drain::Watch;
use hyper::{Body, Request, Response};
use prometheus_client::encoding::text::encode;
use prometheus_client::registry::Registry;

use crate::config::Config;
use crate::hyper_util::{empty_response, Server};
use crate::signal;

pub struct Service {
    s: Server<Mutex<Registry>>,
}

impl Service {
    pub fn new(
        config: Config,
        registry: Registry,
        shutdown_trigger: signal::ShutdownTrigger,
        drain_rx: Watch,
    ) -> hyper::Result<Self> {
        Server::<Mutex<Registry>>::bind(
            "stats",
            config.stats_addr,
            shutdown_trigger,
            drain_rx,
            Mutex::new(registry),
        )
        .map(|s| Service { s })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        self.s.spawn(|registry, req| async move {
            match req.uri().path() {
                "/metrics" | "/stats/prometheus" => Ok(handle_metrics(registry, req).await),
                _ => Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

async fn handle_metrics(reg: Arc<Mutex<Registry>>, _req: Request<Body>) -> Response<Body> {
    let mut buf = String::new();
    let reg = reg.lock().unwrap();
    encode(&mut buf, &reg).unwrap();

    Response::builder()
        .status(hyper::StatusCode::OK)
        .header(
            hyper::header::CONTENT_TYPE,
            "application/openmetrics-text;charset=utf-8;version=1.0.0",
        )
        .body(Body::from(buf))
        .unwrap()
}
