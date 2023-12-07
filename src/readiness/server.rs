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

use std::net::SocketAddr;

use bytes::Bytes;
use drain::Watch;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use itertools::Itertools;

use crate::hyper_util;
use crate::{config, readiness};

pub struct Server {
    s: hyper_util::Server<readiness::Ready>,
    ready: readiness::Ready,
}

impl Server {
    pub async fn new(
        config: config::Config,
        drain_rx: Watch,
        ready: readiness::Ready,
    ) -> anyhow::Result<Self> {
        hyper_util::Server::<readiness::Ready>::bind(
            "readiness",
            config.readiness_addr,
            drain_rx,
            ready.clone(),
        )
        .await
        .map(|s| Server { s, ready })
    }

    pub fn ready(&self) -> readiness::Ready {
        self.ready.clone()
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        self.s.spawn(|ready, req| async move {
            match req.uri().path() {
                "/healthz/ready" => Ok(handle_ready(&ready, req).await),
                _ => Ok(hyper_util::empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

async fn handle_ready(ready: &readiness::Ready, req: Request<Incoming>) -> Response<Full<Bytes>> {
    match *req.method() {
        hyper::Method::GET => {
            let pending = ready.pending();
            if pending.is_empty() {
                return hyper_util::plaintext_response(hyper::StatusCode::OK, "ready\n".into());
            }
            hyper_util::plaintext_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "not ready, pending: {}\n",
                    pending.into_iter().sorted().join(", ")
                ),
            )
        }
        _ => hyper_util::empty_response(hyper::StatusCode::METHOD_NOT_ALLOWED),
    }
}
