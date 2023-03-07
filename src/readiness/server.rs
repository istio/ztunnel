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

use drain::Watch;
use hyper::{Body, Request, Response};
use itertools::Itertools;

use crate::hyper_util::{empty_response, plaintext_response, Server};
use crate::{config, readiness, signal};

pub struct Service {
    s: Server<readiness::Ready>,
}

impl Service {
    pub fn new(
        config: config::Config,
        ready: readiness::Ready,
        shutdown_trigger: signal::ShutdownTrigger,
        drain_rx: Watch,
    ) -> hyper::Result<Self> {
        Server::<readiness::Ready>::bind(
            "readiness",
            config.readiness_addr,
            shutdown_trigger,
            drain_rx,
            ready,
        )
        .map(|s| Service { s })
    }

    pub fn address(&self) -> SocketAddr {
        self.s.address()
    }

    pub fn spawn(self) {
        self.s.spawn(|ready, req| async move {
            match req.uri().path() {
                "/healthz/ready" => Ok(handle_ready(&ready, req).await),
                _ => Ok(empty_response(hyper::StatusCode::NOT_FOUND)),
            }
        })
    }
}

async fn handle_ready(ready: &readiness::Ready, req: Request<Body>) -> Response<Body> {
    match *req.method() {
        hyper::Method::GET => {
            let pending = ready.pending();
            if pending.is_empty() {
                return plaintext_response(hyper::StatusCode::OK, "ready\n".into());
            }
            plaintext_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "not ready, pending: {}\n",
                    pending.into_iter().sorted().join(", ")
                ),
            )
        }
        _ => empty_response(hyper::StatusCode::METHOD_NOT_ALLOWED),
    }
}
