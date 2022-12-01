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

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};
use serde::Serialize;
use tokio::net::TcpStream;

use tracing::{error, trace};

use traffic::ConnectionOpen;

use crate::identity::Identity;
use crate::metrics::traffic::ConnectionClose;
use crate::metrics::{traffic, MetricGuard, Metrics};

use super::Error;

#[derive(Clone, Copy, Hash, Debug, Eq, PartialEq)]
pub struct ConnectionTuple {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

/// ConnectionTracker trackers connections. It stores a map of all active connections, and handles recording
/// metrics for connection establishment and termination.
#[derive(Clone)]
pub struct ConnectionTracker {
    conns: Arc<Mutex<HashMap<ConnectionTuple, Option<Identity>>>>,
    metrics: Arc<Metrics>,
}

impl ConnectionTracker {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        ConnectionTracker {
            conns: Default::default(),
            metrics,
        }
    }

    /// fetch looks up a tuple and returns the connection metadata
    pub fn fetch(&self, ctu: &ConnectionTuple) -> Option<ConnectionMetadata> {
        let cm = self.conns.lock().unwrap();
        cm.get(ctu)
            .cloned()
            .map(|identity| ConnectionMetadata { identity })
    }

    pub fn track<'a>(
        &'a self,
        ct: ConnectionTuple,
        conn: &'a ConnectionOpen,
    ) -> ConnectionGuard<'a> {
        {
            let mut c = self.conns.lock().unwrap();

            let id = if let Some(ds) = &conn.derived_source {
                ds.identity.clone()
            } else {
                conn.destination.as_ref().map(|w| w.identity())
            };
            trace!(tuple=?ct, id=?id, "tracking connection");
            c.insert(ct, id);
        }
        let connection_close = self.metrics.increment_defer::<_, ConnectionClose>(conn);
        ConnectionGuard::<'a> {
            _metric: connection_close,
            ct: self,
            tup: ct,
        }
    }
}

pub struct ConnectionGuard<'a> {
    /// _metric is just here to drop when we drop and record the connection close metric
    _metric: MetricGuard<'a, ConnectionClose<'a>>,
    ct: &'a ConnectionTracker,
    tup: ConnectionTuple,
}

impl<'a> Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        trace!(tuple=?self.tup, "forgetting connection");
        let mut cm = self.ct.conns.lock().unwrap();
        cm.remove(&self.tup);
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionMetadata {
    #[serde(default)]
    identity: Option<Identity>,
}

/// METADATA_SERVER_IP provides the well-known metadata server IP.
/// This is captured by the redirection.
pub const METADATA_SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 111));

pub async fn handle_metadata_lookup(
    ct: &ConnectionTracker,
    stream: TcpStream,
    remote_addr: SocketAddr,
) -> Result<(), Error> {
    trace!(remote=%remote_addr, "metadata lookup");
    if let Err(e) = crate::hyper_util::http1_server()
        .half_close(true)
        .header_read_timeout(Duration::from_secs(2))
        .max_buf_size(8 * 1024)
        .serve_connection(
            stream,
            service_fn(|req: hyper::Request<hyper::body::Incoming>| {
                let ct = ct.clone();
                async move {
                    let res: Result<_, Infallible> =
                        serve_request(&ct, remote_addr, req).or_else(|e| {
                            Ok(crate::hyper_util::plaintext_response(
                                StatusCode::UNPROCESSABLE_ENTITY,
                                e.to_string(),
                            ))
                        });
                    res
                }
            }),
        )
        .await
    {
        error!("Error while serving HTTP connection: {}", e);
    }
    Ok(())
}

fn serve_request(
    ct: &ConnectionTracker,
    remote: SocketAddr,
    req: hyper::Request<hyper::body::Incoming>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let query = req.uri().query().ok_or(anyhow!("missing query"))?;

    let params = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();
    let src = SocketAddr::new(
        params
            .get("srcip")
            .ok_or(anyhow!("missing srcip"))?
            .parse()?,
        params
            .get("srcport")
            .ok_or(anyhow!("missing srcport"))?
            .parse()?,
    );
    let dst = SocketAddr::new(
        params
            .get("dstip")
            .ok_or(anyhow!("missing dstip"))?
            .parse()?,
        params
            .get("dstport")
            .ok_or(anyhow!("missing dstport"))?
            .parse()?,
    );
    if remote.ip() != dst.ip() && remote.ip() != src.ip() {
        anyhow::bail!("metadata server request must come from the src or dst address")
    }
    let ctu = ConnectionTuple { src, dst };
    let Some(resp) = ct.fetch(&ctu) else {
        return Ok(crate::hyper_util::plaintext_response(StatusCode::NOT_FOUND, "".to_string()))
    };

    let r = serde_json::to_vec(&resp).unwrap();
    Ok(Response::new(Full::new(Bytes::from(r))))
}
