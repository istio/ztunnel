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

use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Response, StatusCode};

use tokio::net::TcpStream;
use tracing::{error, trace};

use crate::proxy::connection_manager::{ConnectionManager, ConnectionTuple};

use super::Error;

/// METADATA_SERVER_IP provides the well-known metadata server IP.
/// This is captured by the redirection.
pub const METADATA_SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 111));

pub async fn handle_metadata_lookup(
    ct: &ConnectionManager,
    stream: TcpStream,
    remote_addr: SocketAddr,
) -> Result<(), Error> {
    trace!(remote=%remote_addr, "metadata lookup");
    if let Err(e) = crate::hyper_util::http1_server()
        .half_close(true)
        .header_read_timeout(Duration::from_secs(2))
        .max_buf_size(8 * 1024)
        .serve_connection(
            hyper_util::rt::TokioIo::new(stream),
            service_fn(|req: hyper::Request<hyper::body::Incoming>| {
                let ct = ct.clone();
                async move {
                    let res: Result<_, Infallible> =
                        serve_request(&ct, remote_addr, req).await.or_else(|e| {
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

async fn serve_request(
    ct: &ConnectionManager,
    remote: SocketAddr,
    req: hyper::Request<hyper::body::Incoming>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    // Currently only one path, so just check it
    if req.uri().path() != "/connection" {
        anyhow::bail!("invalid path")
    }

    let query = req.uri().query().ok_or(anyhow!("missing query"))?;

    let params = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect::<HashMap<String, String>>();
    let src: SocketAddr = params.get("src").ok_or(anyhow!("missing src"))?.parse()?;
    let dst: SocketAddr = params.get("dst").ok_or(anyhow!("missing dst"))?.parse()?;

    // To restrict access to sensitive metadata, ensure the client is part of the requested connection.
    // This can be error prone if the client has multiple NICs.
    if remote.ip() != dst.ip() && remote.ip() != src.ip() {
        anyhow::bail!("metadata server request must come from the src or dst address (remote {}, dst {}, src {})", remote.ip(), dst.ip(), src.ip())
    }

    let ctu = ConnectionTuple { src, dst };
    let Some(resp) = ct.fetch(&ctu).await else {
        return Ok(crate::hyper_util::plaintext_response(
            StatusCode::NOT_FOUND,
            "".to_string(),
        ));
    };

    let r = serde_json::to_vec(&resp).unwrap();
    Ok(Response::new(Full::new(Bytes::from(r))))
}
