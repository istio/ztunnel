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
                async move { serve_request(&ct, remote_addr, req).await }
            }),
        )
        .await
    {
        error!("Error while serving HTTP connection: {}", e);
    }
    Ok(())
}

/// serve_request handles a metadata request. Any errors will be returned to the client.
async fn serve_request<T>(
    ct: &ConnectionManager,
    remote: SocketAddr,
    req: hyper::Request<T>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    serve_request_helper(ct, remote, req).await.or_else(|e| {
        Ok(crate::hyper_util::plaintext_response(
            StatusCode::UNPROCESSABLE_ENTITY,
            e.to_string(),
        ))
    })
}

// Errors are returned to client
async fn serve_request_helper<T>(
    ct: &ConnectionManager,
    remote: SocketAddr,
    req: hyper::Request<T>,
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
    // TODO: allow lookup as client or server; for now we only write to the ConnectionManager for inbound, so only server is supported
    if remote.ip() != dst.ip() {
        return Ok(crate::hyper_util::plaintext_response(
            StatusCode::UNAUTHORIZED,
            format!(
                "metadata server request must come from the src or dst address (remote {}, dst {})",
                remote.ip(),
                dst.ip()
            ),
        ));
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
#[cfg(test)]
mod tests {
    use http_body_util::{BodyExt, Empty};
    use hyper::Method;
    use std::net::{Ipv4Addr, SocketAddrV4};

    use crate::rbac::Connection;

    use super::ConnectionManager;
    use super::*;

    #[tokio::test]
    async fn test_metadata_server() {
        let connection_manager = ConnectionManager::default();

        let rbac_ctx1 = crate::state::ProxyRbacContext {
            conn: Connection {
                src_identity: Some("spiffe://td/ns/n/sa/s".parse().unwrap()),
                src: "127.0.0.1:1234".parse().unwrap(),
                dst: "127.0.0.2:8080".parse().unwrap(),
                dst_network: "".to_string(),
            },
            dest_workload_info: None,
        };

        connection_manager.register(&rbac_ctx1).await;

        let res = serve_request(
            &connection_manager,
            // Request will come from the destination, with some random port
            "127.0.0.2:4567".parse().unwrap(),
            hyper::Request::builder()
                .uri("http://foo/connection?src=127.0.0.1:1234&dst=127.0.0.2:8080")
                .method(Method::GET)
                .version(hyper::Version::HTTP_11)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            "{\"peer_identity\":\"spiffe://td/ns/n/sa/s\"}",
            std::str::from_utf8(res.collect().await.unwrap().to_bytes().as_ref()).unwrap()
        );

        // Wrong destination port
        let res = serve_request(
            &connection_manager,
            // Request will come from the destination, with some random port
            "127.0.0.2:4567".parse().unwrap(),
            hyper::Request::builder()
                .uri("http://foo/connection?src=127.0.0.1:1234&dst=127.0.0.2:999")
                .method(Method::GET)
                .version(hyper::Version::HTTP_11)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, res.status());

        // Wrong src port
        let res = serve_request(
            &connection_manager,
            // Request will come from the destination, with some random port
            "127.0.0.2:4567".parse().unwrap(),
            hyper::Request::builder()
                .uri("http://foo/connection?src=127.0.0.1:9999&dst=127.0.0.2:8080")
                .method(Method::GET)
                .version(hyper::Version::HTTP_11)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, res.status());

        // Not a part of the connection
        let res = serve_request(
            &connection_manager,
            // Bogus source of request
            "127.0.0.9:4567".parse().unwrap(),
            hyper::Request::builder()
                .uri("http://foo/connection?src=127.0.0.1:1234&dst=127.0.0.2:8080")
                .method(Method::GET)
                .version(hyper::Version::HTTP_11)
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(StatusCode::UNAUTHORIZED, res.status());
    }
}
