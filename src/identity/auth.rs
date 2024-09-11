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

use std::io;
use std::path::PathBuf;

use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::{Code, Request, Status};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthSource {
    // JWT authentication source which contains the token file path and the cluster id.
    Token(PathBuf, String),
    // JWT authentication source which contains a static token file.
    // Note that this token is not refreshed, so its lifetime ought to be longer than ztunnel's
    StaticToken(String, String),
    None,
}

impl AuthSource {
    fn read_token(&self) -> io::Result<Option<(Vec<u8>, String)>> {
        Ok(match self {
            AuthSource::Token(path, cluster_id) => {
                let token = load_token(path).map(|mut t| {
                    let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                    bearer.append(&mut t);
                    bearer
                })?;
                Some((token, cluster_id.to_string()))
            }
            AuthSource::StaticToken(token, cluster_id) => {
                let token = {
                    let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                    bearer.extend_from_slice(token.as_bytes());
                    bearer
                };
                Some((token, cluster_id.to_string()))
            }
            AuthSource::None => None,
        })
    }
}

fn load_token(path: &PathBuf) -> io::Result<Vec<u8>> {
    let t = std::fs::read(path)?;

    if t.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "token file exists, but was empty",
        ));
    }
    Ok(t)
}

impl Interceptor for AuthSource {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some((token, cluster_id)) = self
            .read_token()
            .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))?
        {
            let token = AsciiMetadataValue::try_from(token)
                .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))?;
            request.metadata_mut().insert("authorization", token);
            if !cluster_id.is_empty() {
                let id = AsciiMetadataValue::try_from(cluster_id.as_bytes().to_vec())
                    .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))?;
                request.metadata_mut().insert("clusterid", id);
            }
        }
        Ok(request)
    }
}
