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
}

impl AuthSource {
    pub fn load(&self) -> io::Result<Vec<u8>> {
        match self {
            AuthSource::Token(path, _) => {
                let t = std::fs::read(path)?;

                if t.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "token file exists, but was empty",
                    ));
                }
                Ok(t)
            }
        }
    }
}

impl Interceptor for AuthSource {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let token = self
            .load()
            .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))
            .map(|mut t| {
                let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                bearer.append(&mut t);
                bearer
            })
            .and_then(|b| {
                AsciiMetadataValue::try_from(b)
                    .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))
            })?;

        request.metadata_mut().insert("authorization", token);

        match self {
            AuthSource::Token(_, cluster_id) => {
                if !cluster_id.is_empty() {
                    let id = AsciiMetadataValue::try_from(cluster_id.as_bytes().to_vec())
                        .map_err(|e| Status::new(Code::Unauthenticated, e.to_string()))?;
                    request.metadata_mut().insert("clusterid", id);
                }
            }
        }
        Ok(request)
    }
}
