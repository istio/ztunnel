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
    pub async fn insert_headers(&self, request: &mut http::HeaderMap) -> anyhow::Result<()> {
        const AUTHORIZATION: &str = "authorization";
        const CLUSTER: &str = "clusterid";
        match self {
            AuthSource::Token(path, cluster_id) => {
                let token = load_token(path).await.map(|mut t| {
                    let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                    bearer.append(&mut t);
                    bearer
                })?;
                request.insert(AUTHORIZATION, token.try_into()?);
                request.insert(CLUSTER, cluster_id.try_into()?);
            }
            AuthSource::StaticToken(token, cluster_id) => {
                let token = {
                    let mut bearer: Vec<u8> = b"Bearer ".to_vec();
                    bearer.extend_from_slice(token.as_bytes());
                    bearer
                };
                request.insert(AUTHORIZATION, token.try_into()?);
                request.insert(CLUSTER, cluster_id.try_into()?);
            }
            AuthSource::None => {}
        }
        Ok(())
    }
}

async fn load_token(path: &PathBuf) -> io::Result<Vec<u8>> {
    let t = tokio::fs::read(path).await?;

    if t.is_empty() {
        return Err(io::Error::other("token file exists, but was empty"));
    }
    Ok(t)
}
