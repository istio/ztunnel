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
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Request, Response};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::proxy::connection_manager::ConnectionManager;
use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum State {
    Pending,
    Up,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProxyState {
    pub state: State,

    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "always_none",
        default
    )]
    pub connections: Option<ConnectionManager>,

    // using reference counts to account for possible race between the proxy task that notifies us
    // that a proxy is down, and the proxy factory task that notifies us when it is up.
    #[serde(skip)]
    count: usize,
}

fn always_none<'de, D>(_deserializer: D) -> Result<Option<ConnectionManager>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::de::IgnoredAny::deserialize(_deserializer)?;
    Ok(None)
}

#[derive(Default)]
pub struct WorkloadManagerAdminHandler {
    state: RwLock<HashMap<crate::inpod::WorkloadUid, ProxyState>>,
}

impl WorkloadManagerAdminHandler {
    pub fn proxy_pending(&self, uid: &crate::inpod::WorkloadUid) {
        let mut state = self.state.write().unwrap();

        // don't increment count here, as it is only for up and down. see comment in count.
        match state.get_mut(uid) {
            Some(key) => {
                key.state = State::Pending;
            }
            None => {
                state.insert(
                    uid.clone(),
                    ProxyState {
                        state: State::Pending,
                        connections: None,
                        count: 0,
                    },
                );
            }
        }
    }
    pub fn proxy_up(&self, uid: &crate::inpod::WorkloadUid, cm: Option<ConnectionManager>) {
        let mut state = self.state.write().unwrap();

        match state.get_mut(uid) {
            Some(key) => {
                key.count += 1;
                key.state = State::Up;
                key.connections = cm;
            }
            None => {
                state.insert(
                    uid.clone(),
                    ProxyState {
                        state: State::Up,
                        connections: cm,
                        count: 1,
                    },
                );
            }
        }
    }

    pub fn proxy_down(&self, uid: &crate::inpod::WorkloadUid) {
        let mut state = self.state.write().unwrap();

        match state.get_mut(uid) {
            Some(key) if key.count > 0 => {
                key.count -= 1;
                if key.count == 0 {
                    state.remove(uid);
                }
            }
            _ => {
                error!("proxy_down called where no proxy was created");
                debug_assert!(false, "proxy_down called where no proxy was created");
            }
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let serialized_state = if let Ok(state) = self.state.read() {
            serde_json::to_vec(&*state)
        } else {
            error!("Failed to read state");
            return vec![];
        };
        match serialized_state {
            Ok(v) => v,
            Err(e) => {
                error!("Failed serializing state {:?}", e);
                vec![]
            }
        }
    }
}

impl crate::admin::AdminHandler for WorkloadManagerAdminHandler {
    fn path(&self) -> &'static str {
        "/workloadmanager"
    }
    fn description(&self) -> &'static str {
        "Workload Manager Admin Handler"
    }

    fn handle(
        &self,
        _req: Request<Incoming>,
    ) -> std::pin::Pin<Box<dyn futures_util::Future<Output = Response<Full<Bytes>>> + Sync + Send>>
    {
        let data = self.to_bytes();
        let ready = std::future::ready(
            Response::builder()
                .status(hyper::StatusCode::OK)
                .body(data.into())
                .unwrap(),
        );
        Box::pin(ready)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_proxy_state() {
        let handler = WorkloadManagerAdminHandler::default();
        let data = || String::from_utf8_lossy(&handler.to_bytes()).to_string();

        let uid1 = crate::inpod::WorkloadUid::new("uid1".to_string());
        handler.proxy_pending(&uid1);
        assert_eq!(data(), "{\"uid1\":{\"state\":\"Pending\"}}");
        handler.proxy_up(&uid1, None);
        assert_eq!(data(), "{\"uid1\":{\"state\":\"Up\"}}");
        handler.proxy_down(&uid1);
        assert_eq!(data(), "{}");

        let state = handler.state.read().unwrap();
        assert_eq!(state.len(), 0);
    }
}
