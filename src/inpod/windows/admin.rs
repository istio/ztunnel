use serde::{Deserialize, Serialize};
use tracing::error;
use anyhow::anyhow;

use crate::proxy::connection_manager::ConnectionManager;
use crate::state::WorkloadInfo;

use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum State {
    Pending,
    Up,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyState {
    pub state: State,

    #[serde(
        skip_serializing_if = "Option::is_none",
        deserialize_with = "always_none",
        default
    )]
    pub connections: Option<ConnectionManager>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub info: Option<WorkloadInfo>,

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
    state: RwLock<HashMap<crate::inpod::windows::WorkloadUid, ProxyState>>,
}

impl WorkloadManagerAdminHandler {
    pub fn proxy_pending(
        &self,
        uid: &crate::inpod::windows::WorkloadUid,
        workload_info: &Option<WorkloadInfo>,
    ) {
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
                        info: workload_info.clone(),
                    },
                );
            }
        }
    }

    pub fn proxy_up(
        &self,
        uid: &crate::inpod::windows::WorkloadUid,
        workload_info: &Option<WorkloadInfo>,
        cm: Option<ConnectionManager>,
    ) {
        let mut state = self.state.write().unwrap();

        match state.get_mut(uid) {
            Some(key) => {
                key.count += 1;
                key.state = State::Up;
                key.connections = cm;
                key.info.clone_from(workload_info);
            }
            None => {
                state.insert(
                    uid.clone(),
                    ProxyState {
                        state: State::Up,
                        connections: cm,
                        count: 1,
                        info: workload_info.clone(),
                    },
                );
            }
        }
    }

    pub fn proxy_down(&self, uid: &crate::inpod::windows::WorkloadUid) {
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

    fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        if let Ok(state) = self.state.read() {
            Ok(serde_json::to_value(&*state)?)
        } else {
            Err(anyhow!("Failed to read state"))
        }
    }
}

impl crate::admin::AdminHandler2 for WorkloadManagerAdminHandler {
    fn key(&self) -> &'static str {
        "workloadState"
    }

    fn handle(&self) -> anyhow::Result<serde_json::Value> {
        self.to_json()
    }
}