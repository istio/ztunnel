use serde::{Deserialize, Serialize};
use tracing::error;

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
}