use std::collections::HashMap;
use std::sync::RwLock;

#[derive(Default)]
pub struct WorkloadManagerAdminHandler {
    state: RwLock<HashMap<crate::inpod::windows::WorkloadUid, crate::state::ProxyState>>,
}