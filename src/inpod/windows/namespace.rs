use nix::sched::{setns, CloneFlags};
use windows::Win32::System::HostComputeNetwork::HcnQueryNamespaceProperties;
use std::sync::Arc;
use uuid::Uuid;
use windows::Win32::NetworkManagement::IpHelper::{SetCurrentThreadCompartmentId, GetCurrentThreadCompartmentId};

#[derive(Clone, Debug)]
pub struct InpodNetns {
    inner: Arc<NetnsInner>,
}

#[derive(Debug)]
struct NetnsInner {
    current_namespace: Uuid,
    namespace_id: Uuid,
}

impl InpodNetns {
    pub fn current() -> std::io::Result<Uuid> {
        let curns = unsafe {
            GetCurrentThreadCompartmentId()
        };
        curns.map(|f| f.into())
    }

    pub fn capable() -> std::io::Result<()> {
        // set the netns to our current netns. This is intended to be a no-op,
        // and meant to be used as a test, so we can fail early if we can't set the netns
        let curns = Self::current()?;
        SetCurrentThreadCompartmentScope();
        setns(curns, CloneFlags::CLONE_NEWNET)
            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
    }
}
