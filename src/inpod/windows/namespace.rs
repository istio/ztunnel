use nix::sched::{setns, CloneFlags};
use windows::Win32::{Foundation::NOERROR, System::HostComputeNetwork::HcnQueryNamespaceProperties};
use std::sync::Arc;
use uuid::Uuid;
use windows::Win32::NetworkManagement::IpHelper::{SetCurrentThreadCompartmentScope, SetCurrentThreadCompartmentId, GetCurrentThreadCompartmentId};

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
        let ret = unsafe {
            SetCurrentThreadCompartmentId(curns)
        };
        if ret != NOERROR {
            return Err(std::io::Error::from_raw_os_error(ret));
        }
        return Ok(())
    }
}
