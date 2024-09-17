use std::sync::Arc;
use uuid::Uuid;
use windows::Win32::NetworkManagement::IpHelper::{SetCurrentThreadCompartmentId, GetCurrentThreadCompartmentId};

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct NetnsID {
    pub inode: libc::ino_t,
    pub dev: libc::dev_t,
}

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
    pub fn current() -> std::io::Result<u32> {
        let curns = unsafe {
            GetCurrentThreadCompartmentId().0
        };
        if curns == 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok(curns)
    }

    pub fn capable() -> std::io::Result<()> {
        // set the netns to our current netns. This is intended to be a no-op,
        // and meant to be used as a test, so we can fail early if we can't set the netns
        let curns = Self::current()?;
        let ret = unsafe {
            SetCurrentThreadCompartmentId(curns)
        };
        if ret.is_err() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    // useful for logging / debugging
    pub fn workload_netns_id(&self) -> NetnsID {
        //// from previous implementation
        // self.inner.netns_id
        
        // TODO: Implement this
        NetnsID {
            inode: 0,
            dev: 0,
        }
    }
}
