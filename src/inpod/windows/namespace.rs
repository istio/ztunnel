use std::sync::Arc;
use log::warn;
use windows::core::GUID;
use windows::Win32::NetworkManagement::IpHelper::{SetCurrentThreadCompartmentId, GetCurrentThreadCompartmentId};
// use windows::Win32::System::HostComputeNetwork as hcn;


#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct NetnsID {
    pub inode: libc::ino_t,
    pub dev: libc::dev_t,
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Namespace {
    pub id: u32,
    pub guid: GUID,
}

#[derive(Clone, Debug)]
pub struct InpodNetns {
    inner: Arc<NetnsInner>,
}

#[derive(Debug, Eq, PartialEq)]
struct NetnsInner {
    current_namespace: u32,
    workload_namespace: Namespace,
}

impl InpodNetns {
    pub fn current() -> std::io::Result<u32> {
        let curr_namespace = unsafe { GetCurrentThreadCompartmentId() };
        if curr_namespace.0 == 0 {
            warn!("GetCurrentThreadCompartmentId failed");
            return Err(std::io::Error::last_os_error());
        }
        Ok(curr_namespace.0)
    }

    pub fn capable() -> std::io::Result<()> {
        // set the netns to our current netns. This is intended to be a no-op,
        // and meant to be used as a test, so we can fail early if we can't set the netns
        let curr_namespace = Self::current()?;
        setns(curr_namespace)
    }

    // pub fn new(cur_namespace: u32, workload_namespace: String) -> std::io::Result<Self> {
    //     let ns = hcn::get_namespace(&workload_namespace);
    //     match ns {
    //         Err(e) => {
    //             warn!("Failed to get namespace: {}", e);
    //             return Err(std::io::Error::last_os_error());
    //         }
    //         Ok(ns) => Ok(InpodNamespace {
    //             inner: Arc::new(NetnsInner {
    //                 current_namespace: cur_namespace,
    //                 workload_namespace: Namespace {
    //                     id: ns
    //                         .namespace_id
    //                         .expect("There must always be a namespace id"),
    //                     guid: GUID::from(ns.id.as_str()),
    //                 },
    //             }),
    //         }),
    //     }
    // }

    pub fn workload_namespace(&self) -> u32 {
        self.inner.workload_namespace.id
    }

    // Useful for logging / debugging
    pub fn workload_namespace_guid(&self) -> GUID {
        self.inner.workload_namespace.guid
    }

    // useful for logging / debugging
    pub fn workload_netns_id(&self) -> NetnsID {  // FIXME
        //// from previous implementation
        // self.inner.netns_id
        
        // TODO: Implement this
        NetnsID {
            inode: 0,
            dev: 0,
        }
    }
}

fn setns(namespace: u32) -> std::io::Result<()> {
    let error = unsafe { SetCurrentThreadCompartmentId(namespace) };
    if error.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(error.0 as i32));
    }
    Ok(())
}
