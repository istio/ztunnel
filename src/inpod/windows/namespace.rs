use std::sync::Arc;
use log::warn;
use windows::core::GUID;
use windows::Win32::NetworkManagement::IpHelper::{SetCurrentThreadCompartmentId, GetCurrentThreadCompartmentId};
// use windows::Win32::System::HostComputeNetwork as hcn;


#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub struct Namespace {
    pub id: u32,
    pub guid: GUID,
}

#[derive(Clone, Debug)]
pub struct InpodNetns {
    // sjinxuan: this Arc seems unecessary.
    // In linux, a netns is represented by a file descriptor, we have to be mindful of copies, lifetimes, ownership, etc.
    // In windows, a netns is represented by a u32. 
    inner: Arc<NetnsInner>,
}

#[derive(Debug, Eq, PartialEq)]
struct NetnsInner {
    current_namespace: u32,
    workload_namespace: Namespace,
}

impl InpodNetns {
    pub fn current() -> std::io::Result<u32> {
        // GetCurrentThreadCompartmentId returns 0 on failure, which not how WIN32_ERROR is documented.
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

    pub fn new(cur_namespace: u32, workload_namespace: u32) -> std::io::Result<Self> {
        // We should check if the namespace is valid, but idk how to do that, so just assume the namespace exists
        // Maybe we can try switching in and out of it.
        // the i32 doesn't matter, but i can't give it () and i need to give it something
        // FIXME: sjinxuan (or anybody else)
        let ns: Result<u32, f32> = Ok(workload_namespace); // = Compartment(&workload_namespace);
        match ns {
            Err(e) => {
                warn!("Failed to get namespace: {}", e);
                return Err(std::io::Error::last_os_error());
            }
            Ok(ns) => Ok(InpodNetns {
                inner: Arc::new(NetnsInner {
                    current_namespace: cur_namespace,
                    workload_namespace: Namespace {
                        id: ns,
                            // .namespace_id
                            // .expect("There must always be a namespace id"),
                        // FIXME: sjinxuan (or anybody else)
                        // since I couldnt figure out how to query namespace stuff, i can't get the guid so i just set it to zero.
                        // this might not matter if we only use the id to move around
                        guid: GUID::from(0),
                    },
                }),
            }),
        }
    }

    pub fn workload_namespace(&self) -> u32 {
        self.inner.workload_namespace.id
    }

    // Useful for logging / debugging
    // sjinxuan: maybe we can delete this since the api only seems to be using u32 ids instead of the GUIDs.
    pub fn workload_namespace_guid(&self) -> GUID {
        self.inner.workload_namespace.guid
    }

    pub fn run<F, T>(&self, f: F) -> std::io::Result<T>
    where
        F: FnOnce() -> T,
    {
        setns(self.inner.workload_namespace.id)?;
        let ret = f();
        setns(self.inner.current_namespace).expect("this must never fail");
        Ok(ret)
    }
}

/// Hop into a namespace
fn setns(namespace: u32) -> std::io::Result<()> {
    let error = unsafe { SetCurrentThreadCompartmentId(namespace) };
    if error.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(error.0 as i32));
    }
    Ok(())
}
