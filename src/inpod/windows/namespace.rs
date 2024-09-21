use std::sync::Arc;
use tracing::warn;
use windows::Win32::NetworkManagement::IpHelper::{
    GetCurrentThreadCompartmentId, SetCurrentThreadCompartmentId,
};

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Namespace {
    pub id: u32,
    pub guid: String,
}

#[derive(Clone, Debug)]
pub struct InpodNamespace {
    inner: Arc<NetnsInner>,
}

#[derive(Debug, Eq, PartialEq)]
struct NetnsInner {
    current_namespace: u32,
    workload_namespace: Namespace,
}

impl InpodNamespace {
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

    pub fn new(cur_namespace: u32, workload_namespace: String) -> std::io::Result<Self> {
        let ns = hcn::get_namespace(&workload_namespace);
        match ns {
            Err(e) => {
                warn!("Failed to get namespace: {}", e);
                Err(std::io::Error::last_os_error())
            }
            Ok(ns) => Ok(InpodNamespace {
                inner: Arc::new(NetnsInner {
                    current_namespace: cur_namespace,
                    workload_namespace: Namespace {
                        id: ns
                            .namespace_id
                            .expect("There must always be a namespace id"),
                        guid: ns.id,
                    },
                }),
            }),
        }
    }

    pub fn workload_namespace(&self) -> u32 {
        self.inner.workload_namespace.id
    }

    // Useful for logging / debugging
    pub fn workload_namespace_guid(&self) -> String {
        self.inner.workload_namespace.guid.clone()
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

// hop into a namespace
fn setns(namespace: u32) -> std::io::Result<()> {
    let error = unsafe { SetCurrentThreadCompartmentId(namespace) };
    if error.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(error.0 as i32));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hcn::schema::HostComputeQuery;
    use hcn::api;
    use windows::core::GUID;

    use super::*;

    fn new_namespace() -> Namespace {
        let api_namespace = hcn::schema::HostComputeNamespace::default();

        let api_namespace = serde_json::to_string(&api_namespace).unwrap();
        let handle = hcn::api::create_namespace(&GUID::zeroed(), &api_namespace).unwrap();

        // we don't get info back so need to query to get metadata about network
        let query = HostComputeQuery::default();
        let query = serde_json::to_string(&query).unwrap();

        let api_namespace = api::query_namespace_properties(handle, &query).unwrap();

        let api_namespace: hcn::schema::HostComputeNamespace =
            serde_json::from_str(&api_namespace).unwrap();

        Namespace {
            id: api_namespace.namespace_id.unwrap(),
            guid: api_namespace.id,
        }
    }

    #[test]
    fn test_run_works() {
        if !crate::test_helpers::can_run_privilged_test() {
            eprintln!("This test requires root; skipping");
            return;
        }

        // TODO: Right now, creating a namespace doesn't automatically create a compartment
        // (the actual network stack/context). Add these tests back when that capability is added
        // in Windows Server 2025.
        // start with new netns to not impact the current netns
        // unshare(CloneFlags::CLONE_NEWNET).unwrap();
        // let cur_netns = InpodNetns::current().unwrap();
        // helpers::run_command("ip link add name dummy1 type dummy").unwrap();

        // let other_netns = new_netns();

        // let sync_netns =
        //     netns_rs::get_from_path(format!("/proc/self/fd/{}", other_netns.as_raw_fd())).unwrap();
        // sync_netns
        //     .run(|_| helpers::run_command("ip link add name dummy2 type dummy"))
        //     .expect("netns run failed")
        //     .unwrap();

        // // test with future netns
        // let netns = InpodNetns::new(Arc::new(cur_netns), other_netns).unwrap();

        // let output = netns
        //     .run(|| Command::new("ip").args(["link", "show"]).output())
        //     .expect("netns run failed")
        //     .expect("tokio command failed");

        // assert!(output.status.success());
        // let out_str = String::from_utf8_lossy(output.stdout.as_slice());
        // assert!(!out_str.contains("dummy1"));
        // assert!(out_str.contains("dummy2"));

        // // make sure we returned to the original ns

        // let output = Command::new("ip").args(["link", "show"]).output().unwrap();

        // assert!(output.status.success());
        // let out_str = String::from_utf8_lossy(output.stdout.as_slice());
        // assert!(out_str.contains("dummy1"));
        // assert!(!out_str.contains("dummy2"));
    }
}
