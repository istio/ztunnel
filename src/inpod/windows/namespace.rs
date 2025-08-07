use tracing::warn;
use windows::Win32::NetworkManagement::IpHelper::{
    GetCurrentThreadCompartmentId, SetCurrentThreadCompartmentId,
};

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct NetworkNamespace {
    // On Windows every network namespace is based
    // on a network compartment ID. This is the reference
    // we need when we want to create sockets inside
    // a network namespace or change IP stack configuration.
    pub compartment_id: u32,
    pub namespace_guid: String,
}

impl NetworkNamespace {
    pub fn current() -> std::io::Result<u32> {
        let curr_namespace = unsafe { GetCurrentThreadCompartmentId() };
        if curr_namespace.0 == 0 {
            warn!("GetCurrentThreadCompartmentId failed");
            return Err(std::io::Error::last_os_error());
        }
        Ok(curr_namespace.0)
    }

    pub fn capable() -> std::io::Result<()> {
        // Set the network compartment to the host compartment. This is intended to be a no-op,
        // and meant to be used as a test, so we can fail early if we can't set the netns.
        set_compartment(1)
    }

    pub fn new(workload_namespace: String) -> std::io::Result<Self> {
        let ns = hcn::get_namespace(&workload_namespace);
        match ns {
            Err(e) => {
                warn!("Failed to get namespace: {}", e);
                Err(std::io::Error::last_os_error())
            }
            Ok(ns) => Ok(NetworkNamespace {
                compartment_id: ns
                    .namespace_id
                    // Compartment ID 0 means undefined compartment ID.
                    // At the moment the JSON serialization ommits the field
                    // if it is set to 0. This happens when the compartment
                    // for the container is not yet available.
                    .unwrap_or(0),
                namespace_guid: ns.id,
            }),
        }
    }

    pub fn run<F, T>(&self, f: F) -> std::io::Result<T>
    where
        F: FnOnce() -> T,
    {
        set_compartment(self.compartment_id)?;
        let ret = f();
        // The Windows API defines the network compartment ID 1 as the
        // comapartment backing up the host network namespace.
        set_compartment(1).expect("failed to switch to host namespace");
        Ok(ret)
    }
}

// Hop into a network compartment
fn set_compartment(compartment_id: u32) -> std::io::Result<()> {
    if compartment_id == 0 {
        return Err(std::io::Error::other("undefined compartment ID"));
    }
    let error = unsafe { SetCurrentThreadCompartmentId(compartment_id) };
    if error.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(error.0 as i32));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use hcn::api;
    use hcn::schema::HostComputeQuery;
    use windows::core::GUID;

    use super::*;

    fn new_namespace() -> NetworkNamespace {
        let api_namespace = hcn::schema::HostComputeNamespace::default();

        let api_namespace = serde_json::to_string(&api_namespace).unwrap();
        let handle = hcn::api::create_namespace(&GUID::zeroed(), &api_namespace).unwrap();

        // we don't get info back so need to query to get metadata about network
        let query = HostComputeQuery::default();
        let query = serde_json::to_string(&query).unwrap();

        let api_namespace = api::query_namespace_properties(handle, &query).unwrap();

        let api_namespace: hcn::schema::HostComputeNamespace =
            serde_json::from_str(&api_namespace).unwrap();

        NetworkNamespace {
            compartment_id: api_namespace.namespace_id.unwrap(),
            namespace_guid: api_namespace.id,
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
