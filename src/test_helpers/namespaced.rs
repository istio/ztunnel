// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use libc::getpid;
use nix::sched::{setns, CloneFlags};
use nix::unistd::mkdtemp;
use std::fs;
use std::fs::File;
use std::path::PathBuf;

#[macro_export]
macro_rules! function {
    () => {{
        fn f() {}
        fn type_name_of<T>(_: T) -> &'static str {
            std::any::type_name::<T>()
        }
        let name = type_name_of(f);
        &name[..name.len() - 3]
    }};
}

/// setup_netns_test prepares a test using network namespaces. This checks we have root,
/// and automatically setups up a namespace based on the test name (to avoid conflicts).
#[macro_export]
macro_rules! setup_netns_test {
    ($mode:expr) => {{
        if unsafe { libc::getuid() } != 0 {
            panic!("CI tests should run as root; this is supposed to happen automatically?");
        }
        ztunnel::test_helpers::helpers::initialize_telemetry();
        let function_name = ztunnel::function!()
            .strip_prefix(module_path!())
            .unwrap()
            .strip_prefix("::")
            .unwrap();
        let function_name = function_name
            .strip_suffix("::{{closure}}")
            .unwrap_or_else(|| function_name);
        ztunnel::test_helpers::linux::WorkloadManager::new(function_name, $mode)?
    }};
}
/// initialize_namespace_tests sets up the namespace tests.
/// These utilize the `unshare` syscall to setup an environment where we:
/// * Are "root"
/// * Have our own network namespace to mess with (and create other network namespaces within)
/// * Have a few shared files re-mounted to not impact the host
///
/// This should be called like
/// ```ignore
/// #[ctor::ctor]
//  fn initialize_namespace_tests() {
//      ztunnel::test_helpers::namespaced::initialize_namespace_tests();
//  }
// ```
/// The special ctor macro ensures this is run *before* any code. In particular, before tokio runtime.
pub fn initialize_namespace_tests() {
    use libc::getuid;
    use nix::mount::{mount, MsFlags};
    use nix::sched::{unshare, CloneFlags};
    use std::io::Write;

    // First, drop into a new user namespace.
    let original_uid = unsafe { getuid() };
    unshare(CloneFlags::CLONE_NEWUSER).unwrap();
    let mut data_file = File::create("/proc/self/uid_map").expect("creation failed");

    // Map our current user to root in the new network namespace
    data_file
        .write_all(format!("{} {} 1", 0, original_uid).as_bytes())
        .expect("write failed");

    // Setup a new network namespace
    unshare(CloneFlags::CLONE_NEWNET).unwrap();

    // Setup a new mount namespace
    unshare(CloneFlags::CLONE_NEWNS).unwrap();

    // Temporary directory will hold all our mounts
    let tp = std::env::temp_dir().join("ztunnel_namespaced.XXXXXX");
    let tmp = mkdtemp(&tp).expect("tmp dir");

    // Create /var/run/netns and if it doesn't exist. Technically this requires root, but any system should have this
    fs::create_dir_all("/var/run/netns").expect("host netns dir doesn't exist and we are not root");
    let _ = File::create_new("/run/xtables.lock");
    // Bind mount /var/run/netns so we can make our own independent network namespaces
    fs::create_dir(tmp.join("netns")).expect("netns dir");
    mount(
        Some(&tmp.join("netns")),
        "/var/run/netns",
        None::<&PathBuf>,
        MsFlags::MS_BIND,
        None::<&PathBuf>,
    )
    .expect("network namespace bindmount");

    // Bind xtables lock so we can access it (otherwise, permission denied)
    File::create(tmp.join("xtables.lock")).expect("xtables file");
    mount(
        Some(&tmp.join("xtables.lock")),
        "/run/xtables.lock",
        None::<&PathBuf>,
        MsFlags::MS_BIND,
        None::<&PathBuf>,
    )
    .expect("xtables bindmount");

    let pid = unsafe { getpid() };
    eprintln!("Starting test in {tmp:?}. Debug with `sudo nsenter --mount --net -t {pid}`");
}
