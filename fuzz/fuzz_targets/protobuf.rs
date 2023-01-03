#![no_main]

use libfuzzer_sys::fuzz_target;
use ztunnel::xds::istio::workload::Workload as XdsWorkload;
use ztunnel::xds::istio::workload::Rbac as XdsRbac;
use prost::Message;
use ztunnel::workload::Workload;
use ztunnel::rbac::Rbac;

fuzz_target!(|data: &[u8]| {
    let _ = run_workload(data);
    let _ = run_rbac(data);
});

fn run_workload(data: &[u8]) -> anyhow::Result<()> {
    Workload::try_from(&XdsWorkload::decode(data)?)?;
    Ok(())
}

fn run_rbac(data: &[u8]) -> anyhow::Result<()> {
    Rbac::try_from(&XdsRbac::decode(data)?)?;
    Ok(())
}
