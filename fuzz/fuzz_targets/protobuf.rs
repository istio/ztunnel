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
