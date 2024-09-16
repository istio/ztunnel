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

struct WorkloadProxyNetworkHandler {
    uds: PathBuf,
}

struct WorkloadProxyReadinessHandler {
    ready: readiness::Ready,
    // Manually drop as we don't want to mark ready if we are dropped.
    // This can happen when the server drains.
    block_ready: Option<std::mem::ManuallyDrop<readiness::BlockReady>>,
    backoff: ExponentialBackoff,
}

pub struct WorkloadProxyManager {
    state: super::statemanager::WorkloadProxyManagerState,
    networking: WorkloadProxyNetworkHandler,
    // readiness - we are only ready when we are connected. if we get disconnected, we become not ready.
    readiness: WorkloadProxyReadinessHandler,
}

struct WorkloadProxyManagerProcessor<'a> {
    state: &'a mut super::statemanager::WorkloadProxyManagerState,
    readiness: &'a mut WorkloadProxyReadinessHandler,

    next_pending_retry: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}