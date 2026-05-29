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

//! Generated bindings for the SPIFFE Broker API.
//!
//! The proto definition lives at `proto/brokerapi.proto` and is vendored from
//! the draft upstream specification. See that file's header for tracking PR
//! references and the pinned commit it was copied from.
//!
//! These bindings are wired up here so that the build pipeline produces them.
//! The full Broker client implementation lands in a follow-up step.

// Generated code triggers a number of lints we don't control.
#[allow(warnings)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod spiffe {
    pub mod broker {
        tonic::include_proto!("spiffe.broker");
    }
}
