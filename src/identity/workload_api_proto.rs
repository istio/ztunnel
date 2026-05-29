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

//! Generated bindings for the minimal SPIFFE Workload API subset used by
//! the SPIFFE Broker provider to bootstrap ztunnel's own SVID.
//!
//! Only the message types are generated; the gRPC service descriptor is
//! hand-rolled in [`crate::identity::broker::workload_api`] because the
//! canonical SPIFFE Workload API uses `package _;` in its proto, which
//! `tonic-prost-build` does not model.

// Generated code triggers a number of lints we don't control.
#[allow(warnings)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod spiffe {
    pub mod workloadapi {
        tonic::include_proto!("spiffe.workloadapi");
    }
}
