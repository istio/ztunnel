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

//! SPIFFE Broker provider for [`crate::identity::SecretManager`].
//!
//! This module is intentionally Linux-only: the broker provider only makes
//! sense in inpod mode (already enforced in `config::validate_config`), where
//! ztunnel has the per-pod context the attestor needs.

pub mod attestor;
pub mod bundles;
pub mod channel;
pub mod client;
pub mod svid_source;
pub mod workload_api;
