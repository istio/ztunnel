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

use crate::tls;
use std::str::Utf8Error;
use std::sync::Arc;

mod caclient;
pub use caclient::*;

pub mod manager;
pub use manager::*;

mod auth;
use crate::state::WorkloadInfo;
pub use auth::*;

// Generated protobuf bindings for the SPIFFE Broker API. The full Broker
// client implementation is staged in follow-up steps; declaring the module
// here ensures the build pipeline produces and links the generated code.
#[allow(dead_code)]
pub mod broker_proto;

// Generated protobuf bindings for the (minimal) SPIFFE Workload API. Used
// by the Broker provider to bootstrap ztunnel's own SVID before opening
// the broker mTLS channel.
#[allow(dead_code)]
pub mod workload_api_proto;

// SPIFFE Broker provider. Linux-only: depends on inpod-only data structures.
// Broker mode is itself rejected outside inpod by `config::validate_config`.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub mod broker;

#[cfg(any(test, feature = "testing"))]
pub mod mock {
    pub use super::caclient::mock::CaClient;
    pub use super::manager::mock::{
        Config as SecretManagerConfig, new_secret_manager, new_secret_manager_cfg,
    };
}

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("failed to create CSR: {0}")]
    Signing(Arc<tls::Error>),
    #[error("signing gRPC error ({}): {}", .0.code(), .0.message())]
    SigningRequest(#[from] Box<tonic::Status>),
    #[error("failed to process string: {0}")]
    Utf8(#[from] Utf8Error),
    #[error("did not find expected SAN: {0}")]
    SanError(Identity),
    #[error("chain returned from CA is empty for: {0}")]
    EmptyResponse(Identity),
    #[error("invalid spiffe identity: {0}")]
    Spiffe(String),
    #[error("workload is unknown: {0}")]
    UnknownWorkload(Arc<WorkloadInfo>),
    #[error("the identity is no longer needed")]
    Forgotten,
    #[error("BUG: identity requested {0}, but only allowed {1:?}")]
    BugInvalidIdentityRequest(Identity, Arc<WorkloadInfo>),
    // SPIFFE Broker provider errors.
    #[error("SPIFFE Broker KubernetesObject attestor requires a workload pod UID")]
    BrokerMissingUid,
    #[error("SPIFFE Broker KubernetesObject attestor requires WorkloadInfo")]
    BrokerMissingWorkload,
    #[error("SPIFFE Broker transport error: {0}")]
    BrokerTransport(Arc<str>),
    #[error("SPIFFE Broker subscription stream ended without an SVID")]
    BrokerStreamEmpty,
    #[error("SPIFFE Broker returned no SVIDs in response")]
    BrokerNoSvids,
    #[error(
        "SPIFFE Broker returned SVID for {actual}, expected {expected}"
    )]
    BrokerSpiffeIdMismatch { expected: Identity, actual: String },
    #[error("SPIFFE Broker subscription timed out")]
    BrokerTimeout,
}

impl From<tls::Error> for Error {
    fn from(value: tls::Error) -> Self {
        Error::Signing(Arc::new(value))
    }
}
