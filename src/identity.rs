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

mod spireclient;
pub use spireclient::*;

pub mod manager;
pub use manager::*;

mod auth;
use crate::state::WorkloadInfo;
pub use auth::*;

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
    #[error("failed to fetch pid for workload: {0}")]
    FailedToFetchBundle(String),
    #[error("certificate is in invalid format")]
    CertificateInvalidFormat(),
    #[error("invalid trust domain: {0}")]
    InvalidTrustDomain(String),
    #[error("failed to fetch certificate for workload: {0}")]
    FailedToFetchCertificate(String),
    #[error("failed to fetch pid for workload: {0}")]
    FailedToFetchPidForWorkload(i32),
    #[error("unable to determine pid for workload: {0}")]
    UnableToDeterminePidForWorkload(String),
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
}

impl From<tls::Error> for Error {
    fn from(value: tls::Error) -> Self {
        Error::Signing(Arc::new(value))
    }
}
