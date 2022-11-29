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

mod client;

pub use client::*;
use tokio::sync::mpsc;
mod types;
use self::service::discovery::v3::DeltaDiscoveryRequest;
pub use types::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("gRPC error ({}): {}", .0.code(), .0.message())]
    GrpcStatus(#[from] tonic::Status),
    #[error("gRPC connection error ({}): {}", .0.code(), .0.message())]
    Connection(#[source] tonic::Status),
    /// Attempted to send on a MPSC channel which has been canceled
    #[error(transparent)]
    RequestFailure(#[from] Box<mpsc::error::SendError<DeltaDiscoveryRequest>>),
    #[error("failed to send on demand resource")]
    OnDemandSend(),
}
