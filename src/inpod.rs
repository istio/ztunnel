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

//! In-pod (co-located) data plane support.
//!
//! The actual in-pod capture backend is platform specific: on Linux it is implemented by
//! joining each workload's network namespace and putting sockets into that namespace
//! ([`self::linux`]). Other platforms do not (yet) have a capture backend, so on those
//! platforms only a [not-supported stub](self::windows) is available.

pub mod metrics;
pub use metrics::Metrics;

/// Linux network-namespace capture backend. See the [module](self::linux) for details.
#[cfg(target_os = "linux")]
pub mod linux;

/// Capture backend for non-Linux platforms. See the [module](self::windows) for details.
#[cfg(not(target_os = "linux"))]
pub mod windows;

pub mod istio {
    pub mod zds {
        tonic::include_proto!("istio.workload.zds");
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error creating proxy {0}: {1}")]
    ProxyError(String, crate::proxy::Error),
    #[error("error receiving message: {0}")]
    ReceiveMessageError(String),
    #[error("error sending ack: {0}")]
    SendAckError(String),
    #[error("error sending nack: {0}")]
    SendNackError(String),
    #[error("protocol error: {0}")]
    ProtocolError(String),
    #[error("announce error: {0}")]
    AnnounceError(String),
    /// The requested in-pod feature is not supported on this platform.
    #[error("not supported: {0}")]
    NotSupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct WorkloadUid(String);

impl WorkloadUid {
    pub fn new(uid: String) -> Self {
        Self(uid)
    }
    pub fn into_string(self) -> String {
        self.0
    }
}
