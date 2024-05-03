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

use crate::strng;
use crate::strng::Strng;

// We don't control the codegen, so disable any code warnings in the
// proto modules.
#[allow(warnings)]
#[allow(clippy::derive_partial_eq_without_eq)]
pub mod service {
    pub mod discovery {
        pub mod v3 {
            tonic::include_proto!("envoy.service.discovery.v3");
        }
    }
}

#[allow(warnings)]
#[warn(clippy::derive_partial_eq_without_eq)]
pub mod istio {
    pub mod workload {
        tonic::include_proto!("istio.workload");
    }
    pub mod security {
        tonic::include_proto!("istio.security");
    }
    pub mod ca {
        tonic::include_proto!("istio.v1.auth");
    }
}

pub const ADDRESS_TYPE: Strng = strng::literal!("type.googleapis.com/istio.workload.Address");
pub const AUTHORIZATION_TYPE: Strng = strng::literal!("type.googleapis.com/istio.security.Authorization");
