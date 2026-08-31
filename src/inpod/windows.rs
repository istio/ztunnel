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

//! Windows in-pod (co-located) capture backend stub.
//!
//! Windows does not provide the transparent (network-namespace) capture primitives that the
//! in-pod data plane relies on. Until a Windows capture backend exists, `in-pod` mode reports
//! `crate::inpod::Error::NotSupported` from this module instead of leaking Linux `cfg`
//! through the rest of the crate. A future Windows backend can implement the same entry
//! points without touching non-platform code.

use std::sync::Arc;

use crate::config as zconfig;
use crate::inpod::Error;
use crate::inpod::metrics::Metrics;
use crate::proxyfactory::ProxyFactory;
use crate::readiness;

/// Shortcut for the error reported whenever a Windows capture backend is requested.
pub fn unsupported() -> Error {
    Error::NotSupported(
        "in-pod (network capture) mode is not yet supported on this platform".into(),
    )
}

/// Attempt to start the in-pod data plane: always fails with `[Error::NotSupported]` until a
/// Windows capture backend is implemented.
pub fn init_and_new(
    _metrics: Arc<Metrics>,
    _admin_server: &mut crate::admin::Service,
    _cfg: &zconfig::Config,
    _proxy_gen: ProxyFactory,
    _ready: readiness::Ready,
) -> anyhow::Result<()> {
    Err(unsupported().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inpod_capture_is_not_supported_on_windows() {
        let err = unsupported();
        assert!(matches!(err, Error::NotSupported(_)));
        assert!(err.to_string().contains("not supported"));
    }
}
