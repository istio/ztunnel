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

use pin_project_lite::pin_project;
use tonic::Status;
use tonic::body::BoxBody;
use tower::{BoxError, ServiceExt};

// Copied from https://github.com/hyperium/tonic/blob/34b863b1d2a204ef3dd871ec86860fc92aafb451/examples/src/tls_rustls/server.rs

/// An adaptor which converts a [`tower::Service`] to a [`hyper::service::Service`].
///
/// The [`hyper::service::Service`] trait is used by hyper to handle incoming requests,
/// and does not support the `poll_ready` method that is used by tower services.
///
/// This is provided here because the equivalent adaptor in hyper-util does not support
/// tonic::body::BoxBody bodies.
#[derive(Debug, Clone)]
pub struct TowerToHyperService<S> {
    service: S,
}

impl<S> TowerToHyperService<S> {
    /// Create a new `TowerToHyperService` from a tower service.
    pub fn new(service: S) -> Self {
        Self { service }
    }
}

impl<S> hyper::service::Service<hyper::Request<hyper::body::Incoming>> for TowerToHyperService<S>
where
    S: tower::Service<hyper::Request<BoxBody>> + Clone,
    S::Error: Into<BoxError> + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = TowerToHyperServiceFuture<S, hyper::Request<BoxBody>>;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        use http_body_util::BodyExt;
        let req = req.map(|incoming| {
            incoming
                .map_err(|err| Status::from_error(err.into()))
                .boxed_unsync()
        });
        TowerToHyperServiceFuture {
            future: self.service.clone().oneshot(req),
        }
    }
}

pin_project! {
    /// Future returned by [`TowerToHyperService`].
    #[derive(Debug)]
    pub struct TowerToHyperServiceFuture<S, R>
    where
        S: tower::Service<R>,
    {
        #[pin]
        future: tower::util::Oneshot<S, R>,
    }
}

impl<S, R> std::future::Future for TowerToHyperServiceFuture<S, R>
where
    S: tower::Service<R>,
    S::Error: Into<BoxError> + 'static,
{
    type Output = Result<S::Response, BoxError>;

    #[inline]
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().future.poll(cx).map_err(Into::into)
    }
}
