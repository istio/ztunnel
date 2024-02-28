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

mod certificate;
mod control;
pub mod csr;
mod lib;
#[cfg(any(test, feature = "testing"))]
pub mod mock;
mod workload;

use std::sync::Arc;

pub use crate::tls::certificate::*;
pub use crate::tls::control::*;
pub use crate::tls::lib::*;
pub use crate::tls::workload::*;
use hyper::http::uri::InvalidUri;
use rustls::server::VerifierBuilderError;

#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    #[error("invalid root certificate: {0}")]
    InvalidRootCert(String),

    #[error("invalid uri: {0}")]
    InvalidUri(#[from] Arc<InvalidUri>),

    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),

    #[error("certificate parse: {0}")]
    CertificateParseNomError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),

    #[error("certificate: {0}")]
    CertificateError(#[from] x509_parser::error::X509Error),

    #[error("certificate: {0}")]
    CertificateParseError(String),

    #[error("invalid operation: {0:?}")]
    #[cfg(feature = "tls-boring")]
    SslError(#[from] boring::error::ErrorStack),

    #[error("failed to build server verifier: {0}")]
    ServerVerifierBuilderError(#[from] VerifierBuilderError),
}

impl From<InvalidUri> for Error {
    fn from(err: InvalidUri) -> Self {
        Error::InvalidUri(Arc::new(err))
    }
}
