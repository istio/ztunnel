pub mod caclient;

pub use caclient::*;
use std::str::Utf8Error;
pub mod manager;
pub use manager::*;
pub mod auth;

use crate::tls;
pub use auth::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to create CSR: {0}")]
    Signing(#[from] tls::Error),
    #[error("signing gRPC error ({}): {}", .0.code(), .0.message())]
    SigningRequest(#[from] tonic::Status),
    #[error("failed to process string: {0}")]
    Utf8(#[from] Utf8Error),
}
