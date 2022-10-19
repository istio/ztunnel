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
    SigningError(#[from] tls::Error),
    #[error("failed to process string: {0}")]
    Utf8Error(#[from] Utf8Error),
}
