pub mod boring;

pub use crate::tls::boring::*;
use ::boring::error::ErrorStack;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid operation: {0}")]
    SslError(#[from] ErrorStack),
}
