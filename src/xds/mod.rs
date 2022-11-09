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
