#[cfg(target_os = "linux")]
pub mod linux;
pub mod metrics;
#[cfg(target_os = "windows")]
pub mod windows;

pub mod istio {
    pub mod zds {
        tonic::include_proto!("istio.workload.zds");
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("error creating proxy: {0}")]
    ProxyError(crate::proxy::Error),
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
}
