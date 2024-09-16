struct WorkloadProxyNetworkHandler {
    uds: PathBuf,
}

struct WorkloadProxyReadinessHandler {
    ready: readiness::Ready,
    // Manually drop as we don't want to mark ready if we are dropped.
    // This can happen when the server drains.
    block_ready: Option<std::mem::ManuallyDrop<readiness::BlockReady>>,
    backoff: ExponentialBackoff,
}

pub struct WorkloadProxyManager {
    state: super::statemanager::WorkloadProxyManagerState,
    networking: WorkloadProxyNetworkHandler,
    // readiness - we are only ready when we are connected. if we get disconnected, we become not ready.
    readiness: WorkloadProxyReadinessHandler,
}

struct WorkloadProxyManagerProcessor<'a> {
    state: &'a mut super::statemanager::WorkloadProxyManagerState,
    readiness: &'a mut WorkloadProxyReadinessHandler,

    next_pending_retry: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}