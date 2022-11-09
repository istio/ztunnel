use once_cell::sync::Lazy;
use ztunnel::telemetry;

// Ensure that the `tracing` stack is only initialised once using `once_cell`
pub static TRACING: Lazy<()> = Lazy::new(telemetry::setup_logging);
