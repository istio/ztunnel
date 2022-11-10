use tracing_subscriber::prelude::*;

#[cfg(feature = "console")]
pub fn setup_logging() {
    let console_layer = console_subscriber::spawn();

    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(console_layer)
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

#[cfg(not(feature = "console"))]
pub fn setup_logging() {
    let filter_layer = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new("info"))
        .unwrap();
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
