use prometheus_client::registry::Registry;

mod meta;
pub mod traffic;
pub mod xds;

/// Set of Swarm and protocol metrics derived from emitted events.
pub struct Metrics {
    xds: xds::Metrics,
    #[allow(dead_code)]
    meta: meta::Metrics,
    traffic: traffic::Metrics,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        Self {
            xds: xds::Metrics::new(registry),
            meta: meta::Metrics::new(registry),
            traffic: traffic::Metrics::new(registry),
        }
    }
}

/// Recorder that can record events
pub trait Recorder<E> {
    /// Record the given event.
    fn record(&self, event: &E);
}
