use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use crate::metrics::Recorder;

pub(super) struct Metrics {
    pub(super) connection_opens: Family<ConnectionOpen, Counter>,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub struct ConnectionOpen {
    // TODO: add full set of labels
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let connection_opens = Family::default();
        registry.register(
            "connections_opened",
            "The total number of TCP connections opened",
            Box::new(connection_opens.clone()),
        );

        Self { connection_opens }
    }
}

impl Recorder<ConnectionOpen> for super::Metrics {
    fn record(&self, reason: &ConnectionOpen) {
        self.traffic.connection_opens.get_or_create(reason).inc();
    }
}
