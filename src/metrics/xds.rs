use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::Registry;

use crate::metrics::Recorder;

pub(super) struct Metrics {
    pub(super) connection_terminations: Family<ConnectionTermination, Counter>,
}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub struct ConnectionTermination {
    pub reason: ConnectionTerminationReason,
}

#[derive(Copy, Clone, Hash, PartialEq, Eq, Encode)]
pub enum ConnectionTerminationReason {
    ConnectionError,
    Error,
    Complete,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let connection_terminations = Family::default();
        registry.register(
            "connection_terminations",
            "The total number of completed connections to xds server",
            Box::new(connection_terminations.clone()),
        );

        Self {
            connection_terminations,
        }
    }
}

impl Recorder<ConnectionTerminationReason> for super::Metrics {
    fn record(&self, reason: &ConnectionTerminationReason) {
        self.xds
            .connection_terminations
            .get_or_create(&ConnectionTermination { reason: *reason })
            .inc();
    }
}
