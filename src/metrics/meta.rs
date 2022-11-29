use prometheus_client::encoding::text::Encode;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

use crate::version;

pub(super) struct Metrics {}

#[derive(Clone, Hash, PartialEq, Eq, Encode)]
pub struct IstioBuildLabel {
    component: String,
    tag: String,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let build_gauge: Family<IstioBuildLabel, Gauge> = Default::default();
        registry.register(
            "build",
            "Istio component build info",
            Box::new(build_gauge.clone()),
        );

        let git_tag = version::BuildInfo::new().git_tag;
        build_gauge
            .get_or_create(&IstioBuildLabel {
                component: "ztunnel".to_string(),
                tag: git_tag,
            })
            .set(1);

        Self {}
    }
}
