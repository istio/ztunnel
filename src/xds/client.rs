use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;
use hyper::Uri;

use prost::Message;
use tracing::{debug, info, warn};

use crate::xds::istio::workload::Workload;
use crate::xds::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::service::discovery::v3::Resource as ProtoResource;
use crate::xds::service::discovery::v3::*;
use crate::{tls, xds};

use super::Error;

#[derive(Eq, Hash, PartialEq)]
struct ResourceKey {
    name: String,
    type_url: String,
}

#[derive(Default)]
pub struct HandlerContext {
    rejects: Vec<RejectedConfig>,
}

struct RejectedConfig {
    name: String,
    reason: anyhow::Error,
}

impl fmt::Display for RejectedConfig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.reason,)
    }
}

impl HandlerContext {
    pub fn reject(&mut self, name: String, reason: anyhow::Error) {
        self.rejects.push(RejectedConfig { name, reason })
    }
}

pub trait Handler<T: prost::Message>: Send + Sync + 'static {
    fn handle(&self, ctx: &mut HandlerContext, res: Vec<XdsUpdate<T>>);
}

struct NopHandler {}

impl<T: prost::Message> Handler<T> for NopHandler {
    fn handle(&self, _ctx: &mut HandlerContext, _res: Vec<XdsUpdate<T>>) {}
}

pub struct Config {
    workload_handler: Box<dyn Handler<Workload>>,
    initial_watches: Vec<String>,
}

impl Config {
    pub fn new() -> Config {
        Config {
            workload_handler: Box::new(NopHandler {}),
            initial_watches: Vec::new(),
        }
    }

    pub fn with_workload_handler(mut self, f: impl Handler<Workload>) -> Config {
        self.workload_handler = Box::new(f);
        self
    }

    pub fn watch(mut self, type_url: String) -> Config {
        self.initial_watches.push(type_url);
        self
    }

    pub fn build(self) -> AdsClient {
        AdsClient {
            config: self,
            workloads: HashSet::new(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AdsClient {
    config: Config,
    /// Stores all known workload resources (by name)
    workloads: HashSet<String>,
}

impl AdsClient {
    pub async fn run(mut self) -> Result<(), Error> {
        let mut backoff = Duration::from_millis(10);
        let max_backoff = Duration::from_secs(15);
        loop {
            let res = self.run_internal().await;
            match res {
                Err(e @ Error::Connection(_)) => {
                    // For connection errors, we add backoff
                    backoff = std::cmp::min(max_backoff, backoff * 2);
                    warn!("XDS client error: {}, retrying in {:?}", e, backoff);
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => {
                    // For other errors, we connect immediately
                    // TODO: we may need more nuance here; if we fail due to invalid initial request we may overload
                    // But we want to reconnect from MaxConnectionAge immediately.
                    warn!("XDS client error: {}, retrying", e);
                }
                Ok(_) => {
                    warn!("XDS client complete");
                    backoff = Duration::from_millis(10);
                }
            }
        }
    }

    async fn run_internal(&mut self) -> Result<(), Error> {
        let initial_watches = &self.config.initial_watches;
        let workload_handler = &self.config.workload_handler;
        let workloads = &mut self.workloads;
        match workloads.len() {
            0 => info!("Starting initial ADS client"),
            n => info!("Starting ADS client with {n} workloads"),
        };

        // TODO: use UDS
        let address = "http://localhost:15010";

        let mut client = AggregatedDiscoveryServiceClient::connect(address).await.unwrap();

        let (discovery_req_tx, mut discovery_req_rx) =
            tokio::sync::mpsc::channel::<DeltaDiscoveryRequest>(100);
        let watches = initial_watches.clone();
        let irv: HashMap<String, String> = workloads
            .iter()
            .map(|n| (n.clone(), "".to_string()))
            .collect();
        let outbound = async_stream::stream! {
            for request_type in watches {
                let irv = irv.clone();
                let initial = DeltaDiscoveryRequest {
                    type_url: request_type.clone(),
                    node: Some(Node{
                        id: format!("{}~{}~{}.{}~{}.svc.cluster.local", "sidecar", "1.1.1.1", "test", "test", "test"),
                        ..Default::default()
                    }),
                    initial_resource_versions: irv,
                    ..Default::default()
                };
                info!(type_url=request_type, "sending initial request");
                yield initial;
            }
            while let Some(message) = discovery_req_rx.recv().await {
                info!(type_url=message.type_url, "sending request");
                yield message
            }
            warn!("outbound stream complete");
        };

        info!("Starting stream");
        let mut _response_stream = client
            .delta_aggregated_resources(tonic::Request::new(outbound))
            .await
            .map_err(Error::Connection)?
            .into_inner();

        info!("Stream established");

        while let Some(response) = _response_stream.message().await? {
            info!(
                type_url = response.type_url,
                size = response.resources.len(),
                "received response"
            );
            let mut updates: Vec<XdsUpdate<Workload>> = Vec::new();
            // TODO: on reconnect we need to handle this as SotW I imagine?
            for res in response.resources.iter().cloned() {
                let resource = Resource::try_from(res).unwrap();
                match resource {
                    Resource::Workload(inner) => {
                        let name = inner.name.clone();
                        let up = XdsUpdate::Update(inner);
                        updates.push(up);
                        workloads.insert(name);
                    }
                }
            }
            for res in response.removed_resources {
                workloads.remove(&res.clone());
                debug!("received delete resource {:#?}", res);
                match response.type_url.as_str() {
                    xds::WORKLOAD_TYPE => {
                        updates.push(XdsUpdate::Remove(res));
                    }
                    _ => warn!("ignoring unwatched type {}", response.type_url),
                }
            }

            let mut ctx = HandlerContext {
                ..Default::default()
            };
            workload_handler.handle(&mut ctx, updates);

            let error_detail = match ctx.rejects.len() {
                0 => None,
                _ => Some(
                    ctx.rejects
                        .into_iter()
                        .map(|reject| reject.to_string())
                        .collect::<Vec<String>>()
                        .join("; "),
                ),
            };
            info!(
                type_url = response.type_url,
                none = response.nonce,
                "sending {}",
                if error_detail.is_some() {
                    "NACK"
                } else {
                    "ACK"
                }
            );
            discovery_req_tx
                .send(DeltaDiscoveryRequest {
                    type_url: response.type_url.clone(),
                    node: Some(Node {
                        id: format!(
                            "{}~{}~{}.{}~{}.svc.cluster.local",
                            "sidecar", "1.1.1.1", "test", "test", "test"
                        ),
                        ..Default::default()
                    }),
                    response_nonce: response.nonce.clone(),
                    error_detail: error_detail.map(|msg| Status {
                        message: msg,
                        ..Default::default()
                    }),
                    ..Default::default()
                })
                .await
                .map_err(Error::RequestFailure)?;
        }
        info!("Stream terminate");
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct XdsResource<T: prost::Message> {
    pub name: String,
    pub resource: T,
}

pub enum XdsUpdate<T: prost::Message> {
    Update(XdsResource<T>),
    Remove(String),
}

impl<T: prost::Message> XdsUpdate<T> {
    pub fn name(&self) -> String {
        match self {
            XdsUpdate::Update(ref r) => r.name.clone(),
            XdsUpdate::Remove(n) => n.to_string(),
        }
    }
}

// TODO: consider using https://crates.io/crates/prost-reflect to dynamically create types allowing any
// compiled protos. For now, we just hardcode
#[derive(Clone, Debug)]
pub enum Resource {
    Workload(XdsResource<Workload>),
}

impl TryFrom<ProtoResource> for Resource {
    type Error = AdsError;

    fn try_from(resource: ProtoResource) -> Result<Self, Self::Error> {
        let res = resource.resource.unwrap();
        Ok(match &*res.type_url {
            xds::WORKLOAD_TYPE => {
                let inner = <Workload>::decode(&*res.value).unwrap();
                Resource::Workload(XdsResource {
                    name: resource.name,
                    resource: inner,
                })
            }
            url => return Err(AdsError::UnknownResourceType(url.into())),
        })
    }
}

#[derive(Clone, Debug)]
pub enum AdsError {
    UnknownResourceType(String),
}
