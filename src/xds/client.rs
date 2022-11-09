use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use prost::Message;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

use crate::xds::istio::workload::Workload;
use crate::xds::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::service::discovery::v3::Resource as ProtoResource;
use crate::xds::service::discovery::v3::*;
use crate::{tls, xds};

use super::Error;

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct ResourceKey {
    pub name: String,
    pub type_url: String,
}

#[derive(Default)]
pub struct HandlerContext {
    rejects: Vec<RejectedConfig>,
}

impl HandlerContext {
    pub fn new() -> HandlerContext {
        HandlerContext {
            ..Default::default()
        }
    }
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
    on_demand: bool,
}

impl Config {
    pub fn new(config: crate::config::Config) -> Config {
        Config {
            workload_handler: Box::new(NopHandler {}),
            initial_watches: Vec::new(),
            on_demand: config.xds_on_demand,
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
        let (tx, rx) = mpsc::channel(100);
        AdsClient {
            config: self,
            workloads: HashSet::new(),
            pending: Default::default(),
            demand: rx,
            demand_tx: tx,
        }
    }
}

pub struct AdsClient {
    config: Config,
    /// Stores all known workload resources (by name)
    workloads: HashSet<String>,

    /// pending stores a list of all resources that are pending and XDS push
    pending: HashMap<ResourceKey, oneshot::Sender<()>>,

    demand: mpsc::Receiver<(oneshot::Sender<()>, ResourceKey)>,
    demand_tx: mpsc::Sender<(oneshot::Sender<()>, ResourceKey)>,
}

/// Demanded allows awaiting for an on-demand XDS resource
pub struct Demanded {
    b: oneshot::Receiver<()>,
}

impl Demanded {
    /// recv awaits for the requested resource
    /// Note: the actual resource is not directly returned. Instead, callers are notified that the event
    /// has been handled through the configured resource handler.
    pub async fn recv(self) {
        let _ = self.b.await;
    }
}

/// Demander allows requesting XDS resources on-demand
#[derive(Debug, Clone)]
pub struct Demander {
    demand: mpsc::Sender<(oneshot::Sender<()>, ResourceKey)>,
}

impl Demander {
    /// Demand requests a given workload by name
    pub async fn demand(&self, name: String) -> Demanded {
        let (tx, rx) = oneshot::channel::<()>();
        self.demand
            .send((
                tx,
                ResourceKey {
                    name,
                    type_url: xds::WORKLOAD_TYPE.to_string(),
                },
            ))
            .await
            .unwrap();
        Demanded { b: rx }
    }
}

impl AdsClient {
    /// demander returns a Demander instance which can be used to request resources on-demand
    pub fn demander(&self) -> Demander {
        Demander {
            demand: self.demand_tx.clone(),
        }
    }

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
                    backoff = Duration::from_millis(10);
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
        let workloads = &mut self.workloads;
        match workloads.len() {
            0 => info!("Starting initial ADS client"),
            n => info!("Starting ADS client with {n} workloads"),
        };

        // TODO: copy JWT auth logic from CA client and use TLS here
        let _address = if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            "https://istiod.istio-system:15012"
        } else {
            "https://localhost:15012"
        };
        let address = if std::env::var("KUBERNETES_SERVICE_HOST").is_ok() {
            "http://istiod.istio-system:15010"
        } else {
            "http://localhost:15010"
        };
        let svc = tls::grpc_connector(address).unwrap();
        let mut client = AggregatedDiscoveryServiceClient::new(svc);
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DeltaDiscoveryRequest>(100);
        let watches = initial_watches.clone();
        let irv: HashMap<String, String> = workloads
            .iter()
            .map(|n| (n.clone(), "".to_string()))
            .collect();

        let (sub, unsub) = if self.config.on_demand {
            // XDS doesn't have a way to subscribe to zero resources. We workaround this by subscribing and unsubscribing
            // in one event, effectively giving us "subscribe to nothing".
            (vec!["*".to_string()], vec!["*".to_string()])
        } else {
            (vec![], vec![])
        };
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
                    resource_names_subscribe: sub.clone(),
                    resource_names_unsubscribe: unsub.clone(),
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
        let mut response_stream = client
            .delta_aggregated_resources(tonic::Request::new(outbound))
            .await
            .map_err(Error::Connection)?
            .into_inner();

        info!("Stream established");

        loop {
            tokio::select! {
                _demand_event = self.demand.recv() => {
                    self.handle_demand_event(None, &discovery_req_tx).await?;
                }
                msg = response_stream.message() =>{
                    self.handle_stream_event(msg?, &discovery_req_tx).await?;
                }

            }
        }
    }

    async fn handle_stream_event(
        &mut self,
        stream_event: Option<DeltaDiscoveryResponse>,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<(), Error> {
        let Some(response) = stream_event else {
            return Ok(());
        };
        let type_url = response.type_url;
        info!(
            type_url = type_url.clone(),
            size = response.resources.len(),
            "received response"
        );
        let mut updates: Vec<XdsUpdate<Workload>> = Vec::new();
        for res in response.resources.iter().cloned() {
            let resource = Resource::try_from(res).unwrap();
            let _cpy = resource.clone();
            match resource {
                Resource::Workload(inner) => {
                    let name = inner.name.clone();
                    let up = XdsUpdate::Update(inner);
                    updates.push(up);
                    self.workloads.insert(name.clone());
                    let pending = {
                        self.pending.remove(&ResourceKey {
                            name: name.clone(),
                            type_url: type_url.clone(),
                        })
                    };
                    if let Some(send) = pending {
                        debug!("on demand notify {}", name);
                        send.send(()).map_err(|_| Error::OnDemandSend())?;
                    }
                }
            }
        }
        for res in response.removed_resources {
            self.workloads.remove(&res.clone());
            debug!("received delete resource {:#?}", res);
            let pending = {
                self.pending.remove(&ResourceKey {
                    name: res.clone(),
                    type_url: type_url.clone(),
                })
            };
            if let Some(send) = pending {
                debug!("on demand notify {}", res);
                send.send(()).map_err(|_| Error::OnDemandSend())?;
            }
            match type_url.clone().as_str() {
                xds::WORKLOAD_TYPE => {
                    updates.push(XdsUpdate::Remove(res));
                }
                _ => warn!("ignoring unwatched type {}", type_url),
            }
        }

        let mut ctx = HandlerContext::new();
        self.config.workload_handler.handle(&mut ctx, updates);

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
            type_url = type_url.clone(),
            none = response.nonce,
            "sending {}",
            if error_detail.is_some() {
                "NACK"
            } else {
                "ACK"
            }
        );
        send.send(DeltaDiscoveryRequest {
            type_url: type_url.clone(),
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
        .map_err(|e| Error::RequestFailure(Box::new(e)))
    }

    async fn handle_demand_event(
        &mut self,
        demand_event: Option<(oneshot::Sender<()>, ResourceKey)>,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<(), Error> {
        info!("received on demand request {demand_event:?}");
        let Some((tx, demand_event)) = demand_event else {
            return Ok(());
        };
        let ResourceKey { type_url, name } = demand_event.clone();
        self.pending.insert(demand_event, tx);
        send.send(DeltaDiscoveryRequest {
            type_url,
            node: Some(Node {
                id: format!(
                    "{}~{}~{}.{}~{}.svc.cluster.local",
                    "sidecar", "1.1.1.1", "test", "test", "test"
                ),
                ..Default::default()
            }),
            resource_names_subscribe: vec![name],
            ..Default::default()
        })
        .await
        .map_err(|e| Error::RequestFailure(Box::new(e)))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct XdsResource<T: prost::Message> {
    pub name: String,
    pub resource: T,
}

#[derive(Debug)]
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
