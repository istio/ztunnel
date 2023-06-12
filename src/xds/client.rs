// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;
use std::{fmt, mem};

use prost::{DecodeError, EncodeError};
use prost_types::value::Kind;
use prost_types::{Struct, Value};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::config::RootCert;
use crate::metrics::xds::*;
use crate::metrics::{IncrementRecorder, Metrics};
use crate::xds::istio::security::Authorization;
use crate::xds::istio::workload::Address;
use crate::xds::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::service::discovery::v3::Resource as ProtoResource;
use crate::xds::service::discovery::v3::*;
use crate::{identity, readiness, tls, xds};

use super::Error;

const INSTANCE_IP: &str = "INSTANCE_IP";
const INSTANCE_IPS: &str = "INSTANCE_IPS";
const DEFAULT_IP: &str = "1.1.1.1";
const POD_NAME: &str = "POD_NAME";
const POD_NAMESPACE: &str = "POD_NAMESPACE";
const NODE_NAME: &str = "NODE_NAME";
const NAME: &str = "NAME";
const NAMESPACE: &str = "NAMESPACE";
const EMPTY_STR: &str = "";

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct ResourceKey {
    pub name: String,
    pub type_url: String,
}

impl Display for ResourceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.type_url, self.name)
    }
}

pub struct RejectedConfig {
    name: String,
    reason: anyhow::Error,
}

impl RejectedConfig {
    pub fn new(name: String, reason: anyhow::Error) -> Self {
        Self { name, reason }
    }
}

impl Display for RejectedConfig {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.reason)
    }
}

pub trait Handler<T: prost::Message>: Send + Sync + 'static {
    fn handle(&self, res: Vec<XdsUpdate<T>>) -> Result<(), Vec<RejectedConfig>>;
}

struct NopHandler {}

impl<T: prost::Message> Handler<T> for NopHandler {
    fn handle(&self, _res: Vec<XdsUpdate<T>>) -> Result<(), Vec<RejectedConfig>> {
        Ok(())
    }
}

/// handle_single_resource is a helper to process a set of updates with a closure that processes items one-by-one.
/// It handles aggregating errors as NACKS.
pub fn handle_single_resource<T: prost::Message, F: FnMut(XdsUpdate<T>) -> anyhow::Result<()>>(
    updates: Vec<XdsUpdate<T>>,
    mut handle_one: F,
) -> Result<(), Vec<RejectedConfig>> {
    let rejects: Vec<RejectedConfig> = updates
        .into_iter()
        .filter_map(|res| {
            let name = res.name();
            if let Err(e) = handle_one(res) {
                Some(RejectedConfig::new(name, e))
            } else {
                None
            }
        })
        .collect();
    if rejects.is_empty() {
        Ok(())
    } else {
        Err(rejects)
    }
}

pub struct Config {
    address: String,
    root_cert: RootCert,
    auth: identity::AuthSource,
    proxy_metadata: HashMap<String, String>,

    address_handler: Box<dyn Handler<Address>>,
    authorization_handler: Box<dyn Handler<Authorization>>,
    initial_watches: Vec<String>,
    on_demand: bool,
}

impl Config {
    pub fn new(config: crate::config::Config) -> Config {
        Config {
            address: config.xds_address.clone().unwrap(),
            root_cert: config.xds_root_cert.clone(),
            auth: config.auth,
            address_handler: Box::new(NopHandler {}),
            authorization_handler: Box::new(NopHandler {}),
            initial_watches: Vec::new(),
            on_demand: config.xds_on_demand,
            proxy_metadata: config.proxy_metadata,
        }
    }

    pub fn with_address_handler(mut self, f: impl Handler<Address>) -> Config {
        self.address_handler = Box::new(f);
        self
    }

    pub fn with_authorization_handler(mut self, f: impl Handler<Authorization>) -> Config {
        self.authorization_handler = Box::new(f);
        self
    }

    pub fn watch(mut self, type_url: String) -> Config {
        self.initial_watches.push(type_url);
        self
    }

    pub fn build(self, metrics: Arc<Metrics>, block_ready: readiness::BlockReady) -> AdsClient {
        let (tx, rx) = mpsc::channel(100);
        AdsClient {
            config: self,
            known_resources: Default::default(),
            pending: Default::default(),
            demand: rx,
            demand_tx: tx,
            metrics,
            block_ready: Some(block_ready),
            connection_id: 0,
        }
    }
}
pub struct AdsClient {
    config: Config,
    /// Stores all known workload resources. Map from type_url to name
    known_resources: HashMap<String, HashSet<String>>,

    /// pending stores a list of all resources that are pending and XDS push
    pending: HashMap<ResourceKey, oneshot::Sender<()>>,

    demand: mpsc::Receiver<(oneshot::Sender<()>, ResourceKey)>,
    demand_tx: mpsc::Sender<(oneshot::Sender<()>, ResourceKey)>,

    pub(crate) metrics: Arc<Metrics>,
    block_ready: Option<readiness::BlockReady>,

    connection_id: u32,
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

#[derive(Debug)]
enum XdsSignal {
    None,
    Ack,
    Nack,
}

impl Display for XdsSignal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            XdsSignal::None => "NONE",
            XdsSignal::Ack => "ACK",
            XdsSignal::Nack => "NACK",
        })
    }
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
                    type_url: xds::ADDRESS_TYPE.to_string(),
                },
            ))
            .await
            .unwrap();
        Demanded { b: rx }
    }
}

impl AdsClient {
    /// demander returns a Demander instance which can be used to request resources on-demand
    pub fn demander(&self) -> Option<Demander> {
        if self.config.on_demand {
            Some(Demander {
                demand: self.demand_tx.clone(),
            })
        } else {
            None
        }
    }

    async fn run_loop(&mut self, backoff: Duration) -> Duration {
        const MAX_BACKOFF: Duration = Duration::from_secs(15);
        match self.run_internal().await {
            Err(e @ Error::Connection(_)) => {
                // For connection errors, we add backoff
                let backoff = std::cmp::min(MAX_BACKOFF, backoff * 2);
                warn!(
                    "XDS client connection error: {}, retrying in {:?}",
                    e, backoff
                );
                self.metrics
                    .increment(&ConnectionTerminationReason::ConnectionError);
                tokio::time::sleep(backoff).await;
                backoff
            }
            Err(ref e @ Error::GrpcStatus(ref status)) => {
                let err_detail = e.to_string();
                // For gRPC errors, we add backoff
                let backoff = std::cmp::min(MAX_BACKOFF, backoff * 2);
                if status.code() == tonic::Code::Unknown
                    || status.code() == tonic::Code::Cancelled
                    || status.code() == tonic::Code::DeadlineExceeded
                    || (status.code() == tonic::Code::Unavailable
                        && status.message().contains("transport is closing"))
                    || (status.code() == tonic::Code::Unavailable
                        && status.message().contains("received prior goaway"))
                {
                    debug!(
                        "XDS client terminated: {}, retrying in {:?}",
                        err_detail, backoff
                    );
                    self.metrics
                        .increment(&ConnectionTerminationReason::Reconnect);
                } else {
                    warn!(
                        "XDS client error: {}, retrying in {:?}",
                        err_detail, backoff
                    );
                    self.metrics.increment(&ConnectionTerminationReason::Error);
                }
                tokio::time::sleep(backoff).await;
                backoff
            }
            Err(e) => {
                // For other errors, we connect immediately
                // TODO: we may need more nuance here; if we fail due to invalid initial request we may overload
                // But we want to reconnect from MaxConnectionAge immediately.
                warn!("XDS client error: {}, retrying", e);
                self.metrics.increment(&ConnectionTerminationReason::Error);
                // Reset backoff
                Duration::from_millis(10)
            }
            Ok(_) => {
                self.metrics
                    .increment(&ConnectionTerminationReason::Complete);
                warn!("XDS client complete");
                // Reset backoff
                Duration::from_millis(10)
            }
        }
    }

    pub async fn run(mut self) -> Result<(), Error> {
        let mut backoff = Duration::from_millis(10);
        loop {
            self.connection_id += 1;
            let id = self.connection_id;
            backoff = self
                .run_loop(backoff)
                .instrument(info_span!("xds", id))
                .await;
        }
    }

    fn build_struct<T: IntoIterator<Item = (S, S)>, S: ToString>(a: T) -> Struct {
        let fields = BTreeMap::from_iter(a.into_iter().map(|(k, v)| {
            (
                k.to_string(),
                Value {
                    kind: Some(Kind::StringValue(v.to_string())),
                },
            )
        }));
        Struct { fields }
    }

    fn node(&self) -> Node {
        let ip = std::env::var(INSTANCE_IP);
        let ip = ip.as_deref().unwrap_or(DEFAULT_IP);
        let pod_name = std::env::var(POD_NAME);
        let pod_name = pod_name.as_deref().unwrap_or(EMPTY_STR);
        let ns = std::env::var(POD_NAMESPACE);
        let ns = ns.as_deref().unwrap_or(EMPTY_STR);
        let node_name = std::env::var(NODE_NAME);
        let node_name = node_name.as_deref().unwrap_or(EMPTY_STR);
        let mut metadata = Self::build_struct([
            (NAME, pod_name),
            (NAMESPACE, ns),
            (INSTANCE_IPS, ip),
            (NODE_NAME, node_name),
        ]);
        metadata
            .fields
            .append(&mut Self::build_struct(self.config.proxy_metadata.clone()).fields);

        Node {
            id: format!("ztunnel~{ip}~{pod_name}.{ns}~{ns}.svc.cluster.local"),
            metadata: Some(metadata),
            ..Default::default()
        }
    }

    async fn run_internal(&mut self) -> Result<(), Error> {
        let address = self.config.address.clone();
        let svc = tls::grpc_connector(address, self.config.root_cert.clone()).unwrap();
        let mut client =
            AggregatedDiscoveryServiceClient::with_interceptor(svc, self.config.auth.clone());
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DeltaDiscoveryRequest>(100);
        // For each type in initial_watches we will send a request on connection to subscribe
        let initial_requests = self.construct_initial_requests();
        let outbound = async_stream::stream! {
            for initial in initial_requests {
                info!(resources=initial.initial_resource_versions.len(), type_url=initial.type_url, "sending initial request");
                yield initial;
            }
            while let Some(message) = discovery_req_rx.recv().await {
                debug!(type_url=message.type_url, "sending request");
                yield message
            }
            warn!("outbound stream complete");
        };

        let mut response_stream = client
            .delta_aggregated_resources(tonic::Request::new(outbound))
            .await
            .map_err(Error::Connection)?
            .into_inner();
        debug!("connected established");

        info!("Stream established");
        // Create a oneshot channel to be notified as soon as we ACK the first XDS response
        let (tx, initial_xds_rx) = oneshot::channel();
        let mut initial_xds_tx = Some(tx);
        let ready = mem::take(&mut self.block_ready);
        tokio::spawn(async move {
            match initial_xds_rx.await {
                Ok(_) => drop(ready),
                Err(_) => {
                    debug!("sender was dropped before initial xds sync event was received");
                }
            }
        });

        loop {
            tokio::select! {
                _demand_event = self.demand.recv() => {
                    self.handle_demand_event(_demand_event, &discovery_req_tx).await?;
                }
                msg = response_stream.message() => {
                    // TODO: If we have responses of different types (e.g. RBAC), we'll want to wait for
                    // each type to receive a response before marking ready
                    if let XdsSignal::Ack = self.handle_stream_event(msg?, &discovery_req_tx).await? {
                        let val = mem::take(&mut initial_xds_tx);
                        if let Some(tx) = val {
                            if let Err(err) = tx.send(()) {
                                warn!("initial xds sync signal send failed: {:?}", err)
                            }
                        }
                    };
                }
            }
        }
    }

    fn construct_initial_requests(&mut self) -> Vec<DeltaDiscoveryRequest> {
        let node = self.node();
        let initial_requests: Vec<DeltaDiscoveryRequest> = self
            .config
            .initial_watches
            .iter()
            .map(|request_type| {
                let irv: HashMap<String, String> = self
                    .known_resources
                    .get(request_type)
                    .map(|hs| {
                        hs.iter()
                            .map(|n| (n.to_owned(), "".to_string())) // Proto expects Name -> Version. We don't care about version
                            .collect()
                    })
                    .unwrap_or_default();
                let (sub, unsub) = if self.config.on_demand {
                    // XDS doesn't have a way to subscribe to zero resources. We workaround this by subscribing and unsubscribing
                    // in one event, effectively giving us "subscribe to nothing".
                    (vec!["*".to_string()], vec!["*".to_string()])
                } else {
                    (vec![], vec![])
                };
                DeltaDiscoveryRequest {
                    type_url: request_type.to_owned(),
                    node: Some(node.clone()),
                    initial_resource_versions: irv,
                    resource_names_subscribe: sub,
                    resource_names_unsubscribe: unsub,
                    ..Default::default()
                }
            })
            .collect();
        initial_requests
    }

    async fn handle_stream_event(
        &mut self,
        stream_event: Option<DeltaDiscoveryResponse>,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<XdsSignal, Error> {
        let Some(response) = stream_event else {
            return Ok( XdsSignal::None);
        };
        let type_url = response.type_url.clone();
        let nonce = response.nonce.clone();
        info!(
            type_url = type_url, // this is a borrow, it's OK
            size = response.resources.len(),
            "received response"
        );
        // Due to lack of dynamic typing in Rust we have some code duplication here. In the future this could be a macro,
        // but for now its easier to just have a bit of duplication.
        let handler_response: Result<(), Vec<RejectedConfig>> = match type_url.as_str() {
            xds::ADDRESS_TYPE => {
                self.decode_and_handle::<Address, _>(|a| &a.config.address_handler, response)
            }
            xds::AUTHORIZATION_TYPE => self.decode_and_handle::<Authorization, _>(
                |a| &a.config.authorization_handler,
                response,
            ),
            _ => {
                error!("unknown type");
                Ok(())
            }
        };

        let (response_type, error) = match handler_response {
            Err(rejects) => {
                let error = rejects
                    .into_iter()
                    .map(|reject| reject.to_string())
                    .collect::<Vec<String>>()
                    .join("; ");
                (XdsSignal::Nack, Some(error))
            }
            _ => (XdsSignal::Ack, None),
        };

        debug!(
            type_url=type_url,
            nonce,
            "type"=?response_type,
            "sending response",
        );
        send.send(DeltaDiscoveryRequest {
            type_url,              // this is owned, OK to move
            response_nonce: nonce, // this is owned, OK to move
            error_detail: error.map(|msg| Status {
                message: msg,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await
        .map_err(|e| Error::RequestFailure(Box::new(e)))
        .map(|_| response_type)
    }

    async fn handle_demand_event(
        &mut self,
        demand_event: Option<(oneshot::Sender<()>, ResourceKey)>,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<(), Error> {
        let Some((tx, demand_event)) = demand_event else {
            return Ok(());
        };
        info!("received on demand request {demand_event}");
        let ResourceKey { type_url, name } = demand_event.clone();
        self.pending.insert(demand_event, tx);
        self.known_resources
            .entry(type_url.clone())
            .or_default()
            .insert(name.clone());
        send.send(DeltaDiscoveryRequest {
            type_url,
            resource_names_subscribe: vec![name],
            ..Default::default()
        })
        .await
        .map_err(|e| Error::RequestFailure(Box::new(e)))?;
        Ok(())
    }
    fn notify_on_demand(&mut self, key: &ResourceKey) {
        if let Some(send) = self.pending.remove(key) {
            debug!("on demand notify {}", key.name);
            if send.send(()).is_err() {
                warn!("on demand dropped event for {}", key.name)
            }
        }
    }
    fn handle_removes(&mut self, resp: &DeltaDiscoveryResponse) -> Vec<String> {
        resp.removed_resources
            .iter()
            .map(|res| {
                let k = ResourceKey {
                    name: res.to_owned(),
                    type_url: resp.type_url.clone(),
                };
                debug!("received delete resource {k}");
                self.known_resources.remove(res);
                self.notify_on_demand(&k);
                k.name
            })
            .collect()
    }

    fn decode_and_handle<
        T: prost::Message + Default + 'static,
        F: FnOnce(&AdsClient) -> &Box<dyn Handler<T>>,
    >(
        &mut self,
        f: F,
        response: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>> {
        let type_url = response.type_url.clone();
        let removes = self.handle_removes(&response);
        let updates: Vec<XdsUpdate<T>> = response
            .resources
            .into_iter()
            .map(|r| {
                let key = ResourceKey {
                    name: r.name.clone(),
                    type_url: type_url.clone(),
                };
                self.notify_on_demand(&key);
                self.known_resources
                    .entry(key.type_url)
                    .or_default()
                    .insert(key.name);
                r
            })
            .map(|raw| decode_proto::<T>(raw).unwrap())
            .map(XdsUpdate::Update)
            .chain(removes.into_iter().map(XdsUpdate::Remove))
            .collect();
        let handler = f(self);

        handler.handle(updates)
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

fn decode_proto<T: prost::Message + Default>(
    resource: ProtoResource,
) -> Result<XdsResource<T>, AdsError> {
    let name = resource.name;
    resource
        .resource
        .ok_or(AdsError::MissingResource())
        .and_then(|res| <T>::decode(&*res.value).map_err(AdsError::Decode))
        .map(|r| XdsResource { name, resource: r })
}

#[derive(Clone, Debug, Error)]
pub enum AdsError {
    #[error("unknown resource type: {0}")]
    UnknownResourceType(String),
    #[error("decode: {0}")]
    Decode(#[from] DecodeError),
    #[error("XDS payload without resource")]
    MissingResource(),
    #[error("encode: {0}")]
    Encode(#[from] EncodeError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::workload::NetworkAddress;
    use crate::state::{workload, DemandProxyState};
    use crate::test_helpers::{
        helpers::{self},
        xds::AdsServer,
    };
    use prost::Message;
    use prost_types::Any;
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::SystemTime,
    };
    use textnonce::TextNonce;
    use tokio::time::sleep;
    use workload::Workload;
    use xds::istio::workload::address::Type as XdsType;
    use xds::istio::workload::Address as XdsAddress;
    use xds::istio::workload::Workload as XdsWorkload;
    use xds::istio::workload::WorkloadType;
    use xds::ADDRESS_TYPE;

    const POLL_RATE: Duration = Duration::from_millis(2);
    const TEST_TIMEOUT: Duration = Duration::from_millis(100);

    async fn verify_address(
        ip: IpAddr,
        expected_address: Option<XdsAddress>,
        source: &DemandProxyState,
    ) {
        let start_time = SystemTime::now();
        let converted = match expected_address {
            Some(a) => match a.r#type {
                Some(XdsType::Workload(w)) => Some(Workload::try_from(&w).unwrap()),
                Some(XdsType::Service(_s)) => None,
                _ => None,
            },
            _ => None,
        };
        // this is a borrow, Ok not to clone
        let mut matched = false;
        let ip_network_addr = NetworkAddress {
            network: "".to_string(),
            address: ip,
        };
        while start_time.elapsed().unwrap() < TEST_TIMEOUT && !matched {
            sleep(POLL_RATE).await;
            let wl = source.fetch_workload(&ip_network_addr).await;
            matched = wl == converted; // Option<Workload> is Ok to compare without needing to unwrap
        }
    }

    #[tokio::test]
    async fn test_add_abort_remove() {
        helpers::initialize_telemetry();

        // TODO: Load this from a file?
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let mut resources = vec![];
        let addresses = vec![XdsAddress {
            r#type: Some(XdsType::Workload(XdsWorkload {
                name: "1.1.1.1".to_string(),
                namespace: "default".to_string(),
                addresses: vec![ip.octets().to_vec().into()],
                tunnel_protocol: 0,
                trust_domain: "local".to_string(),
                service_account: "default".to_string(),
                node: "default".to_string(),
                workload_type: WorkloadType::Deployment.into(),
                workload_name: "".to_string(),
                native_tunnel: true,
                ..Default::default()
            })),
        }];
        for addr in addresses.clone().iter() {
            match &addr.r#type {
                Some(XdsType::Workload(w)) => resources.push(ProtoResource {
                    name: w.name.clone(),
                    aliases: vec![],
                    version: "0.0.1".to_string(),
                    resource: Some(Any {
                        type_url: ADDRESS_TYPE.to_string(),
                        value: addr.encode_to_vec(),
                    }),
                    ttl: None,
                    cache_control: None,
                }),
                Some(XdsType::Service(_s)) => (),
                _ => (),
            }
        }

        let initial_response = Ok(DeltaDiscoveryResponse {
            resources,
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: ADDRESS_TYPE.to_string(),
            removed_resources: vec![],
        });

        let abort_response = Err(tonic::Status::aborted("Aborting for test."));

        let removed_resource_response: Result<DeltaDiscoveryResponse, tonic::Status> =
            Ok(DeltaDiscoveryResponse {
                resources: vec![],
                nonce: TextNonce::new().to_string(),
                system_version_info: "1.0.0".to_string(),
                type_url: ADDRESS_TYPE.to_string(),
                removed_resources: vec!["127.0.0.1".into()],
            });

        // Setup fake xds server
        let (tx, client, state) = AdsServer::spawn().await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        tx.send(initial_response)
            .expect("failed to send server response");
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;
        tx.send(abort_response)
            .expect("failed to send server response");
        sleep(Duration::from_millis(50)).await;
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;
        tx.send(removed_resource_response)
            .expect("failed to send server response");
        verify_address(IpAddr::V4(ip), None, &state).await;
    }
}
