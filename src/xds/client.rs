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
use serde_json;
use split_iter::Splittable;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tracing::{debug, error, info, info_span, warn, Instrument};

use crate::metrics::{IncrementRecorder, Recorder};
use crate::strng::Strng;
use crate::xds::metrics::{ConnectionTerminationReason, Metrics};
use crate::xds::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
use crate::xds::service::discovery::v3::Resource as ProtoResource;
use crate::xds::service::discovery::v3::*;
use crate::{identity, strng, tls};

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
const ISTIO_METAJSON_PREFIX: &str = "ISTIO_METAJSON_";

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub struct ResourceKey {
    pub name: Strng,
    pub type_url: Strng,
}

impl Display for ResourceKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.type_url, self.name)
    }
}

#[derive(Debug)]
pub struct RejectedConfig {
    name: Strng,
    reason: anyhow::Error,
}

impl RejectedConfig {
    pub fn new(name: Strng, reason: anyhow::Error) -> Self {
        Self { name, reason }
    }
}

impl Display for RejectedConfig {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.reason)
    }
}

/// handle_single_resource is a helper to process a set of updates with a closure that processes items one-by-one.
/// It handles aggregating errors as NACKS.
pub fn handle_single_resource<T: prost::Message, F: FnMut(XdsUpdate<T>) -> anyhow::Result<()>>(
    updates: impl Iterator<Item = XdsUpdate<T>>,
    mut handle_one: F,
) -> Result<(), Vec<RejectedConfig>> {
    let rejects: Vec<RejectedConfig> = updates
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

// Handler is responsible for handling a discovery response.
// Handlers can mutate state and return a list of rejected configurations (if there are any).
pub trait Handler<T: prost::Message>: Send + Sync + 'static {
    fn no_on_demand(&self) -> bool {
        false
    }
    fn handle(
        &self,
        res: Box<&mut dyn Iterator<Item = XdsUpdate<T>>>,
    ) -> Result<(), Vec<RejectedConfig>>;
}

// ResponseHandler is responsible for handling a discovery response.
// Handlers can mutate state and return a list of rejected configurations (if there are any).
// This is an internal only trait; public usage uses the Handler type which is typed.
trait RawHandler: Send + Sync + 'static {
    fn handle(
        &self,
        state: &mut State,
        res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>>;
}

// HandlerWrapper is responsible for implementing RawHandler the provided handler.
struct HandlerWrapper<T: prost::Message> {
    h: Box<dyn Handler<T>>,
}

impl<T: 'static + prost::Message + Default> RawHandler for HandlerWrapper<T> {
    fn handle(
        &self,
        state: &mut State,
        res: DeltaDiscoveryResponse,
    ) -> Result<(), Vec<RejectedConfig>> {
        let type_url = strng::new(res.type_url);
        let removes = &res.removed_resources;

        // Keep track of any failures but keep going
        let (decode_failures, updates) = res
            .resources
            .iter()
            .map(|raw| {
                decode_proto::<T>(raw).map_err(|err| RejectedConfig {
                    name: raw.name.as_str().into(),
                    reason: err.into(),
                })
            })
            .split(|i| i.is_ok());

        let mut updates = updates
            // We already filtered to ok
            .map(|r| r.expect("must be ok"))
            .map(XdsUpdate::Update)
            .chain(removes.iter().cloned().map(|s| XdsUpdate::Remove(s.into())));

        // First, call handlers that update the proxy state.
        // other wise on-demand notifications might observe a cache without their resource
        let updates: Box<&mut dyn Iterator<Item = XdsUpdate<T>>> = Box::new(&mut updates);
        let result = self.h.handle(updates);

        // Collecting after handle() is important, as the split() will cache the side we use last.
        // Updates >>> Errors (hopefully), so we want this one to do the allocations.
        let decode_failures: Vec<_> = decode_failures
            .map(|r| r.expect_err("must be err"))
            .collect();

        // after we update the proxy cache, we can update our xds cache. it's important that we do this after
        // as we make on demand notifications here, so the proxy cache must be updated first.
        for name in res.removed_resources {
            let k = ResourceKey {
                name: name.into(),
                type_url: type_url.clone(),
            };
            debug!("received delete resource {k}");
            if let Some(rm) = state.known_resources.get_mut(&k.type_url) {
                rm.remove(&k.name);
            }
            state.notify_on_demand(&k);
        }

        for r in res.resources {
            let key = ResourceKey {
                name: r.name.into(),
                type_url: type_url.clone(),
            };
            state.notify_on_demand(&key);
            state.add_resource(key.type_url, key.name);
        }

        // Either can fail. Merge the results
        match (result, decode_failures.is_empty()) {
            (Ok(()), true) => Ok(()),
            (Ok(_), false) => Err(decode_failures),
            (r @ Err(_), true) => r,
            (Err(mut rejects), false) => {
                rejects.extend(decode_failures);
                Err(rejects)
            }
        }
    }
}

pub struct Config {
    address: String,
    tls_builder: Box<dyn tls::ControlPlaneClientCertProvider>,
    auth: identity::AuthSource,
    proxy_metadata: HashMap<String, String>,
    handlers: HashMap<Strng, Box<dyn RawHandler>>,
    initial_requests: Vec<DeltaDiscoveryRequest>,
    on_demand: bool,

    /// alt_hostname provides an alternative accepted SAN for the control plane TLS verification
    alt_hostname: Option<String>,

    xds_headers: HashMap<String, String>,
}

pub struct State {
    /// Stores all known workload resources. Map from type_url to name
    known_resources: HashMap<Strng, HashSet<Strng>>,

    /// pending stores a list of all resources that are pending and XDS push
    pending: HashMap<ResourceKey, oneshot::Sender<()>>,

    demand: mpsc::Receiver<(oneshot::Sender<()>, ResourceKey)>,
    demand_tx: mpsc::Sender<(oneshot::Sender<()>, ResourceKey)>,
}

impl State {
    fn notify_on_demand(&mut self, key: &ResourceKey) {
        if let Some(send) = self.pending.remove(key) {
            debug!("on demand notify {}", key.name);
            if send.send(()).is_err() {
                warn!("on demand dropped event for {}", key.name)
            }
        }
    }
    fn add_resource(&mut self, type_url: Strng, name: Strng) {
        self.known_resources
            .entry(type_url)
            .or_default()
            .insert(name.clone());
    }
}

impl Config {
    pub fn new(
        config: Arc<crate::config::Config>,
        tls_builder: Box<dyn tls::ControlPlaneClientCertProvider>,
    ) -> Config {
        Config {
            address: config
                .xds_address
                .clone()
                .expect("xds_address must be set to use xds"),
            tls_builder,
            auth: config.auth.clone(),
            handlers: HashMap::new(),
            initial_requests: Vec::new(),
            on_demand: config.xds_on_demand,
            proxy_metadata: config.proxy_metadata.clone(),
            alt_hostname: config.alt_xds_hostname.clone(),
            xds_headers: config.xds_headers.clone(),
        }
    }

    pub fn with_watched_handler<F>(self, type_url: Strng, f: impl Handler<F>) -> Config
    where
        F: 'static + prost::Message + Default,
    {
        let no_on_demand = f.no_on_demand();
        self.with_handler(type_url.clone(), f)
            .watch(type_url, no_on_demand)
    }

    fn with_handler<F>(mut self, type_url: Strng, f: impl Handler<F>) -> Config
    where
        F: 'static + prost::Message + Default,
    {
        let h = HandlerWrapper { h: Box::new(f) };
        self.handlers.insert(type_url, Box::new(h));
        self
    }

    fn watch(mut self, type_url: Strng, no_on_demand: bool) -> Config {
        self.initial_requests
            .push(self.construct_initial_request(type_url, no_on_demand));
        self
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

    fn json_to_struct(json: serde_json::Map<String, serde_json::Value>) -> prost_types::Struct {
        prost_types::Struct {
            fields: json
                .into_iter()
                .map(|(k, v)| (k, Self::json_to_value(v)))
                .collect(),
        }
    }

    fn json_to_value(json: serde_json::Value) -> prost_types::Value {
        use prost_types::value::Kind::*;
        use serde_json::Value::*;

        prost_types::Value {
            kind: Some(match json {
                Null => NullValue(0),
                Bool(v) => BoolValue(v),
                Number(n) => NumberValue(n.as_f64().unwrap_or_else(|| {
                    error!("error parsing JSON number: {}", n);
                    0f64
                })),
                String(s) => StringValue(s),
                Array(v) => ListValue(prost_types::ListValue {
                    values: v.into_iter().map(Self::json_to_value).collect(),
                }),
                Object(v) => StructValue(Self::json_to_struct(v)),
            }),
        }
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
            .append(&mut Self::build_struct(self.proxy_metadata.clone()).fields);

        // Lookup ISTIO_METAJSON_* environment variables and add them to the node metadata
        for (key, val) in std::env::vars().filter(|(key, _)| key.starts_with(ISTIO_METAJSON_PREFIX))
        {
            if let Ok(v) = serde_json::from_str(&val) {
                metadata.fields.insert(
                    key.trim_start_matches(ISTIO_METAJSON_PREFIX).to_string(),
                    Self::json_to_value(v),
                );
            } else {
                error!("failed to parse {}={}", key, val);
            }
        }

        Node {
            id: format!("ztunnel~{ip}~{pod_name}.{ns}~{ns}.svc.cluster.local"),
            metadata: Some(metadata),
            ..Default::default()
        }
    }
    fn construct_initial_request(
        &self,
        request_type: Strng,
        no_on_demand: bool,
    ) -> DeltaDiscoveryRequest {
        let node = self.node();

        let (sub, unsub) = if (!no_on_demand) && self.on_demand {
            // XDS doesn't have a way to subscribe to zero resources. We workaround this by subscribing and unsubscribing
            // in one event, effectively giving us "subscribe to nothing".
            (vec!["*".to_string()], vec!["*".to_string()])
        } else {
            (vec![], vec![])
        };
        DeltaDiscoveryRequest {
            type_url: request_type.to_string(),
            node: Some(node.clone()),
            resource_names_subscribe: sub,
            resource_names_unsubscribe: unsub,
            ..Default::default()
        }
    }

    pub fn build(self, metrics: Metrics, block_ready: tokio::sync::watch::Sender<()>) -> AdsClient {
        AdsClient::new(self, metrics, block_ready)
    }
}

/// AdsClient provides a (mostly) generic DeltaAggregatedResources XDS client.
///
/// The client works by accepting arbitrary handlers for types, configured by user.
/// These handlers can do whatever they want with incoming responses, but are responsible for maintaining their own state.
/// For example, if a usage wants to keep track of all Foo resources received, it needs to handle the add/removes in the configured handler.
///
/// The client also supports on-demand lookup of resources; see demander() for more information.
///
/// Currently, this is not quite a fully general purpose XDS client, as there is no dependant resource support.
/// This could be added if needed, though.
pub struct AdsClient {
    config: Config,

    state: State,

    pub(crate) metrics: Metrics,
    block_ready: Option<tokio::sync::watch::Sender<()>>,

    connection_id: u32,
    types_to_expect: HashSet<String>,
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
    Ack,
    Nack,
}

impl Display for XdsSignal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            XdsSignal::Ack => "ACK",
            XdsSignal::Nack => "NACK",
        })
    }
}

impl Demander {
    /// Demand requests a given workload by name
    pub async fn demand(&self, type_url: Strng, name: Strng) -> Demanded {
        let (tx, rx) = oneshot::channel::<()>();
        self.demand
            .send((tx, ResourceKey { name, type_url }))
            .await
            // TODO: is this guaranteed? How can we handle the failure
            .expect("demand channel should not close");
        Demanded { b: rx }
    }
}

const INITIAL_BACKOFF: Duration = Duration::from_millis(10);
const MAX_BACKOFF: Duration = Duration::from_secs(15);

impl AdsClient {
    fn is_initial_request_on_demand(r: &DeltaDiscoveryRequest) -> bool {
        !r.resource_names_subscribe.is_empty()
    }

    fn new(config: Config, metrics: Metrics, block_ready: tokio::sync::watch::Sender<()>) -> Self {
        let (tx, rx) = mpsc::channel(100);
        let state = State {
            known_resources: Default::default(),
            pending: Default::default(),
            demand: rx,
            demand_tx: tx,
        };
        let types_to_expect: HashSet<String> = config
            .initial_requests
            .iter()
            .filter(|e| !Self::is_initial_request_on_demand(e)) // is_empty implies not ondemand
            .map(|e| e.type_url.clone())
            .collect();
        AdsClient {
            config,
            state,
            metrics,
            block_ready: Some(block_ready),
            connection_id: 0,
            types_to_expect,
        }
    }

    /// demander returns a Demander instance which can be used to request resources on-demand
    pub fn demander(&self) -> Option<Demander> {
        if self.config.on_demand {
            Some(Demander {
                demand: self.state.demand_tx.clone(),
            })
        } else {
            None
        }
    }

    async fn run_loop(&mut self, backoff: Duration) -> Duration {
        match self.run_internal().await {
            Err(e @ Error::Connection(_, _)) => {
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
                let backoff = if status.code() == tonic::Code::Unknown
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
                    INITIAL_BACKOFF
                } else {
                    warn!(
                        "XDS client error: {}, retrying in {:?}",
                        err_detail, backoff
                    );
                    self.metrics.increment(&ConnectionTerminationReason::Error);
                    // For gRPC errors, we add backoff
                    std::cmp::min(MAX_BACKOFF, backoff * 2)
                };
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
                INITIAL_BACKOFF
            }
            Ok(_) => {
                self.metrics
                    .increment(&ConnectionTerminationReason::Complete);
                warn!("XDS client complete");
                // Reset backoff
                INITIAL_BACKOFF
            }
        }
    }

    pub async fn run(mut self) -> Result<(), Error> {
        let mut backoff = INITIAL_BACKOFF;
        loop {
            self.connection_id += 1;
            let id = self.connection_id;
            backoff = self
                .run_loop(backoff)
                .instrument(info_span!("xds", id))
                .await;
        }
    }

    async fn run_internal(&mut self) -> Result<(), Error> {
        let (discovery_req_tx, mut discovery_req_rx) = mpsc::channel::<DeltaDiscoveryRequest>(100);
        // For each type in initial_watches we will send a request on connection to subscribe
        let initial_requests: Vec<DeltaDiscoveryRequest> = self
            .config
            .initial_requests
            .iter()
            .map(|e| {
                let mut req = e.clone();
                req.initial_resource_versions = self
                    .state
                    .known_resources
                    .get(&strng::new(&req.type_url))
                    .map(|hs| {
                        hs.iter()
                            .map(|n| (n.to_string(), "".to_string())) // Proto expects Name -> Version. We don't care about version
                            .collect()
                    })
                    .unwrap_or_default();
                req
            })
            .collect();

        let outbound = async_stream::stream! {
            for initial in initial_requests {
                debug!(resources=initial.initial_resource_versions.len(), type_url=initial.type_url, "sending initial request");
                yield initial;
            }
            while let Some(message) = discovery_req_rx.recv().await {
                debug!(type_url=message.type_url, "sending request");
                yield message
            }
            warn!("outbound stream complete");
        };

        let addr = self.config.address.clone();
        let tls_grpc_channel = tls::grpc_connector(
            self.config.address.clone(),
            self.config.auth.clone(),
            self.config
                .tls_builder
                .fetch_cert(self.config.alt_hostname.clone())
                .await?,
        )?;

        let mut req = tonic::Request::new(outbound);
        self.config.xds_headers.iter().for_each(|(k,v)| {
            let key: tonic::metadata::MetadataKey<_> =  k.as_str().parse().unwrap();
            let value: tonic::metadata::MetadataValue<_> = v.as_str().parse().unwrap();
            req.metadata_mut().insert(key.clone(), value.clone());
            debug!("XDS header added: {}={}", k, v);
        });

        let ads_connection = AggregatedDiscoveryServiceClient::new(tls_grpc_channel)
            .max_decoding_message_size(200 * 1024 * 1024)
            .delta_aggregated_resources(req)
            .await;

        let mut response_stream = ads_connection
            .map_err(|src| Error::Connection(addr, src))?
            .into_inner();
        debug!("connected established");

        info!("Stream established");
        loop {
            tokio::select! {
                _demand_event = self.state.demand.recv() => {
                    self.handle_demand_event(_demand_event, &discovery_req_tx).await?;
                }
                msg = response_stream.message() => {
                    let Some(msg) = msg? else {
                        // If we got a None message, the stream ended without error.
                        // This could be an explicit OK response, or if the stream is reset without a gRPC status.
                        return Ok(());
                    };
                    let mut received_type = None;
                    if !self.types_to_expect.is_empty() {
                        received_type = Some(msg.type_url.clone())
                    }
                    if let XdsSignal::Ack = self.handle_stream_event(msg, &discovery_req_tx).await? {
                        if let Some(received_type) = received_type {
                            self.types_to_expect.remove(&received_type);
                            if self.types_to_expect.is_empty() {
                                mem::drop(mem::take(&mut self.block_ready));
                            }
                        }
                    };
                }
            }
        }
    }

    async fn handle_stream_event(
        &mut self,
        response: DeltaDiscoveryResponse,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<XdsSignal, Error> {
        let type_url = response.type_url.clone();
        let nonce = response.nonce.clone();
        self.metrics.record(&response, ());
        info!(
            type_url = type_url, // this is a borrow, it's OK
            size = response.resources.len(),
            removes = response.removed_resources.len(),
            "received response"
        );
        let handler_response: Result<(), Vec<RejectedConfig>> =
            match self.config.handlers.get(&strng::new(&type_url)) {
                Some(h) => h.handle(&mut self.state, response),
                None => {
                    error!(%type_url, "unknown type");
                    // TODO: this will just send another discovery request, to server. We should
                    // either send one with an error or not send one at all.
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

        match response_type {
            XdsSignal::Nack => error!(
                type_url=type_url,
                nonce,
                "type"=?response_type,
                error=error,
                "sending response",
            ),
            _ => debug!(
                type_url=type_url,
                nonce,
                "type"=?response_type,
                "sending response",
            ),
        };

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
        self.state.pending.insert(demand_event, tx);
        self.state.add_resource(type_url.clone(), name.clone());
        send.send(DeltaDiscoveryRequest {
            type_url: type_url.to_string(),
            resource_names_subscribe: vec![name.to_string()],
            ..Default::default()
        })
        .await
        .map_err(|e| Error::RequestFailure(Box::new(e)))?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct XdsResource<T: prost::Message> {
    pub name: Strng,
    pub resource: T,
}

#[derive(Debug)]
pub enum XdsUpdate<T: prost::Message> {
    Update(XdsResource<T>),
    Remove(Strng),
}

impl<T: prost::Message> XdsUpdate<T> {
    pub fn name(&self) -> Strng {
        match self {
            XdsUpdate::Update(ref r) => r.name.clone(),
            XdsUpdate::Remove(n) => n.clone(),
        }
    }
}

fn decode_proto<T: prost::Message + Default>(
    resource: &ProtoResource,
) -> Result<XdsResource<T>, AdsError> {
    let name = resource.name.as_str().into();
    resource
        .resource
        .as_ref()
        .ok_or(AdsError::MissingResource())
        .and_then(|res| <T>::decode(&res.value[..]).map_err(AdsError::Decode))
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
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::SystemTime,
    };

    use prost::Message;
    use prost_types::Any;
    use textnonce::TextNonce;
    use tokio::time::sleep;

    use crate::xds::istio::security::Authorization as XdsAuthorization;
    use crate::xds::istio::workload::Address as XdsAddress;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::WorkloadType;
    use crate::xds::ADDRESS_TYPE;
    use crate::xds::{istio::workload::address::Type as XdsType, AUTHORIZATION_TYPE};
    use workload::Workload;

    use crate::state::workload::NetworkAddress;
    use crate::state::{workload, DemandProxyState};
    use crate::test_helpers::{
        helpers::{self},
        test_default_workload,
        xds::AdsServer,
    };

    use super::*;

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
                Some(XdsType::Workload(w)) => Some(Workload::try_from(w).unwrap()),
                Some(XdsType::Service(_s)) => None,
                _ => None,
            },
            _ => None,
        };
        // this is a borrow, Ok not to clone
        let mut matched = false;
        let ip_network_addr = NetworkAddress {
            network: strng::EMPTY,
            address: ip,
        };
        while start_time.elapsed().unwrap() < TEST_TIMEOUT && !matched {
            sleep(POLL_RATE).await;
            let wl = source.fetch_workload_by_address(&ip_network_addr);
            matched = wl.await.as_deref() == converted.as_ref(); // Option<Workload> is Ok to compare without needing to unwrap
        }
    }

    fn get_auth(i: usize) -> ProtoResource {
        let addr = XdsAuthorization {
            name: format!("foo{}", i),
            namespace: "default".to_string(),
            scope: crate::xds::istio::security::Scope::Global as i32,
            action: crate::xds::istio::security::Action::Deny as i32,
            rules: vec![crate::xds::istio::security::Rule {
                clauses: vec![crate::xds::istio::security::Clause {
                    matches: vec![crate::xds::istio::security::Match {
                        destination_ports: vec![80],
                        ..Default::default()
                    }],
                }],
            }],
        };
        ProtoResource {
            name: format!("foo{}", i),
            aliases: vec![],
            version: "0.0.1".to_string(),
            resource: Some(Any {
                type_url: AUTHORIZATION_TYPE.to_string(),
                value: addr.encode_to_vec(),
            }),
            ttl: None,
            cache_control: None,
        }
    }
    fn get_address(i: usize, addr: std::net::IpAddr) -> ProtoResource {
        let octets = match addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let addr = XdsAddress {
            r#type: Some(XdsType::Workload(XdsWorkload {
                name: format!("foo{}", i),
                uid: format!("default/foo{}", i),
                namespace: "default".to_string(),
                addresses: vec![octets.into()],
                tunnel_protocol: 0,
                trust_domain: "local".to_string(),
                service_account: "default".to_string(),
                node: "default".to_string(),
                workload_type: WorkloadType::Deployment.into(),
                workload_name: "".to_string(),
                native_tunnel: true,
                ..Default::default()
            })),
        };

        ProtoResource {
            name: format!("foo{}", i),
            aliases: vec![],
            version: "0.0.1".to_string(),
            resource: Some(Any {
                type_url: ADDRESS_TYPE.to_string(),
                value: addr.encode_to_vec(),
            }),
            ttl: None,
            cache_control: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_that_caches_are_warm_before_unblocked() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, state, mut block) = AdsServer::spawn(false).await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        let mut conn = conn_receiver.recv().await.unwrap();

        let mut auth_seen = false;
        let mut addr_seen = false;

        let timer = tokio::time::sleep(std::time::Duration::from_secs(1));
        futures::pin_mut!(timer);

        loop {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                _ = block.changed() => {
                    // make sure our cache is warm by using our resources
                    state.read()
                    .find_address(&NetworkAddress {
                        network: strng::EMPTY,
                        address: std::net::Ipv4Addr::new(1, 2, 3, 4).into(),
                    })
                    .expect("address not in cache");
                    let conn = crate::rbac::Connection{
                        dst: std::net::SocketAddr::new(std::net::Ipv4Addr::new(1, 2, 3, 4).into(), 80),
                        src_identity: None,
                        src: std::net::SocketAddr::new(std::net::Ipv4Addr::new(1, 2, 3, 4).into(), 80),
                        dst_network: "".into(),
                    };
                    let rbac_ctx = crate::state::ProxyRbacContext {
                        conn: conn.clone(),
                        dest_workload: Arc::new(test_default_workload()),
                    };

                    // rbac should reject port 80
                    let rbac_res = state.assert_rbac(&rbac_ctx).await;
                    assert!(rbac_res.is_err());
                    let conn = crate::rbac::Connection{
                        dst: std::net::SocketAddr::new(std::net::Ipv4Addr::new(1, 2, 3, 4).into(), 81),
                        ..conn
                    };
                    let rbac_ctx = crate::state::ProxyRbacContext {
                        conn,
                        dest_workload: Arc::new(test_default_workload()),
                    };

                    // but allow port 81
                    let rbac_res = state.assert_rbac(&rbac_ctx).await;
                    assert!(rbac_res.is_ok());
                    return;
                }
                req = conn.rx.recv() => {
                    req.unwrap()
                }
            };

            info!("received request: {:?}", req);
            if req.type_url == AUTHORIZATION_TYPE && !auth_seen {
                let response = Ok(DeltaDiscoveryResponse {
                    resources: vec![get_auth(0)],
                    nonce: TextNonce::new().to_string(),
                    system_version_info: "1.0.0".to_string(),
                    type_url: AUTHORIZATION_TYPE.to_string(),
                    removed_resources: vec![],
                });
                conn.tx.send(response).await.unwrap();
                auth_seen = true;
            } else if req.type_url == ADDRESS_TYPE && !addr_seen {
                let response = Ok(DeltaDiscoveryResponse {
                    resources: vec![get_address(0, "1.2.3.4".parse().unwrap())],
                    nonce: TextNonce::new().to_string(),
                    system_version_info: "1.0.0".to_string(),
                    type_url: ADDRESS_TYPE.to_string(),
                    removed_resources: vec![],
                });
                conn.tx.send(response).await.unwrap();
                addr_seen = true;
            }
        }
    }

    #[tokio::test]
    async fn test_on_demand_handling() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, _, _) = AdsServer::spawn(true).await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        let mut conn = conn_receiver.recv().await.unwrap();

        let mut auth_seen = false;
        let mut addr_seen = false;

        let timer = tokio::time::sleep(std::time::Duration::from_secs(1));
        futures::pin_mut!(timer);

        loop {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                req = conn.rx.recv() => {
                    req.unwrap()
                }
            };

            info!("received request: {:?}", req);
            if req.type_url == AUTHORIZATION_TYPE {
                assert_eq!(req.resource_names_subscribe, Vec::<String>::new());
                assert_eq!(req.resource_names_unsubscribe, Vec::<String>::new());
                auth_seen = true;
            } else if req.type_url == ADDRESS_TYPE {
                assert_eq!(req.resource_names_subscribe, vec!["*"]);
                assert_eq!(req.resource_names_unsubscribe, vec!["*"]);
                addr_seen = true;
            }

            if auth_seen && addr_seen {
                return;
            }
        }
    }

    // Tests that when the client processes a large response, the on-demand clients are notified
    // after contents of the cache were updated.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_on_demand_cache_coherency() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, state, _) = AdsServer::spawn(true).await;

        let demander = client.demander().unwrap();

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });
        let result = demander.demand(ADDRESS_TYPE, "foo0".into()).await;

        let mut conn = conn_receiver.recv().await.unwrap();

        let timer = tokio::time::sleep(std::time::Duration::from_secs(5));
        futures::pin_mut!(timer);

        loop {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                req = conn.rx.recv() => {
                    req.unwrap()
                }
            };

            info!("received request: {:?}", req);
            if req.type_url == ADDRESS_TYPE && req.resource_names_subscribe == vec!["foo0"] {
                let mut resources = vec![];

                // send back a big response, to expose the timing issue.
                let mut addr_range = ipnet::Ipv4Net::new(Ipv4Addr::new(1, 0, 0, 0), 8)
                    .unwrap()
                    .hosts();
                for i in 0..10_000 {
                    resources.push(get_address(i, addr_range.next().unwrap().into()));
                }

                let response = Ok(DeltaDiscoveryResponse {
                    resources,
                    nonce: TextNonce::new().to_string(),
                    system_version_info: "1.0.0".to_string(),
                    type_url: ADDRESS_TYPE.to_string(),
                    removed_resources: vec![],
                });

                tokio::spawn(async move { conn.tx.send(response).await });

                // wait for on demand to be notified. this means that the cache was updated with
                // our resource if it exists (and in our case we know it exists).
                result.recv().await;

                state
                    .read()
                    .find_address(&NetworkAddress {
                        network: strng::EMPTY,
                        address: std::net::Ipv4Addr::new(1, 0, 0, 1).into(),
                    })
                    .expect("demander return but resource not in cache");
                return;
            }
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
        let (mut conn_receiver, client, state, _) = AdsServer::spawn(false).await;

        tokio::spawn(async move {
            if let Err(e) = client.run().await {
                info!("workload manager: {}", e);
            }
        });

        let conn = conn_receiver.recv().await.unwrap();

        conn.tx
            .send(initial_response)
            .await
            .expect("failed to send server response");
        sleep(Duration::from_millis(50)).await;
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;
        conn.tx
            .send(abort_response)
            .await
            .expect("failed to send server response");
        sleep(Duration::from_millis(50)).await;
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;

        // original connection should close and client re-connect
        let conn = conn_receiver.recv().await.unwrap();
        conn.tx
            .send(removed_resource_response)
            .await
            .expect("failed to send server response");
        sleep(Duration::from_millis(50)).await;
        verify_address(IpAddr::V4(ip), None, &state).await;
    }

    #[test]
    fn test_json_to_value() {
        use prost_types::value::Kind::*;

        // JSON map
        let mut v = serde_json::json!({ "app": "foo", "version": "v1" });
        assert_eq!(
            Config::json_to_value(v).kind.unwrap(),
            StructValue(prost_types::Struct {
                fields: vec![
                    (
                        "app".to_string(),
                        prost_types::Value {
                            kind: Some(Kind::StringValue("foo".to_string())),
                        }
                    ),
                    (
                        "version".to_string(),
                        prost_types::Value {
                            kind: Some(Kind::StringValue("v1".to_string())),
                        }
                    ),
                ]
                .into_iter()
                .collect()
            }),
        );

        // JSON array
        v = serde_json::json!(["foo", "bar"]);
        assert_eq!(
            Config::json_to_value(v).kind.unwrap(),
            ListValue(prost_types::ListValue {
                values: vec![
                    prost_types::Value {
                        kind: Some(Kind::StringValue("foo".to_string())),
                    },
                    prost_types::Value {
                        kind: Some(Kind::StringValue("bar".to_string())),
                    },
                ]
            })
        );

        // JSON bool
        v = serde_json::json!(true);
        assert_eq!(Config::json_to_value(v).kind.unwrap(), BoolValue(true));

        // JSON Number
        v = serde_json::json!(1);
        assert_eq!(Config::json_to_value(v).kind.unwrap(), NumberValue(1f64));

        // JSON null
        v = serde_json::json!(());
        assert_eq!(Config::json_to_value(v).kind.unwrap(), NullValue(0));
    }
}
