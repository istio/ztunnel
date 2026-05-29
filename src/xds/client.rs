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
use std::fmt;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use prometheus_client::metrics::gauge::Gauge;
use prost::{DecodeError, EncodeError};
use prost_types::value::Kind;
use prost_types::{Struct, Value};
use serde_json;
use split_iter::Splittable;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tonic::metadata::{AsciiMetadataKey, AsciiMetadataValue};
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::metrics::{IncrementRecorder, Recorder};
use crate::strng::Strng;
use crate::xds::metrics::{ConnectionTerminationReason, Metrics};
use crate::xds::service::discovery::v3::Resource as ProtoResource;
use crate::xds::service::discovery::v3::aggregated_discovery_service_client::AggregatedDiscoveryServiceClient;
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

impl<T: 'static + fmt::Debug + prost::Message + Default> RawHandler for HandlerWrapper<T> {
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
    xds_headers: Vec<(AsciiMetadataKey, AsciiMetadataValue)>,
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
            xds_headers: config.xds_headers.vec.clone(),
        }
    }

    pub fn with_watched_handler<F>(self, type_url: Strng, f: impl Handler<F>) -> Config
    where
        F: 'static + fmt::Debug + prost::Message + Default,
    {
        let no_on_demand = f.no_on_demand();
        self.with_handler(type_url.clone(), f)
            .watch(type_url, no_on_demand)
    }

    fn with_handler<F>(mut self, type_url: Strng, f: impl Handler<F>) -> Config
    where
        F: 'static + fmt::Debug + prost::Message + Default,
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
        let (connection_state_tx, _) =
            tokio::sync::watch::channel(XdsConnectionState::initializing());
        AdsClient::new(self, metrics, block_ready, connection_state_tx)
    }
}

/// Tracks the xDS connection state for readiness reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct XdsConnectionState {
    kind: XdsConnectionStateKind,
    freshness_epoch: u64,
}

impl XdsConnectionState {
    pub(crate) const fn initializing() -> Self {
        Self {
            kind: XdsConnectionStateKind::Initializing,
            freshness_epoch: 0,
        }
    }

    pub(crate) const fn connected(freshness_epoch: u64) -> Self {
        Self {
            kind: XdsConnectionStateKind::Connected,
            freshness_epoch,
        }
    }

    pub(crate) const fn synced(freshness_epoch: u64) -> Self {
        Self {
            kind: XdsConnectionStateKind::Synced,
            freshness_epoch,
        }
    }

    pub(crate) const fn disconnected(freshness_epoch: u64) -> Self {
        Self {
            kind: XdsConnectionStateKind::Disconnected,
            freshness_epoch,
        }
    }

    pub(crate) const fn kind(self) -> XdsConnectionStateKind {
        self.kind
    }

    pub(crate) const fn freshness_epoch(self) -> u64 {
        self.freshness_epoch
    }
}

/// Coarse xDS connection state for readiness reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum XdsConnectionStateKind {
    /// Initial state before first successful connection.
    Initializing,
    /// gRPC stream is established but is not currently fresh. This covers both
    /// pre-ACK streams and streams with a watched-type NACK outstanding. NOT a
    /// freshness signal: served state may be stale from before the disconnect.
    Connected,
    /// At least one DeltaDiscoveryResponse has been ACKed on the current stream,
    /// and no watched-type NACK is outstanding. Indicates the control plane has
    /// begun re-asserting state after the (re)connect; readiness can be restored.
    Synced,
    /// Disconnected from xDS server.
    Disconnected,
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

    /// Broadcasts the current xDS connection state for readiness tracking.
    connection_state_tx: tokio::sync::watch::Sender<XdsConnectionState>,
    freshness_epoch: u64,

    connection_id: u32,
    watched_type_urls: HashSet<Strng>,
    rejected_watched_resources: HashSet<ResourceKey>,
    types_to_expect: HashSet<String>,

    /// Tracks when the current disconnect period started, for duration metrics.
    disconnect_start: Option<tokio::time::Instant>,

    /// Set to `true` inside `run_internal` once a gRPC stream has been
    /// established; consulted by `run_loop` after `run_internal` returns to
    /// decide whether to start a disconnect-duration timer. Reset on every
    /// loop iteration.
    reached_connected: bool,
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
    Ack {
        resources: Vec<ResourceKey>,
    },
    AckIgnored,
    Nack {
        rejected: Vec<ResourceKey>,
        accepted: Vec<ResourceKey>,
    },
}

#[derive(Debug)]
struct HandledXdsResponse {
    type_url: String,
    nonce: String,
    signal: XdsSignal,
    error: Option<String>,
}

struct XdsUpGuard(Option<Gauge>);

fn xds_header_value_for_log(_: &AsciiMetadataValue) -> &'static str {
    "<redacted>"
}

impl XdsUpGuard {
    fn connected(up: Option<Gauge>) -> Self {
        if let Some(up) = &up {
            up.set(1);
        }
        Self(up)
    }
}

impl Drop for XdsUpGuard {
    fn drop(&mut self) {
        if let Some(up) = &self.0 {
            up.set(0);
        }
    }
}

impl XdsSignal {
    fn rejected_resources(&self) -> &[ResourceKey] {
        match self {
            XdsSignal::Nack { rejected, .. } => rejected,
            _ => &[],
        }
    }
}

impl Display for XdsSignal {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            XdsSignal::Ack { .. } => "ACK",
            XdsSignal::AckIgnored => "ACK_IGNORED",
            XdsSignal::Nack { .. } => "NACK",
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

    fn new(
        config: Config,
        metrics: Metrics,
        block_ready: tokio::sync::watch::Sender<()>,
        connection_state_tx: tokio::sync::watch::Sender<XdsConnectionState>,
    ) -> Self {
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
        let watched_type_urls = config
            .initial_requests
            .iter()
            .map(|e| strng::new(&e.type_url))
            .collect();
        AdsClient {
            config,
            state,
            metrics,
            block_ready: Some(block_ready),
            connection_state_tx,
            freshness_epoch: 0,
            connection_id: 0,
            watched_type_urls,
            rejected_watched_resources: HashSet::new(),
            types_to_expect,
            disconnect_start: None,
            reached_connected: false,
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

    /// Returns a receiver that tracks the current xDS connection state.
    pub(crate) fn connection_state_receiver(
        &self,
    ) -> tokio::sync::watch::Receiver<XdsConnectionState> {
        self.connection_state_tx.subscribe()
    }

    fn publish_connection_state(&mut self, kind: XdsConnectionStateKind) {
        // Use `send_replace` instead of `send` so the watch's stored value
        // advances even when there are currently no subscribers. With plain
        // `send`, a subscriber that connects after startup would observe the
        // initial `Initializing` value until the next transition.
        if kind == XdsConnectionStateKind::Synced {
            self.freshness_epoch = self.freshness_epoch.wrapping_add(1);
        }
        let state = match kind {
            XdsConnectionStateKind::Initializing => XdsConnectionState::initializing(),
            XdsConnectionStateKind::Connected => {
                XdsConnectionState::connected(self.freshness_epoch)
            }
            XdsConnectionStateKind::Synced => XdsConnectionState::synced(self.freshness_epoch),
            XdsConnectionStateKind::Disconnected => {
                XdsConnectionState::disconnected(self.freshness_epoch)
            }
        };
        self.connection_state_tx.send_replace(state);
    }

    fn remove_accepted_watched_resources(&mut self, resources: &[ResourceKey]) {
        for resource in resources {
            if self.is_watched_resource(resource) {
                self.rejected_watched_resources.remove(resource);
            }
        }
    }

    fn is_watched_resource(&self, resource: &ResourceKey) -> bool {
        self.watched_type_urls.contains(&resource.type_url)
    }

    fn has_watched_resources(&self, resources: &[ResourceKey]) -> bool {
        resources
            .iter()
            .any(|resource| self.is_watched_resource(resource))
    }

    fn should_collect_accepted_resources(&self, type_url: &Strng) -> bool {
        !self.rejected_watched_resources.is_empty() && self.watched_type_urls.contains(type_url)
    }

    fn response_resource_keys(
        response: &DeltaDiscoveryResponse,
        type_url: Strng,
    ) -> Vec<ResourceKey> {
        response
            .resources
            .iter()
            .map(|resource| ResourceKey {
                name: strng::new(&resource.name),
                type_url: type_url.clone(),
            })
            .chain(response.removed_resources.iter().map(|name| ResourceKey {
                name: strng::new(name),
                type_url: type_url.clone(),
            }))
            .collect()
    }

    fn record_watched_resources(&mut self, signal: &XdsSignal) {
        match signal {
            XdsSignal::Ack { resources } => {
                self.remove_accepted_watched_resources(resources);
            }
            XdsSignal::Nack { rejected, accepted } => {
                self.remove_accepted_watched_resources(accepted);
                for resource in rejected {
                    if self.is_watched_resource(resource) {
                        self.rejected_watched_resources.insert(resource.clone());
                    }
                }
            }
            XdsSignal::AckIgnored => {}
        }
    }

    fn maybe_unblock_initial_sync(&mut self) {
        if self.types_to_expect.is_empty()
            && self.rejected_watched_resources.is_empty()
            && let Some(block_ready) = self.block_ready.take()
        {
            block_ready.send_replace(());
        }
    }

    fn demote_synced_on_watched_nack(
        &mut self,
        signal: &XdsSignal,
        synced_on_this_stream: &mut bool,
    ) {
        if self.has_watched_resources(signal.rejected_resources()) && *synced_on_this_stream {
            *synced_on_this_stream = false;
            self.publish_connection_state(XdsConnectionStateKind::Connected);
        }
    }

    async fn run_loop(&mut self, backoff: Duration) -> Duration {
        // `reached_connected` is set inside `run_internal` once the gRPC stream
        // is established. We must sample it AFTER `run_internal` returns and
        // BEFORE we publish `Disconnected`, otherwise the watch we'd inspect
        // already reflects the Disconnected we publish at the tail of the
        // previous iteration.
        self.reached_connected = false;
        let result = self.run_internal().await;
        let was_connected = self.reached_connected;
        self.publish_connection_state(XdsConnectionStateKind::Disconnected);
        // `xds_up` is cleared by `XdsUpGuard::drop` inside `run_internal`,
        // which also covers task cancellation; do not duplicate the write here.
        // Only start the disconnect timer if we were actually connected; otherwise
        // initial-connect retries pollute the disconnect_duration histogram.
        if was_connected && self.disconnect_start.is_none() {
            self.disconnect_start = Some(tokio::time::Instant::now());
        }
        match result {
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
                let backoff = std::cmp::min(MAX_BACKOFF, backoff * 2);
                warn!("XDS client error: {}, retrying in {:?}", e, backoff);
                self.metrics.increment(&ConnectionTerminationReason::Error);
                tokio::time::sleep(backoff).await;
                backoff
            }
            Ok(_) => {
                self.metrics
                    .increment(&ConnectionTerminationReason::Complete);
                warn!("XDS client complete");
                // Reset backoff
                tokio::time::sleep(INITIAL_BACKOFF).await;
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
        self.config.xds_headers.iter().for_each(|(k, v)| {
            req.metadata_mut().insert(k.clone(), v.clone());
            debug!("XDS header added: {}={}", k, xds_header_value_for_log(v));
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
        self.publish_connection_state(XdsConnectionStateKind::Connected);
        self.reached_connected = true;
        let _xds_up_guard = XdsUpGuard::connected(self.metrics.up.clone());
        if let Some(start) = self.disconnect_start.take() {
            if let Some(disconnect_duration) = &self.metrics.disconnect_duration {
                disconnect_duration.observe(start.elapsed().as_secs_f64());
            }
        }
        // Publish `Synced` once the current stream has a usable ACK and no
        // watched type is currently rejected. A later watched-type NACK moves
        // the stream back to `Connected` until that type ACKs successfully.
        // This is stronger than raw transport reachability while avoiding a
        // per-type re-ACK requirement that can permanently block readiness for
        // watched types that are empty or quiet after reconnect.
        let mut synced_on_this_stream = false;
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
                    // NACK-only streams intentionally do not publish `Synced`: a control plane
                    // that is reachable but only sending unusable config should not restore
                    // readiness after a re-arm.
                    let handled = self.handle_response(msg);
                    self.demote_synced_on_watched_nack(&handled.signal, &mut synced_on_this_stream);

                    match Self::send_response(handled, &discovery_req_tx).await? {
                        XdsSignal::Ack { .. } => {
                            if !synced_on_this_stream && self.rejected_watched_resources.is_empty() {
                                synced_on_this_stream = true;
                                self.publish_connection_state(XdsConnectionStateKind::Synced);
                            }
                            if let Some(received_type) = received_type {
                                self.types_to_expect.remove(&received_type);
                            }
                            self.maybe_unblock_initial_sync();
                        }
                        XdsSignal::Nack { .. } => {}
                        XdsSignal::AckIgnored => {}
                    }
                }
            }
        }
    }

    fn handle_response(&mut self, response: DeltaDiscoveryResponse) -> HandledXdsResponse {
        let type_url = response.type_url.clone();
        let nonce = response.nonce.clone();
        let type_url_key = strng::new(&type_url);
        let response_resources = if self.should_collect_accepted_resources(&type_url_key) {
            Some(Self::response_resource_keys(
                &response,
                type_url_key.clone(),
            ))
        } else {
            None
        };
        self.metrics.record(&response, ());
        debug!(
            type_url = type_url, // this is a borrow, it's OK
            size = response.resources.len(),
            removes = response.removed_resources.len(),
            "received response"
        );
        let (response_type, error) = match self.config.handlers.get(&type_url_key) {
            Some(h) => match h.handle(&mut self.state, response) {
                Err(rejects) => {
                    let rejected: Vec<ResourceKey> = rejects
                        .iter()
                        .map(|reject| ResourceKey {
                            name: reject.name.clone(),
                            type_url: type_url_key.clone(),
                        })
                        .collect();
                    let rejected_names: HashSet<Strng> = rejected
                        .iter()
                        .map(|resource| resource.name.clone())
                        .collect();
                    let accepted = response_resources
                        .as_ref()
                        .map(|resources| {
                            resources
                                .iter()
                                .filter(|resource| !rejected_names.contains(&resource.name))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();
                    let error = rejects
                        .into_iter()
                        .map(|reject| reject.to_string())
                        .collect::<Vec<String>>()
                        .join("; ");
                    (XdsSignal::Nack { rejected, accepted }, Some(error))
                }
                Ok(()) => (
                    XdsSignal::Ack {
                        resources: response_resources.unwrap_or_default(),
                    },
                    None,
                ),
            },
            None => {
                error!(%type_url, "unknown type");
                (XdsSignal::AckIgnored, None)
            }
        };

        self.record_watched_resources(&response_type);

        HandledXdsResponse {
            type_url,
            nonce,
            signal: response_type,
            error,
        }
    }

    async fn send_response(
        handled: HandledXdsResponse,
        send: &mpsc::Sender<DeltaDiscoveryRequest>,
    ) -> Result<XdsSignal, Error> {
        let HandledXdsResponse {
            type_url,
            nonce,
            signal,
            error,
        } = handled;

        match &signal {
            XdsSignal::Nack { .. } => error!(
                type_url=type_url,
                nonce,
                "type"=%signal,
                error=error.as_deref(),
                "sending response",
            ),
            _ => debug!(
                type_url=type_url,
                nonce,
                "type"=%signal,
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
        .map(|_| signal)
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
            XdsUpdate::Update(r) => r.name.clone(),
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
    use std::net::{IpAddr, Ipv4Addr};

    use futures_util::FutureExt;
    use prost::Message;
    use prost_types::Any;
    use textnonce::TextNonce;

    use crate::xds::ADDRESS_TYPE;
    use crate::xds::istio::security::Authorization as XdsAuthorization;
    use crate::xds::istio::workload::Address as XdsAddress;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::WorkloadType;
    use crate::xds::{AUTHORIZATION_TYPE, istio::workload::address::Type as XdsType};
    use workload::Workload;

    use crate::state::workload::NetworkAddress;
    use crate::state::{DemandProxyState, workload};
    use crate::test_helpers::{
        helpers::{self},
        test_config, test_default_workload,
        xds::{AdsConnection, AdsServer},
    };
    use crate::{app, identity};

    use super::*;

    struct FailingCertProvider;

    #[async_trait::async_trait]
    impl tls::ControlPlaneClientCertProvider for FailingCertProvider {
        async fn fetch_cert(
            &self,
            _alt_hostname: Option<String>,
        ) -> Result<rustls::ClientConfig, tls::Error> {
            Err(tls::Error::InvalidRootCert(
                "test root certificate failure".to_string(),
            ))
        }
    }

    #[test]
    fn test_xds_header_log_value_is_redacted() {
        let value = AsciiMetadataValue::from_static("bearer-secret-token");

        let rendered = xds_header_value_for_log(&value);

        assert_eq!(rendered, "<redacted>");
        assert!(
            !rendered.contains("bearer-secret-token"),
            "xDS header log value must not expose configured header contents"
        );
    }

    async fn verify_address(
        ip: IpAddr,
        expected_address: Option<XdsAddress>,
        source: &DemandProxyState,
    ) {
        let converted = match expected_address {
            Some(a) => match a.r#type {
                Some(XdsType::Workload(w)) => Some(Workload::try_from(w).unwrap()),
                Some(XdsType::Service(_s)) => None,
                _ => None,
            },
            _ => None,
        };
        let ip_network_addr = NetworkAddress {
            network: strng::EMPTY,
            address: ip,
        };
        let observed = source.fetch_workload_by_address(&ip_network_addr).await;
        assert!(
            observed.as_deref() == converted.as_ref(),
            "workload address mismatch for {ip}; expected {converted:?}, observed {observed:?}"
        );
    }

    #[tokio::test]
    #[should_panic(expected = "workload address mismatch")]
    async fn test_verify_address_panics_on_mismatch() {
        let (_conn_receiver, _client, state, _) = AdsServer::spawn(false).await;
        verify_address(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(XdsAddress {
                r#type: Some(XdsType::Workload(XdsWorkload {
                    name: "missing".to_string(),
                    namespace: "default".to_string(),
                    addresses: vec![Ipv4Addr::LOCALHOST.octets().to_vec().into()],
                    tunnel_protocol: 0,
                    trust_domain: "local".to_string(),
                    service_account: "default".to_string(),
                    node: "default".to_string(),
                    workload_type: WorkloadType::Deployment.into(),
                    workload_name: "".to_string(),
                    native_tunnel: true,
                    ..Default::default()
                })),
            }),
            &state,
        )
        .await;
    }

    fn get_auth(i: usize) -> ProtoResource {
        let addr = XdsAuthorization {
            name: format!("foo{i}"),
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
            dry_run: false,
            extensions: vec![],
        };
        ProtoResource {
            name: format!("foo{i}"),
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

    fn get_invalid_auth(i: usize) -> ProtoResource {
        let mut resource = get_auth(i);
        let auth = XdsAuthorization {
            action: i32::MAX,
            ..XdsAuthorization::decode(resource.resource.as_ref().unwrap().value.as_slice())
                .expect("test auth resource must decode")
        };
        resource.resource.as_mut().unwrap().value = auth.encode_to_vec();
        resource
    }

    fn get_address(i: usize, addr: std::net::IpAddr) -> ProtoResource {
        let octets = match addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let addr = XdsAddress {
            r#type: Some(XdsType::Workload(XdsWorkload {
                name: format!("foo{i}"),
                uid: format!("default/foo{i}"),
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
            name: format!("foo{i}"),
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

    fn get_invalid_address(i: usize, addr: std::net::IpAddr) -> ProtoResource {
        let mut resource = get_address(i, addr);
        let mut address = XdsAddress::decode(resource.resource.as_ref().unwrap().value.as_slice())
            .expect("test address resource must decode");
        let Some(XdsType::Workload(workload)) = &mut address.r#type else {
            panic!("test address resource must contain a workload")
        };
        workload.tunnel_protocol = i32::MAX;
        resource.resource.as_mut().unwrap().value = address.encode_to_vec();
        resource
    }

    async fn send_test_response(conn: &mut AdsConnection, type_url: &str) {
        let resources = if type_url == &*ADDRESS_TYPE {
            vec![get_address(0, "1.2.3.4".parse().unwrap())]
        } else if type_url == &*AUTHORIZATION_TYPE {
            vec![get_auth(0)]
        } else {
            panic!("unexpected request type {type_url}");
        };
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources,
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: type_url.to_string(),
            removed_resources: vec![],
        }))
        .await;
    }

    async fn recv_request_with_nonce(
        conn: &mut AdsConnection,
        nonce: &str,
    ) -> DeltaDiscoveryRequest {
        loop {
            let req = tokio::time::timeout(Duration::from_secs(2), conn.recv_request())
                .await
                .unwrap_or_else(|_| panic!("timed out waiting for xDS request with nonce {nonce}"))
                .expect("channel closed");
            if req.response_nonce == nonce {
                return req;
            }
        }
    }

    async fn prime_initial_sync(conn: &mut AdsConnection) {
        let mut addr_sent = false;
        let mut auth_sent = false;
        while !(addr_sent && auth_sent) {
            let req = tokio::time::timeout(Duration::from_secs(2), conn.recv_request())
                .await
                .expect("timed out waiting for initial xDS request")
                .expect("channel closed");
            if req.type_url.as_str() == &*ADDRESS_TYPE && !addr_sent {
                send_test_response(conn, &ADDRESS_TYPE).await;
                addr_sent = true;
            } else if req.type_url.as_str() == &*AUTHORIZATION_TYPE && !auth_sent {
                send_test_response(conn, &AUTHORIZATION_TYPE).await;
                auth_sent = true;
            }
        }
    }

    async fn prime_initial_sync_after_request(
        conn: &mut AdsConnection,
        first_req: DeltaDiscoveryRequest,
    ) {
        let mut addr_sent = false;
        let mut auth_sent = false;
        send_initial_sync_response_for_request(conn, first_req, &mut addr_sent, &mut auth_sent)
            .await;
        while !(addr_sent && auth_sent) {
            let req = tokio::time::timeout(Duration::from_secs(2), conn.recv_request())
                .await
                .expect("timed out waiting for initial xDS request")
                .expect("channel closed");
            send_initial_sync_response_for_request(conn, req, &mut addr_sent, &mut auth_sent).await;
        }
    }

    async fn send_initial_sync_response_for_request(
        conn: &mut AdsConnection,
        req: DeltaDiscoveryRequest,
        addr_sent: &mut bool,
        auth_sent: &mut bool,
    ) {
        if req.type_url.as_str() == &*ADDRESS_TYPE && !*addr_sent {
            send_test_response(conn, &ADDRESS_TYPE).await;
            *addr_sent = true;
        } else if req.type_url.as_str() == &*AUTHORIZATION_TYPE && !*auth_sent {
            send_test_response(conn, &AUTHORIZATION_TYPE).await;
            *auth_sent = true;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_watched_type_nack_suppresses_later_synced_until_same_type_acks() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let mut conn_state_rx = client.connection_state_receiver();

        let client_loop = tokio::spawn(async move {
            let _next_backoff = client.run_loop(Duration::from_millis(250)).await;
        });
        let mut conn = conn_receiver.recv().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for Connected state")
        .expect("sender dropped");

        let rejected_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_invalid_auth(0)],
            nonce: rejected_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let rejected_ack = recv_request_with_nonce(&mut conn, &rejected_nonce).await;
        assert!(
            rejected_ack.error_detail.is_some(),
            "invalid authorization update should be NACKed"
        );

        let address_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_address(0, "1.2.3.4".parse().unwrap())],
            nonce: address_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: ADDRESS_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let address_ack = recv_request_with_nonce(&mut conn, &address_nonce).await;
        assert!(
            address_ack.error_detail.is_none(),
            "valid address update should be ACKed"
        );
        assert_eq!(
            conn_state_rx.borrow().kind(),
            XdsConnectionStateKind::Connected,
            "ACK for a different watched type must not publish Synced while authorization is rejected"
        );

        let unrelated_auth_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_auth(1)],
            nonce: unrelated_auth_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let unrelated_auth_ack = recv_request_with_nonce(&mut conn, &unrelated_auth_nonce).await;
        assert!(
            unrelated_auth_ack.error_detail.is_none(),
            "valid authorization update should be ACKed"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            conn_state_rx.borrow().kind(),
            XdsConnectionStateKind::Connected,
            "ACK for an unrelated authorization resource must not publish Synced while rejected authorization remains stale"
        );

        let remove_rejected_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![],
            nonce: remove_rejected_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec!["foo0".to_string()],
        }))
        .await;
        let remove_rejected_ack = recv_request_with_nonce(&mut conn, &remove_rejected_nonce).await;
        assert!(
            remove_rejected_ack.error_detail.is_none(),
            "removal for rejected authorization should be ACKed"
        );

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Synced),
        )
        .await
        .expect("timed out waiting for Synced after rejected authorization removed")
        .expect("sender dropped");

        abort_ads_run_loop_for_test(client_loop).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_startup_ready_waits_for_rejected_watched_resource_to_clear() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, client, _state, mut block_rx) = AdsServer::spawn(false).await;
        let client_task = spawn_ads_client_for_test(client);
        let mut conn = conn_receiver.recv().await.unwrap();

        let rejected_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_invalid_auth(0)],
            nonce: rejected_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let rejected_ack = recv_request_with_nonce(&mut conn, &rejected_nonce).await;
        assert!(
            rejected_ack.error_detail.is_some(),
            "invalid authorization update should be NACKed"
        );

        let address_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_address(0, "1.2.3.4".parse().unwrap())],
            nonce: address_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: ADDRESS_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let address_ack = recv_request_with_nonce(&mut conn, &address_nonce).await;
        assert!(
            address_ack.error_detail.is_none(),
            "valid address update should be ACKed"
        );
        assert!(
            !block_rx.has_changed().unwrap_or(true),
            "startup readiness must remain blocked while any expected type is still unsynced"
        );

        let unrelated_auth_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_auth(1)],
            nonce: unrelated_auth_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let unrelated_auth_ack = recv_request_with_nonce(&mut conn, &unrelated_auth_nonce).await;
        assert!(
            unrelated_auth_ack.error_detail.is_none(),
            "valid authorization update should be ACKed"
        );
        assert!(
            !block_rx.has_changed().unwrap_or(true),
            "startup readiness must remain blocked while a watched NACK remains outstanding"
        );

        let remove_rejected_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![],
            nonce: remove_rejected_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec!["foo0".to_string()],
        }))
        .await;
        let remove_rejected_ack = recv_request_with_nonce(&mut conn, &remove_rejected_nonce).await;
        assert!(
            remove_rejected_ack.error_detail.is_none(),
            "removal for rejected authorization should be ACKed"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(2), block_rx.changed())
                .await
                .expect("timed out waiting for startup readiness to unblock")
                .is_ok(),
            "startup readiness should unblock after the rejected watched resource is cleared"
        );

        abort_ads_client_for_test(client_task).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_watched_type_nack_survives_reconnect_until_same_type_acks() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, client, _state, _block) = AdsServer::spawn(false).await;
        let mut conn_state_rx = client.connection_state_receiver();
        let client_task = spawn_ads_client_for_test(client);

        let mut conn = conn_receiver.recv().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for Connected state")
        .expect("sender dropped");

        let rejected_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_invalid_auth(0)],
            nonce: rejected_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let rejected_ack = recv_request_with_nonce(&mut conn, &rejected_nonce).await;
        assert!(
            rejected_ack.error_detail.is_some(),
            "invalid authorization update should be NACKed"
        );

        conn.send_response(Err(tonic::Status::aborted("simulated disconnect")))
            .await;

        let mut reconnect = tokio::time::timeout(Duration::from_secs(2), conn_receiver.recv())
            .await
            .expect("timed out waiting for reconnect")
            .expect("connection receiver closed");

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for reconnect Connected state")
        .expect("sender dropped");

        let address_nonce = TextNonce::new().to_string();
        reconnect
            .send_response(Ok(DeltaDiscoveryResponse {
                resources: vec![get_address(0, "1.2.3.4".parse().unwrap())],
                nonce: address_nonce.clone(),
                system_version_info: "1.0.0".to_string(),
                type_url: ADDRESS_TYPE.to_string(),
                removed_resources: vec![],
            }))
            .await;
        let address_ack = recv_request_with_nonce(&mut reconnect, &address_nonce).await;
        assert!(
            address_ack.error_detail.is_none(),
            "valid address update should be ACKed"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            conn_state_rx.borrow().kind(),
            XdsConnectionStateKind::Connected,
            "ACK for a different watched type after reconnect must not publish Synced while authorization remains rejected"
        );

        let unrelated_auth_nonce = TextNonce::new().to_string();
        reconnect
            .send_response(Ok(DeltaDiscoveryResponse {
                resources: vec![get_auth(1)],
                nonce: unrelated_auth_nonce.clone(),
                system_version_info: "1.0.0".to_string(),
                type_url: AUTHORIZATION_TYPE.to_string(),
                removed_resources: vec![],
            }))
            .await;
        let unrelated_auth_ack =
            recv_request_with_nonce(&mut reconnect, &unrelated_auth_nonce).await;
        assert!(
            unrelated_auth_ack.error_detail.is_none(),
            "valid authorization update should be ACKed"
        );
        tokio::task::yield_now().await;
        assert_eq!(
            conn_state_rx.borrow().kind(),
            XdsConnectionStateKind::Connected,
            "ACK for an unrelated authorization after reconnect must not publish Synced while rejected authorization remains stale"
        );

        let remove_rejected_nonce = TextNonce::new().to_string();
        reconnect
            .send_response(Ok(DeltaDiscoveryResponse {
                resources: vec![],
                nonce: remove_rejected_nonce.clone(),
                system_version_info: "1.0.0".to_string(),
                type_url: AUTHORIZATION_TYPE.to_string(),
                removed_resources: vec!["foo0".to_string()],
            }))
            .await;
        let remove_rejected_ack =
            recv_request_with_nonce(&mut reconnect, &remove_rejected_nonce).await;
        assert!(
            remove_rejected_ack.error_detail.is_none(),
            "removal for rejected authorization should be ACKed"
        );

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Synced),
        )
        .await
        .expect("timed out waiting for Synced after rejected authorization removed")
        .expect("sender dropped");

        abort_ads_client_for_test(client_task).await;
    }

    #[tokio::test]
    async fn test_watched_type_nack_survives_failed_response_send() {
        helpers::initialize_telemetry();

        let (_conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);

        let handled = client.handle_response(DeltaDiscoveryResponse {
            resources: vec![get_invalid_auth(0)],
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec![],
        });
        let result = AdsClient::send_response(handled, &closed_tx).await;

        assert!(
            matches!(result, Err(Error::RequestFailure(_))),
            "closed outbound request channel should fail the NACK send: {result:?}"
        );
        assert!(
            client.rejected_watched_resources.contains(&ResourceKey {
                name: "foo0".into(),
                type_url: AUTHORIZATION_TYPE,
            }),
            "watched NACK should be retained even when the response send fails"
        );
    }

    #[tokio::test]
    async fn test_watched_type_nack_demotes_before_backpressured_response_send() {
        helpers::initialize_telemetry();

        let (_conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let conn_state_rx = client.connection_state_receiver();
        client.publish_connection_state(XdsConnectionStateKind::Synced);
        let mut synced_on_this_stream = true;

        let (full_tx, _full_rx) = mpsc::channel(1);
        full_tx
            .send(DeltaDiscoveryRequest::default())
            .await
            .expect("test should fill outbound request channel");

        let response = DeltaDiscoveryResponse {
            resources: vec![get_invalid_auth(0)],
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec![],
        };

        let handled = client.handle_response(response);
        assert!(
            matches!(handled.signal, XdsSignal::Nack { .. }),
            "invalid watched authorization update should classify as NACK"
        );
        assert!(
            client.has_watched_resources(handled.signal.rejected_resources()),
            "watched NACK must be visible before queueing the outbound NACK"
        );
        client.demote_synced_on_watched_nack(&handled.signal, &mut synced_on_this_stream);
        assert!(
            !synced_on_this_stream,
            "watched NACK must clear the stream-local synced marker before the outbound NACK is queued"
        );
        assert_eq!(
            conn_state_rx.borrow().kind(),
            XdsConnectionStateKind::Connected,
            "watched NACK must publish non-fresh state before the outbound NACK is queued"
        );

        assert!(
            AdsClient::send_response(handled, &full_tx)
                .now_or_never()
                .is_none(),
            "outbound request channel should remain backpressured"
        );
    }

    #[tokio::test]
    async fn test_watched_ack_skips_resource_collection_without_rejections() {
        helpers::initialize_telemetry();

        let (_conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let handled = client.handle_response(DeltaDiscoveryResponse {
            resources: vec![get_auth(0)],
            nonce: TextNonce::new().to_string(),
            system_version_info: "1.0.0".to_string(),
            type_url: AUTHORIZATION_TYPE.to_string(),
            removed_resources: vec!["foo-deleted".to_string()],
        });

        let XdsSignal::Ack { resources } = handled.signal else {
            panic!("valid watched authorization update should classify as ACK");
        };
        assert!(
            resources.is_empty(),
            "ACK without rejected watched resources should not collect response resources"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_on_demand_nack_demotes_synced_state() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, client, _state, _block) = AdsServer::spawn(true).await;
        let mut conn_state_rx = client.connection_state_receiver();
        let client_task = spawn_ads_client_for_test(client);

        let mut conn = conn_receiver.recv().await.unwrap();
        prime_initial_sync(&mut conn).await;
        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Synced),
        )
        .await
        .expect("timed out waiting for initial Synced state")
        .expect("sender dropped");

        let rejected_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![get_invalid_address(10, "10.0.0.10".parse().unwrap())],
            nonce: rejected_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: ADDRESS_TYPE.to_string(),
            removed_resources: vec![],
        }))
        .await;
        let rejected_ack = recv_request_with_nonce(&mut conn, &rejected_nonce).await;
        assert!(
            rejected_ack.error_detail.is_some(),
            "invalid on-demand address update should be NACKed"
        );
        tokio::task::yield_now().await;

        assert_eq!(
            conn_state_rx.borrow().kind(),
            XdsConnectionStateKind::Connected,
            "on-demand address NACK must demote freshness"
        );

        abort_ads_client_for_test(client_task).await;
    }

    fn spawn_ads_client_for_test(client: AdsClient) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            match client.run().await {
                Ok(()) => {}
                Err(e) => {
                    panic!("xDS client unexpectedly exited: {e}");
                }
            }
        })
    }

    async fn abort_task_for_test<T>(task: tokio::task::JoinHandle<T>, task_name: &str) {
        assert!(
            !task.is_finished(),
            "{task_name} task exited before test cleanup"
        );
        task.abort();
        match task.await {
            Err(err) if err.is_cancelled() => {}
            Ok(_) => panic!("{task_name} task exited before cancellation"),
            Err(err) if err.is_panic() => {
                panic!("{task_name} task panicked before cancellation: {err:?}")
            }
            Err(err) => panic!("{task_name} task failed before cancellation: {err:?}"),
        }
    }

    async fn abort_ads_client_for_test(client_task: tokio::task::JoinHandle<()>) {
        abort_task_for_test(client_task, "xDS client").await;
    }

    async fn abort_ads_run_loop_for_test(client_task: tokio::task::JoinHandle<()>) {
        abort_task_for_test(client_task, "xDS run loop").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_that_caches_are_warm_before_unblocked() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, state, mut block) = AdsServer::spawn(false).await;

        let client_task = spawn_ads_client_for_test(client);

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
                    }, None)
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
                    assert!(
                        !client_task.is_finished(),
                        "xDS client task exited before caches were verified"
                    );
                        abort_ads_client_for_test(client_task).await;
                        return;
                    }
                req = conn.recv_request() => {
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
                conn.send_response(response).await;
                auth_seen = true;
            } else if req.type_url == ADDRESS_TYPE && !addr_seen {
                let response = Ok(DeltaDiscoveryResponse {
                    resources: vec![get_address(0, "1.2.3.4".parse().unwrap())],
                    nonce: TextNonce::new().to_string(),
                    system_version_info: "1.0.0".to_string(),
                    type_url: ADDRESS_TYPE.to_string(),
                    removed_resources: vec![],
                });
                conn.send_response(response).await;
                addr_seen = true;
            }
        }
    }

    #[tokio::test]
    async fn test_on_demand_handling() {
        helpers::initialize_telemetry();

        // Setup fake xds server
        let (mut conn_receiver, client, _, _) = AdsServer::spawn(true).await;

        let client_task = spawn_ads_client_for_test(client);

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
                req = conn.recv_request() => {
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
                assert!(
                    !client_task.is_finished(),
                    "xDS client task exited before on-demand requests were verified"
                );
                abort_ads_client_for_test(client_task).await;
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

        let client_task = spawn_ads_client_for_test(client);
        let result = demander.demand(ADDRESS_TYPE, "foo0".into()).await;

        let mut conn = conn_receiver.recv().await.unwrap();

        let timer = tokio::time::sleep(std::time::Duration::from_secs(5));
        futures::pin_mut!(timer);

        loop {
            let req = tokio::select! {
                _ = &mut timer => {
                    panic!("expected requests were not received");
                }
                req = conn.recv_request() => {
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

                conn.send_response(response).await;

                // wait for on demand to be notified. this means that the cache was updated with
                // our resource if it exists (and in our case we know it exists).
                result.recv().await;

                state
                    .read()
                    .find_address(
                        &NetworkAddress {
                            network: strng::EMPTY,
                            address: std::net::Ipv4Addr::new(1, 0, 0, 1).into(),
                        },
                        None,
                    )
                    .expect("demander return but resource not in cache");
                assert!(
                    !client_task.is_finished(),
                    "xDS client task exited before on-demand cache coherency was verified"
                );
                abort_ads_client_for_test(client_task).await;
                return;
            }
        }
    }

    #[tokio::test]
    async fn test_add_abort_remove() {
        helpers::initialize_telemetry();

        // TODO: Load this from a file?
        let ip: Ipv4Addr = "127.0.0.1".parse().unwrap();
        let workload_uid = "default/1.1.1.1".to_string();
        let mut resources = vec![];
        let addresses = vec![XdsAddress {
            r#type: Some(XdsType::Workload(XdsWorkload {
                uid: workload_uid.clone(),
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
                    name: w.uid.clone(),
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

        let initial_nonce = TextNonce::new().to_string();
        let initial_response = Ok(DeltaDiscoveryResponse {
            resources,
            nonce: initial_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: ADDRESS_TYPE.to_string(),
            removed_resources: vec![],
        });

        let abort_response = Err(tonic::Status::aborted("Aborting for test."));

        let remove_nonce = TextNonce::new().to_string();
        let removed_resource_response: Result<DeltaDiscoveryResponse, tonic::Status> =
            Ok(DeltaDiscoveryResponse {
                resources: vec![],
                nonce: remove_nonce.clone(),
                system_version_info: "1.0.0".to_string(),
                type_url: ADDRESS_TYPE.to_string(),
                removed_resources: vec![workload_uid],
            });

        // Setup fake xds server
        let (mut conn_receiver, client, state, _) = AdsServer::spawn(false).await;

        let client_task = spawn_ads_client_for_test(client);

        let mut conn = conn_receiver.recv().await.unwrap();

        conn.send_response(initial_response).await;
        recv_request_with_nonce(&mut conn, &initial_nonce).await;
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;
        conn.send_response(abort_response).await;
        verify_address(IpAddr::V4(ip), Some(addresses[0].clone()), &state).await;

        // original connection should close and client re-connect
        let mut conn = conn_receiver.recv().await.unwrap();
        conn.send_response(removed_resource_response).await;
        recv_request_with_nonce(&mut conn, &remove_nonce).await;
        verify_address(IpAddr::V4(ip), None, &state).await;
        assert!(
            !client_task.is_finished(),
            "xDS client task exited before add/abort/remove verification completed"
        );
        abort_ads_client_for_test(client_task).await;
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

    /// Verifies that the xDS connection state signal correctly transitions:
    /// Initializing -> Connected (on stream established) -> Disconnected (on error/abort)
    /// -> Connected (on reconnect).
    ///
    /// This is the foundation for the readiness re-arm feature: app.rs watches
    /// this signal and re-registers a readiness task on sustained disconnect.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_xds_connection_state_signals() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let mut conn_state_rx = client.connection_state_receiver();

        assert_eq!(*conn_state_rx.borrow(), XdsConnectionState::initializing());

        // Run a single loop iteration first so the test can observe
        // `Disconnected` without racing the client's next reconnect attempt.
        let first_loop = tokio::spawn(async move {
            let next_backoff = client.run_loop(Duration::from_millis(250)).await;
            (client, next_backoff)
        });

        let mut conn = conn_receiver.recv().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for Connected state")
        .expect("sender dropped");

        assert_eq!(*conn_state_rx.borrow(), XdsConnectionState::connected(0));

        conn.send_response(Err(tonic::Status::aborted("simulated disconnect")))
            .await;

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Disconnected),
        )
        .await
        .expect("timed out waiting for Disconnected state")
        .expect("sender dropped");

        assert_eq!(*conn_state_rx.borrow(), XdsConnectionState::disconnected(0));
        let (client, backoff) = first_loop.await.expect("first xDS run loop panicked");
        assert_eq!(*conn_state_rx.borrow(), XdsConnectionState::disconnected(0));

        let second_loop = tokio::spawn(async move {
            let mut client = client;
            let _next_backoff = client.run_loop(backoff).await;
        });
        let mut conn2 = conn_receiver.recv().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for re-Connected state")
        .expect("sender dropped");

        assert_eq!(*conn_state_rx.borrow(), XdsConnectionState::connected(0));

        prime_initial_sync(&mut conn2).await;

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Synced),
        )
        .await
        .expect("timed out waiting for Synced state after reconnect ACK")
        .expect("sender dropped");
        assert_eq!(*conn_state_rx.borrow(), XdsConnectionState::synced(1));

        abort_ads_run_loop_for_test(second_loop).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_xds_up_cleared_when_run_loop_task_is_cancelled() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let mut conn_state_rx = client.connection_state_receiver();
        let up = client
            .metrics
            .up
            .as_ref()
            .expect("remote xDS test client should export xds_up")
            .clone();

        assert_eq!(up.get(), 0);

        let client_loop = tokio::spawn(async move {
            let _next_backoff = client.run_loop(Duration::from_millis(250)).await;
        });
        let _conn = conn_receiver.recv().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for Connected state")
        .expect("sender dropped");

        assert_eq!(up.get(), 1);

        abort_ads_run_loop_for_test(client_loop).await;
        assert_eq!(
            up.get(),
            0,
            "xDS stream gauge must clear when the connected client task is cancelled"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_tls_setup_error_sleeps_before_retrying() {
        helpers::initialize_telemetry();

        let (_conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        client.config.tls_builder = Box::new(FailingCertProvider);

        let retry = tokio::spawn(async move { client.run_loop(Duration::from_millis(250)).await });
        tokio::task::yield_now().await;

        assert!(
            !retry.is_finished(),
            "TLS setup failure returned before any retry delay elapsed"
        );

        tokio::time::advance(Duration::from_millis(500)).await;
        let next_backoff = tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("TLS setup failure did not return after retry delay")
            .expect("retry task panicked");

        assert_eq!(next_backoff, Duration::from_millis(500));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_clean_stream_completion_sleeps_before_retrying() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let mut conn_state_rx = client.connection_state_receiver();

        let retry = tokio::spawn(async move { client.run_loop(Duration::from_millis(250)).await });
        let conn = conn_receiver.recv().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for Connected state")
        .expect("sender dropped");

        drop(conn);

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Disconnected),
        )
        .await
        .expect("timed out waiting for Disconnected state")
        .expect("sender dropped");
        tokio::task::yield_now().await;

        assert!(
            !retry.is_finished(),
            "clean ADS stream completion returned before any retry delay elapsed"
        );

        let next_backoff = tokio::time::timeout(Duration::from_secs(1), retry)
            .await
            .expect("clean completion did not return after retry delay")
            .expect("retry task panicked");

        assert_eq!(next_backoff, INITIAL_BACKOFF);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unknown_xds_type_does_not_publish_synced() {
        helpers::initialize_telemetry();

        let (mut conn_receiver, mut client, _state, _block) = AdsServer::spawn(false).await;
        let mut conn_state_rx = client.connection_state_receiver();

        let client_loop = tokio::spawn(async move {
            let _next_backoff = client.run_loop(Duration::from_millis(250)).await;
        });
        let mut conn = conn_receiver.recv().await.unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state_rx.wait_for(|s| s.kind() == XdsConnectionStateKind::Connected),
        )
        .await
        .expect("timed out waiting for Connected state")
        .expect("sender dropped");

        let unknown_nonce = TextNonce::new().to_string();
        conn.send_response(Ok(DeltaDiscoveryResponse {
            resources: vec![],
            nonce: unknown_nonce.clone(),
            system_version_info: "1.0.0".to_string(),
            type_url: "type.googleapis.com/unknown.Type".to_string(),
            removed_resources: vec![],
        }))
        .await;

        let ack = recv_request_with_nonce(&mut conn, &unknown_nonce).await;
        assert!(
            ack.error_detail.is_none(),
            "unknown xDS type should receive an ACK_IGNORED response"
        );

        abort_ads_run_loop_for_test(client_loop).await;
        assert_eq!(
            *conn_state_rx.borrow(),
            XdsConnectionState::connected(0),
            "unknown xDS type must not publish Synced after the response is processed"
        );
    }

    #[tokio::test]
    async fn test_app_wires_xds_unhealthy_threshold_to_readiness_rearm() {
        helpers::initialize_telemetry();
        let (mut conn_receiver, mut cfg) = AdsServer::spawn_app_server().await;
        // 200 ms threshold gives loaded CI enough headroom to schedule the
        // monitor task before the threshold expires, while still keeping the
        // test fast.
        cfg.xds_unhealthy_threshold = Some(Duration::from_millis(200));

        let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
        let app = app::build_with_cert(Arc::new(cfg), cert_manager)
            .await
            .unwrap();
        let shutdown = app.shutdown.trigger().clone();
        let readiness_address = app.readiness_address;
        let metrics_address = app.metrics_address;
        let mut xds_connection_state = app
            .xds_connection_state
            .clone()
            .expect("remote xDS app should expose connection state");
        let mut xds_startup = app.xds_startup.clone();
        let app_task = tokio::spawn(app.wait_termination());

        let mut conn = tokio::time::timeout(Duration::from_secs(2), conn_receiver.recv())
            .await
            .expect("timed out waiting for initial app xDS connection")
            .expect("channel closed");

        prime_initial_sync(&mut conn).await;
        wait_for_startup_sync(&mut xds_startup).await;
        wait_for_xds_state(
            &mut xds_connection_state,
            |s| s.kind() == XdsConnectionStateKind::Synced,
            "initial app xDS sync",
        )
        .await;
        wait_for_readiness(readiness_address, true, "initial app readiness").await;
        let synced_epoch = xds_connection_state.borrow().freshness_epoch();

        conn.send_response(Err(tonic::Status::aborted("simulated disconnect")))
            .await;

        let mut restore_conn = tokio::time::timeout(Duration::from_secs(2), conn_receiver.recv())
            .await
            .expect("timed out waiting for restore xDS connection")
            .expect("channel closed");

        wait_for_xds_state(
            &mut xds_connection_state,
            |s| {
                s.kind() == XdsConnectionStateKind::Connected && s.freshness_epoch() == synced_epoch
            },
            "raw xDS reconnect before ACK",
        )
        .await;

        let first_reconnect_req =
            tokio::time::timeout(Duration::from_secs(2), restore_conn.recv_request())
                .await
                .expect("timed out waiting for reconnect's first xDS request")
                .expect("channel closed before reconnect's first xDS request");

        wait_for_readiness(
            readiness_address,
            false,
            "readiness to re-arm after reconnect without ACK",
        )
        .await;

        let metrics = metrics_request(metrics_address).await;
        // Anchor on a full line to avoid matching a future metric whose
        // name happens to share this prefix, and to assert the value
        // unambiguously.
        assert!(
            metrics
                .lines()
                .any(|l| l == "istio_xds_readiness_rearmed_total 1"),
            "app did not wire XDS_UNHEALTHY_THRESHOLD to readiness rearm:\n{metrics}"
        );

        assert!(
            readiness_request(readiness_address).await.is_err(),
            "raw xDS reconnect restored readiness before any ACK"
        );

        prime_initial_sync_after_request(&mut restore_conn, first_reconnect_req).await;
        wait_for_xds_state(
            &mut xds_connection_state,
            |s| s.kind() == XdsConnectionStateKind::Synced && s.freshness_epoch() != synced_epoch,
            "post-reconnect xDS ACK",
        )
        .await;
        wait_for_readiness(
            readiness_address,
            true,
            "readiness to restore after post-reconnect ACK",
        )
        .await;

        shutdown.shutdown_now().await;
        app_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_app_keeps_readiness_ready_after_disconnect_when_rearm_disabled() {
        helpers::initialize_telemetry();
        let (mut conn_receiver, cfg) = AdsServer::spawn_app_server().await;
        assert_eq!(cfg.xds_unhealthy_threshold, None);

        let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
        let app = app::build_with_cert(Arc::new(cfg), cert_manager)
            .await
            .unwrap();
        let shutdown = app.shutdown.trigger().clone();
        let readiness_address = app.readiness_address;
        let metrics_address = app.metrics_address;
        let mut xds_connection_state = app
            .xds_connection_state
            .clone()
            .expect("remote xDS app should expose connection state");
        let mut xds_startup = app.xds_startup.clone();
        let app_task = tokio::spawn(app.wait_termination());

        let mut conn = tokio::time::timeout(Duration::from_secs(2), conn_receiver.recv())
            .await
            .expect("timed out waiting for initial app xDS connection")
            .expect("channel closed");

        prime_initial_sync(&mut conn).await;
        wait_for_startup_sync(&mut xds_startup).await;
        wait_for_xds_state(
            &mut xds_connection_state,
            |s| s.kind() == XdsConnectionStateKind::Synced,
            "initial app xDS sync",
        )
        .await;
        wait_for_readiness(readiness_address, true, "initial app readiness").await;

        conn.send_response(Err(tonic::Status::aborted("simulated disconnect")))
            .await;

        let mut reconnect = tokio::time::timeout(Duration::from_secs(2), conn_receiver.recv())
            .await
            .expect("timed out waiting for reconnect")
            .expect("channel closed");
        tokio::time::timeout(Duration::from_secs(2), reconnect.recv_request())
            .await
            .expect("timed out waiting for reconnect's first xDS request")
            .expect("channel closed before reconnect's first xDS request");
        readiness_request(readiness_address)
            .await
            .expect("readiness re-armed even though XDS_UNHEALTHY_THRESHOLD is unset");

        let metrics = metrics_request(metrics_address).await;
        assert!(
            metrics
                .lines()
                .any(|l| l == "istio_xds_readiness_rearmed_total 0"),
            "readiness rearm counter should remain zero when disabled:\n{metrics}"
        );

        shutdown.shutdown_now().await;
        app_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn test_app_without_remote_xds_does_not_export_remote_stream_metrics() {
        helpers::initialize_telemetry();
        let cfg = test_config();

        let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
        let app = app::build_with_cert(Arc::new(cfg), cert_manager)
            .await
            .unwrap();
        let shutdown = app.shutdown.trigger().clone();
        let metrics_address = app.metrics_address;
        let app_task = tokio::spawn(app.wait_termination());

        let metrics = metrics_request(metrics_address).await;

        shutdown.shutdown_now().await;
        app_task.await.unwrap().unwrap();

        assert!(
            !metrics.lines().any(|l| l.starts_with("istio_xds_up ")),
            "no-remote xDS config must not export a disconnected xDS stream gauge:\n{metrics}"
        );
        assert!(
            !metrics.contains("istio_xds_disconnect_duration_seconds"),
            "no-remote xDS config must not export remote xDS disconnect histogram:\n{metrics}"
        );
    }

    /// Regression test for the bug where `was_connected` was sampled from the
    /// connection-state watch BEFORE `run_internal()` ran, which on every
    /// iteration after the first read back `Disconnected` (just published at
    /// the tail of the previous iteration) and so never started the
    /// `disconnect_start` timer. The result was that
    /// `xds_disconnect_duration_seconds` never received any observations.
    /// Asserts the histogram count goes above zero after one full
    /// connect → disconnect → reconnect cycle.
    #[tokio::test]
    async fn test_disconnect_duration_histogram_observed_after_reconnect() {
        helpers::initialize_telemetry();
        let (mut conn_receiver, cfg) = AdsServer::spawn_app_server().await;

        let cert_manager = identity::mock::new_secret_manager(Duration::from_secs(10));
        let app = app::build_with_cert(Arc::new(cfg), cert_manager)
            .await
            .unwrap();
        let shutdown = app.shutdown.trigger().clone();
        let metrics_address = app.metrics_address;
        let app_task = tokio::spawn(app.wait_termination());

        // First connection: drive an ACK so we transition Initializing →
        // Connected → Synced. Without an ACK on this stream, `reached_connected`
        // would still be set (it flips on stream establishment), but driving a
        // real ACK matches production behavior more closely.
        let mut conn = tokio::time::timeout(Duration::from_secs(2), conn_receiver.recv())
            .await
            .expect("timed out waiting for initial xDS connection")
            .expect("channel closed");

        prime_initial_sync(&mut conn).await;

        // Force a disconnect, then accept (and immediately reject) a few
        // reconnect attempts to give the server-side drop a chance to flow
        // through `run_loop` and observe a sample on the histogram.
        conn.send_response(Err(tonic::Status::aborted("simulated disconnect")))
            .await;

        // Accept and immediately allow one full reconnect; the sample is
        // recorded at the start of the NEW stream (`disconnect_start.take()`),
        // so we need at least one successful re-establishment for the count
        // to advance.
        let mut conn2 = tokio::time::timeout(Duration::from_secs(5), conn_receiver.recv())
            .await
            .expect("timed out waiting for reconnect")
            .expect("channel closed");
        // Drain one request to keep the stream alive long enough for the
        // sample to flush before we tear down.
        tokio::time::timeout(Duration::from_secs(2), conn2.recv_request())
            .await
            .expect("timed out waiting for reconnect's first xDS request")
            .expect("channel closed before reconnect's first xDS request");

        // Read /metrics until the histogram count becomes non-zero. The full metric name
        // includes the istio_ prefix and the _seconds_count suffix.
        wait_for_metric(
            metrics_address,
            "disconnect duration histogram count",
            |metrics| {
                metrics
                    .lines()
                    .find(|l| l.starts_with("istio_xds_disconnect_duration_seconds_count "))
                    .and_then(|line| {
                        line.strip_prefix("istio_xds_disconnect_duration_seconds_count ")
                    })
                    .and_then(|rest| rest.trim().parse::<u64>().ok())
                    .is_some_and(|n| n > 0)
            },
        )
        .await;

        shutdown.shutdown_now().await;
        app_task.await.unwrap().unwrap();
    }

    async fn wait_for_startup_sync(xds_startup: &mut tokio::sync::watch::Receiver<()>) {
        tokio::time::timeout(Duration::from_secs(2), xds_startup.changed())
            .await
            .expect("timed out waiting for app startup xDS sync")
            .expect("xDS startup sender dropped");
    }

    async fn wait_for_xds_state(
        conn_state: &mut tokio::sync::watch::Receiver<XdsConnectionState>,
        mut predicate: impl FnMut(XdsConnectionState) -> bool,
        reason: &str,
    ) {
        tokio::time::timeout(
            Duration::from_secs(2),
            conn_state.wait_for(|s| predicate(*s)),
        )
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {reason}"))
        .expect("xDS connection state sender dropped");
    }

    async fn wait_for_readiness(addr: std::net::SocketAddr, ready: bool, reason: &str) {
        let mut last_result = None;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let result = readiness_request(addr).await;
                let matches = result.is_ok() == ready;
                last_result = Some(format!("{result:?}"));
                if matches {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("timed out waiting for {reason}; last readiness result: {last_result:?}")
        });
    }

    async fn wait_for_metric(
        addr: std::net::SocketAddr,
        reason: &str,
        mut predicate: impl FnMut(&str) -> bool,
    ) {
        let mut last_metrics = String::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                last_metrics = metrics_request(addr).await;
                if predicate(&last_metrics) {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!("timed out waiting for {reason}; last metrics:\n{last_metrics}")
        });
    }

    async fn readiness_request(addr: std::net::SocketAddr) -> anyhow::Result<()> {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("http://localhost:{}/healthz/ready", addr.port()))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let client = crate::hyper_util::pooling_client();
        let resp = client.request(req).await?;
        if resp.status() == http::StatusCode::OK {
            Ok(())
        } else {
            anyhow::bail!("readiness status {}", resp.status())
        }
    }

    async fn metrics_request(addr: std::net::SocketAddr) -> String {
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("http://{addr}/metrics"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        let client = crate::hyper_util::pooling_client();
        let body = client.request(req).await.unwrap().into_body();
        let body = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }
}
