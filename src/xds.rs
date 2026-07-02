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

use std::collections::{HashMap, HashSet};
use std::error::Error as StdErr;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tracing::Level;

use tokio::sync::mpsc;
#[cfg(any(test, feature = "testing"))]
use tracing::error;
use tracing::{debug, info, instrument, trace, warn};

pub use client::*;
pub use metrics::*;
pub use types::*;
use xds::istio::security::Authorization as XdsAuthorization;
use xds::istio::workload::Address as XdsAddress;
use xds::istio::workload::PortList;
use xds::istio::workload::Service as XdsService;
use xds::istio::workload::Workload as XdsWorkload;
use xds::istio::workload::address::Type as XdsType;

use crate::cert_fetcher::{CertFetcher, NoCertFetcher};
use crate::config::ConfigSource;
use crate::rbac::Authorization;
use crate::state::ProxyState;
use crate::state::service::{Endpoint, Service, ServiceStore};
use crate::state::workload::{NamespacedHostname, Workload, WorkloadStore};
use crate::strng::Strng;
use crate::{rbac, strng};
use crate::{tls, xds};

use self::service::discovery::v3::DeltaDiscoveryRequest;

mod client;
pub mod metrics;
mod types;

struct DisplayStatus<'a>(&'a tonic::Status);

impl fmt::Display for DisplayStatus<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = &self.0;
        write!(f, "status: {:?}, message: {:?}", s.code(), s.message())?;

        if s.message().to_string().contains("authentication failure") {
            write!(
                f,
                " (hint: check the control plane logs for more information)"
            )?;
        }
        if !s.details().is_empty()
            && let Ok(st) = std::str::from_utf8(s.details())
        {
            write!(f, ", details: {st}")?;
        }
        if let Some(src) = s.source().and_then(|s| s.source()) {
            write!(f, ", source: {src}")?;
            // Error is not public to explicitly match on, so do a fuzzy match
            if format!("{src}").contains("Temporary failure in name resolution") {
                write!(f, " (hint: is the DNS server reachable?)")?;
            }
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("gRPC error {}", DisplayStatus(.0))]
    GrpcStatus(#[from] tonic::Status),
    #[error("gRPC connection error connecting to {}: {}", .0, DisplayStatus(.1))]
    Connection(String, #[source] tonic::Status),
    /// Attempted to send on a MPSC channel which has been canceled
    #[error(transparent)]
    RequestFailure(#[from] Box<mpsc::error::SendError<DeltaDiscoveryRequest>>),
    #[error("failed to send on demand resource")]
    OnDemandSend(),
    #[error("TLS Error: {0}")]
    TLSError(#[from] tls::Error),
}

/// Updates the [ProxyState] from XDS.
/// All state updates code goes in ProxyStateUpdateMutator, that takes state as a parameter.
/// this guarantees that the state is always locked when it is updated.
#[derive(Clone)]
pub struct ProxyStateUpdateMutator {
    cert_fetcher: Arc<dyn CertFetcher>,
}

/// Accumulates per-service endpoint changes during a single xDS push so they can
/// be applied to each service with one clone + one reindex, instead of once per
/// endpoint (which is O(E²) for a service with E endpoints — see
/// [ServiceStore::apply_endpoints]).
///
/// A `(service, uid)` may legitimately appear in both `removals` and `upserts`:
/// re-inserting a workload removes its old endpoints and adds its new ones in the
/// same push. [ServiceStore::apply_endpoints] applies removals before upserts so
/// the new endpoint wins — and, crucially, if the new endpoint is health-filtered
/// out the stale one is still removed.
#[derive(Default)]
struct EndpointAccumulator {
    upserts: HashMap<NamespacedHostname, HashMap<Strng, Endpoint>>,
    removals: HashMap<NamespacedHostname, HashSet<Strng>>,
}

impl EndpointAccumulator {
    fn upsert(&mut self, service: NamespacedHostname, uid: Strng, ep: Endpoint) {
        self.upserts.entry(service).or_default().insert(uid, ep);
    }

    fn remove(&mut self, service: NamespacedHostname, uid: Strng) {
        self.removals.entry(service).or_default().insert(uid);
    }

    /// Drains the accumulator into the store, touching each service once.
    fn apply(self, services: &mut ServiceStore) {
        let EndpointAccumulator {
            mut upserts,
            removals,
        } = self;
        for (service, removals) in removals {
            let upserts = upserts.remove(&service).unwrap_or_default();
            services.apply_endpoints(&service, upserts, removals);
        }
        for (service, upserts) in upserts {
            services.apply_endpoints(&service, upserts, HashSet::new());
        }
    }
}

#[derive(Clone)]
pub struct ProxyStateUpdater {
    state: Arc<RwLock<ProxyState>>,
    updater: ProxyStateUpdateMutator,
}

impl ProxyStateUpdater {
    /// Creates a new updater for the given stores. Will prefetch certs when workloads are updated.
    pub fn new(state: Arc<RwLock<ProxyState>>, cert_fetcher: Arc<dyn CertFetcher>) -> Self {
        Self {
            state,
            updater: ProxyStateUpdateMutator { cert_fetcher },
        }
    }
    /// Creates a new updater that does not prefetch workload certs.
    pub fn new_no_fetch(state: Arc<RwLock<ProxyState>>) -> Self {
        Self {
            state,
            updater: ProxyStateUpdateMutator::new_no_fetch(),
        }
    }
}

impl ProxyStateUpdateMutator {
    /// Creates a new updater that does not prefetch workload certs.
    pub fn new_no_fetch() -> Self {
        ProxyStateUpdateMutator {
            cert_fetcher: Arc::new(NoCertFetcher()),
        }
    }

    #[instrument(
        level = Level::TRACE,
        name="insert_workload",
        skip_all,
        fields(uid=%w.uid),
    )]
    pub fn insert_workload(&self, state: &mut ProxyState, w: XdsWorkload) -> anyhow::Result<()> {
        let mut acc = EndpointAccumulator::default();
        self.insert_workload_into(state, w, &mut acc)?;
        acc.apply(&mut state.services);
        Ok(())
    }

    /// Inserts a workload into the workload store and accumulates its service
    /// endpoint changes into `acc` (rather than applying them per-endpoint). The
    /// caller drains `acc` once per push via [EndpointAccumulator::apply].
    fn insert_workload_into(
        &self,
        state: &mut ProxyState,
        w: XdsWorkload,
        acc: &mut EndpointAccumulator,
    ) -> anyhow::Result<()> {
        debug!("handling insert");

        // Convert the workload first, so a malformed update leaves the existing
        // workload untouched.
        let (workload, services): (Workload, HashMap<String, PortList>) = w.try_into()?;
        let workload = Arc::new(workload);

        // First, remove the entry entirely to make sure things are cleaned up properly.
        self.remove_workload_for_insert(state, &workload.uid, acc);

        // Prefetch the cert for the workload.
        self.cert_fetcher.prefetch_cert(&workload);

        // Lock and upstate the stores.
        state.workloads.insert(workload.clone());
        accumulate_service_endpoints(&workload, &services, acc)?;

        Ok(())
    }

    pub fn remove(&self, state: &mut ProxyState, xds_name: &Strng) {
        let mut acc = EndpointAccumulator::default();
        self.remove_internal(state, xds_name, false, &mut acc);
        acc.apply(&mut state.services);
    }

    fn remove_workload_for_insert(
        &self,
        state: &mut ProxyState,
        xds_name: &Strng,
        acc: &mut EndpointAccumulator,
    ) {
        self.remove_internal(state, xds_name, true, acc);
    }

    #[instrument(
        level = Level::TRACE,
        name="remove",
        skip_all,
        fields(name=%xds_name, for_workload_insert=%for_workload_insert),
    )]
    fn remove_internal(
        &self,
        state: &mut ProxyState,
        xds_name: &Strng,
        for_workload_insert: bool,
        acc: &mut EndpointAccumulator,
    ) {
        // remove workload by UID; if xds_name is a service then this will no-op
        if let Some(prev) = state.workloads.remove(&strng::new(xds_name)) {
            // Also remove this workload's endpoints from each of its services.
            // Routed through the accumulator so a service touched many times in a
            // push is reindexed once.
            for svc in prev.services.iter() {
                acc.remove(svc.clone(), prev.uid.clone());
            }

            // This is a real removal (not a removal before insertion), and nothing else references the cert
            // Clear it out
            if !for_workload_insert
                && state
                    .workloads
                    .was_last_identity_on_node(&prev.node, &prev.identity())
            {
                self.cert_fetcher.clear_cert(&prev.identity());
            }
            // We removed a workload, no reason to attempt to remove a service with the same name
            return;
        }
        if for_workload_insert {
            // This is a workload, don't attempt to remove as a service
            return;
        }

        let Ok(name) = NamespacedHostname::from_str(xds_name) else {
            // we don't have namespace/hostname xds primary key for service
            warn!(
                "tried to remove service but it did not have the expected namespace/hostname format"
            );
            return;
        };

        if name.hostname.contains('/') {
            // avoid trying to delete obvious workload UIDs as a service,
            // which can result in noisy logs when new workloads are added
            // (we remove then add workloads on initial update)
            //
            // we can make this assumption because namespaces and hostnames cannot have `/` in them
            trace!("not a service, not attempting to delete as such",);
            return;
        }
        if !state.services.remove(&name) {
            warn!("tried to remove service, but it was not found");
        }
    }

    pub fn insert_address(&self, state: &mut ProxyState, a: XdsAddress) -> anyhow::Result<()> {
        let mut acc = EndpointAccumulator::default();
        self.insert_address_into(state, a, &mut acc)?;
        acc.apply(&mut state.services);
        Ok(())
    }

    fn insert_address_into(
        &self,
        state: &mut ProxyState,
        a: XdsAddress,
        acc: &mut EndpointAccumulator,
    ) -> anyhow::Result<()> {
        match a.r#type {
            Some(XdsType::Workload(w)) => self.insert_workload_into(state, w, acc),
            // Services are applied immediately (already a single clone + reindex,
            // and they must be present before phase-2 endpoint application so the
            // staged-endpoint flush runs first).
            Some(XdsType::Service(s)) => self.insert_service(state, s),
            _ => Err(anyhow::anyhow!("unknown address type")),
        }
    }

    #[instrument(
        level = Level::TRACE,
        name="insert_service",
        skip_all,
        fields(name=%service.name),
    )]
    pub fn insert_service(
        &self,
        state: &mut ProxyState,
        service: XdsService,
    ) -> anyhow::Result<()> {
        debug!("handling insert");
        let mut service = Service::try_from(&service)?;

        // If the service already exists, add existing endpoints into the new service.
        if let Some(prev) = state
            .services
            .get_by_namespaced_host(&service.namespaced_hostname())
        {
            for ep in prev.endpoints.iter() {
                if service.should_include_endpoint(ep.status) {
                    service
                        .endpoints
                        .insert(ep.workload_uid.clone(), ep.clone());
                }
            }
        }

        state.services.insert(service);
        Ok(())
    }

    pub fn insert_authorization(
        &self,
        state: &mut ProxyState,
        xds_name: Strng,
        r: XdsAuthorization,
    ) -> anyhow::Result<()> {
        info!("handling RBAC update {}", r.name);

        let rbac = rbac::Authorization::try_from(r)?;
        trace!(
            "insert policy {}, {}",
            xds_name,
            serde_json::to_string(&rbac)?
        );
        state.policies.insert(xds_name, rbac);
        Ok(())
    }

    pub fn remove_authorization(&self, state: &mut ProxyState, xds_name: Strng) {
        info!("handling RBAC delete {}", xds_name);
        state.policies.remove(xds_name);
    }
}

impl Handler<XdsWorkload> for ProxyStateUpdater {
    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsWorkload>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        // use deepsize::DeepSizeOf;
        let mut state = self.state.write().unwrap();
        let mut acc = EndpointAccumulator::default();
        let result = handle_single_resource(updates, |res: XdsUpdate<XdsWorkload>| {
            match res {
                XdsUpdate::Update(w) => self
                    .updater
                    .insert_workload_into(&mut state, w.resource, &mut acc)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.updater
                        .remove_internal(&mut state, &strng::new(name), false, &mut acc)
                }
            }
            Ok(())
        });
        // Apply all accumulated endpoint changes, one clone + reindex per service.
        acc.apply(&mut state.services);
        result
    }
}

impl Handler<XdsAddress> for ProxyStateUpdater {
    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsAddress>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut state = self.state.write().unwrap();
        let mut acc = EndpointAccumulator::default();
        // Phase 1: apply workloads to the workload store and services to the
        // service store immediately, accumulating each workload's endpoint
        // changes (keyed by service) into `acc`.
        let result = handle_single_resource(updates, |res: XdsUpdate<XdsAddress>| {
            match res {
                XdsUpdate::Update(w) => self
                    .updater
                    .insert_address_into(&mut state, w.resource, &mut acc)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.updater
                        .remove_internal(&mut state, &strng::new(name), false, &mut acc)
                }
            }
            Ok(())
        });
        // Phase 2: apply the accumulated endpoint changes, one clone + reindex
        // per distinct service rather than once per endpoint.
        acc.apply(&mut state.services);
        result
    }
}

fn accumulate_service_endpoints(
    workload: &Workload,
    services: &HashMap<String, PortList>,
    acc: &mut EndpointAccumulator,
) -> anyhow::Result<()> {
    for (namespaced_host, ports) in services {
        // Parse the namespaced hostname for the service.
        let namespaced_host = NamespacedHostname::from_str(namespaced_host)?;
        acc.upsert(
            namespaced_host,
            workload.uid.clone(),
            Endpoint {
                workload_uid: workload.uid.clone(),
                port: ports.into(),
                status: workload.status,
            },
        );
    }
    Ok(())
}

/// Applies a single workload's service endpoints directly (one-shot). Used by the
/// file-based [LocalClient], which builds state fresh and isn't on the xDS push
/// hot path.
fn insert_service_endpoints(
    workload: &Workload,
    services: &HashMap<String, PortList>,
    services_state: &mut ServiceStore,
) -> anyhow::Result<()> {
    let mut acc = EndpointAccumulator::default();
    accumulate_service_endpoints(workload, services, &mut acc)?;
    acc.apply(services_state);
    Ok(())
}

impl Handler<XdsAuthorization> for ProxyStateUpdater {
    fn no_on_demand(&self) -> bool {
        true
    }

    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsAuthorization>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut state = self.state.write().unwrap();
        let handle = |res: XdsUpdate<XdsAuthorization>| {
            match res {
                XdsUpdate::Update(w) => self
                    .updater
                    .insert_authorization(&mut state, w.name, w.resource)?,
                XdsUpdate::Remove(name) => self.updater.remove_authorization(&mut state, name),
            }
            Ok(())
        };
        let mut len_updates = 0;
        let updates = updates.inspect(|_| len_updates += 1);
        match handle_single_resource(updates, handle) {
            Ok(()) => {
                state.policies.send();
                Ok(())
            }
            Err(e) => {
                if e.len() < len_updates {
                    // not all config was rejected, we have _some_ valide update
                    state.policies.send();
                }
                Err(e)
            }
        }
    }
}

/// LocalClient serves as a local file reader alternative for XDS. This is intended for testing.
pub struct LocalClient {
    pub cfg: ConfigSource,
    pub state: Arc<RwLock<ProxyState>>,
    pub cert_fetcher: Arc<dyn CertFetcher>,
    pub local_node: Option<Strng>,
}

#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalWorkload {
    #[serde(flatten)]
    pub workload: Workload,
    pub services: HashMap<String, HashMap<u16, u16>>,
}

#[derive(Default, Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LocalConfig {
    #[serde(default)]
    pub workloads: Vec<LocalWorkload>,
    #[serde(default)]
    pub policies: Vec<Authorization>,
    #[serde(default)]
    pub services: Vec<Service>,
}

impl LocalClient {
    #[instrument(skip_all, name = "local_client")]
    pub async fn run(self) -> Result<(), anyhow::Error> {
        // Load initial state
        match &self.cfg {
            #[cfg(any(test, feature = "testing"))]
            ConfigSource::Dynamic(rx) => {
                let mut rx = rx.lock().await;
                let r = rx
                    .recv()
                    .await
                    .ok_or(anyhow::anyhow!("did not get initial config"))?;
                self.load_config(r)?;
                rx.ack().await?;
            }
            f => {
                let r: LocalConfig = serde_yaml::from_str(&f.read_to_string().await?)?;
                self.load_config(r)?;
            }
        };
        #[cfg(any(test, feature = "testing"))]
        if let ConfigSource::Dynamic(ref rx) = self.cfg {
            let rx = rx.clone();
            tokio::spawn(async move {
                // Mutex is just for borrow checker; we know we are the only user and can hold the lock forever.
                let mut rx = rx.lock().await;
                while let Some(req) = rx.recv().await {
                    if let Err(e) = self.load_config(req) {
                        error!("failed to load dynamic config update: {e:?}");
                    }
                    if let Err(e) = rx.ack().await {
                        error!("failed to ack: {}", e);
                    }
                }
            });
        };
        Ok(())
    }

    fn load_config(&self, r: LocalConfig) -> anyhow::Result<()> {
        debug!(
            "load local config: {}",
            serde_yaml::to_string(&r).unwrap_or_default()
        );
        let mut state = self.state.write().unwrap();
        // Clear the state
        state.workloads = WorkloadStore::new(self.local_node.clone());
        state.services = Default::default();
        // Policies have some channels, so we don't want to reset it entirely
        state.policies.clear_all_policies();
        let num_workloads = r.workloads.len();
        let num_policies = r.policies.len();
        for wl in r.workloads {
            trace!("inserting local workload {}", &wl.workload.uid);
            self.cert_fetcher.prefetch_cert(&wl.workload);
            let w = Arc::new(wl.workload);
            state.workloads.insert(w.clone());

            let services: HashMap<String, PortList> = wl
                .services
                .into_iter()
                .map(|(k, v)| (k, PortList::from(v)))
                .collect();

            insert_service_endpoints(&w, &services, &mut state.services)?;
        }
        for rbac in r.policies {
            let xds_name = rbac.to_key();
            state.policies.insert(xds_name, rbac);
        }
        for svc in r.services {
            state.services.insert(svc);
        }
        info!(%num_workloads, %num_policies, "local config initialized");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::workload::NamespacedHostname;
    use crate::xds::istio::workload::{
        NetworkAddress as XdsNetworkAddress, Port, WorkloadStatus as XdsStatus,
    };
    use bytes::Bytes;
    use std::net::Ipv4Addr;

    const NS: &str = "ns";
    const HOST: &str = "svc1.ns.svc.cluster.local";

    fn updater_and_state() -> (ProxyStateUpdater, Arc<RwLock<ProxyState>>) {
        let state = Arc::new(RwLock::new(ProxyState::new(None)));
        let updater = ProxyStateUpdater::new_no_fetch(state.clone());
        (updater, state)
    }

    fn service() -> XdsService {
        XdsService {
            name: "svc1".to_string(),
            namespace: NS.to_string(),
            hostname: HOST.to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "".to_string(),
                address: Ipv4Addr::new(127, 0, 1, 1).octets().to_vec(),
                length: None,
            }],
            ports: vec![Port {
                service_port: 80,
                target_port: 80,
            }],
            ..Default::default()
        }
    }

    fn workload(i: usize, status: XdsStatus) -> XdsWorkload {
        XdsWorkload {
            uid: format!("cluster1//v1/Pod/{NS}/pod-{i}"),
            addresses: vec![Bytes::copy_from_slice(&[
                127,
                0,
                (i / 255) as u8,
                (i % 255) as u8,
            ])],
            name: format!("pod-{i}"),
            services: HashMap::from([(
                format!("{NS}/{HOST}"),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                    }],
                },
            )]),
            status: status as i32,
            ..Default::default()
        }
    }

    fn host() -> NamespacedHostname {
        NamespacedHostname {
            namespace: NS.into(),
            hostname: HOST.into(),
        }
    }

    fn wl_update(w: XdsWorkload) -> XdsUpdate<XdsAddress> {
        XdsUpdate::Update(XdsResource {
            name: w.uid.as_str().into(),
            resource: XdsAddress {
                r#type: Some(XdsType::Workload(w)),
            },
        })
    }

    fn svc_update(s: XdsService) -> XdsUpdate<XdsAddress> {
        XdsUpdate::Update(XdsResource {
            name: s.hostname.as_str().into(),
            resource: XdsAddress {
                r#type: Some(XdsType::Service(s)),
            },
        })
    }

    fn apply(updater: &ProxyStateUpdater, batch: Vec<XdsUpdate<XdsAddress>>) -> Result<(), usize> {
        let handler = updater as &dyn Handler<XdsAddress>;
        handler
            .handle(Box::new(&mut batch.into_iter()))
            .map_err(|rejects| rejects.len())
    }

    fn endpoint_count(state: &Arc<RwLock<ProxyState>>) -> usize {
        state
            .read()
            .unwrap()
            .services
            .get_by_namespaced_host(&host())
            .map(|s| s.endpoints.len())
            .unwrap_or(0)
    }

    // All N workloads land on one service, applied in a single push, with the
    // service in the middle of the batch. The service must end with N endpoints
    // and must have been reindexed exactly once (not once per endpoint).
    #[test]
    fn batch_groups_endpoints_per_service() {
        let (updater, state) = updater_and_state();
        const N: usize = 50;

        let mut batch: Vec<_> = (0..N / 2)
            .map(|i| wl_update(workload(i, XdsStatus::Healthy)))
            .collect();
        batch.push(svc_update(service()));
        batch.extend((N / 2..N).map(|i| wl_update(workload(i, XdsStatus::Healthy))));

        apply(&updater, batch).unwrap();

        assert_eq!(endpoint_count(&state), N);
        assert_eq!(state.read().unwrap().services.num_staged_services(), 0);
        // One clone + reindex for the single service, regardless of N endpoints.
        assert_eq!(state.read().unwrap().services.endpoint_reindexes(), 1);
    }

    // Equivalent batch with the service first must produce the same result.
    #[test]
    fn batch_service_before_workloads() {
        let (updater, state) = updater_and_state();
        let mut batch = vec![svc_update(service())];
        batch.extend((0..10).map(|i| wl_update(workload(i, XdsStatus::Healthy))));

        apply(&updater, batch).unwrap();

        assert_eq!(endpoint_count(&state), 10);
        assert_eq!(state.read().unwrap().services.endpoint_reindexes(), 1);
    }

    // Unhealthy workloads in a batch are excluded from the service's endpoints.
    #[test]
    fn batch_filters_unhealthy() {
        let (updater, state) = updater_and_state();
        let batch = vec![
            svc_update(service()),
            wl_update(workload(0, XdsStatus::Healthy)),
            wl_update(workload(1, XdsStatus::Unhealthy)),
            wl_update(workload(2, XdsStatus::Healthy)),
        ];

        apply(&updater, batch).unwrap();

        assert_eq!(endpoint_count(&state), 2);
    }

    // A malformed resource only rejects itself; the rest of the batch applies.
    #[test]
    fn batch_partial_failure() {
        let (updater, state) = updater_and_state();
        let bad = XdsUpdate::Update(XdsResource {
            name: "bad".into(),
            resource: XdsAddress { r#type: None },
        });
        let batch = vec![
            svc_update(service()),
            wl_update(workload(0, XdsStatus::Healthy)),
            bad,
            wl_update(workload(1, XdsStatus::Healthy)),
        ];

        assert_eq!(apply(&updater, batch), Err(1));
        assert_eq!(endpoint_count(&state), 2);
    }

    // Removing a workload in a later push drops its endpoint from the service.
    #[test]
    fn remove_drops_endpoint() {
        let (updater, state) = updater_and_state();
        apply(
            &updater,
            vec![
                svc_update(service()),
                wl_update(workload(0, XdsStatus::Healthy)),
                wl_update(workload(1, XdsStatus::Healthy)),
            ],
        )
        .unwrap();
        assert_eq!(endpoint_count(&state), 2);

        let remove = XdsUpdate::<XdsAddress>::Remove(workload(0, XdsStatus::Healthy).uid.into());
        apply(&updater, vec![remove]).unwrap();
        assert_eq!(endpoint_count(&state), 1);
    }
}
