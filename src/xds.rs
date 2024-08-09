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

use std::collections::HashMap;
use std::error::Error as StdErr;
use std::fmt;
use std::fmt::Formatter;
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use tracing::Level;

use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, trace, warn};

pub use client::*;
pub use metrics::*;
pub use types::*;
use xds::istio::security::Authorization as XdsAuthorization;
use xds::istio::workload::address::Type as XdsType;
use xds::istio::workload::Address as XdsAddress;
use xds::istio::workload::PortList;
use xds::istio::workload::Service as XdsService;
use xds::istio::workload::Workload as XdsWorkload;

use crate::cert_fetcher::{CertFetcher, NoCertFetcher};
use crate::config::ConfigSource;
use crate::rbac::Authorization;
use crate::state::service::{endpoint_uid, Endpoint, Service, ServiceStore};
use crate::state::workload::{network_addr, NamespacedHostname, Workload};
use crate::state::ProxyState;
use crate::strng::Strng;
use crate::{rbac, strng};
use crate::{tls, xds};

use self::service::discovery::v3::DeltaDiscoveryRequest;

mod client;
pub mod metrics;
mod types;

struct DisplayStatus<'a>(&'a tonic::Status);

impl<'a> fmt::Display for DisplayStatus<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let s = &self.0;
        write!(f, "status: {:?}, message: {:?}", s.code(), s.message())?;

        if s.message().to_string().contains("authentication failure") {
            write!(
                f,
                " (hint: check the control plane logs for more information)"
            )?;
        }
        if !s.details().is_empty() {
            if let Ok(st) = std::str::from_utf8(s.details()) {
                write!(f, ", details: {st}")?;
            }
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
    #[error("gRPC connection error connecting to {0}: {}", DisplayStatus(.1))]
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
        debug!("handling insert");

        // Clone services, so we can pass full ownership of the rest of XdsWorkload to build our Workload
        // object, which doesn't include Services.
        // In theory, I think we could avoid this if Workload::try_from returning the services.
        // let services = w.services.clone();
        // Convert the workload.
        let (workload, services): (Workload, HashMap<String, PortList>) = w.try_into()?;
        let workload = Arc::new(workload);

        // First, remove the entry entirely to make sure things are cleaned up properly.
        self.remove_for_insert(state, &workload.uid);

        // Prefetch the cert for the workload.
        self.cert_fetcher.prefetch_cert(&workload);

        // Lock and upstate the stores.
        let track = self
            .cert_fetcher
            .should_track_certificates_for_removal(&workload);
        state.workloads.insert(workload.clone(), track);
        insert_service_endpoints(&workload, &services, &mut state.services)?;

        Ok(())
    }

    pub fn remove(&self, state: &mut ProxyState, xds_name: &Strng) {
        self.remove_internal(state, xds_name, false);
    }

    fn remove_for_insert(&self, state: &mut ProxyState, xds_name: &Strng) {
        self.remove_internal(state, xds_name, true);
    }

    #[instrument(
        level = Level::TRACE,
        name="remove",
        skip_all,
        fields(name=%xds_name, for_insert=%for_insert),
    )]
    fn remove_internal(&self, state: &mut ProxyState, xds_name: &Strng, for_insert: bool) {
        // remove workload by UID; if xds_name is a service then this will no-op
        if let Some(prev) = state.workloads.remove(&strng::new(xds_name)) {
            // Also remove service endpoints for the workload.
            for wip in prev.workload_ips.iter() {
                let prev_addr = &network_addr(prev.network.clone(), *wip);
                state
                    .services
                    .remove_endpoint(&prev.uid, &endpoint_uid(&prev.uid, Some(prev_addr)));
            }
            if prev.workload_ips.is_empty() {
                state
                    .services
                    .remove_endpoint(&prev.uid, &endpoint_uid(&prev.uid, None));
            }

            // This is a real removal (not a removal before insertion), and nothing else references the cert
            // Clear it out
            if !for_insert
                && self
                    .cert_fetcher
                    .should_track_certificates_for_removal(&prev)
                && !state.workloads.has_identity(&prev.identity())
            {
                self.cert_fetcher.clear_cert(&prev.identity());
            }
            // We removed a workload, no reason to attempt to remove a service with the same name
            return;
        }

        let Ok(name) = NamespacedHostname::from_str(xds_name) else {
            // we don't have namespace/hostname xds primary key for service
            if !for_insert {
                warn!(
                    "tried to remove service but it did not have the expected namespace/hostname format",
                );
            }
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
        if state.services.remove(&name).is_none() && !for_insert {
            warn!("tried to remove service, but it was not found");
        }
    }

    pub fn insert_address(&self, state: &mut ProxyState, a: XdsAddress) -> anyhow::Result<()> {
        match a.r#type {
            Some(XdsType::Workload(w)) => self.insert_workload(state, w),
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
        let mut service = Service::try_from(&service)?;

        // If the service already exists, add existing endpoints into the new service.
        if let Some(prev) = state
            .services
            .get_by_namespaced_host(&service.namespaced_hostname())
        {
            for (wip, ep) in prev.endpoints.iter() {
                if service.should_include_endpoint(ep.status) {
                    service.endpoints.insert(wip.clone(), ep.clone());
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
        trace!("insert policy {}, {}", xds_name, serde_json::to_string(&rbac)?);
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
        let handle = |res: XdsUpdate<XdsWorkload>| {
            match res {
                XdsUpdate::Update(w) => self.updater.insert_workload(&mut state, w.resource)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.updater.remove(&mut state, &strng::new(name))
                }
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
    }
}

impl Handler<XdsAddress> for ProxyStateUpdater {
    fn handle(
        &self,
        updates: Box<&mut dyn Iterator<Item = XdsUpdate<XdsAddress>>>,
    ) -> Result<(), Vec<RejectedConfig>> {
        let mut state = self.state.write().unwrap();
        let handle = |res: XdsUpdate<XdsAddress>| {
            match res {
                XdsUpdate::Update(w) => self.updater.insert_address(&mut state, w.resource)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.updater.remove(&mut state, &strng::new(name))
                }
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
    }
}

fn insert_service_endpoints(
    workload: &Workload,
    services: &HashMap<String, PortList>,
    services_state: &mut ServiceStore,
) -> anyhow::Result<()> {
    for (namespaced_host, ports) in services {
        // Parse the namespaced hostname for the service.
        let namespaced_host = match namespaced_host.split_once('/') {
            Some((namespace, hostname)) => NamespacedHostname {
                namespace: namespace.into(),
                hostname: hostname.into(),
            },
            None => {
                return Err(anyhow::anyhow!(
                    "failed parsing service name: {namespaced_host}"
                ));
            }
        };

        // Create service endpoints for all the workload IPs.
        for wip in &workload.workload_ips {
            services_state.insert_endpoint(Endpoint {
                workload_uid: workload.uid.clone(),
                service: namespaced_host.clone(),
                address: Some(network_addr(workload.network.clone(), *wip)),
                port: ports.into(),
                status: workload.status,
            })
        }
        if workload.workload_ips.is_empty() {
            services_state.insert_endpoint(Endpoint {
                workload_uid: workload.uid.clone(),
                service: namespaced_host.clone(),
                address: None,
                port: ports.into(),
                status: workload.status,
            })
        }
    }
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
                XdsUpdate::Update(w) => {
                    self.updater.insert_authorization(&mut state, w.name, w.resource)?
                }
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
        state.workloads = Default::default();
        state.services = Default::default();
        // Policies have some channels, so we don't want to reset it entirely
        state.policies.clear_all_policies();
        let num_workloads = r.workloads.len();
        let num_policies = r.policies.len();
        for wl in r.workloads {
            trace!("inserting local workload {}", &wl.workload.uid);
            self.cert_fetcher.prefetch_cert(&wl.workload);
            let w = Arc::new(wl.workload);
            state.workloads.insert(
                w.clone(),
                self.cert_fetcher.should_track_certificates_for_removal(&w),
            );

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
