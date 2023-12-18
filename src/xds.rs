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

use tokio::sync::mpsc;
use tracing::{debug, info, instrument, trace, warn};

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
use crate::rbac;
use crate::rbac::Authorization;
use crate::state::service::{endpoint_uid, Endpoint, Service};
use crate::state::workload::{network_addr, HealthStatus, NamespacedHostname, Workload};
use crate::state::ProxyState;
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
        if !s.details().is_empty() {
            if let Ok(st) = std::str::from_utf8(s.details()) {
                write!(f, ", details: {st}")?;
            }
        }
        if let Some(src) = s.source().and_then(|s| s.source()) {
            write!(f, ", source: {src}")?;
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("gRPC error {}", DisplayStatus(.0))]
    GrpcStatus(#[from] tonic::Status),
    #[error("gRPC connection error:{}", DisplayStatus(.0))]
    Connection(#[source] tonic::Status),
    /// Attempted to send on a MPSC channel which has been canceled
    #[error(transparent)]
    RequestFailure(#[from] Box<mpsc::error::SendError<DeltaDiscoveryRequest>>),
    #[error("failed to send on demand resource")]
    OnDemandSend(),
    #[error("TLS Error: {0}")]
    TLSError(#[from] tls::Error),
}

/// Updates the [ProxyState] from XDS.
#[derive(Clone)]
pub struct ProxyStateUpdater {
    state: Arc<RwLock<ProxyState>>,
    cert_fetcher: Arc<dyn CertFetcher>,
}

impl ProxyStateUpdater {
    /// Creates a new updater for the given stores. Will prefetch certs when workloads are updated.
    pub fn new(state: Arc<RwLock<ProxyState>>, cert_fetcher: Arc<dyn CertFetcher>) -> Self {
        Self {
            state,
            cert_fetcher,
        }
    }

    /// Creates a new updater that does not prefetch workload certs.
    pub fn new_no_fetch(state: Arc<RwLock<ProxyState>>) -> Self {
        Self::new(state, Arc::new(NoCertFetcher()))
    }

    pub fn insert_workload(&self, w: XdsWorkload) -> anyhow::Result<()> {
        debug!("handling insert {}", w.uid);

        // Convert the workload.
        let workload = Workload::try_from(&w)?;

        // First, remove the entry entirely to make sure things are cleaned up properly.
        self.remove(&w.uid);

        // Unhealthy workloads are always inserted, as we may get or receive traffic to them.
        // But we shouldn't include them in load balancing we do to Services.
        let mut endpoints = if workload.status == HealthStatus::Healthy {
            service_endpoints(&workload, &w.services)?
        } else {
            Vec::new()
        };

        // Prefetch the cert for the workload.
        self.cert_fetcher.prefetch_cert(&workload);

        // Lock and upstate the stores.
        let mut state = self.state.write().unwrap();
        state.workloads.insert(workload)?;
        while let Some(endpoint) = endpoints.pop() {
            state.services.insert_endpoint(endpoint);
        }

        Ok(())
    }

    pub fn remove(&self, xds_name: &String) {
        let mut state = self.state.write().unwrap();

        // remove workload by UID; if xds_name is a service then this will no-op
        if let Some(prev) = state.workloads.remove(xds_name) {
            // Also remove service endpoints for the workload.
            for wip in prev.workload_ips.iter() {
                let prev_addr = &network_addr(&prev.network, *wip);
                state
                    .services
                    .remove_endpoint(&prev.uid, &endpoint_uid(&prev.uid, Some(prev_addr)));
            }
            if prev.workload_ips.is_empty() {
                state
                    .services
                    .remove_endpoint(&prev.uid, &endpoint_uid(&prev.uid, None));
            }

            // We removed a workload, no reason to attempt to remove a service with the same name
            return;
        }

        let Ok(name) = NamespacedHostname::from_str(xds_name) else {
            // we don't have namespace/hostname xds primary key for service
            warn!(
                "tried to remove service keyed by {} but it did not have the expected namespace/hostname format",
                xds_name
            );
            return;
        };

        if name.hostname.contains('/') {
            // avoid trying to delete obvious workload UIDs as a service,
            // which can result in noisy logs when new workloads are added
            // (we remove then add workloads on initial update)
            //
            // we can make this assumption because namespaces and hostnames cannot have `/` in them
            trace!(
                "xds_name {} is obviously not a service, not attempting to delete as such",
                xds_name
            );
            return;
        }
        if state.services.remove(&name).is_none() {
            warn!("tried to remove service keyed by {name}, but it was not found");
        }
    }

    pub fn insert_address(&self, a: XdsAddress) -> anyhow::Result<()> {
        match a.r#type {
            Some(XdsType::Workload(w)) => self.insert_workload(w),
            Some(XdsType::Service(s)) => self.insert_service(s),
            _ => Err(anyhow::anyhow!("unknown address type")),
        }
    }

    pub fn insert_service(&self, service: XdsService) -> anyhow::Result<()> {
        let mut service = Service::try_from(&service)?;

        // Lock the store.
        let mut state = self.state.write().unwrap();

        // If the service already exists, add existing endpoints into the new service.
        if let Some(prev) = state
            .services
            .get_by_namespaced_host(&service.namespaced_hostname())
        {
            for (wip, ep) in prev.endpoints.iter() {
                service.endpoints.insert(wip.clone(), ep.clone());
            }
        }

        state.services.insert(service);
        Ok(())
    }

    pub fn insert_authorization(&self, r: XdsAuthorization) -> anyhow::Result<()> {
        info!("handling RBAC update {}", r.name);

        let rbac = rbac::Authorization::try_from(&r)?;
        trace!("insert policy {}", serde_json::to_string(&rbac)?);
        let mut state = self.state.write().unwrap();
        state.policies.insert(rbac);
        Ok(())
    }

    pub fn remove_authorization(&self, name: String) {
        info!("handling RBAC delete {}", name);
        let mut state = self.state.write().unwrap();
        state.policies.remove(name);
    }
}

impl Handler<XdsWorkload> for ProxyStateUpdater {
    fn handle(&self, updates: Vec<XdsUpdate<XdsWorkload>>) -> Result<(), Vec<RejectedConfig>> {
        let handle = |res: XdsUpdate<XdsWorkload>| {
            match res {
                XdsUpdate::Update(w) => self.insert_workload(w.resource)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.remove(&name)
                }
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
    }
}

impl Handler<XdsAddress> for ProxyStateUpdater {
    fn handle(&self, updates: Vec<XdsUpdate<XdsAddress>>) -> Result<(), Vec<RejectedConfig>> {
        let handle = |res: XdsUpdate<XdsAddress>| {
            match res {
                XdsUpdate::Update(w) => self.insert_address(w.resource)?,
                XdsUpdate::Remove(name) => {
                    debug!("handling delete {}", name);
                    self.remove(&name)
                }
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
    }
}

fn service_endpoints(
    workload: &Workload,
    services: &HashMap<String, PortList>,
) -> anyhow::Result<Vec<Endpoint>> {
    let mut out = Vec::new();
    for (namespaced_host, ports) in services {
        // Parse the namespaced hostname for the service.
        let namespaced_host = match namespaced_host.split_once('/') {
            Some((namespace, hostname)) => NamespacedHostname {
                namespace: namespace.to_string(),
                hostname: hostname.to_string(),
            },
            None => {
                return Err(anyhow::anyhow!(
                    "failed parsing service name: {namespaced_host}"
                ));
            }
        };

        // Create service endpoints for all the workload IPs.
        for wip in &workload.workload_ips {
            out.push(Endpoint {
                workload_uid: workload.uid.clone(),
                service: namespaced_host.clone(),
                address: Some(network_addr(&workload.network, *wip)),
                port: ports.into(),
            })
        }
        if workload.workload_ips.is_empty() {
            out.push(Endpoint {
                workload_uid: workload.uid.clone(),
                service: namespaced_host.clone(),
                address: None,
                port: ports.into(),
            })
        }
    }
    Ok(out)
}

impl Handler<XdsAuthorization> for ProxyStateUpdater {
    fn no_on_demand(&self) -> bool {
        true
    }

    fn handle(&self, updates: Vec<XdsUpdate<XdsAuthorization>>) -> Result<(), Vec<RejectedConfig>> {
        let handle = |res: XdsUpdate<XdsAuthorization>| {
            match res {
                XdsUpdate::Update(w) => self.insert_authorization(w.resource)?,
                XdsUpdate::Remove(name) => self.remove_authorization(name),
            }
            Ok(())
        };
        handle_single_resource(updates, handle)
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
        // Currently, we just load the file once. In the future, we could dynamically reload.
        let data = self.cfg.read_to_string().await?;
        debug!("local config: {data}");
        let r: LocalConfig = serde_yaml::from_str(&data)?;
        let mut state = self.state.write().unwrap();
        let num_workloads = r.workloads.len();
        let num_policies = r.policies.len();
        for wl in r.workloads {
            trace!("inserting local workload {}", &wl.workload.uid);
            state.workloads.insert(wl.workload.clone())?;
            self.cert_fetcher.prefetch_cert(&wl.workload);

            let services: HashMap<String, PortList> = wl
                .services
                .into_iter()
                .map(|(k, v)| (k, PortList::from(v)))
                .collect();

            let mut endpoints = service_endpoints(&wl.workload, &services)?;
            while let Some(ep) = endpoints.pop() {
                state.services.insert_endpoint(ep)
            }
        }
        for rbac in r.policies {
            state.policies.insert(rbac);
        }
        for svc in r.services {
            state.services.insert(svc);
        }
        info!(%num_workloads, %num_policies, "local config initialized");
        Ok(())
    }
}
