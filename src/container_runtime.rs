use std::{collections::HashMap};

use hyper_util::rt::TokioIo;
use tokio::net::{UnixStream};
use tonic::{async_trait, transport::{Channel, Endpoint}};
use tower::service_fn;
use cri::runtime_service_client::RuntimeServiceClient;
use tonic::transport::{Uri};

use crate::{config::Config, identity::{PidClientTrait, WorkloadPid}, inpod::WorkloadUid};

pub mod cri {
    tonic::include_proto!("runtime.v1"); // matches package name in proto
}

pub struct ContainerRuntimeManager {
    runtime_client: RuntimeServiceClient<Channel>,
}

impl ContainerRuntimeManager {
    pub async fn new(cfg: &Config) -> Result<Self,std::io::Error> {
        let path = cfg.container_runtime_sock_path.clone().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Container runtime socket path not configured")
        })?;

        let channel = Self::uds_channel(path).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("Failed to create UDS channel: {}", e))
        })?;

        let client = RuntimeServiceClient::new(channel);

        Ok(ContainerRuntimeManager { runtime_client: client })
    }

    async fn uds_channel(path: String) -> Result<Channel, tonic::transport::Error> {
        let endpoint = Endpoint::try_from("http://[::1]:50051")?
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?))
                }
            }))
            .await?;
        Ok(endpoint)
    }

    pub async fn get_pids_for_pod(&self, pod_uid: String) -> Result<Vec<i32>, tonic::Status> {
        let mut client = self.runtime_client.clone();

        tracing::info!("Fetching PIDs for pod UID: {}", pod_uid);

        let mut map: HashMap<String,String> = std::collections::HashMap::new();
        map.insert("io.kubernetes.pod.uid".to_string(), pod_uid.clone());

        let pod_filter = cri::PodSandboxFilter {
            label_selector: map,
            ..Default::default()
        };

        tracing::debug!("Listing pod sandboxes with filter: {:?}", pod_filter);
        
        // 1. Find the sandbox
        let sandboxes = match client
            .list_pod_sandbox(cri::ListPodSandboxRequest { filter: Some(pod_filter) })
            .await {
            Ok(response) => response.into_inner().items,
            Err(e) => {
                tracing::error!("Failed to list pod sandboxes: {}", e);
                return Err(e);
            }
        };

        tracing::debug!("Found {} sandboxes for pod UID: {}", sandboxes.len(), pod_uid);

        let sandbox = sandboxes.first().ok_or_else(|| {
            tracing::error!("No sandbox found for pod UID: {}", pod_uid);
            tonic::Status::not_found(format!("No sandbox found for pod UID: {}", pod_uid))
        })?;

        let sandbox_id = sandbox.id.clone();
        tracing::info!("Found sandbox for pod UID: {}, sandbox_id: {}", pod_uid, sandbox_id);

        // 2. List containers in that sandbox
        let containers = match client
            .list_containers(cri::ListContainersRequest {
                filter: Some(cri::ContainerFilter {
                    pod_sandbox_id: sandbox_id.clone(),
                    ..Default::default()
                }),
            })
            .await {
            Ok(response) => response.into_inner().containers,
            Err(e) => {
                tracing::error!("Failed to list containers in sandbox {}: {}", sandbox_id, e);
                return Err(e);
            }
        };

        tracing::debug!("Found {} containers in sandbox {}", containers.len(), sandbox_id);

        let mut pids = Vec::new();

        // 3. Query container status → get PID
        for c in containers {
            tracing::debug!("Processing container: {}", c.id);
            let status = match client
                .container_status(cri::ContainerStatusRequest {
                    container_id: c.id.clone(),
                    verbose: true,
                })
                .await {
                Ok(response) => response.into_inner(),
                Err(e) => {
                    tracing::error!("Failed to get status for container {}: {}", c.id, e);
                    return Err(e);
                }
            };

            let info = status.info.get("info");

            //info is json string, parse it to get the pid field
            #[derive(serde::Deserialize)]
            struct ContainerInfo {
                pid: i32,
            }
            let info_json = info.ok_or_else(|| {
                tracing::error!("Container info not found for container: {}, available keys: {:?}", c.id, status.info.keys().collect::<Vec<_>>());
                tonic::Status::internal(format!("Container info not found for container: {}", c.id))
            })?;

            let pid: ContainerInfo = serde_json::from_str(&info_json).map_err(|e| {
                tracing::error!("Failed to parse container info for container {}: {}", c.id, e);
                tonic::Status::internal(format!("Failed to parse container info for container {}: {}", c.id, e))
            })?;

            tracing::debug!("Found PID {} for container {}", pid.pid, c.id);
            pids.push(pid.pid);
        }

        tracing::info!("Successfully collected {} PIDs for pod UID: {}", pids.len(), pod_uid);
        Ok(pids)
    }
}

#[async_trait]
impl PidClientTrait for ContainerRuntimeManager {
    async fn fetch_pid(&self, uid: &WorkloadUid) -> Result<WorkloadPid, std::io::Error> {
        let pids = self.get_pids_for_pod(uid.clone().into_string()).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("CRI error: {}", e))
        })?;

        let pid = pids.get(0).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "No PID found for pod")
        })?;

        Ok(WorkloadPid::new(*pid))
    }
}