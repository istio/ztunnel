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

use cri::runtime_service_client::RuntimeServiceClient;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::Uri;
use tonic::{
    async_trait,
    transport::{Channel, Endpoint},
};
use tower::service_fn;

use crate::{
    config::Config,
    container_runtime::cri::{ContainerStatusRequest, ListContainersRequest},
    identity::{PidClientTrait, WorkloadPid},
    inpod::WorkloadUid,
};

pub mod cri {
    tonic::include_proto!("runtime.v1"); // matches package name in proto
}

pub struct ContainerRuntimeManager {
    runtime_client: RuntimeServiceClient<Channel>,
}

impl ContainerRuntimeManager {
    pub async fn new(cfg: &Config) -> Result<Self, std::io::Error> {
        let path = cfg.container_runtime_sock_path.clone();

        let channel = Self::uds_channel(path)
            .await
            .map_err(|e| std::io::Error::other(format!("Failed to create UDS channel: {}", e)))?;

        let client = RuntimeServiceClient::new(channel);

        Ok(ContainerRuntimeManager {
            runtime_client: client,
        })
    }

    pub fn new_with_client(client: RuntimeServiceClient<Channel>) -> Self {
        ContainerRuntimeManager {
            runtime_client: client,
        }
    }

    async fn uds_channel(path: String) -> Result<Channel, tonic::transport::Error> {
        let endpoint =
            Endpoint::try_from("http://[::1]:50051")?
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

        let mut map: HashMap<String, String> = std::collections::HashMap::new();
        map.insert("io.kubernetes.pod.uid".to_string(), pod_uid.clone());


        let ready_state = cri::PodSandboxStateValue{
            state: 0, // PodSandboxState::SandboxReady
        };

        let pod_filter = cri::PodSandboxFilter {
            label_selector: map,
            state: Some(ready_state),
            ..Default::default()
        };

        tracing::debug!("Listing pod sandboxes with filter: {:?}", pod_filter);

        // 1. Find the sandbox
        let sandboxes = match client
            .list_pod_sandbox(cri::ListPodSandboxRequest {
                filter: Some(pod_filter),
            })
            .await
        {
            Ok(response) => response.into_inner().items,
            Err(e) => {
                tracing::error!("Failed to list pod sandboxes: {}", e);
                return Err(e);
            }
        };

        tracing::debug!(
            "Found {} sandboxes for pod UID: {}",
            sandboxes.len(),
            pod_uid
        );

        let sandbox = sandboxes.first().ok_or_else(|| {
            tracing::error!("No sandbox found for pod UID: {}", pod_uid);
            tonic::Status::not_found(format!("No sandbox found for pod UID: {}", pod_uid))
        })?;

        let sandbox_id = sandbox.id.clone();
        tracing::info!(
            "Found sandbox for pod UID: {}, sandbox_id: {}",
            pod_uid,
            sandbox_id
        );

        let container_ready = cri::ContainerStateValue {
            state: 1, // ContainerState::ContainerRunning
        };

        // 2. List containers in that sandbox
        let containers = match client
            .list_containers(ListContainersRequest {
                filter: Some(cri::ContainerFilter {
                    pod_sandbox_id: sandbox_id.clone(),
                    state: Some(container_ready),
                    ..Default::default()
                }),
            })
            .await
        {
            Ok(response) => response.into_inner().containers,
            Err(e) => {
                tracing::error!("Failed to list containers in sandbox {}: {}", sandbox_id, e);
                return Err(e);
            }
        };

        tracing::debug!(
            "Found {} containers in sandbox {}",
            containers.len(),
            sandbox_id
        );

        let mut pids = Vec::new();

        // 3. Query container status → get PID
        for c in containers {
            tracing::debug!("Processing container: {}", c.id);
            let status = match client
                .container_status(ContainerStatusRequest {
                    container_id: c.id.clone(),
                    verbose: true,
                })
                .await
            {
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
                tracing::error!(
                    "Container info not found for container: {}, available keys: {:?}",
                    c.id,
                    status.info.keys().collect::<Vec<_>>()
                );
                tonic::Status::internal(format!("Container info not found for container: {}", c.id))
            })?;

            let pid: ContainerInfo = serde_json::from_str(info_json).map_err(|e| {
                tracing::error!(
                    "Failed to parse container info for container {}: {}",
                    c.id,
                    e
                );
                tonic::Status::internal(format!(
                    "Failed to parse container info for container {}: {}",
                    c.id, e
                ))
            })?;

            tracing::debug!("Found PID {} for container {}", pid.pid, c.id);
            pids.push(pid.pid);
        }

        if pids.is_empty() {
            tracing::error!("No running containers found for pod UID: {}", pod_uid);
            return Err(tonic::Status::not_found(format!(
                "No running containers found for pod UID: {}",
                pod_uid
            )));
        }

        tracing::info!(
            "Successfully collected {} PIDs for pod UID: {}",
            pids.len(),
            pod_uid
        );
        Ok(pids)
    }
}

#[async_trait]
impl PidClientTrait for ContainerRuntimeManager {
    async fn fetch_pid(&self, uid: &WorkloadUid) -> Result<WorkloadPid, std::io::Error> {
        let pids = self
            .get_pids_for_pod(uid.clone().into_string())
            .await
            .map_err(|e| std::io::Error::other(format!("CRI error: {}", e)))?;

        let pid = pids.first().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "No PID found for pod")
        })?;

        Ok(WorkloadPid::new(*pid))
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use http::Uri;
    use hyper_util::rt::TokioIo;
    use tokio::{
        net::{UnixListener, UnixStream},
        sync::Mutex,
    };
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::{
        Response,
        transport::{Endpoint, Server},
    };
    use tower::service_fn;

    use crate::container_runtime::{
        ContainerRuntimeManager,
        cri::{
            self, Container, ContainerStatusRequest, ContainerStatusResponse,
            ListContainersRequest, ListContainersResponse, PodSandbox, PodSandboxStatusRequest,
            PodSandboxStatusResponse, VersionRequest, VersionResponse,
            runtime_service_client::RuntimeServiceClient,
            runtime_service_server::{RuntimeService, RuntimeServiceServer},
        },
    };

    #[derive(Clone, Default)]
    struct MockRuntimeService {
        // You can put shared state here to control responses from your tests
        containers: Arc<Mutex<Vec<Container>>>,
        sandboxes: Arc<Mutex<Vec<PodSandbox>>>,
        container_statuses: Arc<Mutex<HashMap<String, ContainerStatusResponse>>>,
    }

    #[tonic::async_trait]
    impl RuntimeService for MockRuntimeService {
        async fn version(
            &self,
            _request: tonic::Request<VersionRequest>,
        ) -> std::result::Result<tonic::Response<VersionResponse>, tonic::Status> {
            Ok(tonic::Response::new(VersionResponse::default()))
        }

        async fn pod_sandbox_status(
            &self,
            _request: tonic::Request<PodSandboxStatusRequest>,
        ) -> std::result::Result<tonic::Response<PodSandboxStatusResponse>, tonic::Status> {
            Ok(tonic::Response::new(PodSandboxStatusResponse::default()))
        }

        async fn list_pod_sandbox(
            &self,
            request: tonic::Request<cri::ListPodSandboxRequest>,
        ) -> std::result::Result<tonic::Response<cri::ListPodSandboxResponse>, tonic::Status>
        {
            let sandboxes = self.sandboxes.lock().await.clone();
            let req = request.into_inner();

            let filtered = if let Some(filter) = req.filter {
                sandboxes
                    .into_iter()
                    .filter(|sandbox| {
                        // Filter by label selector
                        let labels_match = filter.label_selector.iter().all(|(key, expected_value)| {
                            sandbox
                                .labels
                                .get(key)
                                .map_or(false, |actual_value| actual_value == expected_value)
                        });
                        // Filter by state if specified
                        let state_match = filter.state.as_ref().map_or(true, |state_filter| {
                            sandbox.state == state_filter.state
                        });
                        labels_match && state_match
                    })
                    .collect()
            } else {
                sandboxes
            };

            Ok(Response::new(cri::ListPodSandboxResponse {
                items: filtered,
            }))
        }

        async fn list_containers(
            &self,
            request: tonic::Request<ListContainersRequest>,
        ) -> std::result::Result<tonic::Response<ListContainersResponse>, tonic::Status> {
            let containers = self.containers.lock().await.clone();
            let req = request.into_inner();

            let filtered = if let Some(filter) = req.filter {
                containers
                    .into_iter()
                    .filter(|container| {
                        // Filter by sandbox ID if specified
                        let sandbox_match = if filter.pod_sandbox_id.is_empty() {
                            true
                        } else {
                            container.pod_sandbox_id == filter.pod_sandbox_id
                        };
                        // Filter by state if specified
                        let state_match = filter.state.as_ref().map_or(true, |state_filter| {
                            container.state == state_filter.state
                        });
                        sandbox_match && state_match
                    })
                    .collect()
            } else {
                containers
            };

            Ok(Response::new(ListContainersResponse { containers: filtered }))
        }

        async fn container_status(
            &self,
            request: tonic::Request<ContainerStatusRequest>,
        ) -> std::result::Result<tonic::Response<ContainerStatusResponse>, tonic::Status> {
            let container_status = self.container_statuses.lock().await;

            let container_id = request.into_inner().container_id.clone();

            let resp = container_status.get(&container_id).unwrap();

            Ok(tonic::Response::new(resp.clone()))
        }

        async fn status(
            &self,
            _request: tonic::Request<cri::StatusRequest>,
        ) -> std::result::Result<tonic::Response<cri::StatusResponse>, tonic::Status> {
            Ok(tonic::Response::new(cri::StatusResponse::default()))
        }
    }

    #[tokio::test]
    async fn test_client_uses_mock_cri_over_uds() {
        // 1. Prepare mock service and data
        let mock = MockRuntimeService::default();
        {
            let mut lock = mock.containers.lock().await;
            lock.push(Container {
                id: "fake-id-123".into(),
                pod_sandbox_id: "fake-sandbox-123".into(),
                state: 1, // CONTAINER_RUNNING
                ..Default::default()
            });

            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "fake-sandbox-123".into(),
                labels: {
                    let mut m = HashMap::new();
                    m.insert("io.kubernetes.pod.uid".into(), "fake-uid-456".into());
                    m
                },
                ..Default::default()
            });

            let mut lock = mock.container_statuses.lock().await;
            lock.insert(
                "fake-id-123".into(),
                cri::ContainerStatusResponse {
                    info: {
                        let mut m = HashMap::new();
                        m.insert("info".into(), r#"{"pid": 4321}"#.into());
                        m
                    },
                    ..Default::default()
                },
            );
            lock.insert(
                "fake-id-321".into(),
                cri::ContainerStatusResponse {
                    info: {
                        let mut m = HashMap::new();
                        m.insert("info".into(), r#"{"pid": 1234}"#.into());
                        m
                    },
                    ..Default::default()
                },
            );
        }

        // 2. Create a temporary Unix socket path
        let socket_path = "/tmp/test-cri-runtime.sock";
        // Ensure old socket is gone if it exists
        let _ = std::fs::remove_file(socket_path);

        // 3. Bind UnixListener
        let uds = UnixListener::bind(socket_path).expect("failed to bind UDS");
        let incoming = UnixListenerStream::new(uds);

        // 4. Start gRPC server over UDS
        let svc = RuntimeServiceServer::new(mock.clone());
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming)
                .await
                .expect("server failed");
        });

        // 5. Build a client Channel that dials the same UDS
        let socket_path_str = socket_path.to_string();
        let endpoint = Endpoint::try_from("http://[::]:50051").unwrap();
        let channel = endpoint
            .connect_with_connector(service_fn(move |_uri: Uri| {
                let path = socket_path_str.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .expect("failed to connect to mock UDS server");

        let client = RuntimeServiceClient::new(channel);

        // 6. Call the real client method against the mock server
        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let pids_result = cri_manager
            .get_pids_for_pod("non-existent-pod-uid".to_string())
            .await;
        assert!(pids_result.is_err()); // Since our mock returns no sandboxes matching the UID, this should error

        let pids_result = cri_manager
            .get_pids_for_pod("fake-uid-456".to_string())
            .await;
        assert!(pids_result.is_ok());
        assert_eq!(pids_result.unwrap(), vec![4321]);

        // 7. Clean up
        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    /// Helper to create a mock server and client for testing
    async fn setup_mock_server(
        mock: MockRuntimeService,
        socket_path: &str,
    ) -> (RuntimeServiceClient<tonic::transport::Channel>, tokio::task::JoinHandle<()>) {
        let _ = std::fs::remove_file(socket_path);
        let uds = UnixListener::bind(socket_path).expect("failed to bind UDS");
        let incoming = UnixListenerStream::new(uds);

        let svc = RuntimeServiceServer::new(mock);
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(svc)
                .serve_with_incoming(incoming)
                .await
                .expect("server failed");
        });

        let socket_path_str = socket_path.to_string();
        let endpoint = Endpoint::try_from("http://[::]:50051").unwrap();
        let channel = endpoint
            .connect_with_connector(service_fn(move |_uri: Uri| {
                let path = socket_path_str.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .expect("failed to connect to mock UDS server");

        (RuntimeServiceClient::new(channel), server_handle)
    }

    #[tokio::test]
    async fn test_sandbox_not_ready_returns_not_found() {
        // Test that a sandbox in NotReady state (state=1) is filtered out
        let mock = MockRuntimeService::default();
        {
            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "not-ready-sandbox".into(),
                state: 1, // SANDBOX_NOTREADY
                labels: {
                    let mut m = HashMap::new();
                    m.insert("io.kubernetes.pod.uid".into(), "not-ready-pod-uid".into());
                    m
                },
                ..Default::default()
            });
        }

        let socket_path = "/tmp/test-cri-sandbox-not-ready.sock";
        let (client, server_handle) = setup_mock_server(mock, socket_path).await;

        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let result = cri_manager
            .get_pids_for_pod("not-ready-pod-uid".to_string())
            .await;

        // Should return not found because sandbox is not in Ready state
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);

        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn test_exited_containers_filtered_out() {
        // Test that containers not in Running state are filtered out
        let mock = MockRuntimeService::default();
        {
            // Add a ready sandbox
            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "ready-sandbox-123".into(),
                state: 0, // SANDBOX_READY
                labels: {
                    let mut m = HashMap::new();
                    m.insert("io.kubernetes.pod.uid".into(), "pod-with-exited-containers".into());
                    m
                },
                ..Default::default()
            });

            // Add containers that are NOT running (exited)
            let mut lock = mock.containers.lock().await;
            lock.push(Container {
                id: "exited-container-1".into(),
                pod_sandbox_id: "ready-sandbox-123".into(),
                state: 2, // CONTAINER_EXITED
                ..Default::default()
            });
            lock.push(Container {
                id: "exited-container-2".into(),
                pod_sandbox_id: "ready-sandbox-123".into(),
                state: 0, // CONTAINER_CREATED
                ..Default::default()
            });

            // Add container statuses (should not be queried since containers are filtered)
            let mut lock = mock.container_statuses.lock().await;
            lock.insert(
                "exited-container-1".into(),
                cri::ContainerStatusResponse {
                    info: {
                        let mut m = HashMap::new();
                        m.insert("info".into(), r#"{"pid": 0}"#.into());
                        m
                    },
                    ..Default::default()
                },
            );
        }

        let socket_path = "/tmp/test-cri-exited-containers.sock";
        let (client, server_handle) = setup_mock_server(mock, socket_path).await;

        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let result = cri_manager
            .get_pids_for_pod("pod-with-exited-containers".to_string())
            .await;

        // Should return NotFound error since no containers are running
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert!(err.message().contains("No running containers found"));

        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }

    #[tokio::test]
    async fn test_mixed_container_states_returns_only_running() {
        // Test that only running containers are returned when there's a mix
        let mock = MockRuntimeService::default();
        {
            let mut lock = mock.sandboxes.lock().await;
            lock.push(cri::PodSandbox {
                id: "mixed-sandbox".into(),
                state: 0, // SANDBOX_READY
                labels: {
                    let mut m = HashMap::new();
                    m.insert("io.kubernetes.pod.uid".into(), "mixed-state-pod".into());
                    m
                },
                ..Default::default()
            });

            let mut lock = mock.containers.lock().await;
            // Running container
            lock.push(Container {
                id: "running-container".into(),
                pod_sandbox_id: "mixed-sandbox".into(),
                state: 1, // CONTAINER_RUNNING
                ..Default::default()
            });
            // Exited container
            lock.push(Container {
                id: "exited-container".into(),
                pod_sandbox_id: "mixed-sandbox".into(),
                state: 2, // CONTAINER_EXITED
                ..Default::default()
            });
            // Created but not started container
            lock.push(Container {
                id: "created-container".into(),
                pod_sandbox_id: "mixed-sandbox".into(),
                state: 0, // CONTAINER_CREATED
                ..Default::default()
            });

            let mut lock = mock.container_statuses.lock().await;
            lock.insert(
                "running-container".into(),
                cri::ContainerStatusResponse {
                    info: {
                        let mut m = HashMap::new();
                        m.insert("info".into(), r#"{"pid": 9999}"#.into());
                        m
                    },
                    ..Default::default()
                },
            );
            // Exited container would have PID 0
            lock.insert(
                "exited-container".into(),
                cri::ContainerStatusResponse {
                    info: {
                        let mut m = HashMap::new();
                        m.insert("info".into(), r#"{"pid": 0}"#.into());
                        m
                    },
                    ..Default::default()
                },
            );
        }

        let socket_path = "/tmp/test-cri-mixed-states.sock";
        let (client, server_handle) = setup_mock_server(mock, socket_path).await;

        let cri_manager = ContainerRuntimeManager::new_with_client(client);
        let result = cri_manager
            .get_pids_for_pod("mixed-state-pod".to_string())
            .await;

        // Should only return the PID of the running container
        assert!(result.is_ok());
        let pids = result.unwrap();
        assert_eq!(pids, vec![9999]);

        server_handle.abort();
        let _ = std::fs::remove_file(socket_path);
    }
}
