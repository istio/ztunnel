// Forked from https://github.com/olix0r/kubert/blob/main/kubert/src/admin.rs

use hyper::{Body, Request, Response};
use pprof::protos::Message;
use std::ops::Deref;
use std::sync::Mutex;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

#[cfg(feature = "gperftools")]
use gperftools::heap_profiler::HEAP_PROFILER;
#[cfg(feature = "gperftools")]
use gperftools::profiler::PROFILER;

#[cfg(feature = "gperftools")]
use tokio::fs::File;

#[cfg(feature = "gperftools")]
use tokio::io::AsyncReadExt;

use crate::workload::WorkloadInformation;
use tracing::info;

/// Supports configuring an admin server
pub struct Builder {
    addr: SocketAddr,
    workload_info: Arc<Mutex<WorkloadInformation>>,
    ready: Readiness,
}

pub struct Server {
    addr: SocketAddr,
    ready: Readiness,
    server: hyper::server::Builder<hyper::server::conn::AddrIncoming>,
    workload_info: Arc<Mutex<WorkloadInformation>>,
}

#[derive(Clone, Debug)]
pub struct Readiness(Arc<AtomicBool>);

impl Builder {
    pub fn new(addr: SocketAddr, f: Arc<Mutex<WorkloadInformation>>) -> Self {
        Self {
            addr,
            ready: Readiness(Arc::new(false.into())),
            workload_info: f,
        }
    }

    pub fn set_ready(self) -> Self {
        self.ready.set(true);
        self
    }

    pub fn bind(self) -> hyper::Result<Server> {
        let Self {
            addr,
            ready,
            workload_info,
        } = self;

        let server = hyper::server::Server::try_bind(&addr)?
            .http1_half_close(true)
            .http1_header_read_timeout(Duration::from_secs(2))
            .http1_max_buf_size(8 * 1024);

        Ok(Server {
            addr,
            ready,
            server,
            workload_info,
        })
    }
}

impl Server {
    pub fn spawn(self) {
        let ready = self.ready.clone();
        let workload_info = self.workload_info.clone();
        let server = self
            .server
            .serve(hyper::service::make_service_fn(move |_conn| {
                let ready = ready.clone();
                let workload_info = workload_info.clone();
                async move {
                    let workload_info = workload_info.clone();
                    Ok::<_, hyper::Error>(hyper::service::service_fn(move |req| {
                        let ready = ready.clone();
                        let workload_info = workload_info.clone();
                        async move {
                            match req.uri().path() {
                                "/healthz/ready" => {
                                    Ok::<_, hyper::Error>(handle_ready(&ready, req).await)
                                }
                                "/debug/pprof/profile" => {
                                    Ok::<_, hyper::Error>(handle_pprof(req).await)
                                }
                                "/debug/gprof/profile" => {
                                    Ok::<_, hyper::Error>(handle_gprof(req).await)
                                }
                                "/debug/gprof/heap" => {
                                    Ok::<_, hyper::Error>(handle_gprof_heap(req).await)
                                }
                                "/config_dump" => Ok::<_, hyper::Error>(
                                    handle_config_dump(workload_info, req).await,
                                ),
                                _ => Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(hyper::StatusCode::NOT_FOUND)
                                        .body(Body::default())
                                        .unwrap(),
                                ),
                            }
                        }
                    }))
                }
            }));

        tokio::spawn(async move {
            info!("Serving admin server at {}", self.addr);
            server.await
        });
    }
}

impl Readiness {
    pub fn set(&self, ready: bool) {
        self.0.store(ready, Ordering::Release);
    }
}

async fn handle_ready(Readiness(ready): &Readiness, req: Request<Body>) -> Response<Body> {
    match *req.method() {
        hyper::Method::GET | hyper::Method::HEAD => {
            if ready.load(Ordering::Acquire) {
                return Response::builder()
                    .status(hyper::StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "text/plain")
                    .body("ready\n".into())
                    .unwrap();
            }

            Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .header(hyper::header::CONTENT_TYPE, "text/plain")
                .body("not ready\n".into())
                .unwrap()
        }
        _ => Response::builder()
            .status(hyper::StatusCode::METHOD_NOT_ALLOWED)
            .body(Body::default())
            .unwrap(),
    }
}

async fn handle_pprof(_req: Request<Body>) -> Response<Body> {
    let guard = pprof::ProfilerGuardBuilder::default()
        .frequency(1000)
        // .blocklist(&["libc", "libgcc", "pthread", "vdso"])
        .build()
        .unwrap();

    tokio::time::sleep(Duration::from_secs(10)).await;
    match guard.report().build() {
        Ok(report) => {
            let profile = report.pprof().unwrap();

            let body = profile.write_to_bytes().unwrap();

            Response::builder()
                .status(hyper::StatusCode::OK)
                .body(body.into())
                .unwrap()
        }
        Err(err) => Response::builder()
            .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(format!("failed to build profile: {}", err).into())
            .unwrap(),
    }
}

async fn handle_config_dump(
    dump: Arc<Mutex<WorkloadInformation>>,
    _req: Request<Body>,
) -> Response<Body> {
    let wli = dump.lock().unwrap();

    let vec = serde_json::to_vec(wli.deref()).unwrap();
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body(vec.into())
        .unwrap()
}

#[cfg(feature = "gperftools")]
async fn handle_gprof(_req: Request<Body>) -> Response<Body> {
    const FILE_PATH: &str = "/tmp/profile.prof";
    PROFILER.lock().unwrap().start(FILE_PATH).unwrap();

    tokio::time::sleep(Duration::from_secs(10)).await;
    PROFILER.lock().unwrap().stop().unwrap();

    let mut buffer = Vec::new();
    File::open(FILE_PATH)
        .await
        .unwrap()
        .read_to_end(&mut buffer)
        .await
        .unwrap();
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body(buffer.into())
        .unwrap()
}

#[cfg(not(feature = "gperftools"))]
async fn handle_gprof(_req: Request<Body>) -> Response<Body> {
    Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .body("gperftools not enabled".into())
        .unwrap()
}

#[cfg(feature = "gperftools")]
async fn handle_gprof_heap(_req: Request<Body>) -> Response<Body> {
    const FILE_PATH: &str = "/tmp/profile.prof";
    HEAP_PROFILER.lock().unwrap().start(FILE_PATH).unwrap();

    tokio::time::sleep(Duration::from_secs(10)).await;
    HEAP_PROFILER.lock().unwrap().stop().unwrap();

    let mut buffer = Vec::new();
    File::open(FILE_PATH)
        .await
        .unwrap()
        .read_to_end(&mut buffer)
        .await
        .unwrap();
    Response::builder()
        .status(hyper::StatusCode::OK)
        .body(buffer.into())
        .unwrap()
}

#[cfg(not(feature = "gperftools"))]
async fn handle_gprof_heap(_req: Request<Body>) -> Response<Body> {
    Response::builder()
        .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
        .body("gperftools not enabled".into())
        .unwrap()
}
