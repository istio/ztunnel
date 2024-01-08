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

use crate::readiness;
use drain::Watch;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tracing::{debug, error, info, warn};

use super::statemanager::WorkloadProxyManagerState;
use super::Error;

use super::protocol::WorkloadStreamProcessor;

const RETRY_DURATION: Duration = Duration::from_secs(5);

struct WorkloadProxyNetworkHandler {
    uds: PathBuf,
}

struct WorkloadProxyReadinessHandler {
    ready: readiness::Ready,
    // Manually drop as we don't want to mark ready if we are dropped.
    // This can happen when the server drains.
    block_ready: Option<std::mem::ManuallyDrop<readiness::BlockReady>>,
}

pub struct WorkloadProxyManager {
    state: super::statemanager::WorkloadProxyManagerState,
    networking: WorkloadProxyNetworkHandler,
    // readiness - we are only ready when we are connected. if we get disconnected, we become not ready.
    readiness: WorkloadProxyReadinessHandler,
}

struct WorkloadProxyManagerProcessor<'a> {
    state: &'a mut super::statemanager::WorkloadProxyManagerState,
    readiness: &'a mut WorkloadProxyReadinessHandler,

    next_pending_retry: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
}

impl WorkloadProxyReadinessHandler {
    fn new(ready: readiness::Ready) -> Self {
        let mut r = Self {
            ready,
            block_ready: None,
        };
        r.not_ready();
        r
    }
    fn mark_ready(&mut self) {
        // take the block ready out of the ManuallyDrop, and drop it.
        if self.block_ready.is_some() {
            debug!("workload proxy manager is ready");
            let block_ready: Option<readiness::BlockReady> = self
                .block_ready
                .take()
                .map(std::mem::ManuallyDrop::into_inner);

            std::mem::drop(block_ready);
        }
    }

    fn not_ready(&mut self) {
        if self.block_ready.is_none() {
            self.block_ready = Some(std::mem::ManuallyDrop::new(
                self.ready.register_task("workload proxy manager"),
            ));
        }
    }
}

impl WorkloadProxyNetworkHandler {
    fn new(uds: PathBuf) -> std::io::Result<Self> {
        Ok(Self { uds })
    }

    async fn connect(&self) -> UnixStream {
        const MAX_BACKOFF: Duration = Duration::from_secs(15);
        let mut backoff = Duration::from_millis(10);

        debug!("connecting to server: {:?}", self.uds);

        loop {
            match super::packet::connect(&self.uds).await {
                Err(e) => {
                    backoff = std::cmp::min(MAX_BACKOFF, backoff * 2);
                    warn!(
                        "failed to connect to server: {:?}. retrying in {:?}",
                        e, backoff
                    );
                    tokio::time::sleep(backoff).await;
                    continue;
                }

                Ok(conn) => {
                    return conn;
                }
            };
        }
    }
}

impl WorkloadProxyManager {
    pub fn verify_syscalls() -> anyhow::Result<()> {
        // verify that we are capable, so we can fail early if not.
        super::netns::InpodNetns::capable()
            .map_err(|e| anyhow::anyhow!("failed to set netns: {:?}", e))?;
        // verify that we can set the socket mark, so we can fail early if not.
        Self::verify_set_mark().map_err(|e| anyhow::anyhow!("failed to set socket mark: {:?}", e))
    }

    fn verify_set_mark() -> anyhow::Result<()> {
        let socket = tokio::net::TcpSocket::new_v4()?;
        crate::socket::set_mark(&socket, 1337).map_err(|e| anyhow::anyhow!("failed to set mark on socket. make sure ztunnel has CAP_NET_RAW, CAP_NET_ADMIN. error: {:?}", e))
    }

    pub fn new(
        uds: PathBuf,
        state: WorkloadProxyManagerState,
        ready: readiness::Ready,
    ) -> std::io::Result<WorkloadProxyManager> {
        let networking = WorkloadProxyNetworkHandler::new(uds)?;

        let mgr = WorkloadProxyManager {
            state,
            networking,
            readiness: WorkloadProxyReadinessHandler::new(ready),
        };
        Ok(mgr)
    }

    pub async fn run(mut self, drain: Watch) -> Result<(), anyhow::Error> {
        self.run_internal(drain).await;

        // we broke the loop, this can only happen when drain was signaled. drain our proxies.
        debug!("workload proxy manager waiting for proxies to drain");
        self.state.drain().await;
        debug!("workload proxy manager proxies drained");
        Ok(())
    }

    async fn run_internal(&mut self, drain: Watch) {
        // for now just drop block_ready, until we support knowing that our state is in sync.
        debug!("workload proxy manager is running");
        // hold the  release shutdown until we are done with `state.drain` below.
        let _rs = loop {
            // Accept a connection
            let stream = tokio::select! {
                biased; // check the drain first
                rs = drain.clone().signaled() => {
                    info!("drain requested");
                    break rs;
                }
                res =  self.networking.connect() => res,
            };

            info!("handling new stream");

            // TODO: add metrics?

            let processor = WorkloadStreamProcessor::new(stream, drain.clone());
            let mut processor_helper =
                WorkloadProxyManagerProcessor::new(&mut self.state, &mut self.readiness);
            match processor_helper.process(processor).await {
                Ok(()) => {
                    info!("process stream ended with eof");
                }
                Err(e) => {
                    warn!("process stream ended: {:?}", e);
                }
            };
            debug!("workload proxy manager is NOT ready");
            self.readiness.not_ready();
        };
    }
}

impl<'a> WorkloadProxyManagerProcessor<'a> {
    fn new(
        state: &'a mut super::statemanager::WorkloadProxyManagerState,
        readiness: &'a mut WorkloadProxyReadinessHandler,
    ) -> Self {
        state.reset_snapshot();
        Self {
            state,
            readiness,
            next_pending_retry: None,
        }
    }

    async fn read_message_and_retry_proxies(
        &mut self,
        processor: &mut WorkloadStreamProcessor,
    ) -> anyhow::Result<Option<crate::inpod::WorkloadMessage>> {
        let readmsg = processor.read_message();
        // Note: readmsg future is NOT cancel safe, so we want to make sure this function doesn't exit
        // return without completing it.
        futures::pin_mut!(readmsg);
        loop {
            match self.next_pending_retry.take() {
                None => {
                    return readmsg.await;
                }
                Some(timer) => {
                    match futures_util::future::select(timer, readmsg).await {
                        futures_util::future::Either::Left((_, readmsg_fut)) => {
                            self.retry_proxies().await;
                            // we have an uncompleted future. It might be in the middle of recvmsg.
                            // to make sure we don't drop messages, we complete the original
                            // future and not start a new one.
                            readmsg = readmsg_fut;
                        }
                        futures_util::future::Either::Right((res, timer)) => {
                            // we have a message before the timer expired
                            // put the timer back so we will wait for the time remaining next time.
                            self.next_pending_retry = Some(timer);
                            return res;
                        }
                    };
                }
            }
        }
    }

    async fn retry_proxies(&mut self) {
        self.state.retry_pending().await;
        if self.state.have_pending() {
            self.schedule_retry();
        } else {
            self.next_pending_retry.take();
            self.check_ready();
        }
    }

    pub async fn process(&mut self, mut processor: WorkloadStreamProcessor) -> Result<(), Error> {
        processor
            .send_hello()
            .await
            .map_err(|_| Error::ProtocolError)?;

        loop {
            let msg = match self.read_message_and_retry_proxies(&mut processor).await {
                Ok(Some(msg)) => Ok(msg),
                Ok(None) => {
                    return Ok(());
                }
                Err(e) => {
                    error!("failed to read message: {:?}", e);

                    // TODO: make it clear that the error is from reading the message, and not from processing it.
                    //                .map_err(|e| Error::ReceiveMessageError(e.to_string()))?;
                    processor
                        .send_nack(anyhow::anyhow!("failure to read message : {:?}", e))
                        .await
                        .map_err(|e: std::io::Error| Error::SendNackError(e.to_string()))?;
                    Err(Error::ReceiveMessageError(e.to_string()))
                }
            }?;

            debug!("received message: {:?}", msg);

            // send ack:
            match self.state.process_msg(msg).await {
                Ok(()) => {
                    self.check_ready();
                    processor
                        .send_ack()
                        .await
                        .map_err(|e| Error::SendAckError(e.to_string()))?;
                }
                Err(Error::ProxyError(e)) => {
                    // setup the retry timer:
                    self.schedule_retry();
                    // proxy error is a transient error, so report it but don't disconnect
                    // TODO: raise metrics
                    error!("failed to start proxy: {:?}", e);
                    processor
                        .send_nack(anyhow::anyhow!("failure to start proxy : {:?}", e))
                        .await
                        .map_err(|e| Error::SendNackError(e.to_string()))?;
                }
                Err(e) => {
                    // TODO: raise metrics
                    error!("failed to process message: {:?}", e);
                    processor
                        .send_nack(anyhow::anyhow!("failure to process message : {:?}", e))
                        .await
                        .map_err(|e| Error::SendNackError(e.to_string()))?;
                    // other errors are not recoverable, so exit function the function to re-connect.
                    // also, these errors should never happen, so log/metrics/document them.
                    return Err(e);
                }
            };
        }
    }

    fn schedule_retry(&mut self) {
        if self.next_pending_retry.is_none() {
            info!("scheduling retry");
            self.next_pending_retry = Some(Box::pin(tokio::time::sleep(RETRY_DURATION)));
        }
    }
    fn check_ready(&mut self) {
        if self.state.ready() {
            self.readiness.mark_ready();
        } else {
            self.readiness.not_ready();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use super::super::protocol::WorkloadStreamProcessor;

    use super::*;

    use crate::inpod::test_helpers::{
        self, create_proxy_confilct, new_netns, read_hello, read_msg, send_snap_sent,
        send_workload_added, send_workload_del, uid,
    };

    use std::{collections::HashSet, sync::Arc};

    fn assert_end_stream(res: Result<(), Error>) {
        match res {
            Err(Error::ReceiveMessageError(e)) => {
                assert!(e.contains("EOF"));
            }
            Ok(()) => {}
            Err(e) => panic!("expected error due to EOF {:?}", e),
        }
    }

    struct Fixture {
        state: WorkloadProxyManagerState,
        inpod_metrics: Arc<crate::inpod::Metrics>,
        drain_rx: drain::Watch,
        _drain_tx: drain::Signal,
    }

    macro_rules! fixture {
        () => {{
            if !crate::test_helpers::can_run_privilged_test() {
                eprintln!("This test requires root; skipping");
                return;
            }
            let f = test_helpers::Fixture::default();
            let state = WorkloadProxyManagerState::new(
                f.proxy_factory,
                f.ipc,
                f.inpod_metrics.clone(),
                Default::default(),
            );
            Fixture {
                state,
                inpod_metrics: f.inpod_metrics,
                drain_rx: f.drain_rx,
                _drain_tx: f.drain_tx,
            }
        }};
    }

    #[tokio::test]
    async fn test_process_add() {
        let f = fixture!();
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor = WorkloadStreamProcessor::new(s1, f.drain_rx.clone());
        let mut state = f.state;

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), new_netns()).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new());
        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);

        let res = processor_helper.process(processor).await;
        // make sure that the error is due to eof:
        assert_end_stream(res);
        assert!(!readiness.ready.pending().is_empty());
        state.drain().await;
        server.await.unwrap();
    }

    #[tokio::test]
    async fn test_process_failed() {
        let f = fixture!();
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor: WorkloadStreamProcessor =
            WorkloadStreamProcessor::new(s1, f.drain_rx.clone());
        let mut state = f.state;

        let podns = new_netns();
        let socket = create_proxy_confilct(&podns);

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), podns).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new());
        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);

        let res = processor_helper.process(processor).await;
        assert_end_stream(res);
        std::mem::drop(socket);
        server.await.unwrap();

        // not ready as we have a failing proxy
        assert!(!processor_helper.readiness.ready.pending().is_empty());
        assert!(processor_helper.next_pending_retry.is_some());

        // now make sure that re-trying works:
        // all should be ready:
        processor_helper.retry_proxies().await;
        assert!(processor_helper.readiness.ready.pending().is_empty());
        assert!(processor_helper.next_pending_retry.is_none());

        state.drain().await;
    }

    #[tokio::test]
    async fn test_process_add_and_del() {
        let f = fixture!();
        let m = f.inpod_metrics;
        let mut state = f.state;
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor: WorkloadStreamProcessor =
            WorkloadStreamProcessor::new(s1, f.drain_rx.clone());

        let podns = new_netns();
        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), podns).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
            send_workload_del(&mut s2, uid(0)).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new());
        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);

        let res = processor_helper.process(processor).await;
        server.await.unwrap();
        // make sure that the error is due to eof:
        assert_end_stream(res);

        assert_eq!(state.workload_states().len(), 0);
        assert_eq!(m.active_proxy_count.get_or_create(&()).get(), 0);
        assert!(readiness.ready.pending().is_empty());

        state.drain().await;
    }

    #[tokio::test]
    async fn test_process_snapshot_with_missing_workload() {
        let f = fixture!();
        let m = f.inpod_metrics;
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor = WorkloadStreamProcessor::new(s1, f.drain_rx.clone());
        let mut state = f.state;

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(0), new_netns()).await;
            read_msg(&mut s2).await;
            send_workload_added(&mut s2, uid(1), new_netns()).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
        });

        let mut readiness = WorkloadProxyReadinessHandler::new(readiness::Ready::new());

        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        let res = processor_helper.process(processor).await;

        assert_end_stream(res);
        server.await.unwrap();
        assert!(readiness.ready.pending().is_empty());

        // first proxy should be here:
        assert_eq!(state.workload_states().len(), 2);
        let key_set: HashSet<crate::inpod::WorkloadUid> =
            state.workload_states().keys().cloned().collect();
        let expected_key_set: HashSet<crate::inpod::WorkloadUid> = [0, 1]
            .into_iter()
            .map(uid)
            .map(crate::inpod::WorkloadUid::from)
            .collect();
        assert_eq!(key_set, expected_key_set);
        assert_eq!(m.active_proxy_count.get_or_create(&()).get(), 2);

        // second connection - don't send the one of the proxies here, to see ztunnel reconciles and removes it:
        let (s1, mut s2) = UnixStream::pair().unwrap();
        let processor = WorkloadStreamProcessor::new(s1, f.drain_rx.clone());

        let server = tokio::spawn(async move {
            read_hello(&mut s2).await;
            send_workload_added(&mut s2, uid(1), new_netns()).await;
            read_msg(&mut s2).await;
            send_snap_sent(&mut s2).await;
            read_msg(&mut s2).await;
        });

        let mut processor_helper = WorkloadProxyManagerProcessor::new(&mut state, &mut readiness);
        let res = processor_helper.process(processor).await;

        assert_end_stream(res);
        server.await.unwrap();

        // only second workload should remain
        assert_eq!(state.workload_states().len(), 1);
        assert_eq!(state.workload_states().keys().next(), Some(&uid(1)));
        assert_eq!(m.active_proxy_count.get_or_create(&()).get(), 1);
        assert!(readiness.ready.pending().is_empty());

        state.drain().await;
    }
}
