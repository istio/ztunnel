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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use futures_util::TryFutureExt;
use hyper::header::FORWARDED;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::watch;

use tracing::{Instrument, debug, error, info, info_span, trace_span};

use crate::identity::Identity;
use crate::strng::Strng;

use crate::proxy::connection_manager::{OutboundConnectionGuard, await_revocation};
use crate::proxy::metrics::Reporter;
use crate::proxy::{
    BAGGAGE_HEADER, Error, HboneAddress, ProxyInputs, TRACEPARENT_HEADER, TraceParent,
    X_FORWARDED_NETWORK_HEADER, util,
};
use crate::proxy::{
    ConnectionOpen, ConnectionResult, ConnectionResultBuilder, DerivedWorkload, metrics,
};

use crate::baggage::{self, Baggage};
use crate::drain::DrainWatcher;
use crate::drain::run_with_drain;
use crate::proxy::h2::{H2Stream, client::WorkloadKey};
use crate::state::service::{LoadBalancerMode, Service, ServiceDescription};
use crate::state::workload::OutboundProtocol;
use crate::state::workload::{InboundProtocol, NetworkAddress, Workload, address::Address};
use crate::state::{DeprioritizedEndpoints, ServiceResolutionMode, Upstream};
use crate::{assertions, copy, proxy, socket, tls};

use super::h2::TokioH2Stream;

pub struct Outbound {
    pi: Arc<ProxyInputs>,
    drain: DrainWatcher,
    listener: socket::Listener,
}

impl Outbound {
    pub(super) async fn new(pi: Arc<ProxyInputs>, drain: DrainWatcher) -> Result<Outbound, Error> {
        let mut listener = pi
            .socket_factory
            .tcp_bind(pi.cfg.outbound_addr)
            .map_err(|e| Error::Bind(pi.cfg.outbound_addr, e))?;
        let transparent = super::maybe_set_transparent(&pi, &listener)?;
        listener.set_socket_options(Some(pi.cfg.socket_config));

        info!(
            address=%listener.local_addr(),
            component="outbound",
            transparent,
            "listener established",
        );
        Ok(Outbound {
            pi,
            listener,
            drain,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.listener.local_addr()
    }

    pub(super) async fn run(self) {
        let pool = proxy::pool::WorkloadHBONEPool::new(
            self.pi.cfg.clone(),
            self.pi.socket_factory.clone(),
            self.pi.local_workload_information.clone(),
            self.pi.crl_manager.clone(),
            self.pi.metrics.clone(),
        );
        let pi = self.pi.clone();
        let accept = async move |drain: DrainWatcher, force_shutdown: watch::Receiver<()>| {
            loop {
                // Asynchronously wait for an inbound socket.
                let socket = self.listener.accept().await;
                let start = Instant::now();
                let drain = drain.clone();
                let mut force_shutdown = force_shutdown.clone();
                match socket {
                    Ok((stream, _remote)) => {
                        let socket_labels = metrics::SocketLabels {
                            reporter: Reporter::source,
                        };
                        self.pi.metrics.record_socket_open(&socket_labels);

                        let mut oc = OutboundConnection {
                            pi: self.pi.clone(),
                            id: TraceParent::new(),
                            pool: pool.clone(),
                            hbone_port: self.pi.cfg.inbound_addr.port(),
                        };
                        let span = info_span!("outbound", id=%oc.id);
                        let metrics_for_socket_close = self.pi.metrics.clone();
                        let serve_outbound_connection = async move {
                            let _socket_guard = metrics::SocketCloseGuard::new(
                                metrics_for_socket_close,
                                Reporter::source,
                            );
                            debug!(component="outbound", "connection started");
                            // Since this task is spawned, make sure we are guaranteed to terminate
                            tokio::select! {
                                _ = force_shutdown.changed() => {
                                    debug!(component="outbound", "connection forcefully terminated");
                                }
                                _ = oc.proxy(stream) => {}
                            }
                            // Mark we are done with the connection, so drain can complete
                            drop(drain);
                            debug!(component="outbound", dur=?start.elapsed(), "connection completed");
                        }.instrument(span);

                        assertions::size_between_ref(600, 1200, &serve_outbound_connection);
                        tokio::spawn(serve_outbound_connection);
                    }
                    Err(e) => {
                        if util::is_runtime_shutdown(&e) {
                            return;
                        }
                        error!("Failed TCP handshake {}", e);
                    }
                }
            }
        };

        run_with_drain(
            "outbound".to_string(),
            self.drain,
            pi.cfg.self_termination_deadline,
            accept,
        )
        .await
    }
}

/// An established upstream connection, before any downstream bytes have moved.
///
/// Named `ConnectedUpstream` because `crate::state::Upstream` already exists. Double HBONE collapses
/// into `Hbone` too: by the time we splice, its inner `H2Stream` is indistinguishable from a
/// single-hop one.
enum ConnectedUpstream {
    Hbone {
        stream: H2Stream,
        /// CRL revocation signal of each tunnel leg the stream rides on, outermost first. Double
        /// HBONE fills both (outer gateway, inner destination); a single hop leaves the second
        /// `None`, which `await_revocation` parks on forever. The splice therefore races a fixed two
        /// arms and attributes revocation identically on both paths.
        revoked: [Option<watch::Receiver<bool>>; 2],
        /// Graceful termination signal for double HBONE's inner tunnel, fired once the copy is done.
        /// A single hop's tunnel is pooled, so the pool owns its draining and this is `None`.
        inner_drain: Option<watch::Sender<bool>>,
    },
    Tcp(TcpStream),
}

pub(super) struct OutboundConnection {
    pub(super) pi: Arc<ProxyInputs>,
    pub(super) id: TraceParent,
    pub(super) pool: proxy::pool::WorkloadHBONEPool,
    pub(super) hbone_port: u16,
}

impl OutboundConnection {
    async fn proxy(&mut self, source_stream: TcpStream) {
        let peer = match source_stream.peer_addr() {
            Ok(addr) => addr,
            Err(e) => {
                debug!(
                    component = "outbound",
                    "failed to get peer address, dropping connection: {}", e
                );
                return;
            }
        };

        let source_addr = socket::to_canonical(peer);
        let dst_addr = socket::orig_dst_addr_or_default(&source_stream);
        self.proxy_to(source_stream, source_addr, dst_addr).await;
    }

    /// Whether a failed attempt is worth repeating.
    ///
    /// Two families qualify. A *build* failure means this ztunnel's view of the mesh may simply
    /// not have converged yet -- an endpoint list caught mid-rollout is the common case -- and
    /// rebuilding re-reads state. A *connect* failure means the endpoint we picked did not
    /// answer; selection deprioritizes it on the way back around, so the retry lands somewhere
    /// else. Without that deprioritization retrying a connect would be pointless, since it would
    /// mostly re-pick the same dead endpoint.
    ///
    /// Deliberately excluded:
    /// - `Identity` and `WorkloadHBONEPoolDraining`, which fail identically against every
    ///   endpoint: the first is a local certificate fetch, the second is our own shutdown.
    /// - `HttpStatus`, where the peer answered and refused. This carries RBAC denials, and a
    ///   policy decision does not change on retry. The exception is any 5xx: the destination
    ///   failed on its side, most often a 503 because it cannot reach the application (typically
    ///   the pod is shutting down and the app already exited). It is the CONNECT response, so no
    ///   data has been sent yet and another endpoint can take the connection.
    /// - `CertificateRevoked`, which is a deliberate security outcome.
    ///
    /// `MaybeHBONENetworkPolicyError` is retried even though its usual cause, a NetworkPolicy
    /// blocking 15008 mesh-wide, fails every attempt the same way. The attempts share one
    /// `CONNECTION_TIMEOUT` (see [`Self::connect_budget`]), so retrying a blocked port gives up no
    /// later than a single attempt would have. Not retrying it would be worse: retries shrink each
    /// attempt's connect timeout, so a slow but reachable endpoint would time out on its share and
    /// then get no second try, where a plain TCP connect timeout (`Io`) does.
    ///
    /// `HandshakeTimeout` is retried for the same reason, and because the peer accepted the TCP
    /// connection, it is this endpoint that stalled rather than anything blocking the port.
    fn is_retriable_connection_error(err: &Error) -> bool {
        matches!(
            err,
            // Build: our view of the mesh may not have caught up.
            Error::NoHealthyUpstream(_)
                | Error::NoValidDestination(_)
                | Error::NoService(_)
                // Connect: this endpoint did not answer.
                | Error::Io(_)
                | Error::Tls(_)
                | Error::Http2Handshake(_)
                | Error::H2(_)
                | Error::HandshakeTimeout(_)
                | Error::MaybeHBONENetworkPolicyError(_)
        ) || matches!(err, Error::HttpStatus(status) if status.is_server_error())
    }

    /// The delay before retry number `retry` (1-based): `base` for the first retry, doubling
    /// after each subsequent failure, capped at `max`.
    fn retry_backoff(retry: usize, base: Duration, max: Duration) -> Duration {
        let doublings = u32::try_from(retry.saturating_sub(1)).unwrap_or(u32::MAX);
        base.saturating_mul(2u32.saturating_pow(doublings)).min(max)
    }

    /// [`Self::retry_backoff`] with this proxy's configured base and max.
    fn configured_retry_backoff(&self, retry: usize) -> Duration {
        Self::retry_backoff(
            retry,
            self.pi.cfg.outbound_connect_base_backoff,
            self.pi.cfg.outbound_connect_max_backoff,
        )
    }

    /// The backoff to sleep before retrying after `err`, or `None` if the connect should give up:
    /// the error is not worth retrying, the retries are spent, or the retry could not start before
    /// `CONNECTION_TIMEOUT` runs out.
    fn retry_delay(
        &self,
        err: &Error,
        retries: usize,
        max_retries: usize,
        start: Instant,
    ) -> Option<Duration> {
        if !Self::is_retriable_connection_error(err) || retries >= max_retries {
            return None;
        }
        let backoff = self.configured_retry_backoff(retries + 1);
        Self::retry_within_deadline(start, backoff).then_some(backoff)
    }

    /// The smallest connect timeout an attempt may be handed.
    ///
    /// A share small enough to expire during an ordinary connect is worse than no retry at all:
    /// it fails a connect that would have succeeded, and burns a retry doing it. This is the
    /// floor below which the split stops dividing -- either because the retry count is high
    /// enough to slice `CONNECTION_TIMEOUT` that thin, or because the earlier attempts already
    /// spent the budget.
    const MIN_CONNECT_BUDGET: Duration = Duration::from_millis(50);

    /// The connect timeout a single attempt is allowed.
    ///
    /// `CONNECTION_TIMEOUT` bounds a connect as a whole, not each attempt, so retrying must not
    /// multiply the time a client waits before we give up. Whatever is left of that budget at
    /// `start` -- the same timestamp the access log measures connect latency from, so the backoff
    /// sleeps between attempts are charged against it too -- is split evenly across the attempts
    /// still allowed: the one about to run, plus every retry still owed after it. The bound
    /// therefore holds however many of those attempts we end up spending.
    ///
    /// An attempt that finishes early leaves its unspent share to the attempts behind it, so a
    /// fast failure (a refused connect, say) does not cost the retry its full share.
    ///
    /// The split is floored at [`Self::MIN_CONNECT_BUDGET`]. That floor could let the attempts
    /// overrun `CONNECTION_TIMEOUT`, so [`Self::retry_within_deadline`] also refuses to start a
    /// retry once the deadline has passed. Together they bound a connect at `CONNECTION_TIMEOUT`
    /// plus one floor, the most the final attempt can overrun by.
    fn connect_budget(start: Instant, retries: usize, max_retries: usize) -> Duration {
        let time_left = super::CONNECTION_TIMEOUT.saturating_sub(start.elapsed());
        let attempts_left = u32::try_from(max_retries.saturating_sub(retries).saturating_add(1))
            .unwrap_or(u32::MAX);
        let share = time_left / attempts_left;
        std::cmp::max(share, Self::MIN_CONNECT_BUDGET)
    }

    /// Whether a retry that first sleeps `backoff` would still start before the overall
    /// `CONNECTION_TIMEOUT` measured from `start` runs out.
    ///
    /// Checked before sleeping, so a retry that could not start in time does not make the client
    /// wait through a backoff first.
    fn retry_within_deadline(start: Instant, backoff: Duration) -> bool {
        start.elapsed().saturating_add(backoff) < super::CONNECTION_TIMEOUT
    }

    async fn connect_with_retries(
        &mut self,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
        max_retries: usize,
        start: Instant,
    ) -> Option<(
        ConnectedUpstream,
        Option<DerivedWorkload>,
        Box<ConnectionResultBuilder>,
        Box<Request>,
        // Handed back rather than dropped here: it is what lists the connection in the connection
        // manager, and the connection is not established until the caller has spliced it. Dropping
        // it at the end of a successful connect would leave every live connection unlisted.
        OutboundConnectionGuard,
    )> {
        let mut retries = 0;
        // Endpoints a previous attempt already failed on. Endpoint selection prefers anything
        // else, so a retry does not just re-roll the dice onto the same dead endpoint.
        let mut deprioritized = DeprioritizedEndpoints::default();
        loop {
            // First find the source workload of this traffic. If we don't know where the request is from
            // we will reject it.
            let build = self
                .pi
                .local_workload_information
                .get_workload()
                .and_then(|source| {
                    self.build_request(source, source_addr.ip(), dest_addr, &deprioritized)
                });

            let req = match Box::pin(build).await {
                Ok(req) => Box::new(req),
                Err(err) => {
                    // Nothing was selected, so there is no endpoint to deprioritize; the retry
                    // just re-reads state, which is the whole point here.
                    if let Some(backoff) = self.retry_delay(&err, retries, max_retries, start) {
                        retries += 1;
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    // No `ConnectionResultBuilder` exists yet, so this is the only place a build
                    // failure gets recorded.
                    metrics::log_early_deny(source_addr, dest_addr, Reporter::source, err);
                    return None;
                }
            };
            // TODO: should we use the original address or the actual address? Both seems nice!
            let conn_guard = self.pi.connection_manager.track_outbound(
                source_addr,
                dest_addr,
                req.actual_destination,
                req.protocol,
            );

            let metrics = self.pi.metrics.clone();
            let hbone_target = req.hbone_target_destination.clone();
            let connection_result_builder = Box::new(ConnectionResultBuilder::new(
                source_addr,
                req.actual_destination,
                hbone_target,
                start,
                Self::conn_metrics_from_request(&req),
                metrics,
            ));

            // This attempt's share of the overall connect budget. Recomputed per attempt, so it
            // picks up both the time the attempts before it spent and the backoff they slept.
            //
            // With retries off there is nothing to share the budget with, so no deadline is set
            // and each step keeps the bound it had before retries existed: the TCP connect at
            // `CONNECTION_TIMEOUT`, the handshakes and CONNECT unbounded.
            let budget =
                (max_retries > 0).then(|| Self::connect_budget(start, retries, max_retries));

            // Establish the upstream connection. This half touches no part of the downstream socket and
            // copies nothing, so on failure `source_stream` is still owned and untouched here.
            let connected = match req.protocol {
                OutboundProtocol::DOUBLEHBONE => {
                    // We box this since its not a common path and it would make the future really big.
                    Box::pin(self.connect_hbone_double(source_addr, &req, budget)).await
                }
                OutboundProtocol::HBONE => self
                    .connect_hbone(source_addr, &req, budget)
                    .await
                    .map(|upstream| (upstream, None)),
                OutboundProtocol::TCP => self
                    .connect_tcp(&req, budget)
                    .await
                    .map(|upstream| (upstream, None)),
            };

            match connected {
                Ok((connected, derived_workload)) => {
                    return Some((
                        connected,
                        derived_workload,
                        connection_result_builder,
                        req,
                        conn_guard,
                    ));
                }
                Err(e) => {
                    let backoff = self.retry_delay(&e, retries, max_retries, start);
                    connection_result_builder.build().record(Err(e));
                    let backoff = backoff?;
                    // Deprioritize the endpoint we just failed on, so the next `build_request`
                    // prefers a different one. This is the next hop, which for waypointed or
                    // cross-network traffic is the waypoint or E/W gateway rather than the
                    // backend -- the same endpoint that actually failed here.
                    if let Some(wl) = &req.actual_destination_workload {
                        deprioritized.push(wl.uid.clone());
                    }
                    retries += 1;
                    tokio::time::sleep(backoff).await;
                    continue;
                }
            };
        }
    }

    pub async fn proxy_to(
        &mut self,
        source_stream: TcpStream,
        source_addr: SocketAddr,
        dest_addr: SocketAddr,
    ) {
        let start = Instant::now();

        let illegal_call =
            dest_addr.ip().is_loopback() && self.pi.cfg.illegal_ports.contains(&dest_addr.port());
        if illegal_call {
            metrics::log_early_deny(source_addr, dest_addr, Reporter::source, Error::SelfCall);
            return;
        }
        // Boxed: the retry loop holds a build, a connect and their per-attempt state, and
        // inlining that here would put all of it in every connection's future for the whole life
        // of the connection -- including the splice below, which needs none of it.
        // `_conn_guard` keeps this connection listed in the connection manager. It has to stay
        // bound through the splice below: dropping it is what unlists the connection, so it is the
        // one piece of connect state that deliberately outlives the connect.
        let (connected, derived_workload, mut connection_result_builder, req, _conn_guard) =
            match Box::pin(self.connect_with_retries(
                source_addr,
                dest_addr,
                self.pi.cfg.outbound_connect_max_retries,
                start,
            ))
            .await
            {
                Some(result) => result,
                None => return,
            };
        // Only double HBONE learns anything about the destination while connecting (from the peer's
        // baggage). Grafting it on here keeps the connect half free of metrics entirely.
        if let Some(derived_workload) = derived_workload {
            *connection_result_builder =
                connection_result_builder.with_derived_destination(&derived_workload);
        }
        // `build()` emits the "connection open" access log entry, so it happens exactly once, after
        // the connect has settled.
        let connection_stats = Box::new(connection_result_builder.build());
        debug!(
            dst=%req.actual_destination,
            target=?req.hbone_target_destination,
            "starting copy",
        );
        // Dropped explicitly, not left to fall out of scope: the splice below is the long-lived
        // half of a connection, and nothing in it reads the request. Holding `req` across that
        // await would pin its allocation for as long as the connection is open, for no reason.
        drop(req);
        let res = Box::pin(self.splice(source_stream, connected, &connection_stats)).await;
        connection_stats.record(res);
    }

    /// Connects a request through two layers of HBONE.
    ///
    /// Called directly rather than through a shared connect dispatcher, because this is the only
    /// connect that learns something about the destination on the way: the `DerivedWorkload` built
    /// from the peer's baggage, which the caller grafts onto the access log record.
    async fn connect_hbone_double(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
        connect_timeout: Option<Duration>,
    ) -> Result<(ConnectedUpstream, Option<DerivedWorkload>), Error> {
        // Fetched before the deadline starts, for the reason given in `deadline_after_cert_fetch`.
        // The inner leg needs it anyway, and the pool's fetch for the outer tunnel is then a cache
        // hit.
        let cert = self
            .pi
            .local_workload_information
            .fetch_certificate()
            .await?;
        let deadline = connect_timeout.map(|timeout| tokio::time::Instant::now() + timeout);
        // One deadline for the whole attempt, shared by both legs: the inner tunnel rides on the
        // outer one, so a stall anywhere in either handshake is this attempt's stall.
        // Create the outer HBONE stream. The outer tunnel's revocation signal is captured here so
        // it can still be attributed once we are splicing over the inner tunnel.
        let (upgraded, _, outer_revoked) =
            Box::pin(self.send_hbone_request(remote_addr, req, deadline)).await?;
        // Wrap upgraded to implement tokio's Async{Write,Read}
        let upgraded = TokioH2Stream::new(upgraded);

        // For the inner one, we do it manually to avoid connection pooling.
        // Otherwise, we would only ever reach one workload in the remote cluster.
        // We also need to abort tasks the right way to get graceful terminations.
        let wl_key = WorkloadKey {
            src_id: req.source.identity(),
            dst_id: req.final_sans.clone(),
            src: remote_addr.ip(),
            dst: req.actual_destination,
        };

        // Establish inner TLS connection.
        let connector =
            cert.outbound_connector(wl_key.dst_id.clone(), self.pi.crl_manager.clone())?;
        let tls_stream = super::with_deadline(
            deadline,
            super::HandshakeStage::InnerTls,
            connector.connect(upgraded).inspect_err(|e| {
                if crate::tls::io_error_is_cert_revoked(e) {
                    self.pi
                        .metrics
                        .record_crl_rejection(crate::proxy::metrics::Reporter::source);
                }
            }),
        )
        .await?;
        let (_, ssl) = tls_stream.get_ref();
        let peer_identity = {
            let x509_cert = tls::certificate_from_connection(ssl);
            tls::identity(&x509_cert)
        };

        // Spawn inner CONNECT tunnel
        let (drain_tx, drain_rx) = tokio::sync::watch::channel(false);
        // Enforce CRL revocation on this inner tunnel for its lifetime
        let revocation = self.pi.crl_manager.as_ref().map(|crl_manager| {
            crl_manager.register(crate::tls::revocation::ConnRegistration::from_conn(
                ssl,
                peer_identity.clone(),
                cert.root_store(),
                webpki::KeyUsage::server_auth(),
                crate::proxy::metrics::Reporter::source,
            ))
        });
        let mut sender = super::with_deadline(
            deadline,
            super::HandshakeStage::InnerHttp2,
            super::h2::client::spawn_connection(
                self.pi.cfg.clone(),
                tls_stream,
                drain_rx,
                wl_key,
                revocation,
            ),
        )
        .await?;
        // The inner tunnel's revocation signal
        let inner_revoked = sender.revoked_receiver();
        let origin_network = &self.pi.cfg.network;
        let http_request = self.create_hbone_request(remote_addr, req, Some(origin_network));
        let (inner_upgraded, baggage) = super::with_deadline(
            deadline,
            super::HandshakeStage::InnerConnect,
            sender.send_request(http_request),
        )
        .await?;

        let derived_workload = baggage.map(|baggage| DerivedWorkload {
            workload_name: baggage.workload_name,
            app: baggage.service_name,
            namespace: baggage.namespace,
            identity: peer_identity,
            cluster_id: baggage.cluster_id,
            region: baggage.region,
            zone: baggage.zone,
            revision: baggage.revision,
        });
        Ok((
            ConnectedUpstream::Hbone {
                stream: inner_upgraded,
                revoked: [outer_revoked, inner_revoked],
                inner_drain: Some(drain_tx),
            },
            derived_workload,
        ))
    }

    /// Connects a single HBONE tunnel to `req.actual_destination`.
    async fn connect_hbone(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
        connect_timeout: Option<Duration>,
    ) -> Result<ConnectedUpstream, Error> {
        let deadline = self.deadline_after_cert_fetch(connect_timeout).await?;
        let (stream, _, revoked) =
            Box::pin(self.send_hbone_request(remote_addr, req, deadline)).await?;
        Ok(ConnectedUpstream::Hbone {
            stream,
            // Single hop: there is no inner leg, and `await_revocation(None)` parks forever.
            revoked: [revoked, None],
            // The tunnel is pooled, so the pool owns its draining.
            inner_drain: None,
        })
    }

    /// Starts an attempt's `connect_timeout` deadline, after making sure this workload's
    /// certificate is fetched.
    ///
    /// The deadline bounds network steps, and the fetch is not one: on a freshly started pod it
    /// waits on the CSR, which can take seconds. Started before the fetch, the deadline could run
    /// out before the TCP connect even began, failing an attempt against a healthy endpoint. The
    /// pool fetches the certificate again when it opens a tunnel, but that is now a cache hit.
    /// With no timeout there is nothing to protect, so nothing is fetched.
    async fn deadline_after_cert_fetch(
        &self,
        connect_timeout: Option<Duration>,
    ) -> Result<Option<tokio::time::Instant>, Error> {
        let Some(timeout) = connect_timeout else {
            return Ok(None);
        };
        self.pi
            .local_workload_information
            .fetch_certificate()
            .await?;
        Ok(Some(tokio::time::Instant::now() + timeout))
    }

    /// Copies bytes between the downstream socket and an established upstream until one side closes.
    ///
    /// Unlike the connect half this consumes `source`, so it cannot be re-run: once it has been
    /// entered, downstream bytes may already have moved.
    async fn splice(
        &self,
        source: TcpStream,
        upstream: ConnectedUpstream,
        connection_stats: &ConnectionResult,
    ) -> Result<(), Error> {
        match upstream {
            ConnectedUpstream::Hbone {
                stream: upstream,
                revoked: [outer_revoked, inner_revoked],
                inner_drain,
            } => {
                // Race the data copy against every tunnel leg's revocation signal (for double HBONE,
                // inner = final dest, outer = e/w gw). `biased` with the revocation arms first makes
                // attribution deterministic: the driver sets the signal before tearing the tunnel
                // down, so a teardown from either hop surfaces as CERT_REVOKED rather than the
                // generic reset the copy observed.
                let res = tokio::select! {
                    biased;
                    _ = await_revocation(outer_revoked) => Err(Error::CertificateRevoked),
                    _ = await_revocation(inner_revoked) => Err(Error::CertificateRevoked),
                    res = copy::copy_bidirectional(
                        copy::TcpStreamSplitter(source),
                        upstream,
                        connection_stats,
                    ) => res,
                };
                if let Some(inner_drain) = inner_drain {
                    let _ = inner_drain.send(true);
                }
                res
            }
            ConnectedUpstream::Tcp(upstream) => {
                copy::copy_bidirectional(
                    copy::TcpStreamSplitter(source),
                    copy::TcpStreamSplitter(upstream),
                    connection_stats,
                )
                .await
            }
        }
    }

    fn create_hbone_request(
        &self,
        remote_addr: SocketAddr,
        req: &Request,
        origin_network: Option<&Strng>,
    ) -> http::Request<()> {
        let mut builder = http::Request::builder()
            .uri(
                req.hbone_target_destination
                    .as_ref()
                    .expect("HBONE must have target")
                    .to_string(),
            )
            .method(hyper::Method::CONNECT)
            .version(hyper::Version::HTTP_2)
            .header(BAGGAGE_HEADER, baggage(req))
            .header(
                FORWARDED,
                build_forwarded(remote_addr, &req.intended_destination_service),
            )
            .header(TRACEPARENT_HEADER, self.id.header());

        // Add x-istio-origin-network header for inner CONNECT requests in double HBONE
        if let Some(network) = origin_network {
            builder = builder.header(X_FORWARDED_NETWORK_HEADER, network.as_str());
        }

        builder
            .body(())
            .expect("builder with known status code should not fail")
    }

    /// returns upgraded stream, peer's baggage, and the tunnel's CRL revocation signal
    async fn send_hbone_request(
        &mut self,
        remote_addr: SocketAddr,
        req: &Request,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<(H2Stream, Option<Baggage>, Option<watch::Receiver<bool>>), Error> {
        // This is the single cluster/single-HBONE codepath (and also the outer tunnel
        // for double HBONE). We don't need the x-istio-origin-network header here because:
        // - For single HBONE: both source and destination are in the same network
        // - For double HBONE outer: the gateway doesn't need origin network info
        let request = self.create_hbone_request(remote_addr, req, None);
        let pool_key = Box::new(WorkloadKey {
            src_id: req.source.identity(),
            // Clone here shouldn't be needed ideally, we could just take ownership of Request.
            dst_id: req.upstream_sans.clone(),
            src: remote_addr.ip(),
            dst: req.actual_destination,
        });
        // The deadline bounds whatever the pool has to do for this request: opening a new tunnel
        // (TCP connect, TLS and HTTP/2 handshakes) if there is none to reuse, and the CONNECT
        // either way.
        Box::pin(self.pool.send_request_pooled(&pool_key, request, deadline))
            .instrument(trace_span!("outbound connect"))
            .await
    }

    /// Connects a plaintext TCP stream to `req.actual_destination`.
    async fn connect_tcp(
        &self,
        req: &Request,
        connect_timeout: Option<Duration>,
    ) -> Result<ConnectedUpstream, Error> {
        let outbound = super::freebind_connect(
            None, // No need to spoof source IP on outbound
            req.actual_destination,
            self.pi.socket_factory.as_ref(),
            connect_timeout,
        )
        .await?;
        Ok(ConnectedUpstream::Tcp(outbound))
    }

    fn conn_metrics_from_request(req: &Request) -> ConnectionOpen {
        let (derived_source, security_policy) = match req.protocol {
            OutboundProtocol::HBONE | OutboundProtocol::DOUBLEHBONE => (
                Some(DerivedWorkload {
                    // We are going to do mTLS, so report our identity
                    identity: Some(req.source.as_ref().identity()),
                    ..Default::default()
                }),
                metrics::SecurityPolicy::mutual_tls,
            ),
            OutboundProtocol::TCP => (None, metrics::SecurityPolicy::unknown),
        };
        ConnectionOpen {
            reporter: Reporter::source,
            derived_source,
            source: Some(req.source.clone()),
            destination: req.actual_destination_workload.clone(),
            connection_security_policy: security_policy,
            destination_service: req.intended_destination_service.clone(),
        }
    }

    // This function is called when the select next hop is on a different network,
    // so we expect the upstream workload to have a network gatewy configured.
    //
    // When we use a gateway to reach to a workload on a remote network we have to
    // use double HBONE (HBONE incapsulated inside HBONE). The gateway will
    // terminate the outer HBONE tunnel and forward the inner HBONE to the actual
    // destination as a opaque stream of bytes and the actual destination will
    // interpret it as an HBONE connection.
    //
    // If the upstream workload does not have an E/W gateway this function returns
    // an error indicating that it could not find a valid destination.
    //
    // A note about double HBONE, in double HBONE both inner and outer HBONE use
    // destination service name as HBONE target URI.
    //
    // Having target URI in the outer HBONE tunnel allows E/W gateway to figure out
    // where to route the data next witout the need to terminate inner HBONE tunnel.
    // In other words, it could forward inner HBONE as if it's an opaque stream of
    // bytes without trying to interpret it.
    //
    // NOTE: when connecting through an E/W gateway, regardless of whether there is
    // a waypoint or not, we always use service hostname and the service port. It's
    // somewhat different from how regular HBONE works, so I'm calling it out here.
    async fn build_request_through_gateway(
        &self,
        source: Arc<Workload>,
        // next hop on the remote network that we picked as our destination.
        // It may be a local view of a Waypoint workload on remote network or
        // a local view of the service workload (when waypoint is not
        // configured).
        upstream: Upstream,
        // This is a target service we wanted to reach in the first place.
        //
        // NOTE: Crossing network boundaries is only supported for services
        // at the moment, so we should always have a service we could use.
        service: &Service,
        target: SocketAddr,
        deprioritized: &DeprioritizedEndpoints,
    ) -> Result<Request, Error> {
        if let Some(gateway) = &upstream.workload.network_gateway {
            let gateway_upstream = self
                .pi
                .state
                .fetch_network_gateway(gateway, &source, target, deprioritized)
                .await?;
            let hbone_target_destination = Some(HboneAddress::SvcHostname(
                service.hostname.clone(),
                target.port(),
            ));

            debug!("built request to a destination on another network through an E/W gateway");
            Ok(Request {
                protocol: OutboundProtocol::DOUBLEHBONE,
                source,
                hbone_target_destination,
                actual_destination_workload: Some(gateway_upstream.workload.clone()),
                intended_destination_service: Some(ServiceDescription::from(service)),
                actual_destination: gateway_upstream.workload_socket_addr().ok_or(
                    Error::NoValidDestination(Box::new((*gateway_upstream.workload).clone())),
                )?,
                // The outer tunnel of double HBONE is terminated by the E/W
                // gateway and so for the credentials of the next hop
                // (upstream_sans) we use gateway credentials.
                upstream_sans: gateway_upstream.workload_and_services_san(),
                // The inner HBONE tunnel is terminated by either the server
                // we want to reach or a Waypoint in front of it, depending on
                // the configuration. So for the final destination credentials
                // (final_sans) we use the upstream workload credentials.
                final_sans: upstream.service_sans(),
            })
        } else {
            // Do not try to send cross-network traffic without network gateway.
            Err(Error::NoValidDestination(Box::new(
                (*upstream.workload).clone(),
            )))
        }
    }

    // build_request computes all information about the request we should send
    // TODO: Do we want a single lock for source and upstream...?
    async fn build_request(
        &self,
        source_workload: Arc<Workload>,
        downstream: IpAddr,
        target: SocketAddr,
        deprioritized: &DeprioritizedEndpoints,
    ) -> Result<Request, Error> {
        let state = &self.pi.state;

        // If this is to-service traffic check for a service waypoint
        // Capture result of whether this is svc addressed
        let service = if let Some(Address::Service(target_service)) = state
            .fetch_address(
                &NetworkAddress {
                    network: self.pi.cfg.network.clone(),
                    address: target.ip(),
                },
                Some(&source_workload.namespace),
            )
            .await
        {
            // if we have a waypoint for this svc, use it; otherwise route traffic normally
            if let Some(waypoint) = state
                .fetch_service_waypoint(&target_service, &source_workload, target, deprioritized)
                .await?
            {
                if waypoint.workload.network != source_workload.network {
                    debug!("picked a waypoint on remote network");
                    return self
                        .build_request_through_gateway(
                            source_workload.clone(),
                            waypoint,
                            &target_service,
                            target,
                            deprioritized,
                        )
                        .await;
                }

                let upstream_sans = waypoint.workload_and_services_san();
                let actual_destination =
                    waypoint
                        .workload_socket_addr()
                        .ok_or(Error::NoValidDestination(Box::new(
                            (*waypoint.workload).clone(),
                        )))?;
                debug!("built request to service waypoint proxy");
                return Ok(Request {
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload,
                    hbone_target_destination: Some(HboneAddress::SocketAddr(target)),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: Some(ServiceDescription::from(&*target_service)),
                    actual_destination,
                    upstream_sans,
                    final_sans: vec![],
                });
            }
            // this was service addressed but we did not find a waypoint
            Some(target_service)
        } else {
            // this wasn't service addressed
            None
        };

        let Some(us) = state
            .fetch_upstream(
                source_workload.network.clone(),
                &source_workload,
                target,
                ServiceResolutionMode::Standard,
                deprioritized,
            )
            .await?
        else {
            if let Some(service) = service
                && service.
                load_balancer.
                as_ref().
                // If we are not a passthrough service, we should have an upstream
                map(|lb| lb.mode != LoadBalancerMode::Passthrough).
                // If the service had no lb, we should have an upstream
                unwrap_or(true)
            {
                return Err(Error::NoHealthyUpstream(target));
            }
            debug!("built request as passthrough; no upstream found");
            return Ok(Request {
                protocol: OutboundProtocol::TCP,
                source: source_workload,
                hbone_target_destination: None,
                actual_destination_workload: None,
                intended_destination_service: None,
                actual_destination: target,
                upstream_sans: vec![],
                final_sans: vec![],
            });
        };

        // Check whether we are using an E/W gateway and sending cross network traffic
        if us.workload.network != source_workload.network {
            // Workloads on remote network must be service addressed, so if we got here
            // and we don't have a service for the original target address then it's a
            // bug either in ztunnel itself or in istiod.
            //
            // For a double HBONE protocol implementation we have to know the
            // destination service and if there is no service for the target it's a bug.
            //
            // This situation "should never happen" because for workloads fetch_upstream
            // above only checks the workloads on the same network as this ztunnel
            // instance and therefore it should not be able to find a workload on a
            // different network.
            debug_assert!(
                service.is_some(),
                "workload on remote network is not service addressed"
            );
            debug!("picked a workload on remote network");
            let service = service.as_ref().ok_or(Error::NoService(target))?;
            return self
                .build_request_through_gateway(
                    source_workload.clone(),
                    us,
                    service,
                    target,
                    deprioritized,
                )
                .await;
        }

        // We are not using a network gateway and there is no workload address.
        let from_waypoint = proxy::check_from_waypoint(
            state,
            &us.workload,
            Some(&source_workload.identity()),
            &downstream,
        )
        .await;

        // Check if we need to go through a workload addressed waypoint.
        // Don't traverse waypoint twice if the source is sandwich-outbound.
        // Don't traverse waypoint if traffic was addressed to a service (handled before)
        if !from_waypoint && service.is_none() {
            // For case upstream server has enabled waypoint
            let waypoint = state
                .fetch_workload_waypoint(&us.workload, &source_workload, target, deprioritized)
                .await?;
            if let Some(waypoint) = waypoint {
                let actual_destination =
                    waypoint
                        .workload_socket_addr()
                        .ok_or(Error::NoValidDestination(Box::new(
                            (*waypoint.workload).clone(),
                        )))?;
                let upstream_sans = waypoint.workload_and_services_san();
                debug!("built request to workload waypoint proxy");
                return Ok(Request {
                    // Always use HBONE here
                    protocol: OutboundProtocol::HBONE,
                    source: source_workload,
                    // Use the original VIP, not translated
                    hbone_target_destination: Some(HboneAddress::SocketAddr(target)),
                    actual_destination_workload: Some(waypoint.workload),
                    intended_destination_service: us.destination_service.clone(),
                    actual_destination,
                    upstream_sans,
                    final_sans: vec![],
                });
            }
            // Workload doesn't have a waypoint; send directly
        }

        let selected_workload_ip = us
            .selected_workload_ip
            .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?;

        // only change the port if we're sending HBONE
        let actual_destination = match us.workload.protocol {
            InboundProtocol::HBONE => SocketAddr::from((selected_workload_ip, self.hbone_port)),
            InboundProtocol::TCP => us
                .workload_socket_addr()
                .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?,
        };
        let hbone_target_destination = match us.workload.protocol {
            InboundProtocol::HBONE => Some(HboneAddress::SocketAddr(
                us.workload_socket_addr()
                    .ok_or(Error::NoValidDestination(Box::new((*us.workload).clone())))?,
            )),
            InboundProtocol::TCP => None,
        };

        // For case no waypoint for both side and direct to remote node proxy
        let (upstream_sans, final_sans) = (us.workload_and_services_san(), vec![]);
        debug!("built request to workload");
        Ok(Request {
            protocol: OutboundProtocol::from(us.workload.protocol),
            source: source_workload,
            hbone_target_destination,
            actual_destination_workload: Some(us.workload.clone()),
            intended_destination_service: us.destination_service.clone(),
            actual_destination,
            upstream_sans,
            final_sans,
        })
    }
}

fn build_forwarded(remote_addr: SocketAddr, server: &Option<ServiceDescription>) -> String {
    match server {
        None => {
            format!("for=\"{remote_addr}\"")
        }
        Some(svc) => {
            format!("for=\"{remote_addr}\";host={}", svc.hostname)
        }
    }
}

fn baggage(r: &Request) -> String {
    baggage::baggage_header_val(&r.source.baggage(), &r.source.workload_type)
}

#[derive(Debug)]
struct Request {
    protocol: OutboundProtocol,
    // Source workload sending the request
    source: Arc<Workload>,
    // The actual destination workload we are targeting. When proxying through a waypoint, this is the waypoint,
    // not the original.
    // May be unset in case of passthrough.
    actual_destination_workload: Option<Arc<Workload>>,
    // The intended destination service for the request. When proxying through a waypoint, this is *not* the waypoint
    // service, but rather the original intended service.
    // May be unset in case of non-service traffic
    intended_destination_service: Option<ServiceDescription>,
    // The address we should actually request to. This is the "next hop" address; could be a waypoint, network gateway,
    // etc.
    // When using HBONE, the `hbone_target_destination` is the inner :authority and `actual_destination` is the TCP destination.
    actual_destination: SocketAddr,
    // If using HBONE, the inner (:authority) of the HBONE request.
    hbone_target_destination: Option<HboneAddress>,

    // The identity we will assert for the next hop; this may not be the same as actual_destination_workload
    // in the case of proxies along the path.
    upstream_sans: Vec<Identity>,

    // The identity of workload that will ultimately process this request.
    // This field only matters if we need to know both the identity of the next hop, as well as the
    // final hop (currently, this is only double HBONE).
    final_sans: Vec<Identity>,
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::config::Config;
    use crate::proxy::HandshakeStage;
    use crate::proxy::connection_manager::ConnectionManager;
    use crate::proxy::{LocalWorkloadInformation, pool::WorkloadHBONEPool};
    use crate::state::WorkloadInfo;
    use crate::test_helpers::helpers::{initialize_telemetry, test_proxy_metrics};
    use crate::test_helpers::new_proxy_state;
    use crate::xds::istio::workload::Workload as XdsWorkload;
    use crate::xds::istio::workload::address::Type as XdsAddressType;
    use crate::xds::istio::workload::{IpFamilies, Port};
    use crate::xds::istio::workload::{LoadBalancing, TunnelProtocol as XdsProtocol};
    use crate::xds::istio::workload::{
        NamespacedHostname as XdsNamespacedHostname, NetworkAddress as XdsNetworkAddress, PortList,
    };
    use crate::xds::istio::workload::{NetworkMode, Service as XdsService};
    use crate::{identity, xds};

    async fn run_build_request(
        from: &str,
        to: &str,
        xds: XdsAddressType,
        expect: Option<ExpectedRequest<'_>>,
    ) {
        run_build_request_multi(from, to, vec![xds], expect).await;
    }

    async fn run_build_request_multi(
        from: &str,
        to: &str,
        xds: Vec<XdsAddressType>,
        expect: Option<ExpectedRequest<'_>>,
    ) -> Option<Request> {
        let cfg = Arc::new(Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        });
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 1]),
                Bytes::copy_from_slice("::1".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            node: "local-node".to_string(),
            ..Default::default()
        };
        let waypoint = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/waypoint-workload".to_string(),
            name: "waypoint-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 10])],
            node: "local-node".to_string(),
            service_account: "waypoint-sa".to_string(),
            ..Default::default()
        };
        let waypoint_dual = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/waypoint-workload-dual".to_string(),
            name: "waypoint-workload-dual".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 11]),
                Bytes::copy_from_slice("ff06::c5".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            node: "local-node".to_string(),
            service_account: "waypoint-sa".to_string(),
            ..Default::default()
        };
        let mut workloads = vec![source, waypoint, waypoint_dual];
        let mut services = vec![];
        for x in xds {
            match x {
                XdsAddressType::Workload(wl) => workloads.push(wl),
                XdsAddressType::Service(svc) => services.push(svc),
            };
        }
        let state = new_proxy_state(&workloads, &services, &[]);

        let sock_fact = std::sync::Arc::new(crate::proxy::DefaultSocketFactory::default());

        let wi = WorkloadInfo {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            service_account: "default".to_string(),
        };
        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(wi.clone()),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));
        let outbound = OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state: state.clone(),
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sock_fact.clone(),
                local_workload_information: local_workload_information.clone(),
                connection_manager: ConnectionManager::default(),
                resolver: None,
                disable_inbound_freebind: false,
                crl_manager: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(
                cfg.clone(),
                sock_fact,
                local_workload_information.clone(),
                None,
                test_proxy_metrics(),
            ),
            hbone_port: cfg.inbound_addr.port(),
        };

        let local = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();
        let req = outbound
            .build_request(
                local,
                from.parse().unwrap(),
                to.parse().unwrap(),
                &Default::default(),
            )
            .await
            .ok();
        if let Some(ref r) = req {
            assert_eq!(
                expect,
                Some(ExpectedRequest {
                    protocol: r.protocol,
                    hbone_destination: &r
                        .hbone_target_destination
                        .as_ref()
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    destination: &r.actual_destination.to_string(),
                })
            );
        } else {
            assert_eq!(expect, None);
        }
        req
    }

    #[tokio::test]
    async fn build_request_unknown_dest() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_wrong_network() {
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                        length: None,
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 0, 0, 2])],
                    network: "remote".to_string(),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                                app_protocol: 0,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_double_hbone() {
        // example.com service has a workload on remote network.
        // E/W gateway is addressed by an IP.
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                        length: None,
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Address(
                                XdsNetworkAddress {
                                    network: "remote".to_string(),
                                    address: vec![10, 22, 1, 1],
                                    length: None,
                                },
                            ),
                        ),
                        hbone_mtls_port: 15009,
                    }),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                                app_protocol: 0,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
                    network: "remote".to_string(),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
        // example.com service has a workload on remote network.
        // E/W gateway is addressed by a hostname.
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                        length: None,
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Service(XdsService {
                    hostname: "ew-gtw".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 4],
                        length: None,
                    }],
                    ports: vec![Port {
                        service_port: 15009,
                        target_port: 15009,
                        app_protocol: 0,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/remote-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 6])],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        hbone_mtls_port: 15009,
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Hostname(
                                XdsNamespacedHostname {
                                    namespace: Default::default(),
                                    hostname: "ew-gtw".into(),
                                },
                            ),
                        ),
                    }),
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 8080,
                                app_protocol: 0,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 5])],
                    network: "remote".to_string(),
                    services: std::collections::HashMap::from([(
                        "/ew-gtw".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 15009,
                                target_port: 15008,
                                app_protocol: 0,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "127.0.0.5:15008",
            }),
        )
        .await;
        // example.com service has a waypoint and waypoint workload is on remote network.
        // E/W gateway is addressed by an IP.
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                        length: None,
                    }],
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                    waypoint: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Hostname(
                                XdsNamespacedHostname {
                                    namespace: Default::default(),
                                    hostname: "waypoint.com".into(),
                                },
                            ),
                        ),
                        hbone_mtls_port: 15008,
                    }),
                    ..Default::default()
                }),
                XdsAddressType::Service(XdsService {
                    hostname: "waypoint.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 4],
                        length: None,
                    }],
                    ports: vec![Port {
                        service_port: 15008,
                        target_port: 15008,
                        app_protocol: 0,
                    }],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "Kubernetes//Pod/default/remote-waypoint-pod".to_string(),
                    addresses: vec![],
                    network: "remote".to_string(),
                    network_gateway: Some(xds::istio::workload::GatewayAddress {
                        destination: Some(
                            xds::istio::workload::gateway_address::Destination::Address(
                                XdsNetworkAddress {
                                    network: "remote".to_string(),
                                    address: vec![10, 22, 1, 1],
                                    length: None,
                                },
                            ),
                        ),
                        hbone_mtls_port: 15009,
                    }),
                    services: std::collections::HashMap::from([(
                        "/waypoint.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 15008,
                                target_port: 15008,
                                app_protocol: 0,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "Kubernetes//Pod/default/remote-ew-gtw".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
                    network: "remote".to_string(),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_failover_to_remote() {
        // Similar to the double HBONE test that we already have, but it sets up a scenario when
        // load balancing logic will pick a workload on a remote cluster when local workloads are
        // unhealthy, thus showing the expected failover behavior.
        let service = XdsAddressType::Service(XdsService {
            hostname: "example.com".to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "".to_string(),
                address: vec![127, 0, 0, 3],
                length: None,
            }],
            ports: vec![Port {
                service_port: 80,
                target_port: 8080,
                app_protocol: 0,
            }],
            // Prefer routing to workloads on the same network, but when nothing is healthy locally
            // allow failing over to remote networks.
            load_balancing: Some(xds::istio::workload::LoadBalancing {
                routing_preference: vec![
                    xds::istio::workload::load_balancing::Scope::Network.into(),
                ],
                mode: xds::istio::workload::load_balancing::Mode::Failover.into(),
                ..Default::default()
            }),
            ..Default::default()
        });
        let ew_gateway = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/remote-ew-gtw".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[10, 22, 1, 1])],
            network: "remote".to_string(),
            ..Default::default()
        });
        let remote_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/remote-example.com-pod".to_string(),
            addresses: vec![],
            network: "remote".to_string(),
            network_gateway: Some(xds::istio::workload::GatewayAddress {
                destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                    XdsNetworkAddress {
                        network: "remote".to_string(),
                        address: vec![10, 22, 1, 1],
                        length: None,
                    },
                )),
                hbone_mtls_port: 15009,
            }),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                },
            )]),
            ..Default::default()
        });
        let healthy_local_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/local-example.com-pod".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
            network: "".to_string(),
            tunnel_protocol: xds::istio::workload::TunnelProtocol::Hbone.into(),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                },
            )]),
            status: xds::istio::workload::WorkloadStatus::Healthy.into(),
            ..Default::default()
        });
        let unhealthy_local_workload = XdsAddressType::Workload(XdsWorkload {
            uid: "Kubernetes//Pod/default/local-example.com-pod".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
            network: "".to_string(),
            tunnel_protocol: xds::istio::workload::TunnelProtocol::Hbone.into(),
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                },
            )]),
            status: xds::istio::workload::WorkloadStatus::Unhealthy.into(),
            ..Default::default()
        });

        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                service.clone(),
                ew_gateway.clone(),
                remote_workload.clone(),
                healthy_local_workload.clone(),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:8080",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;

        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                service.clone(),
                ew_gateway.clone(),
                remote_workload.clone(),
                unhealthy_local_workload.clone(),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::DOUBLEHBONE,
                hbone_destination: "example.com:80",
                destination: "10.22.1.1:15009",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_remote_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "remote-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_tcp() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::None as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_known_dest_local_node_hbone() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
                name: "test-tcp".to_string(),
                namespace: "ns".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                tunnel_protocol: XdsProtocol::Hbone as i32,
                node: "local-node".to_string(),
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_source_waypoint() {
        run_build_request(
            "127.0.0.2",
            "127.0.0.1:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                            length: None,
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Even though source has a waypoint, we don't use it
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.1:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                            length: None,
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.10:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_waypoint_mismatch_ip() {
        run_build_request(
            "127.0.0.1",
            "[ff06::c3]:80",
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/my-pod".to_string(),
                addresses: vec![
                    Bytes::copy_from_slice(&[127, 0, 0, 2]),
                    Bytes::copy_from_slice(
                        "ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice(),
                    ),
                ],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 11].to_vec(),
                            length: None,
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "127.0.0.11:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_destination_svc_waypoint() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.3:80",
            XdsAddressType::Service(XdsService {
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                    length: None,
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                    app_protocol: 0,
                }],
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                            length: None,
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                ..Default::default()
            }),
            // Should use the waypoint
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.3:80",
                destination: "127.0.0.10:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_empty_service() {
        run_build_request(
            "127.0.0.1",
            "127.0.0.3:80",
            XdsAddressType::Service(XdsService {
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                    length: None,
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 8080,
                    app_protocol: 0,
                }],
                ..Default::default()
            }),
            // Should use the waypoint
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_target_port() {
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![
                XdsAddressType::Service(XdsService {
                    hostname: "example.com".to_string(),
                    addresses: vec![XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                        length: None,
                    }],
                    ports: vec![
                        Port {
                            service_port: 80,
                            target_port: 0, // named port
                            app_protocol: 0,
                        },
                        Port {
                            service_port: 8080,
                            target_port: 0, // named port
                            app_protocol: 0,
                        },
                    ],
                    ..Default::default()
                }),
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/matching-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 80,
                                target_port: 1234,
                                app_protocol: 0,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
                // This pod does not have a port 80 defined at all
                XdsAddressType::Workload(XdsWorkload {
                    uid: "cluster1//v1/Pod/default/unmatching-pod".to_string(),
                    addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 4])],
                    services: std::collections::HashMap::from([(
                        "/example.com".to_string(),
                        PortList {
                            ports: vec![Port {
                                service_port: 8080,
                                target_port: 9999,
                                app_protocol: 0,
                            }],
                        },
                    )]),
                    ..Default::default()
                }),
            ],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:1234",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_host_network() {
        let xds = vec![
            // Normal service
            XdsAddressType::Service(XdsService {
                hostname: "example.com".to_string(),
                addresses: vec![XdsNetworkAddress {
                    network: "".to_string(),
                    address: vec![127, 0, 0, 3],
                    length: None,
                }],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                    app_protocol: 0,
                }],
                ..Default::default()
            }),
            // Workload is host network, so it's going to have the same IP as another workload
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/pod1".to_string(),
                name: "pod1".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                services: std::collections::HashMap::from([(
                    "/example.com".to_string(),
                    PortList {
                        ports: vec![Port {
                            service_port: 80,
                            target_port: 80,
                            app_protocol: 0,
                        }],
                    },
                )]),
                network_mode: NetworkMode::HostNetwork as i32,
                ..Default::default()
            }),
            XdsAddressType::Workload(XdsWorkload {
                uid: "cluster1//v1/Pod/default/pod2".to_string(),
                name: "pod2".to_string(),
                addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 2])],
                network_mode: NetworkMode::HostNetwork as i32,
                ..Default::default()
            }),
        ];
        let res = run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            xds.clone(),
            // Traffic to the service should go to the pod in the service
            Some(ExpectedRequest {
                destination: "127.0.0.2:80",
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
            }),
        )
        .await
        .expect("must resolve");
        // Ensure it actually went to pod1, not the other pod with the same IP
        assert_eq!(
            res.actual_destination_workload.expect("found a dest").name,
            "pod1"
        );

        // Traffic to the node directly. We should forward the request, but as passthrough, rather than
        // associating it with a random pod.
        let res = run_build_request_multi(
            "127.0.0.1",
            "127.0.0.2:80",
            xds.clone(),
            // Traffic to the service should go to the pod in the service
            Some(ExpectedRequest {
                destination: "127.0.0.2:80",
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
            }),
        )
        .await
        .expect("must resolve");
        // Ensure it actually went to pod1, not the other pod with the same IP
        assert_eq!(res.actual_destination_workload, None);
    }

    #[tokio::test]
    async fn multiple_address_workload() {
        let workload = XdsAddressType::Workload(XdsWorkload {
            uid: "cluster1//v1/Pod/ns/test-tcp".to_string(),
            name: "test-tcp".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 2]),
                Bytes::copy_from_slice("ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            tunnel_protocol: XdsProtocol::None as i32,
            node: "remote-node".to_string(),
            ..Default::default()
        });
        // v4 goes go v4
        run_build_request(
            "127.0.0.1",
            "127.0.0.2:80",
            workload.clone(),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "127.0.0.2:80",
            }),
        )
        .await;
        // v6 goes go v6
        run_build_request(
            "127.0.0.1",
            "[ff06::c3]:80",
            workload.clone(),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "[ff06::c3]:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn service_ip_families() {
        initialize_telemetry();
        let workload = XdsAddressType::Workload(XdsWorkload {
            uid: "cluster1//v1/Pod/default/dual".to_string(),
            addresses: vec![
                Bytes::copy_from_slice(&[127, 0, 0, 2]),
                Bytes::copy_from_slice("ff06::c3".parse::<Ipv6Addr>().unwrap().octets().as_slice()),
            ],
            tunnel_protocol: 1,
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList { ports: vec![] },
            )]),
            ..Default::default()
        });
        let svc = |f: IpFamilies| {
            let mut s = XdsService {
                hostname: "example.com".to_string(),
                addresses: vec![
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![127, 0, 0, 3],
                        length: None,
                    },
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: "::3".parse::<Ipv6Addr>().unwrap().octets().into(),
                        length: None,
                    },
                ],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                    app_protocol: 0,
                }],
                ..Default::default()
            };
            s.set_ip_families(f);
            XdsAddressType::Service(s)
        };
        // V6 only should always use V6 IP
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Ipv6Only), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "[ff06::c3]:15008",
            }),
        )
        .await;
        // V4 only should always use V4 IP
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Ipv4Only), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
        // Dual stack should always prefer the original family (here ipv4)
        run_build_request_multi(
            "127.0.0.1",
            "127.0.0.3:80",
            vec![svc(IpFamilies::Dual), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "127.0.0.2:80",
                destination: "127.0.0.2:15008",
            }),
        )
        .await;
        // Dual stack should always prefer the original family (here ipv6)
        run_build_request_multi(
            "::1",
            "[::3]:80",
            vec![svc(IpFamilies::Dual), workload.clone()],
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                hbone_destination: "[ff06::c3]:80",
                destination: "[ff06::c3]:15008",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_passthrough_svc() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsAddressType::Service(XdsService {
                hostname: "example.com".to_string(),
                waypoint: None,
                load_balancing: Some(LoadBalancing {
                    mode: xds::istio::workload::load_balancing::Mode::Passthrough.into(),
                    ..Default::default()
                }),
                addresses: vec![
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 2, 3, 4],
                        length: None,
                    },
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 5, 6, 7],
                        length: None,
                    },
                ],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                    app_protocol: 0,
                }],
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::TCP,
                hbone_destination: "",
                destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn build_request_passthrough_svc_with_waypoint() {
        run_build_request(
            "127.0.0.1",
            "1.2.3.4:80",
            XdsAddressType::Service(XdsService {
                hostname: "example.com".to_string(),
                waypoint: Some(xds::istio::workload::GatewayAddress {
                    destination: Some(xds::istio::workload::gateway_address::Destination::Address(
                        XdsNetworkAddress {
                            network: "".to_string(),
                            address: [127, 0, 0, 10].to_vec(),
                            length: None,
                        },
                    )),
                    hbone_mtls_port: 15008,
                }),
                load_balancing: Some(LoadBalancing {
                    mode: xds::istio::workload::load_balancing::Mode::Passthrough.into(),
                    ..Default::default()
                }),
                addresses: vec![
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 2, 3, 4],
                        length: None,
                    },
                    XdsNetworkAddress {
                        network: "".to_string(),
                        address: vec![1, 5, 6, 7],
                        length: None,
                    },
                ],
                ports: vec![Port {
                    service_port: 80,
                    target_port: 80,
                    app_protocol: 0,
                }],
                ..Default::default()
            }),
            Some(ExpectedRequest {
                protocol: OutboundProtocol::HBONE,
                destination: "127.0.0.10:15008",
                hbone_destination: "1.2.3.4:80",
            }),
        )
        .await;
    }

    #[test]
    fn build_forwarded() {
        assert_eq!(
            super::build_forwarded("127.0.0.1:80".parse().unwrap(), &None),
            r#"for="127.0.0.1:80""#,
        );
        assert_eq!(
            super::build_forwarded("[::1]:80".parse().unwrap(), &None),
            r#"for="[::1]:80""#,
        );
        assert_eq!(
            super::build_forwarded(
                "127.0.0.1:80".parse().unwrap(),
                &Some(ServiceDescription {
                    hostname: "example.com".into(),
                    name: Default::default(),
                    namespace: Default::default(),
                }),
            ),
            r#"for="127.0.0.1:80";host=example.com"#,
        );
    }

    #[tokio::test]
    async fn test_x_forwarded_network_header() {
        initialize_telemetry();

        // Create a test config with a specific network
        let cfg = Arc::new(Config {
            network: "test-network".into(),
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        });

        // Create a source workload and add it to state
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 1])],
            node: "local-node".to_string(),
            ..Default::default()
        };

        let state = new_proxy_state(&[source], &[], &[]);
        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory::default());

        let wi = WorkloadInfo {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            service_account: "default".to_string(),
        };
        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(wi.clone()),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));

        let outbound = OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state: state.clone(),
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sock_fact.clone(),
                local_workload_information: local_workload_information.clone(),
                connection_manager: ConnectionManager::default(),
                resolver: None,
                disable_inbound_freebind: false,
                crl_manager: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(
                cfg.clone(),
                sock_fact,
                local_workload_information.clone(),
                None,
                test_proxy_metrics(),
            ),
            hbone_port: cfg.inbound_addr.port(),
        };

        // Get the source workload from state
        let source_workload = outbound
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();

        // Create a minimal test request with required fields
        let req = Request {
            protocol: OutboundProtocol::HBONE,
            source: source_workload,
            hbone_target_destination: Some(HboneAddress::SocketAddr(
                "10.0.0.1:8080".parse().unwrap(),
            )),
            actual_destination_workload: None,
            intended_destination_service: None,
            actual_destination: "10.0.0.1:8080".parse().unwrap(),
            upstream_sans: vec![],
            final_sans: vec![],
        };

        let remote_addr = "127.0.0.1:12345".parse().unwrap();

        // Test the single HBONE case - header should NOT be added when origin_network is None
        let http_request_no_header = outbound.create_hbone_request(remote_addr, &req, None);
        assert!(
            http_request_no_header
                .headers()
                .get(X_FORWARDED_NETWORK_HEADER)
                .is_none(),
            "x-istio-origin-network header should not be present when origin_network is None (single HBONE)"
        );

        // Test the double HBONE inner request case - header should be added when network is specified
        let network = crate::strng::Strng::from("test-network");
        let http_request_with_header =
            outbound.create_hbone_request(remote_addr, &req, Some(&network));
        assert_eq!(
            http_request_with_header
                .headers()
                .get(X_FORWARDED_NETWORK_HEADER)
                .unwrap(),
            "test-network",
            "x-istio-origin-network header should contain the network name for double HBONE inner request"
        );
    }

    /// Builds an `OutboundConnection` over the given XDS state (plus the well-known
    /// `source-workload`), for tests that need to drive the connect path rather than just
    /// `build_request`.
    async fn test_outbound_connection(
        workloads: Vec<XdsWorkload>,
        services: Vec<XdsService>,
    ) -> OutboundConnection {
        let cfg = Arc::new(Config {
            local_node: Some("local-node".to_string()),
            ..crate::config::parse_config().unwrap()
        });
        let source = XdsWorkload {
            uid: "cluster1//v1/Pod/ns/source-workload".to_string(),
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, 1])],
            node: "local-node".to_string(),
            ..Default::default()
        };
        let mut all_workloads = vec![source];
        all_workloads.extend(workloads);
        let state = new_proxy_state(&all_workloads, &services, &[]);

        let sock_fact = Arc::new(crate::proxy::DefaultSocketFactory::default());
        let wi = WorkloadInfo {
            name: "source-workload".to_string(),
            namespace: "ns".to_string(),
            service_account: "default".to_string(),
        };
        let local_workload_information = Arc::new(LocalWorkloadInformation::new(
            Arc::new(wi),
            state.clone(),
            identity::mock::new_secret_manager(Duration::from_secs(10)),
        ));
        OutboundConnection {
            pi: Arc::new(ProxyInputs {
                state,
                cfg: cfg.clone(),
                metrics: test_proxy_metrics(),
                socket_factory: sock_fact.clone(),
                local_workload_information: local_workload_information.clone(),
                connection_manager: ConnectionManager::default(),
                resolver: None,
                disable_inbound_freebind: false,
                crl_manager: None,
            }),
            id: TraceParent::new(),
            pool: WorkloadHBONEPool::new(
                cfg.clone(),
                sock_fact,
                local_workload_information,
                None,
                test_proxy_metrics(),
            ),
            hbone_port: cfg.inbound_addr.port(),
        }
    }

    /// The `example.com` service. Its endpoints come from whichever workloads declare it in
    /// their `services` map, so with no such workloads `build_request` fails with
    /// `NoHealthyUpstream`.
    fn example_service() -> XdsService {
        XdsService {
            hostname: "example.com".to_string(),
            addresses: vec![XdsNetworkAddress {
                network: "".to_string(),
                address: vec![127, 0, 0, 3],
                length: None,
            }],
            ports: vec![Port {
                service_port: 80,
                target_port: 8080,
                app_protocol: 0,
            }],
            ..Default::default()
        }
    }

    fn dest_workload(last_octet: u8, name: &str) -> XdsWorkload {
        XdsWorkload {
            uid: format!("cluster1//v1/Pod/ns/{name}"),
            name: name.to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, last_octet])],
            ..Default::default()
        }
    }

    #[test]
    fn retry_backoff_is_exponential_and_capped() {
        let base = Duration::from_millis(50);
        let max = Duration::from_millis(500);
        let backoff = |retry| OutboundConnection::retry_backoff(retry, base, max);
        // The first retry waits exactly the base; each one after doubles it.
        assert_eq!(backoff(1), Duration::from_millis(50));
        assert_eq!(backoff(2), Duration::from_millis(100));
        assert_eq!(backoff(3), Duration::from_millis(200));
        assert_eq!(backoff(4), Duration::from_millis(400));
        // 800ms and up would exceed the ceiling.
        assert_eq!(backoff(5), max);
        assert_eq!(backoff(20), max);
        // The retry count is operator configured, so doubling must saturate, not overflow.
        assert_eq!(backoff(33), max);
        assert_eq!(backoff(usize::MAX), max);
        // `connect_with_retries` never sleeps before the first attempt, but 0 must not
        // underflow either.
        assert_eq!(backoff(0), base);

        for i in 0..40 {
            assert!(backoff(i) <= backoff(i + 1), "backoff must not shrink");
            assert!(backoff(i) <= max, "backoff must stay capped");
        }
    }

    #[test]
    fn outbound_connect_defaults() {
        let cfg = crate::config::parse_config().unwrap();
        // Retries are opt-in, so an upgrade does not change connect behavior.
        assert_eq!(cfg.outbound_connect_max_retries, 0);
        assert_eq!(cfg.outbound_connect_base_backoff, Duration::from_millis(10));
        assert_eq!(cfg.outbound_connect_max_backoff, Duration::from_millis(500));
    }

    /// A connect that started `spent` ago. `connect_budget` reads a real clock, so a budget
    /// computed from this is a hair under the ideal value; [`assert_budget`] allows for that.
    fn started_ago(spent: Duration) -> Instant {
        Instant::now() - spent
    }

    #[track_caller]
    fn assert_budget(actual: Duration, expected: Duration) {
        // Whatever the test spent reading the clock comes out of the budget, never gets added
        // to it, so the error is one-sided.
        let slack = Duration::from_millis(50);
        assert!(
            actual <= expected && actual + slack >= expected,
            "expected a budget of about {expected:?}, got {actual:?}"
        );
    }

    #[test]
    fn connect_budget_splits_the_connect_timeout_across_attempts() {
        let budget = OutboundConnection::connect_budget;
        let total = crate::proxy::CONNECTION_TIMEOUT;

        // Nothing spent yet: three attempts (the first, plus two retries) each get a
        // third of the budget, not a full `CONNECTION_TIMEOUT` apiece.
        assert_budget(budget(started_ago(Duration::ZERO), 0, 2), total / 3);
        // An unretried connect still gets the whole thing, so a deployment that never retries
        // sees exactly the timeout it saw before.
        assert_budget(budget(started_ago(Duration::ZERO), 0, 0), total);

        // Time already spent comes off the top, and what is left is split across the attempts
        // that remain.
        let half = started_ago(total / 2);
        assert_budget(budget(half, 1, 2), total / 4); // half left, two attempts to go
        assert_budget(budget(half, 2, 2), total / 2); // half left, last attempt takes it all

        // An attempt that returned early leaves its unspent share behind: barely any time gone,
        // so the retry gets close to half of the full budget rather than another third.
        assert_budget(
            budget(started_ago(Duration::from_millis(1)), 1, 2),
            total / 2,
        );

        // An overrun does not wrap, and does not hand back a budget an attempt cannot use: the
        // floor is what a connect gets once the earlier attempts have spent everything.
        assert_eq!(
            budget(started_ago(total * 2), 0, 2),
            OutboundConnection::MIN_CONNECT_BUDGET
        );
    }

    #[test]
    fn connect_budget_stops_dividing_at_the_floor() {
        let budget = OutboundConnection::connect_budget;
        let floor = OutboundConnection::MIN_CONNECT_BUDGET;
        let total = crate::proxy::CONNECTION_TIMEOUT;

        // A modest retry count divides nowhere near the floor, so the floor changes nothing
        // about how a normal connect is budgeted.
        assert!(budget(started_ago(Duration::ZERO), 0, 2) > floor);

        // A retry count high enough to slice the budget below the floor stops at it instead.
        // `CONNECTION_TIMEOUT / 400` is 25ms, half the floor.
        assert_eq!(budget(started_ago(Duration::ZERO), 0, 399), floor);
        // And no retry count, however absurd, divides past it.
        assert_eq!(budget(started_ago(Duration::ZERO), 0, usize::MAX), floor);

        // A budget nearly spent, with attempts still owed, hits the floor the same way.
        assert_eq!(
            budget(started_ago(total - Duration::from_millis(1)), 1, 2),
            floor
        );
    }

    #[test]
    fn connect_budget_never_exceeds_the_connect_timeout() {
        // Walk the attempts of a fully retried connect in order, with each one hanging for its
        // whole share -- the worst case. The total spent connecting must still fit in
        // `CONNECTION_TIMEOUT`, which is the point of splitting it up in the first place. Retry
        // counts this low never divide down to the floor, so it cannot buy any overshoot here.
        for max_retries in 0..8 {
            let mut spent = Duration::ZERO;
            for retries in 0..=max_retries {
                let budget =
                    OutboundConnection::connect_budget(started_ago(spent), retries, max_retries);
                assert!(
                    budget <= crate::proxy::CONNECTION_TIMEOUT,
                    "no single attempt may outlast the whole connect"
                );
                spent += budget;
            }
            assert!(
                spent <= crate::proxy::CONNECTION_TIMEOUT,
                "{max_retries} retries spent {spent:?}, over the {:?} budget",
                crate::proxy::CONNECTION_TIMEOUT
            );
        }
    }

    #[test]
    fn connect_budget_floor_bounds_its_own_overshoot() {
        // `connect_budget` on its own, without the deadline check: once the retry count is high
        // enough for the floor to engage, the floor can overrun the budget by one floor per
        // attempt. `deadline_bounds_a_fully_retried_connect` covers how the loop caps that.
        let floor = OutboundConnection::MIN_CONNECT_BUDGET;
        for max_retries in [8usize, 100, 400] {
            let attempts = max_retries + 1;
            let mut spent = Duration::ZERO;
            for retries in 0..=max_retries {
                spent +=
                    OutboundConnection::connect_budget(started_ago(spent), retries, max_retries);
            }
            let bound = crate::proxy::CONNECTION_TIMEOUT + floor * attempts as u32;
            assert!(
                spent <= bound,
                "{max_retries} retries spent {spent:?}, over the {bound:?} worst case"
            );
        }
    }

    #[test]
    fn retry_within_deadline_stops_at_the_connect_timeout() {
        let within = OutboundConnection::retry_within_deadline;
        let total = crate::proxy::CONNECTION_TIMEOUT;
        let backoff = Duration::from_millis(100);

        assert!(within(started_ago(Duration::ZERO), backoff));
        // A retry whose backoff alone would reach the deadline is not worth sleeping for.
        assert!(!within(started_ago(total - backoff), backoff));
        // Once the deadline has passed, nothing more is attempted, whatever the backoff.
        assert!(!within(started_ago(total), Duration::ZERO));
        assert!(!within(started_ago(total * 2), Duration::ZERO));
        // A huge configured backoff must not overflow the check.
        assert!(!within(started_ago(Duration::ZERO), Duration::MAX));
    }

    #[test]
    fn deadline_bounds_a_fully_retried_connect() {
        // Walk a connect where every attempt hangs for its whole budget, the way
        // `connect_with_retries` would: retry only while the deadline allows it. With the
        // deadline check the floor can overrun `CONNECTION_TIMEOUT` by at most one floor, however
        // many retries are configured -- rather than one floor per attempt.
        let floor = OutboundConnection::MIN_CONNECT_BUDGET;
        let total = crate::proxy::CONNECTION_TIMEOUT;
        for max_retries in [0usize, 2, 8, 100, 400, 10_000] {
            let mut spent = Duration::ZERO;
            let mut retries = 0;
            loop {
                spent +=
                    OutboundConnection::connect_budget(started_ago(spent), retries, max_retries);
                if retries >= max_retries
                    || !OutboundConnection::retry_within_deadline(
                        started_ago(spent),
                        Duration::ZERO,
                    )
                {
                    break;
                }
                retries += 1;
            }
            assert!(
                spent <= total + floor,
                "{max_retries} retries spent {spent:?}, over {total:?} plus one floor"
            );
        }
    }

    #[test]
    fn is_retriable_error_classification() {
        let retriable = OutboundConnection::is_retriable_connection_error;
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();

        // Build failures: our view of the mesh may not have caught up yet.
        assert!(retriable(&Error::NoHealthyUpstream(addr)));
        assert!(retriable(&Error::NoValidDestination(Box::new(
            crate::test_helpers::test_default_workload()
        ))));
        assert!(retriable(&Error::NoService(addr)));

        // Connect failures against the endpoint we picked. Retrying these is only worthwhile
        // because selection deprioritizes that endpoint on the way back around.
        assert!(retriable(&Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused
        ))));
        assert!(retriable(&Error::Io(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));

        // A peer that accepted the TCP connection and then stalled: this endpoint is the problem,
        // so another may well answer.
        for stage in [
            HandshakeStage::Tls,
            HandshakeStage::Http2,
            HandshakeStage::Connect,
            HandshakeStage::InnerTls,
            HandshakeStage::InnerHttp2,
            HandshakeStage::InnerConnect,
        ] {
            assert!(retriable(&Error::HandshakeTimeout(stage)), "{stage}");
        }
        // An HBONE connect timeout. Retrying cannot outlast the shared `CONNECTION_TIMEOUT`, and
        // with retries on, each attempt's share is short enough to expire on a slow but reachable
        // endpoint.
        assert!(retriable(&Error::MaybeHBONENetworkPolicyError(
            std::io::Error::from(std::io::ErrorKind::TimedOut)
        )));

        // A peer that answered and refused: this carries RBAC denials, which a retry cannot
        // change.
        assert!(!retriable(&Error::HttpStatus(
            http::StatusCode::UNAUTHORIZED
        )));
        // Except a 5xx to the CONNECT: the destination failed on its side (a 503 when it could not
        // reach its application), and nothing was sent to it, so another endpoint can serve this.
        assert!(retriable(&Error::HttpStatus(
            http::StatusCode::SERVICE_UNAVAILABLE
        )));
        assert!(retriable(&Error::HttpStatus(
            http::StatusCode::INTERNAL_SERVER_ERROR
        )));
        assert!(retriable(&Error::HttpStatus(http::StatusCode::BAD_GATEWAY)));
        assert!(retriable(&Error::HttpStatus(
            http::StatusCode::GATEWAY_TIMEOUT
        )));
        // A deliberate security outcome, not a flaky endpoint.
        assert!(!retriable(&Error::CertificateRevoked));
        // Our own shutdown: every endpoint fails the same way.
        assert!(!retriable(&Error::WorkloadHBONEPoolDraining));

        // Nothing a retry can influence.
        assert!(!retriable(&Error::SelfCall));
        assert!(!retriable(&Error::NoWorkloadEndpoints(
            "example.com".to_string()
        )));
        assert!(!retriable(&Error::NoResolvedAddresses(
            "example.com".to_string()
        )));
        assert!(!retriable(&Error::UnknownWaypoint(
            "example.com".to_string()
        )));
    }

    /// How many outbound connections the connection manager is currently listing, read the same
    /// way the admin dump reads them.
    fn listed_outbound(cm: &ConnectionManager) -> usize {
        let dump = serde_json::to_value(cm).expect("connection manager serializes");
        dump["outbound"]
            .as_array()
            .expect("dump has an outbound array")
            .len()
    }

    /// A connection stays listed for as long as it is open, not just while it is being
    /// established. The tracking guard is created inside the connect, so `connect_with_retries`
    /// has to hand it back and `proxy_to` has to hold it across the splice -- dropping it when the
    /// connect returns would leave a busy ztunnel reporting no outbound connections at all.
    #[tokio::test]
    async fn an_open_connection_stays_listed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        initialize_telemetry();
        let upstream = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        let dest = upstream.local_addr().unwrap();
        let mut oc =
            test_outbound_connection(vec![dest_workload(2, "dest-workload")], vec![]).await;
        let cm = oc.pi.connection_manager.clone();

        // A downstream connection for `proxy_to` to splice.
        let downstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(downstream.local_addr().unwrap())
            .await
            .unwrap();
        let (source_stream, source_addr) = downstream.accept().await.unwrap();

        assert_eq!(listed_outbound(&cm), 0, "nothing is open yet");

        let proxy = tokio::spawn(async move {
            oc.proxy_to(source_stream, source_addr, dest).await;
        });

        // Round-trip a byte before asserting. Accepting upstream only proves the connect's TCP
        // handshake landed, which this task can observe while `proxy_to` is still returning from
        // the connect; bytes arriving upstream prove it has reached the splice.
        let (mut upstream_side, _) = upstream.accept().await.unwrap();
        client.write_all(b"x").await.unwrap();
        let mut buf = [0u8; 1];
        upstream_side.read_exact(&mut buf).await.unwrap();

        assert_eq!(listed_outbound(&cm), 1, "an open connection must be listed");

        // Closing both ends ends the splice, and the listing with it.
        drop(client);
        drop(upstream_side);
        tokio::time::timeout(Duration::from_secs(5), proxy)
            .await
            .expect("the splice ends once both ends close")
            .unwrap();
        assert_eq!(
            listed_outbound(&cm),
            0,
            "a closed connection must be unlisted"
        );
    }

    #[tokio::test]
    async fn connect_with_retries_succeeds_without_backoff() {
        initialize_telemetry();
        // A real listener, so the TCP connect half actually completes.
        let listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
        let dest = listener.local_addr().unwrap();

        let mut oc =
            test_outbound_connection(vec![dest_workload(2, "dest-workload")], vec![]).await;

        let start = Instant::now();
        let (connected, derived_workload, _builder, req, _conn_guard) = oc
            .connect_with_retries("127.0.0.1:1234".parse().unwrap(), dest, 2, start)
            .await
            .expect("connect to a live listener should succeed");

        assert!(matches!(connected, ConnectedUpstream::Tcp(_)));
        // Only double HBONE derives a workload while connecting.
        assert!(derived_workload.is_none());
        assert_eq!(req.protocol, OutboundProtocol::TCP);
        assert_eq!(req.actual_destination, dest);
        // Nothing failed, so no backoff was paid.
        assert!(
            start.elapsed() < oc.configured_retry_backoff(1),
            "a first-try success must not sleep"
        );
    }

    #[tokio::test]
    async fn connect_with_retries_retries_a_refused_connect() {
        initialize_telemetry();
        // Bind to grab a free port, then drop the listener so the connect is refused.
        let dest = {
            let listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
            listener.local_addr().unwrap()
        };

        let mut oc =
            test_outbound_connection(vec![dest_workload(2, "dest-workload")], vec![]).await;

        let start = Instant::now();
        let res = oc
            .connect_with_retries("127.0.0.1:1234".parse().unwrap(), dest, 2, start)
            .await;

        // This workload is the only endpoint, so every retry lands back on the same refused
        // address and the connect still fails -- but it must have been retried.
        assert!(
            res.is_none(),
            "a refused connect must not yield an upstream"
        );
        let backoffs: Duration = (1..=2).map(|r| oc.configured_retry_backoff(r)).sum();
        assert!(
            start.elapsed() >= backoffs,
            "a refused connect is retriable, so both backoffs must have been paid"
        );
    }

    #[tokio::test]
    async fn connect_with_retries_retries_build_failures() {
        initialize_telemetry();
        let target: SocketAddr = "127.0.0.3:80".parse().unwrap();
        let mut oc = test_outbound_connection(vec![], vec![example_service()]).await;

        // Sanity check: this destination fails at the *build* step, before any endpoint is
        // selected, with an error that means "state may not have converged yet".
        let local = oc
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();
        let err = oc
            .build_request(
                local,
                "127.0.0.1".parse().unwrap(),
                target,
                &Default::default(),
            )
            .await
            .expect_err("a service with no endpoints has no upstream");
        assert!(matches!(err, Error::NoHealthyUpstream(_)));
        assert!(OutboundConnection::is_retriable_connection_error(&err));

        let start = Instant::now();
        let res = oc
            .connect_with_retries("127.0.0.1:1234".parse().unwrap(), target, 2, start)
            .await;

        // No endpoint ever appears, so the connect still fails -- but each attempt re-reads
        // state, which is what rescues a destination caught mid-rollout.
        assert!(res.is_none());
        let backoffs: Duration = (1..=2).map(|r| oc.configured_retry_backoff(r)).sum();
        assert!(
            start.elapsed() >= backoffs,
            "a retriable build failure must pay both backoffs"
        );
        // The failure is still reported, from the build arm's early-deny log.
        crate::telemetry::testing::assert_contains(std::collections::HashMap::from([
            ("error", "no healthy upstream: 127.0.0.3:80"),
            ("message", "connection failed"),
        ]));
    }

    #[tokio::test]
    async fn connect_with_retries_stops_at_the_deadline() {
        initialize_telemetry();
        // A refused connect is retriable and fails fast, so without the deadline this would
        // happily burn through every configured retry.
        let dest = {
            let listener = tokio::net::TcpListener::bind("127.0.0.2:0").await.unwrap();
            listener.local_addr().unwrap()
        };
        let mut oc =
            test_outbound_connection(vec![dest_workload(2, "dest-workload")], vec![]).await;

        // The connect budget is already spent, so the first failure must end the loop.
        let start = started_ago(crate::proxy::CONNECTION_TIMEOUT);
        let before = Instant::now();
        let res = oc
            .connect_with_retries("127.0.0.1:1234".parse().unwrap(), dest, 1000, start)
            .await;

        assert!(res.is_none());
        assert!(
            before.elapsed() < oc.configured_retry_backoff(1),
            "a connect past its deadline must not sleep for a retry"
        );
    }

    #[tokio::test]
    async fn connect_with_retries_stops_build_retries_at_the_deadline() {
        initialize_telemetry();
        // No endpoints, so every build fails with a retriable `NoHealthyUpstream`.
        let target: SocketAddr = "127.0.0.3:80".parse().unwrap();
        let mut oc = test_outbound_connection(vec![], vec![example_service()]).await;

        let start = started_ago(crate::proxy::CONNECTION_TIMEOUT);
        let before = Instant::now();
        let res = oc
            .connect_with_retries("127.0.0.1:1234".parse().unwrap(), target, 1000, start)
            .await;

        assert!(res.is_none());
        assert!(
            before.elapsed() < oc.configured_retry_backoff(1),
            "a build failure past the deadline must not sleep for a retry"
        );
        // The give-up is still reported.
        crate::telemetry::testing::assert_contains(std::collections::HashMap::from([
            ("error", "no healthy upstream: 127.0.0.3:80"),
            ("message", "connection failed"),
        ]));
    }

    #[tokio::test]
    async fn build_request_skips_deprioritized_endpoint() {
        initialize_telemetry();
        let svc_addr: SocketAddr = "127.0.0.3:80".parse().unwrap();
        let backend = |name: &str, last_octet: u8| XdsWorkload {
            uid: format!("cluster1//v1/Pod/ns/{name}"),
            name: name.to_string(),
            namespace: "ns".to_string(),
            addresses: vec![Bytes::copy_from_slice(&[127, 0, 0, last_octet])],
            services: std::collections::HashMap::from([(
                "/example.com".to_string(),
                PortList {
                    ports: vec![Port {
                        service_port: 80,
                        target_port: 8080,
                        app_protocol: 0,
                    }],
                },
            )]),
            ..Default::default()
        };
        let (backend_a, backend_b) = (backend("backend-a", 10), backend("backend-b", 11));
        let addr_a: SocketAddr = "127.0.0.10:8080".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.11:8080".parse().unwrap();

        let oc = test_outbound_connection(
            vec![backend_a.clone(), backend_b.clone()],
            vec![example_service()],
        )
        .await;
        let local = oc
            .pi
            .local_workload_information
            .get_workload()
            .await
            .unwrap();
        let downstream: IpAddr = "127.0.0.1".parse().unwrap();

        let build = async |deprioritized: &DeprioritizedEndpoints| {
            oc.build_request(local.clone(), downstream, svc_addr, deprioritized)
                .await
                .expect("service has healthy endpoints")
                .actual_destination
        };

        // Selection is random, so sample it enough times that a preference which only mostly
        // holds would show up. Baseline: both endpoints get picked.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..50 {
            seen.insert(build(&Default::default()).await);
        }
        assert_eq!(
            seen,
            std::collections::HashSet::from_iter([addr_a, addr_b]),
            "both endpoints must be reachable without a deprioritized list"
        );

        // Deprioritizing one endpoint pins every build to the other, which is what makes a retry
        // worth attempting at all.
        let mut deprioritized = DeprioritizedEndpoints::default();
        deprioritized.push(backend_a.uid.as_str().into());
        for _ in 0..50 {
            assert_eq!(
                build(&deprioritized).await,
                addr_b,
                "a deprioritized endpoint must not be re-selected while another remains"
            );
        }
    }

    #[derive(PartialEq, Debug)]
    struct ExpectedRequest<'a> {
        protocol: OutboundProtocol,
        hbone_destination: &'a str,
        destination: &'a str,
    }
}
