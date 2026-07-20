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
use std::sync::{Arc, RwLock};

use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{CertificateError, CommonState, RootCertStore};
use tokio::sync::watch;
use tracing::warn;
use webpki::{CertRevocationList, KeyUsage};

use crate::identity::Identity;
use crate::proxy::Metrics;
use crate::proxy::metrics::Reporter;
use crate::tls::crl::CrlManager;
use crate::tls::verifier::verify_cert_chain;

// CRL revocation enforcement for existing connections, shared by both directions:
//
// - inbound (`crate::proxy::h2::server::serve_connection`) checks the peer (client) chain
// - outbound (`crate::proxy::h2::client::drive_connection`) checks the upstream server chain
// - in both cases, on revocation the connection's serving task tears the connection down abruptly
//   (a security event), attributing the termination as `CERT_REVOKED` in the access log
//
// `CrlManager::register` tracks a connection at handshake and returns a `RevocationHandle` the tunnel
// holds for its lifetime. On a CRL reload, `CrlManager`'s worker runs `RevocationIndex::navigate`,
// which re-checks only the connections under the CA(s) whose subject DN matches CRL(s) issuer DN by
// walking the issuer-keyed index rather than waking every connection.
// webpki (`verify_cert_chain`) remains the sole judge of revocation.

/// Inputs captured at handshake time to enforce CRL revocation on one HBONE tunnel.
/// Captured because the peer chain is no longer retrievable once the h2 handshake consumes the `TlsStream`.
pub struct ConnRegistration {
    /// peer chain (leaf first).
    /// re-verified via [`verify_cert_chain`] — same webpki path used at handshake time
    chain: Vec<CertificateDer<'static>>,
    /// Trust anchors the peer chain is verified against, matching what the handshake-time verifier used.
    roots: Arc<RootCertStore>,
    /// `client_auth` for an inbound peer (client) chain, `server_auth` for an outbound peer (server) chain.
    key_usage: KeyUsage,
    /// Directional rejection-metric reporter: `destination` inbound, `source` outbound.
    reporter: Reporter,
    /// Peer identity, retained only so a revocation termination is attributable in logs.
    peer_identity: Option<Identity>,
    /// time connection was established.
    /// used in webpki re-verification so expiry/not-yet-valid can never spuriously trip the CRL re-check.
    established: UnixTime,
}

impl ConnRegistration {
    /// from_conn captures all info needed for webpki re-verification during CRL load event
    pub fn from_conn(
        conn_state: &CommonState,
        roots: Arc<RootCertStore>,
        key_usage: KeyUsage,
        reporter: Reporter,
    ) -> Self {
        let chain = conn_state
            .peer_certificates()
            .map(|certs| certs.iter().map(|c| c.clone().into_owned()).collect())
            .unwrap_or_default();
        let peer_identity = crate::tls::identity_from_connection(conn_state);
        Self {
            chain,
            roots,
            key_usage,
            reporter,
            peer_identity,
            established: UnixTime::now(),
        }
    }

    fn peer(&self) -> String {
        self.peer_identity
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), |id| id.to_string())
    }
}

/// Per-connection revocation state + teardown signal, held by the tunnel's task for the connection's lifetime.
/// Dropping it deregisters the connection from the [`RevocationIndex`].
pub struct RevocationHandle {
    /// revocation signal receiver the crl manager's index navigation sends when a connection's cert chain is revoked
    revoked_rx: watch::Receiver<bool>,
    /// peer identity (client cert inbound, server cert outbound), for the access log attribution
    peer_identity: Option<Identity>,
    /// deregisters owner connection from the crl manager's index during drop
    _guard: LeafGuard,
}

impl RevocationHandle {
    /// receiver for this connection's revocation signal
    pub fn subscribe_revoked(&self) -> watch::Receiver<bool> {
        self.revoked_rx.clone()
    }

    /// peer identity string for access log attribution
    pub fn peer(&self) -> String {
        self.peer_identity
            .as_ref()
            .map_or_else(|| "<unknown>".to_string(), |id| id.to_string())
    }

    /// Resolves only when a CRL update actually revokes a cert in this connection's chain.
    /// CRL reloads that don't affect this chain are ignored, so connection is torn down strictly on revocation.
    pub async fn revoked(&mut self) {
        // The index's navigation sends the signal (after recording the metric); just await it
        loop {
            if *self.revoked_rx.borrow_and_update() {
                return;
            }
            if self.revoked_rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// re-run the webpki chain-validation path against a chain that was accepted at handshake.
/// only `CertificateError::Revoked` is considered for revocation status.
fn chain_is_revoked(
    crl_manager: &CrlManager,
    chain: &[CertificateDer<'static>],
    roots: &RootCertStore,
    key_usage: KeyUsage,
    established: UnixTime,
) -> bool {
    let Some((end_entity, intermediates)) = chain.split_first() else {
        return false;
    };
    matches!(
        verify_cert_chain(
            end_entity,
            intermediates,
            roots,
            established, // use conn established time instead of current to avoid supurious CertExpired errors
            key_usage,
            Some(crl_manager)
        ),
        Err(rustls::Error::InvalidCertificate(CertificateError::Revoked))
    )
}

/// Resolves only when a CRL update revokes a cert in this connection's chain (via [`RevocationHandle::revoked`]).
pub async fn wait_for_revocation(handle: Option<&mut RevocationHandle>) {
    match handle {
        None => std::future::pending().await,
        Some(h) => h.revoked().await,
    }
}

// -------------------------------------------------------------
// CRL manager's index for re-validating existing connections
// -------------------------------------------------------------

/// DER-encoded x509 `Name` (subject or issuer), in webpki's encoding (the `SEQUENCE` content,
/// without the outer tag+length) so a cert's DN matches a CRL's `issuer()` byte-for-byte.
type Dn = Vec<u8>;
/// CA node id (root or IA) — globally unique, minted by a monotonic counter (never reused).
type NodeId = u64;
/// Per-tunnel id, minted by a monotonic counter (never reused).
/// Distinguishes tunnels sharing identical peer cert (tunnel multiplex limit is 100).
/// `u64` so the counter cannot realistically wrap over a long-lived proxy's uptime.
type LeafId = u64;

/// x509 serial number, stored as the DER `INTEGER` *content* (value, leading `0x00` sign byte included).
/// used in webpki's [`CertRevocationList::find_serial`] for comparison.
/// created by x509-parser's `raw_serial()`.
/// `Vec` to hold all bytes verbatim so serial of any length isn't truncated (false negative).
type Serial = Vec<u8>;

/// One tracked tunnel, owned by its issuing CA node's `child_leaves`
struct Leaf {
    /// cert chain (leaf -> IA(s), no root) exactly as presented at handshake for identical webpki verification
    chain: Vec<CertificateDer<'static>>,
    established: UnixTime,
    key_usage: KeyUsage,
    reporter: Reporter,
    /// sends when connection is judged revoked.
    /// `Arc` so it can send *outside* the index lock.
    revoked_tx: Arc<watch::Sender<bool>>,
    roots: Arc<RootCertStore>,
    /// leaf cert serial number
    serial: Serial,
}

/// CA node (root or intermediate)
struct CaNode {
    /// Child CA nodes issued by this CA, keyed by the child's serial (unique per issuer)
    child_cas: HashMap<Serial, NodeId>,
    /// Tunnels issued directly by this CA, keyed by a synthetic id
    child_leaves: HashMap<LeafId, Leaf>,
    /// Subject DN — matched against a CRL's issuer during navigation
    subject_dn: Dn,
    /// Serial:
    /// `Some` for intermediate (from cert chain)
    /// `None` for root (cert/serial not sent by peer — only DN is known, from child issuer field or trust store)
    serial: Option<Serial>,
    /// Parent node (`None` for root). Used to prune empty ancestors on deregister.
    parent: Option<NodeId>,
}

#[derive(Default)]
struct IndexInner {
    /// index represents a tree with branches as cert chains (starting at root)
    /// but is a flat hashmap for navigation/lookup speed
    /// note: roots are derived from trust store which only have a subject DN, no serial.
    nodes: HashMap<NodeId, CaNode>,
    next_node_id: NodeId,
    next_leaf_id: LeafId,
}

/// Data for one webpki re-check during CA revocation,
/// cloned out of the index under the snapshot lock so the crypto runs lock-free
struct LeafProbe {
    chain: Vec<CertificateDer<'static>>,
    established: UnixTime,
    key_usage: KeyUsage,
    reporter: Reporter,
    roots: Arc<RootCertStore>,
    revoked_tx: Arc<watch::Sender<bool>>,
}

/// target leaf to drop on a confirmed CA bulk-drop (no per-leaf webpki needed)
struct DropTarget {
    reporter: Reporter,
    revoked_tx: Arc<watch::Sender<bool>>,
}

/// A CA-node bulk-drop candidate: probe `representative` once; if revoked, drop all of `subtree`.
struct CaProbe {
    representative: LeafProbe,
    subtree: Vec<DropTarget>,
}

#[derive(Default)]
struct NavWork {
    leaf_probes: Vec<LeafProbe>,
    ca_probes: Vec<CaProbe>,
}

/// Index of every tracked leaf, owned by [`CrlManager`].
/// Navigation walks only leaves under CRL-issuing CA(s).
/// Root/IA revocation bulk-drops its whole subtree after one confirming webpki call.
/// Leaf revocation re-checks just the leaves whose serial the CRL lists.
/// webpki remains the sole judge of revocation.
///
/// register/deregister take write lock only for map mutations, and
/// navigation snapshots the affected subtree under read lock and then
/// webpki verification and teardown signals run outside the lock.
#[derive(Clone)]
pub struct RevocationIndex {
    metrics: Arc<Metrics>,
    inner: Arc<RwLock<IndexInner>>,
}

impl RevocationIndex {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            inner: Arc::new(RwLock::new(IndexInner::default())),
        }
    }

    /// Track a connection at handshake and return its [`RevocationHandle`].
    /// Inserts the leaf + its CA path into the index,
    /// then runs an immediate self-check against the current CRLs
    /// so a connection registering during/after a reload is still caught.
    pub fn register(&self, crl_manager: &CrlManager, conn: ConnRegistration) -> RevocationHandle {
        let (tx, rx) = watch::channel(false);
        let tx = Arc::new(tx);

        let tracked = self
            .inner
            .write()
            .unwrap()
            .insert(&conn, tx.clone(), &self.metrics); // None if the chain can't be parsed

        // Since the CRL could have been updated since new connection handshake verified,
        // we immediately self-check against the *current* CRLs before the tunnel serves.
        if !crl_manager.get_crls().is_empty()
            && chain_is_revoked(
                crl_manager,
                &conn.chain,
                &conn.roots,
                conn.key_usage,
                conn.established,
            )
        {
            drop_revoked(&self.metrics, conn.reporter, &tx);
        }

        RevocationHandle {
            revoked_rx: rx,
            peer_identity: conn.peer_identity,
            _guard: LeafGuard {
                inner: self.inner.clone(),
                tracked,
            },
        }
    }

    /// Navigate the index and re-evaluate their existing connections after a CRL reload.
    /// Snapshots the matched subtrees under a brief read lock (pre-filtered by serial),
    /// then runs webpki and, on revocation, sends teardown signals outside the lock.
    pub fn navigate(&self, crl_manager: &CrlManager) {
        let crls = crl_manager.get_crls();
        if crls.is_empty() {
            return;
        }
        // group crls by issuer so we can easily find the ca issuer and leaves matching revoked serials
        let mut by_issuer: HashMap<&[u8], Vec<&CertRevocationList<'static>>> = HashMap::new();
        for crl in crls.iter() {
            by_issuer.entry(crl.issuer()).or_default().push(crl);
        }

        let work = self.inner.read().unwrap().collect_work(&by_issuer);

        // Leaf-level revocations: confirm each candidate leaf with webpki
        for p in &work.leaf_probes {
            if chain_is_revoked(crl_manager, &p.chain, &p.roots, p.key_usage, p.established) {
                drop_revoked(&self.metrics, p.reporter, &p.revoked_tx);
            }
        }
        // root or ia revocations: one confirming webpki call on representative leaf, then bulk-drop whole subtree
        for ca in &work.ca_probes {
            let r = &ca.representative;
            if chain_is_revoked(crl_manager, &r.chain, &r.roots, r.key_usage, r.established) {
                for t in &ca.subtree {
                    drop_revoked(&self.metrics, t.reporter, &t.revoked_tx);
                }
            }
        }
    }

    #[cfg(test)]
    fn stats(&self) -> IndexStats {
        let inner = self.inner.read().unwrap();
        IndexStats {
            nodes: inner.nodes.len(),
            roots: inner.nodes.values().filter(|n| n.parent.is_none()).count(),
            leaves: inner.nodes.values().map(|n| n.child_leaves.len()).sum(),
        }
    }
}

#[cfg(test)]
#[derive(Debug, PartialEq, Eq)]
struct IndexStats {
    nodes: usize,
    roots: usize,
    leaves: usize,
}

impl IndexInner {
    fn mint_node(&mut self) -> NodeId {
        let id = self.next_node_id;
        self.next_node_id += 1;
        id
    }

    fn mint_leaf(&mut self) -> LeafId {
        let id = self.next_leaf_id;
        self.next_leaf_id += 1;
        id
    }

    /// Parse the cert chain and insert its CA path + leaf.
    /// Returns `(issuing_node, leaf_id)` to track for deregistration, or `None` if the chain can't be parsed.
    /// Should not return `None` since it's chain was validated at handshake.
    fn insert(
        &mut self,
        conn: &ConnRegistration,
        tx: Arc<watch::Sender<bool>>,
        metrics: &Metrics,
    ) -> Option<(NodeId, LeafId)> {
        // split the connection's peer cert chain into leaf + IA(s)
        let Some((leaf_der, ia_ders)) = conn.chain.split_first() else {
            warn!(
                peer = conn.peer(),
                "crl index: peer presented no certificates; connection not tracked"
            );
            return None;
        };
        let Some(leaf) = parse_cert(leaf_der) else {
            warn!(
                peer = conn.peer(),
                "crl index: could not parse leaf cert; connection not tracked"
            );
            metrics.record_crl_untracked_connection(conn.reporter);
            return None;
        };

        // Parse each IA (leaf-adjacent first) for routing metadata only — DER bytes
        // themselves are retained in the leaf's `chain`. Any parse failure aborts tracking.
        let mut ias: Vec<CertInfo> = Vec::with_capacity(ia_ders.len());
        for der in ia_ders {
            let Some(info) = parse_cert(der) else {
                warn!(
                    peer = conn.peer(),
                    "crl index: could not parse intermediate cert; connection not tracked"
                );
                metrics.record_crl_untracked_connection(conn.reporter);
                return None;
            };
            ias.push(info);
        }

        // root's subject DN is issuer of topmost intermediate (or of leaf, if leaf is issued directly by a root)
        let root_dn = ias
            .last()
            .map(|info| info.issuer_dn.clone())
            .unwrap_or_else(|| leaf.issuer_dn.clone());

        // Descend root → IA_1 → ... → IA_n, creating routing nodes as needed
        let mut cur = self.find_or_create_root(root_dn);
        for info in ias.iter().rev() {
            cur = self.find_or_create_intermediate(cur, info.serial.clone(), &info.subject_dn);
        }

        // `cur` is now the leaf's direct issuer; insert the leaf there
        let leaf_id = self.mint_leaf();
        self.nodes.get_mut(&cur)?.child_leaves.insert(
            leaf_id,
            Leaf {
                chain: conn.chain.clone(),
                roots: conn.roots.clone(),
                key_usage: conn.key_usage,
                established: conn.established,
                reporter: conn.reporter,
                serial: leaf.serial,
                revoked_tx: tx,
            },
        );
        Some((cur, leaf_id))
    }

    fn find_or_create_root(&mut self, subject_dn: Dn) -> NodeId {
        // A root is a top-level node (`parent: None`). Scan for an existing one with this subject DN.
        // The scan is over CA nodes only (leaves live in `child_leaves`), so it is bounded by the
        // CA topology's size, not the connection count.
        if let Some((&id, _)) = self
            .nodes
            .iter()
            .find(|(_, n)| n.parent.is_none() && n.subject_dn == subject_dn)
        {
            return id; // root already exists
        }
        let id = self.mint_node();
        self.nodes.insert(
            id,
            CaNode {
                subject_dn,
                serial: None,
                parent: None,
                child_cas: HashMap::new(),
                child_leaves: HashMap::new(),
            },
        );
        id
    }

    fn find_or_create_intermediate(
        &mut self,
        parent_id: NodeId,
        ia_serial: Serial,
        ia_subject_dn: &Dn,
    ) -> NodeId {
        // lookup the parent node and check the child serial exists
        if let Some(node) = self.nodes.get(&parent_id)
            && let Some(&id) = node.child_cas.get(&ia_serial)
        {
            return id; // exists
        }
        // doesn't exist, create it
        let id = self.mint_node();
        self.nodes.insert(
            id,
            CaNode {
                subject_dn: ia_subject_dn.clone(),
                serial: Some(ia_serial.clone()),
                parent: Some(parent_id),
                child_cas: HashMap::new(),
                child_leaves: HashMap::new(),
            },
        );
        // and update the parent node
        if let Some(p) = self.nodes.get_mut(&parent_id) {
            p.child_cas.insert(ia_serial, id);
        }
        id
    }

    /// Remove a leaf and prune any now-empty ancestor nodes (up to and including a root)
    fn deregister_leaf(&mut self, parent_node: NodeId, leaf: LeafId) {
        if let Some(n) = self.nodes.get_mut(&parent_node) {
            n.child_leaves.remove(&leaf);
        }
        self.prune(parent_node);
    }

    /// Remove dangling ca nodes in the index (i.e. has no child CAs or leaves)
    fn prune(&mut self, mut node: NodeId) {
        loop {
            match self.nodes.get(&node) {
                Some(n) if n.child_cas.is_empty() && n.child_leaves.is_empty() => {} // continue
                _ => return, // missing or non-empty: nothing to prune here or above so exit
            }
            // take ownership so we can read `serial`/`subject_dn` without cloning
            let removed = self.nodes.remove(&node).expect("checked node exists above");
            match removed.parent {
                Some(pid) => {
                    // get the removed ca node's serial and its parent ca node
                    if let (Some(parent_node), Some(s)) =
                        (self.nodes.get_mut(&pid), removed.serial.as_ref())
                    {
                        parent_node.child_cas.remove(s); // remove current node's serial from parent node
                    }
                    node = pid; // set parent node as current node
                }
                None => {
                    return; // no parent: this was a dangling root, already removed from `nodes` above
                }
            }
        }
    }

    fn leaf_probe(&self, leaf: &Leaf) -> LeafProbe {
        LeafProbe {
            chain: leaf.chain.clone(),
            roots: leaf.roots.clone(),
            key_usage: leaf.key_usage,
            established: leaf.established,
            reporter: leaf.reporter,
            revoked_tx: leaf.revoked_tx.clone(),
        }
    }

    /// Walk every node once; a node whose subject DN matches a loaded CRL's issuer is a CRL signer,
    /// so serial-match its children (CAs and leaves) against issuer's CRL(s) to collect webpki re-verification work.
    fn collect_work(
        &self,
        by_issuer: &HashMap<&[u8], Vec<&CertRevocationList<'static>>>,
    ) -> NavWork {
        let mut work = NavWork::default();
        for node in self.nodes.values() {
            // check if ca node is an issuer of any CRLs
            let Some(crls) = by_issuer.get(node.subject_dn.as_slice()) else {
                continue;
            };
            // check issuer's child CA serials for CRL serial match
            for (child_serial, &child_id) in &node.child_cas {
                if serial_in_any(crls, child_serial) {
                    // have a match, collect subtree to be webpki verified and, on success, dropped
                    if let Some(probe) = self.collect_subtree(child_id) {
                        work.ca_probes.push(probe);
                    }
                }
            }
            // check issuer's leaf serials for CRL serial match
            // quick iteration to collect those revoked instead of running everything through webpki flow
            for leaf in node.child_leaves.values() {
                if serial_in_any(crls, &leaf.serial) {
                    work.leaf_probes.push(self.leaf_probe(leaf));
                }
            }
        }
        work
    }

    /// Collect every leaf in the subtree rooted at `ca` so it can be closed.
    /// `representative` is for the confirming webpki call of an IA revocation.
    fn collect_subtree(&self, ca: NodeId) -> Option<CaProbe> {
        let mut representative = None;
        let mut subtree = Vec::new();
        let mut stack = vec![ca];
        while let Some(id) = stack.pop() {
            let Some(node) = self.nodes.get(&id) else {
                continue;
            };
            // collect leaf targets to drop in event webpki returns revoked on IA-level revocation.
            // representative leaf needed to feed to webpki verifier as end entity.
            for leaf in node.child_leaves.values() {
                if representative.is_none() {
                    representative = Some(self.leaf_probe(leaf));
                }
                subtree.push(DropTarget {
                    reporter: leaf.reporter,
                    revoked_tx: leaf.revoked_tx.clone(),
                });
            }
            // if node has child CAs then we need to collect those too
            stack.extend(node.child_cas.values().copied());
        }
        representative.map(|representative| CaProbe {
            representative,
            subtree,
        })
    }
}

fn serial_in_any(crls: &[&CertRevocationList<'static>], serial: &Serial) -> bool {
    crls.iter()
        .any(|crl| matches!(crl.find_serial(serial.as_slice()), Ok(Some(_))))
}

/// Drop a connection by firing a connection's teardown signal and record the CRL-rejection metric on first transition.
/// Idempotent bc a connection can be reached by more than one path for a single revocation —
/// a bulk-drop plus a leaf-serial match in one `navigate`, or
/// a register-time self-check racing a concurrent `navigate`,
fn drop_revoked(metrics: &Metrics, reporter: Reporter, tx: &watch::Sender<bool>) {
    let newly_revoked = tx.send_if_modified(|revoked| {
        if *revoked {
            false
        } else {
            *revoked = true;
            true
        }
    });
    if newly_revoked {
        metrics.record_crl_rejection(reporter);
    }
}

/// Deregisters a leaf from the index when the connection's [`RevocationHandle`] drops.
/// `tracked` is `None` when the chain couldn't be parsed at register time (nothing to remove).
struct LeafGuard {
    inner: Arc<RwLock<IndexInner>>,
    tracked: Option<(NodeId, LeafId)>,
}

impl Drop for LeafGuard {
    fn drop(&mut self) {
        if let Some((node, leaf)) = self.tracked {
            self.inner.write().unwrap().deregister_leaf(node, leaf);
        }
    }
}

/// Subject DN, issuer DN, and serial extracted from a cert (via x509-parser)
struct CertInfo {
    subject_dn: Dn,
    issuer_dn: Dn,
    serial: Serial,
}

/// Parse a cert's subject/issuer DNs and serial via webpki.
/// Subject and issuer DNs are the `Name` SEQUENCE content (webpki's encoding),
/// and the serial is the DER `INTEGER` content (webpki's `find_serial` form).
/// Contents only used for index navigation and pre-checks — webpki remains the sole judge of revocation.
fn parse_cert(der: &CertificateDer) -> Option<CertInfo> {
    let cert = webpki::EndEntityCert::try_from(der).ok()?;
    Some(CertInfo {
        subject_dn: cert.subject().to_vec(),
        issuer_dn: cert.issuer().to_vec(),
        serial: cert.serial().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::helpers::{initialize_telemetry, test_proxy_metrics};
    use crate::tls::WorkloadCertificate;
    use crate::tls::mock::{TEST_ROOT, TEST_ROOT_KEY, TestIdentity, crl_pem_revoking_cert};
    use std::io::Write;
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};
    use tempfile::NamedTempFile;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    // ---- Test Utils ----

    fn crl_manager_empty() -> (NamedTempFile, Arc<CrlManager>) {
        let file = NamedTempFile::new().unwrap();
        let mgr =
            Arc::new(CrlManager::new(file.path().to_path_buf(), test_proxy_metrics()).unwrap());
        (file, mgr)
    }

    fn write_crl(file: &mut NamedTempFile, pem: &str) {
        use std::io::{Seek, SeekFrom};
        file.as_file_mut().set_len(0).unwrap();
        file.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        file.write_all(pem.as_bytes()).unwrap();
        file.flush().unwrap();
    }

    fn conn_reg(
        chain: Vec<CertificateDer<'static>>,
        roots: Arc<RootCertStore>,
    ) -> ConnRegistration {
        ConnRegistration {
            chain,
            roots,
            key_usage: KeyUsage::server_auth(),
            reporter: crate::proxy::metrics::Reporter::source,
            peer_identity: None,
            established: UnixTime::now(),
        }
    }

    type CaMaterial = (rcgen::KeyPair, rcgen::CertificateParams);

    /// A cert and crl signing CA with subject `CN=<cn>` and the given serial.
    fn gen_ca(cn: &str, serial: u64) -> CaMaterial {
        use rcgen::*;
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        p.serial_number = Some(SerialNumber::from(serial));
        let now = SystemTime::now();
        p.not_before = now.into();
        p.not_after = (now + Duration::from_secs(3600)).into();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        p.distinguished_name = dn;
        (kp, p)
    }

    /// A workload leaf (serverAuth+clientAuth, SPIFFE URI SAN) with the given serial.
    fn gen_leaf(spiffe: &str, serial: u64) -> CaMaterial {
        use rcgen::*;
        let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = CertificateParams::default();
        p.serial_number = Some(SerialNumber::from(serial));
        let now = SystemTime::now();
        p.not_before = now.into();
        p.not_after = (now + Duration::from_secs(3600)).into();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "leaf");
        p.distinguished_name = dn;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        p.subject_alt_names = vec![SanType::URI(
            string::Ia5String::try_from(spiffe.to_string()).unwrap(),
        )];
        (kp, p)
    }

    fn self_signed(ca: &CaMaterial) -> CertificateDer<'static> {
        ca.1.self_signed(&ca.0).unwrap().der().clone()
    }

    fn signed_by(subject: &CaMaterial, issuer: &CaMaterial) -> CertificateDer<'static> {
        let iss = rcgen::Issuer::from_params(&issuer.1, &issuer.0);
        subject.1.signed_by(&subject.0, &iss).unwrap().der().clone()
    }

    /// A PEM CRL signed by `issuer` revoking the given serials.
    /// Loaded into crl manager.
    fn crl_pem_signed(issuer: &CaMaterial, crl_number: u64, revoked_serials: &[u64]) -> String {
        use rcgen::*;
        let now = time::OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs: revoked_serials
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(*s),
                    revocation_time: now,
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let iss = Issuer::from_params(&issuer.1, &issuer.0);
        params.signed_by(&iss).unwrap().pem().unwrap()
    }

    /// A CRL signed by `issuer` revoking the given serials, parsed into webpki's
    /// `CertRevocationList` exactly as [`CrlManager`] does — the concrete type `navigate` inspects.
    /// Lets a test call `issuer()`/`find_serial()` directly to assert cross-crate encoding parity.
    fn webpki_crl(
        issuer: &CaMaterial,
        crl_number: u64,
        revoked_serials: &[u64],
    ) -> CertRevocationList<'static> {
        use rcgen::*;
        let now = time::OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs: revoked_serials
                .iter()
                .map(|s| RevokedCertParams {
                    serial_number: SerialNumber::from(*s),
                    revocation_time: now,
                    reason_code: Some(RevocationReason::KeyCompromise),
                    invalidity_date: None,
                })
                .collect(),
            key_identifier_method: KeyIdMethod::Sha256,
        };
        let iss = Issuer::from_params(&issuer.1, &issuer.0);
        let signed = params.signed_by(&iss).unwrap();
        let owned = webpki::OwnedCertRevocationList::from_der(signed.der().as_ref()).unwrap();
        CertRevocationList::from(owned)
    }

    // ---- encoding parity between x509-parser and webpki crates ----

    /// `parse_cert` derives index routing keys, `navigate` matches them against webpki's `CertRevocationList`.
    /// If the byte encodings diverge, `collect_work`'s issuer-DN lookup and
    /// `serial_in_any`'s serial match miss silently and a revoked cert keeps serving (false negative).
    #[test]
    fn parse_cert_matches_webpki_crl_encoding() {
        let ca = gen_ca("parity-ca", 1);
        let ca_der = self_signed(&ca);
        let leaf_der = signed_by(&gen_leaf("spiffe://td/ns/n/sa/a", 99), &ca);

        // The CRL `navigate` would inspect: signed by `ca`, revoking the leaf's serial (99).
        let crl = webpki_crl(&ca, 1, &[99]);

        let ca_info = parse_cert(&ca_der).expect("parse ca cert");
        let leaf_info = parse_cert(&leaf_der).expect("parse leaf cert");

        // subject <-> issuer DN join (what collect_work does):
        // the x509-parser DN (SEQUENCE content) must byte-match webpki's crl.issuer()
        assert_eq!(
            ca_info.subject_dn.as_slice(),
            crl.issuer(),
            "CA subject DN must byte-match webpki CRL issuer()"
        );
        assert_eq!(
            leaf_info.issuer_dn.as_slice(),
            crl.issuer(),
            "leaf issuer DN must byte-match its issuing CA's webpki CRL issuer()"
        );

        // parsed leaf serial must be findable in the webpki CRL listing it.
        assert!(
            matches!(crl.find_serial(leaf_info.serial.as_slice()), Ok(Some(_))),
            "leaf serial (x509-parser raw_serial) must be findable via webpki find_serial"
        );

        // a serial the CRL does not list must not match.
        let other = parse_cert(&signed_by(&gen_leaf("spiffe://td/ns/n/sa/b", 100), &ca))
            .expect("parse other leaf");
        assert!(
            matches!(crl.find_serial(other.serial.as_slice()), Ok(None)),
            "an unrevoked serial must not match"
        );
    }

    // ---- RevocationHandle & cert expiry regression guard ----

    /// Re-checking an existing connection re-runs the shared webpki chain-validation path
    /// against the peer chain captured at *handshake* time.
    /// `wait_for_revocation` must not resolve while the CRL doesn't cover the peer's cert,
    /// and must resolve once a reload revokes it.
    #[tokio::test]
    async fn wait_for_revocation_resolves_on_webpki_revocation() {
        initialize_telemetry();

        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();
        let (server_key, server_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let server_wl = WorkloadCertificate::new(
            server_key.as_bytes(),
            server_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();
        let (client_key, client_cert) = crate::tls::mock::generate_test_certs_with_root(
            &TestIdentity::Identity(id.clone()),
            SystemTime::now(),
            SystemTime::now() + Duration::from_secs(3600),
            None,
            TEST_ROOT_KEY,
        );
        let client_wl = WorkloadCertificate::new(
            client_key.as_bytes(),
            client_cert.as_bytes(),
            vec![TEST_ROOT],
        )
        .unwrap();

        // Start with an empty (non-revoking) CRL so the handshake succeeds.
        let (mut crl_file, crl_mgr) = crl_manager_empty();

        let server_tls = TlsAcceptor::from(Arc::new(
            server_wl.server_config(Some(crl_mgr.clone())).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_tls.accept(stream).await.unwrap()
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = client_wl
            .outbound_connector(vec![id], Some(crl_mgr.clone()))
            .unwrap();
        let client_tls = connector.connect(stream).await.unwrap();
        let _server_tls_stream = accept.await.unwrap();

        let (_, ssl) = client_tls.get_ref();
        let reg = ConnRegistration::from_conn(
            ssl,
            server_wl.root_store(),
            KeyUsage::server_auth(),
            crate::proxy::metrics::Reporter::source,
        );
        // Retain what the expiry-masking regression check at the end needs,
        // since `register` consumes the conn registration.
        let chain = reg.chain.clone();
        let roots = reg.roots.clone();
        let established = reg.established;
        // populate index by registering the connection
        let mut revocation = Some(crl_mgr.register(reg));

        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                wait_for_revocation(revocation.as_mut()) // revocation handle hasn't fired yet
            )
            .await
            .is_err(),
            "must not resolve before the CRL revokes the peer cert"
        );

        // Revoke server cert and directly load CRL so the test is deterministic
        write_crl(
            &mut crl_file,
            &crl_pem_revoking_cert(&server_wl.cert.serial_bytes()),
        );
        crl_mgr.load_crl().unwrap(); // load crl runs index navigation

        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_revocation(revocation.as_mut()), // revocation handle fired
        )
        .await
        .expect("must resolve once the CRL revokes the peer cert");

        // Regression guard for expiry masking revocation.
        // webpki verification should be pinned to the handshake time in the case that
        // an expired cert is still in use for an existing tunnel during revocation event
        // the revocation still passes.
        let past_expiry = UnixTime::since_unix_epoch(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                + Duration::from_secs(7200), // well past the cert's 3600s not_after
        );
        assert!(
            !chain_is_revoked(
                &crl_mgr,
                &chain,
                &roots,
                KeyUsage::server_auth(),
                past_expiry
            ),
            "checking past the cert's not_after yields CertExpired, not Revoked — this is the \
             masking a wall-clock re-check would suffer"
        );
        assert!(
            chain_is_revoked(
                &crl_mgr,
                &chain,
                &roots,
                KeyUsage::server_auth(),
                established
            ),
            "checking at the handshake time still detects the revocation despite later expiry"
        );
    }

    // ---- RevocationIndex behavior ----

    /// A CRL reload closes an existing connection when it revokes the leaf.
    /// Exercises the reload → navigate → signal → teardown pipeline.
    #[tokio::test]
    async fn index_closes_connection_on_leaf_revocation() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        let leaf = gen_leaf("spiffe://td/ns/n/sa/a", 2);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let chain = vec![signed_by(&leaf, &root)];

        let (mut crl_file, crl_mgr) = crl_manager_empty();
        let mut handle = crl_mgr.register(conn_reg(chain, Arc::new(roots)));

        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                wait_for_revocation(Some(&mut handle))
            )
            .await
            .is_err(),
            "must not resolve before the CRL revokes the leaf"
        );

        // root revokes the leaf's serial
        write_crl(&mut crl_file, &crl_pem_signed(&root, 1, &[2]));
        crl_mgr.load_crl().unwrap(); // navigates/inspects index after loading

        tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_revocation(Some(&mut handle)),
        )
        .await
        .expect("navigation must close the connection after its leaf is revoked");
    }

    /// A CRL reload closes an existing connection when it revokes an intermediate.
    /// Exercises [`ConnRegistration::from_conn`] capturing a multi-cert peer chain from a live TLS session,
    /// and drives IA bulk-drop path through handshake + reload + navigate.
    /// If `from_conn` ever dropped or reordered intermediates,
    /// the index would build the wrong tree and this revocation would be missed.
    #[tokio::test]
    async fn wait_for_revocation_resolves_on_intermediate_revocation() {
        initialize_telemetry();

        let id = Identity::from_str("spiffe://td/ns/n/sa/a").unwrap();
        // An intermediate CA signed by TEST_ROOT, and a leaf signed by that intermediate.
        let (ia_key, ia_cert, ia_serial) =
            crate::tls::mock::generate_intermediate_ca(TEST_ROOT_KEY);
        let build_wl = |id: &Identity| {
            let (leaf_key, leaf_cert) = crate::tls::mock::generate_test_certs_with_root(
                &TestIdentity::Identity(id.clone()),
                SystemTime::now(),
                SystemTime::now() + Duration::from_secs(3600),
                None,
                ia_key.as_bytes(),
            );
            // chain = [intermediate, root]; the presented peer chain is therefore [leaf, IA].
            WorkloadCertificate::new(
                leaf_key.as_bytes(),
                leaf_cert.as_bytes(),
                vec![ia_cert.as_bytes(), TEST_ROOT],
            )
            .unwrap()
        };
        let server_wl = build_wl(&id);
        let client_wl = build_wl(&id);

        // Start with an empty (non-revoking) CRL so the handshake succeeds.
        let (mut crl_file, crl_mgr) = crl_manager_empty();

        let server_tls = TlsAcceptor::from(Arc::new(
            server_wl.server_config(Some(crl_mgr.clone())).unwrap(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            server_tls.accept(stream).await.unwrap()
        });

        let stream = TcpStream::connect(addr).await.unwrap();
        let connector = client_wl
            .outbound_connector(vec![id], Some(crl_mgr.clone()))
            .unwrap();
        let client_tls = connector.connect(stream).await.unwrap();
        let _server_tls_stream = accept.await.unwrap();

        let (_, ssl) = client_tls.get_ref();
        let reg = ConnRegistration::from_conn(
            ssl,
            server_wl.root_store(),
            KeyUsage::server_auth(),
            crate::proxy::metrics::Reporter::source,
        );
        // The peer chain captured from the live session must include the intermediate.
        assert_eq!(
            reg.chain.len(),
            2,
            "from_conn must capture the full [leaf, intermediate] peer chain"
        );
        let mut revocation = Some(crl_mgr.register(reg));

        assert!(
            tokio::time::timeout(
                Duration::from_secs(1),
                wait_for_revocation(revocation.as_mut())
            )
            .await
            .is_err(),
            "must not resolve before the CRL revokes the intermediate"
        );

        // Revoke the intermediate (by its serial); the leaf's own serial is never listed, so this
        // can only close the connection via the IA bulk-drop path.
        write_crl(&mut crl_file, &crl_pem_revoking_cert(&ia_serial));
        crl_mgr.load_crl().unwrap();

        tokio::time::timeout(
            Duration::from_secs(1),
            wait_for_revocation(revocation.as_mut()),
        )
        .await
        .expect("bulk-drop must close the connection once its intermediate is revoked");
    }

    /// Register-time self-check closes a connection whose cert is revoked after initial handshake.
    /// Validates that a CRL is loaded after new connection handshake but before conn registration is enforced.
    #[tokio::test]
    async fn index_register_self_check_closes_already_revoked() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        let leaf = gen_leaf("spiffe://td/ns/n/sa/a", 2);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let chain = vec![signed_by(&leaf, &root)];

        // A CRL revoking the leaf is loaded *before* registration.
        let mut crl_file = NamedTempFile::new().unwrap();
        write_crl(&mut crl_file, &crl_pem_signed(&root, 1, &[2]));
        let crl_mgr =
            Arc::new(CrlManager::new(crl_file.path().to_path_buf(), test_proxy_metrics()).unwrap());

        let mut handle = crl_mgr.register(conn_reg(chain, Arc::new(roots)));

        tokio::time::timeout(
            Duration::from_millis(50),
            wait_for_revocation(Some(&mut handle)),
        )
        .await
        .expect("register-time self-check must close an already-revoked connection");
    }

    /// Validate index can insert, deregister, and prune empty ancestors
    #[test]
    fn index_insert_and_deregister_prunes() {
        let root = gen_ca("test-root", 1);
        let ia = gen_ca("test-ia", 2);
        let leaf = gen_leaf("spiffe://td/ns/n/sa/a", 3);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let chain = vec![signed_by(&leaf, &ia), signed_by(&ia, &root)];

        let index = RevocationIndex::new(test_proxy_metrics());
        let (_, crl_mgr) = crl_manager_empty();

        let handle = index.register(&crl_mgr, conn_reg(chain, Arc::new(roots)));
        assert_eq!(
            index.stats(),
            IndexStats {
                nodes: 2,
                roots: 1,
                leaves: 1
            },
            "root node + IA node, one leaf, one root entry"
        );

        drop(handle);
        assert_eq!(
            index.stats(),
            IndexStats {
                nodes: 0,
                roots: 0,
                leaves: 0
            },
            "dropping the handle deregisters the leaf and prunes the empty IA + root nodes"
        );
    }

    /// Validate the bulk-drop path:
    /// revoked ia (serial only) closes the leaf via its IA's subtree
    #[tokio::test]
    async fn index_bulk_drops_subtree_on_ia_revocation() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        let ia = gen_ca("test-ia", 2);
        let leaf = gen_leaf("spiffe://td/ns/n/sa/a", 3);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let chain = vec![signed_by(&leaf, &ia), signed_by(&ia, &root)];

        let (mut crl_file, crl_mgr) = crl_manager_empty();
        let mut handle = crl_mgr.register(conn_reg(chain, Arc::new(roots)));

        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                wait_for_revocation(Some(&mut handle))
            )
            .await
            .is_err(),
            "not revoked before the IA is"
        );

        // root revokes IA, leaf is intentionally absent from CRL
        write_crl(&mut crl_file, &crl_pem_signed(&root, 1, &[2]));
        crl_mgr.load_crl().unwrap(); // after crl load, navigates tree to find any revocations

        tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_revocation(Some(&mut handle)),
        )
        .await
        .expect("bulk-drop must close the leaf when its intermediate CA is revoked");
    }

    /// leaf revocation via IA-signed CRL should close it
    #[tokio::test]
    async fn index_closes_leaf_revoked_by_its_ia() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        let ia = gen_ca("test-ia", 2);
        let leaf = gen_leaf("spiffe://td/ns/n/sa/a", 3);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let chain = vec![signed_by(&leaf, &ia), signed_by(&ia, &root)];

        let (mut crl_file, crl_mgr) = crl_manager_empty();
        let mut handle = crl_mgr.register(conn_reg(chain, Arc::new(roots)));

        // ia revokes leaf serial
        write_crl(&mut crl_file, &crl_pem_signed(&ia, 1, &[3]));
        crl_mgr.load_crl().unwrap(); // after crl load, navigates tree to find any revocations

        tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_revocation(Some(&mut handle)),
        )
        .await
        .expect("leaf revoked by its issuing IA must close");
    }

    /// Subject DN-collision handling:
    /// two IAs share a subject DN but have distinct keys/serials (can happen during a renewal).
    /// revoking one only closes its subtree; other is kept —
    /// webpki's check disambiguates, so no valid connection is spuriously dropped.
    #[tokio::test]
    async fn index_dn_collision_only_revoked_subtree_drops() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        // Same subject DN ("CN=shared-ia"), distinct keys and serials.
        let ia_a = gen_ca("shared-ia", 10);
        let ia_b = gen_ca("shared-ia", 11);
        let leaf_a = gen_leaf("spiffe://td/ns/n/sa/a", 20);
        let leaf_b = gen_leaf("spiffe://td/ns/n/sa/b", 21);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let roots = Arc::new(roots);

        let (mut crl_file, crl_mgr) = crl_manager_empty();
        let mut handle_a = crl_mgr.register(conn_reg(
            vec![signed_by(&leaf_a, &ia_a), signed_by(&ia_a, &root)],
            roots.clone(),
        ));
        let mut handle_b = crl_mgr.register(conn_reg(
            vec![signed_by(&leaf_b, &ia_b), signed_by(&ia_b, &root)],
            roots,
        ));

        // Root revokes IA-A only
        write_crl(&mut crl_file, &crl_pem_signed(&root, 1, &[10]));
        crl_mgr.load_crl().unwrap(); // after crl loaded, navigates index for revocations

        tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_revocation(Some(&mut handle_a)),
        )
        .await
        .expect("revoked IA's connections must close");

        assert!(
            tokio::time::timeout(
                Duration::from_secs(2),
                wait_for_revocation(Some(&mut handle_b))
            )
            .await
            .is_err(),
            "un-revoked, but same DN IA's connections must stay up"
        );
    }

    // ---- topology coverage: shared-IA dedup/prune, bulk fan-out, multi-level, self-check no-op ----

    /// Shared-IA topology:
    /// Two connections issued by the same IA must share a single IA node (dedup),
    /// and dropping one connection must prune only its own leaf — IA node and sibling leaf stay.
    #[test]
    fn index_shared_ia_dedups_and_partial_prunes() {
        let root = gen_ca("shared-root", 1);
        let ia = gen_ca("shared-ia", 2);
        let leaf_a = gen_leaf("spiffe://td/ns/n/sa/a", 3);
        let leaf_b = gen_leaf("spiffe://td/ns/n/sa/b", 4);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let roots = Arc::new(roots);

        let index = RevocationIndex::new(test_proxy_metrics());
        let (_f, crl_mgr) = crl_manager_empty();

        let ia_der = signed_by(&ia, &root);
        let handle_a = index.register(
            &crl_mgr,
            conn_reg(vec![signed_by(&leaf_a, &ia), ia_der.clone()], roots.clone()),
        );
        let handle_b = index.register(
            &crl_mgr,
            conn_reg(vec![signed_by(&leaf_b, &ia), ia_der], roots),
        );

        // Both leaves hang off one shared IA node: root + IA = 2 nodes, not 3.
        assert_eq!(
            index.stats(),
            IndexStats {
                nodes: 2,
                roots: 1,
                leaves: 2
            },
            "two connections under the same IA must dedup to a single IA node"
        );

        // Dropping one connection prunes only its leaf
        // the IA + sibling leaf remain (prune stops at the still-populated IA node).
        drop(handle_a);
        assert_eq!(
            index.stats(),
            IndexStats {
                nodes: 2,
                roots: 1,
                leaves: 1
            },
            "dropping one leaf must not prune the still-populated IA/root"
        );

        // Dropping the last connection prunes the now-empty IA and root.
        drop(handle_b);
        assert_eq!(
            index.stats(),
            IndexStats {
                nodes: 0,
                roots: 0,
                leaves: 0
            },
            "dropping the last leaf prunes the empty IA and root"
        );
    }

    /// Bulk-drop fan-out:
    /// revoked IA must close all leaves beneath it after single confirming webpki call.
    #[tokio::test]
    async fn index_bulk_drop_all_leaves_under_revoked_ia() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        let ia = gen_ca("test-ia", 2);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let roots = Arc::new(roots);
        let ia_der = signed_by(&ia, &root);

        let (mut crl_file, crl_mgr) = crl_manager_empty();
        // register 3 leaves with index using shared ia and root
        let mut handles: Vec<RevocationHandle> = (0..3)
            .map(|i| {
                let leaf = gen_leaf(&format!("spiffe://td/ns/n/sa/{i}"), 10 + i as u64);
                crl_mgr.register(conn_reg(
                    vec![signed_by(&leaf, &ia), ia_der.clone()],
                    roots.clone(),
                ))
            })
            .collect();

        // Revoke IA
        write_crl(&mut crl_file, &crl_pem_signed(&root, 1, &[2]));
        crl_mgr.load_crl().unwrap(); // after crl loaded, navigates index for revocations

        for (i, handle) in handles.iter_mut().enumerate() {
            tokio::time::timeout(Duration::from_secs(2), wait_for_revocation(Some(handle)))
                .await
                .unwrap_or_else(|_| panic!("leaf {i} under the revoked IA must close"));
        }
    }

    /// Multi-level chain (root → IA_1 → IA_2 → leaf):
    /// revoking IA_1 must close a leaf two levels below it.
    /// exercises multi-level insert and subtree walk recursing through a child CA.
    #[tokio::test]
    async fn index_bulk_drop_through_multiple_ia_levels() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        let ia1 = gen_ca("test-ia-1", 2);
        let ia2 = gen_ca("test-ia-2", 3);
        let leaf = gen_leaf("spiffe://td/ns/n/sa/a", 4);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();

        // leaf ← IA_2 ← IA_1 ← root
        let chain = vec![
            signed_by(&leaf, &ia2),
            signed_by(&ia2, &ia1),
            signed_by(&ia1, &root),
        ];

        let (mut crl_file, crl_mgr) = crl_manager_empty();
        let mut handle = crl_mgr.register(conn_reg(chain, Arc::new(roots)));

        // root revokes IA_1
        write_crl(&mut crl_file, &crl_pem_signed(&root, 1, &[2]));
        crl_mgr.load_crl().unwrap();

        tokio::time::timeout(
            Duration::from_secs(2),
            wait_for_revocation(Some(&mut handle)),
        )
        .await
        .expect("revoking an upper-level IA must close a leaf below it");
    }

    /// register-time webpki check must not fire when a CRL is loaded but does not revoke the peer.
    /// connection registered against a populated but unrelated CRL set stays up.
    #[tokio::test]
    async fn index_register_self_check_no_op_when_not_revoked() {
        initialize_telemetry();
        let root = gen_ca("test-root", 1);
        let ia = gen_ca("test-ia", 2);
        let leaf = gen_leaf("spiffe://td/ns/n/sa/a", 3);

        let mut roots = RootCertStore::empty();
        roots.add(self_signed(&root)).unwrap();
        let chain = vec![signed_by(&leaf, &ia), signed_by(&ia, &root)];

        // non-empty CRL revoking irrelevant serial (not in this chain)
        let mut crl_file = NamedTempFile::new().unwrap();
        write_crl(&mut crl_file, &crl_pem_signed(&root, 1, &[99]));
        let crl_mgr =
            Arc::new(CrlManager::new(crl_file.path().to_path_buf(), test_proxy_metrics()).unwrap());

        let mut handle = crl_mgr.register(conn_reg(chain, Arc::new(roots)));

        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                wait_for_revocation(Some(&mut handle))
            )
            .await
            .is_err(),
            "a connection registering against a non-revoking CRL must stay up"
        );
    }

    /// A peer chain whose leaf certificate cannot be parsed leaves the connection untracked for
    /// existing-connection CRL enforcement, and must increment `crl_untracked_connections`.
    #[tokio::test]
    async fn insert_unparseable_cert_increments_untracked_metric() {
        initialize_telemetry();
        let metrics = test_proxy_metrics();
        let file = NamedTempFile::new().unwrap();
        let crl_mgr = CrlManager::new(file.path().to_path_buf(), metrics.clone()).unwrap();

        // Not a valid X.509 certificate, so `parse_cert` fails during index insertion.
        let bad_leaf = CertificateDer::from(vec![0x30, 0x00]);
        let _handle = crl_mgr.register(conn_reg(vec![bad_leaf], Arc::new(RootCertStore::empty())));

        // conn_reg registers with reporter=source.
        let count = metrics
            .crl_untracked_connections
            .get_or_create(&crate::proxy::metrics::CrlLabels {
                reporter: crate::proxy::metrics::Reporter::source,
            })
            .get();
        assert_eq!(
            count, 1,
            "an unparseable leaf cert must increment crl_untracked_connections"
        );
    }
}
