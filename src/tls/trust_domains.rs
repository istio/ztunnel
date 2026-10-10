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

use notify::{Config, RecommendedWatcher};
use notify_debouncer_full::{
    DebounceEventResult, Debouncer, FileIdMap, new_debouncer_opt, notify::RecursiveMode,
};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::strng::Strng;

/// Accepts peers from any trust domain, as sidecars and waypoints do when istiod runs with
/// `PILOT_SKIP_VALIDATE_TRUST_DOMAIN`.
pub const ANY_TRUST_DOMAIN: &str = "*";

#[derive(Debug, thiserror::Error)]
pub enum TrustDomainsError {
    #[error("failed to read trust domains file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("failed to watch trust domains file: {0}")]
    WatchError(String),
}

/// Tracks the trust domains, beyond the one our own certificate is in, that inbound peers may present.
///
/// The set is read from a file istiod publishes (one trust domain per line, or [`ANY_TRUST_DOMAIN`]) and
/// reloaded when it changes,
/// so updates take effect without a restart. New connections are verified against the current set.
/// Existing connections register the trust domain their peer used; when a reload removes that trust domain,
/// only those connections are signalled to close.
#[derive(Clone)]
pub struct TrustDomainManager {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for TrustDomainManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustDomainManager")
            .field("path", &self.inner.path)
            .finish_non_exhaustive()
    }
}

struct Inner {
    path: PathBuf,
    /// The currently accepted set. Read on every inbound handshake, so kept separate from `conns`.
    accepted: RwLock<Arc<HashSet<Strng>>>,
    /// Existing connections, keyed by the trust domain their peer was accepted with.
    /// Reloads swap `accepted` while holding this lock, so a registration either sees the new set
    /// or is present in the map when the reload looks for connections to close.
    conns: Mutex<Conns>,
    // WARNING: must use FileIdMap, NOT NoCache. Kubernetes configmap volume updates
    // use atomic symlink swaps — FileIdMap tracks inode identity across renames so these
    // are detected correctly.
    debouncer: Mutex<Option<Debouncer<RecommendedWatcher, FileIdMap>>>,
}

#[derive(Default)]
struct Conns {
    next_id: u64,
    by_trust_domain: HashMap<Strng, HashMap<u64, watch::Sender<bool>>>,
}

impl TrustDomainManager {
    /// Creates a manager reading `path`. A missing file is not an error: it means no trust domains
    /// are configured beyond our own, and the file may appear later once the ConfigMap exists.
    pub fn new(path: PathBuf) -> Self {
        let manager = Self {
            inner: Arc::new(Inner {
                path,
                accepted: RwLock::new(Arc::new(HashSet::new())),
                conns: Mutex::new(Conns::default()),
                debouncer: Mutex::new(None),
            }),
        };
        match manager.reload() {
            Ok(()) => {}
            Err(TrustDomainsError::IoError(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = ?manager.inner.path, "trust domains file not found, accepting only our own trust domain");
            }
            Err(e) => warn!(path = ?manager.inner.path, error = %e, "failed to load trust domains"),
        }
        manager
    }

    #[cfg(test)]
    pub fn from_trust_domains(trust_domains: &[&str]) -> Self {
        let manager = Self::new(PathBuf::new());
        manager.set(trust_domains.iter().map(|td| Strng::from(*td)).collect());
        manager
    }

    /// The trust domains currently accepted in addition to our own. May contain [`ANY_TRUST_DOMAIN`].
    pub fn accepted(&self) -> Arc<HashSet<Strng>> {
        self.inner.accepted.read().unwrap().clone()
    }

    /// Whether peers from any trust domain are currently accepted.
    pub fn accepts_any(&self) -> bool {
        self.inner
            .accepted
            .read()
            .unwrap()
            .contains(ANY_TRUST_DOMAIN)
    }

    /// Re-reads the file and applies it. On any error the current set is kept: a transiently missing or
    /// unreadable file must not close connections that are still allowed.
    pub fn reload(&self) -> Result<(), TrustDomainsError> {
        let content = std::fs::read_to_string(&self.inner.path)?;
        self.set(parse(&content));
        Ok(())
    }

    fn set(&self, next: HashSet<Strng>) {
        let mut conns = self.inner.conns.lock().unwrap();
        let prev = std::mem::replace(
            &mut *self.inner.accepted.write().unwrap(),
            Arc::new(next.clone()),
        );
        if *prev == next {
            return;
        }
        info!(trust_domains = ?sorted(&next), "accepted trust domains updated");
        // Close connections whose peer trust domain the new set no longer accepts. Checking every tracked trust
        // domain, rather than only the removed entries, also covers ANY_TRUST_DOMAIN being removed.
        let rejected: Vec<Strng> = conns
            .by_trust_domain
            .keys()
            .filter(|td| !accepts(&next, td))
            .cloned()
            .collect();
        for td in rejected {
            let Some(senders) = conns.by_trust_domain.remove(&td) else {
                continue;
            };
            info!(
                trust_domain = %td,
                connections = senders.len(),
                "trust domain no longer accepted, closing its connections"
            );
            for tx in senders.values() {
                let _ = tx.send(true);
            }
        }
    }

    /// Tracks an existing connection whose peer was accepted with `peer_trust_domain`.
    /// Returns `None` when there is nothing to track: the peer is in our own trust domain, which is always
    /// accepted regardless of the configured set.
    pub fn register(
        &self,
        peer_trust_domain: Strng,
        own_trust_domain: Option<&Strng>,
    ) -> Option<TrustDomainHandle> {
        if own_trust_domain == Some(&peer_trust_domain) {
            return None;
        }
        let (tx, rx) = watch::channel(false);
        let mut conns = self.inner.conns.lock().unwrap();
        // The handshake verified against the set at that time; it may have changed since. Checking under the
        // lock reloads take means we cannot miss a removal that happened in between.
        if !accepts(&self.inner.accepted.read().unwrap(), &peer_trust_domain) {
            let _ = tx.send(true);
            return Some(TrustDomainHandle {
                rx,
                trust_domain: peer_trust_domain,
                _guard: None,
            });
        }
        let id = conns.next_id;
        conns.next_id += 1;
        conns
            .by_trust_domain
            .entry(peer_trust_domain.clone())
            .or_default()
            .insert(id, tx);
        Some(TrustDomainHandle {
            rx,
            trust_domain: peer_trust_domain.clone(),
            _guard: Some(Guard {
                inner: Arc::downgrade(&self.inner),
                trust_domain: peer_trust_domain,
                id,
            }),
        })
    }

    /// Starts watching the file for changes. The parent directory is watched, so ConfigMap updates
    /// (an atomic swap of the `..data` symlink) and the file appearing later are both picked up.
    pub fn start_file_watcher(&self) -> Result<(), TrustDomainsError> {
        let watch_path = self.inner.path.parent().ok_or_else(|| {
            TrustDomainsError::WatchError("trust domains path has no parent directory".to_string())
        })?;
        let manager = self.clone();
        let mut debouncer = new_debouncer_opt(
            Duration::from_secs(2),
            None,
            move |result: DebounceEventResult| match result {
                Ok(events) if !events.is_empty() => {
                    debug!("trust domains directory changed, reloading");
                    if let Err(e) = manager.reload() {
                        warn!(error = %e, "failed to reload trust domains, keeping the current set");
                    }
                }
                Ok(_) => {}
                Err(errors) => {
                    for error in errors {
                        debug!(error = ?error, "trust domains watcher error");
                    }
                }
            },
            FileIdMap::new(),
            Config::default(),
        )
        .map_err(|e| TrustDomainsError::WatchError(e.to_string()))?;
        debouncer
            .watch(watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| TrustDomainsError::WatchError(e.to_string()))?;
        *self.inner.debouncer.lock().unwrap() = Some(debouncer);
        Ok(())
    }
}

fn accepts(set: &HashSet<Strng>, trust_domain: &Strng) -> bool {
    set.contains(trust_domain) || set.contains(ANY_TRUST_DOMAIN)
}

/// One trust domain per line; blank lines and `#` comments are ignored.
fn parse(content: &str) -> HashSet<Strng> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(Strng::from)
        .collect()
}

fn sorted(set: &HashSet<Strng>) -> Vec<&Strng> {
    let mut v: Vec<_> = set.iter().collect();
    v.sort();
    v
}

/// Per-connection state held for the connection's lifetime. Dropping it stops tracking the connection.
pub struct TrustDomainHandle {
    rx: watch::Receiver<bool>,
    trust_domain: Strng,
    _guard: Option<Guard>,
}

impl TrustDomainHandle {
    /// Receiver that flips to `true` when the peer's trust domain is no longer accepted.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.rx.clone()
    }

    pub fn trust_domain(&self) -> &Strng {
        &self.trust_domain
    }

    /// Resolves once the peer's trust domain is no longer accepted.
    pub async fn removed(&mut self) {
        loop {
            if *self.rx.borrow_and_update() {
                return;
            }
            if self.rx.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Resolves only when the connection's peer trust domain is removed from the accepted set.
pub async fn wait_for_removal(handle: Option<&mut TrustDomainHandle>) {
    match handle {
        None => std::future::pending().await,
        Some(h) => h.removed().await,
    }
}

struct Guard {
    inner: Weak<Inner>,
    trust_domain: Strng,
    id: u64,
}

impl Drop for Guard {
    fn drop(&mut self) {
        let Some(inner) = self.inner.upgrade() else {
            return;
        };
        let mut conns = inner.conns.lock().unwrap();
        if let Some(senders) = conns.by_trust_domain.get_mut(&self.trust_domain) {
            senders.remove(&self.id);
            if senders.is_empty() {
                conns.by_trust_domain.remove(&self.trust_domain);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn set_of(tds: &[&str]) -> HashSet<Strng> {
        tds.iter().map(|td| Strng::from(*td)).collect()
    }

    fn write(file: &mut NamedTempFile, content: &str) {
        let f = file.as_file_mut();
        f.set_len(0).unwrap();
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(0)).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
    }

    fn tracked(m: &TrustDomainManager) -> usize {
        m.inner
            .conns
            .lock()
            .unwrap()
            .by_trust_domain
            .values()
            .map(HashMap::len)
            .sum()
    }

    #[test]
    fn parse_ignores_blanks_and_comments() {
        assert_eq!(
            parse("# header\ncluster.local\n\n  other.example  \n"),
            set_of(&["cluster.local", "other.example"])
        );
    }

    #[test]
    fn missing_file_accepts_nothing_extra() {
        let m = TrustDomainManager::new(PathBuf::from("/nonexistent/trust-domains"));
        assert!(m.accepted().is_empty());
    }

    #[test]
    fn reload_failure_keeps_current_set() {
        let mut file = NamedTempFile::new().unwrap();
        write(&mut file, "a.example\n");
        let path = file.path().to_path_buf();
        let m = TrustDomainManager::new(path.clone());
        assert_eq!(*m.accepted(), set_of(&["a.example"]));

        drop(file);
        assert!(m.reload().is_err());
        assert_eq!(*m.accepted(), set_of(&["a.example"]));
    }

    #[tokio::test]
    async fn removal_closes_only_that_trust_domain() {
        let mut file = NamedTempFile::new().unwrap();
        write(&mut file, "a.example\nb.example\n");
        let m = TrustDomainManager::new(file.path().to_path_buf());

        let mut a = m.register("a.example".into(), None).unwrap();
        let b = m.register("b.example".into(), None).unwrap();
        assert!(!*a.subscribe().borrow());

        // Adding a trust domain leaves everything open.
        write(&mut file, "a.example\nb.example\nc.example\n");
        m.reload().unwrap();
        assert!(!*a.subscribe().borrow());
        assert!(!*b.subscribe().borrow());

        // Removing one closes only connections that used it.
        write(&mut file, "b.example\nc.example\n");
        m.reload().unwrap();
        tokio::time::timeout(Duration::from_secs(1), a.removed())
            .await
            .expect("a.example connection should be closed");
        assert!(!*b.subscribe().borrow());
        assert_eq!(tracked(&m), 1);
    }

    #[test]
    fn own_trust_domain_is_not_tracked() {
        let m = TrustDomainManager::from_trust_domains(&["cluster.local"]);
        let own = Strng::from("cluster.local");
        assert!(m.register(own.clone(), Some(&own)).is_none());
        assert_eq!(tracked(&m), 0);
    }

    #[test]
    fn register_after_removal_is_closed_immediately() {
        let m = TrustDomainManager::from_trust_domains(&["a.example"]);
        m.set(HashSet::new());
        let h = m.register("a.example".into(), None).unwrap();
        assert!(*h.subscribe().borrow());
        assert_eq!(tracked(&m), 0);
    }

    #[test]
    fn any_trust_domain() {
        let m = TrustDomainManager::from_trust_domains(&["*"]);
        assert!(m.accepts_any());
        let a = m.register("a.example".into(), None).unwrap();
        let b = m.register("b.example".into(), None).unwrap();
        assert!(!*a.subscribe().borrow());

        // Narrowing from any to a list closes connections from trust domains not in it.
        m.set(set_of(&["b.example"]));
        assert!(!m.accepts_any());
        assert!(*a.subscribe().borrow());
        assert!(!*b.subscribe().borrow());
        assert_eq!(tracked(&m), 1);
    }

    #[test]
    fn dropping_handle_stops_tracking() {
        let m = TrustDomainManager::from_trust_domains(&["a.example"]);
        let h = m.register("a.example".into(), None).unwrap();
        assert_eq!(tracked(&m), 1);
        drop(h);
        assert_eq!(tracked(&m), 0);
    }
}
