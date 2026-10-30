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
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateRevocationListDer, UnixTime};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::sync::watch;
use tracing::{debug, warn};
use webpki::{CertRevocationList, KeyUsage, OwnedCertRevocationList};

use crate::proxy::Metrics;
use crate::tls::WorkloadCertificate;
use crate::tls::revocation::{
    ConnRegistration, RevocationHandle, RevocationIndex, verify_cert_chain,
};

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("failed to read CRL file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("failed to parse CRL: {0}")]
    ParseError(String),

    #[error("CRL error: {0}")]
    WebPkiError(String),
}

#[derive(Clone)]
/// CRLs are enforced on both inbound and outbound connections.
/// Existing connections are tracked in the index and applicable ones are re-verified after a CRL load event.
pub struct CrlManager {
    inner: Arc<RwLock<CrlManagerInner>>,
    /// Existing connection enforcement index. CRL reload path drives navigation.
    index: RevocationIndex,
    /// Monotonic counter bumped on every CRL set reload
    generation: Arc<AtomicU64>,
    /// Notifies subscribers after each successful CRL reload. Sends the generation counter.
    crl_reload_tx: watch::Sender<u64>,
    /// Stored for cloning via `subscribe_reloads()`.
    crl_reload_rx: watch::Receiver<u64>,
}

impl std::fmt::Debug for CrlManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlManager").finish_non_exhaustive()
    }
}

struct CrlManagerInner {
    /// Pre-parsed CRLs for webpki's RevocationOptionsBuilder,
    /// avoiding DER re-parse and mem alloc for every outbound handshake and exising connection verification.
    /// None = not loaded, Some = loaded (may be empty).
    crls: Option<Arc<Vec<CertRevocationList<'static>>>>,
    /// Pre-parsed CRL DERs for rustls's with_crls(),
    /// avoiding DER re-parse and mem alloc on `ServerConfig` creation for new inbound mesh TLS connections.
    /// None = not loaded, Some = loaded (may be empty)
    crl_ders: Option<Arc<Vec<CertificateRevocationListDer<'static>>>>,
    crl_path: PathBuf,
    // WARNING: must use FileIdMap, NOT NoCache. Kubernetes secret/configmap volume updates
    // use atomic symlink swaps — FileIdMap tracks inode identity across renames so these
    // are detected correctly. NoCache silently misses them, breaking CRL hot-reload entirely.
    _debouncer: Option<Debouncer<RecommendedWatcher, FileIdMap>>,
}

impl CrlManager {
    /// creates a new CRL manager. `metrics` is used by the owned [`RevocationIndex`] to record
    /// existing-connection revocations.
    pub fn new(crl_path: PathBuf, metrics: Arc<Metrics>) -> Result<Self, CrlError> {
        debug!(path = ?crl_path, "initializing crl manager");

        let (crl_reload_tx, crl_reload_rx) = watch::channel(0u64);
        let manager = Self {
            inner: Arc::new(RwLock::new(CrlManagerInner {
                crls: None,
                crl_ders: None,
                crl_path: crl_path.clone(),
                _debouncer: None,
            })),
            index: RevocationIndex::new(metrics),
            generation: Arc::new(AtomicU64::new(0)),
            crl_reload_tx,
            crl_reload_rx,
        };

        // try to load the CRL, but don't fail if the file doesn't exist yet
        // (it might be mounted later via ConfigMap)
        if let Err(e) = manager.load_crl() {
            match e {
                CrlError::IoError(ref io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                    warn!(
                        path = ?crl_path,
                        "crl file not found, will retry on first validation"
                    );
                }
                _ => {
                    debug!(error = %e, "failed to initialize crl manager");
                    return Err(e);
                }
            }
        }

        Ok(manager)
    }

    /// Track an existing connection for CRL revocation enforcement, returning its [`RevocationHandle`].
    pub fn register(&self, conn: ConnRegistration) -> RevocationHandle {
        self.index.register(self, conn)
    }

    /// Reloads the CRL set from disk and, on success, re-evaluates existing connections against the new set.
    pub fn load_crl(&self) -> Result<(), CrlError> {
        let res = self.reload_crl_data();
        if res.is_ok() {
            self.index.navigate(self);
            let _ = self.crl_reload_tx.send(self.generation());
        }
        res
    }

    /// Reloads and re-parses the CRL set, replacing the cached set.
    fn reload_crl_data(&self) -> Result<(), CrlError> {
        // Snapshot the path under a brief read lock, then release it before blocking on I/O.
        let crl_path = self.inner.read().unwrap().crl_path.clone();

        let (crls, crl_ders) = Self::parse_crl_file(&crl_path)?;

        // Swap in the finished set under a brief write lock.
        {
            let mut inner = self.inner.write().unwrap();
            inner.crls = Some(Arc::new(crls));
            inner.crl_ders = Some(Arc::new(crl_ders));
        }
        // bump generation so connections being simultaneously registered re-verify
        self.generation.fetch_add(1, Ordering::Release);
        Ok(())
    }

    /// Current CRL-reload generation.
    /// Bumped by [`Self::reload_crl_data`] on every reload.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Reads and parses the CRL file into webpki's pre-parsed form.
    /// An empty file — or one with no CRL blocks — is valid and yields an empty set (no revocations)
    fn parse_crl_file(
        crl_path: &Path,
    ) -> Result<
        (
            Vec<CertRevocationList<'static>>,
            Vec<CertificateRevocationListDer<'static>>,
        ),
        CrlError,
    > {
        let data = std::fs::read(crl_path)?;

        // empty file means no revocations - this is valid
        if data.is_empty() {
            debug!(path = ?crl_path, "crl file is empty, treating as no revocations");
            return Ok((Vec::new(), Vec::new()));
        }

        // parse all CRL blocks (handles concatenated CRLs)
        let is_pem = data.starts_with(b"-----BEGIN");
        let der_crls: Vec<CertificateRevocationListDer<'static>> = if is_pem {
            Self::parse_pem_crls(&data)?
        } else {
            vec![CertificateRevocationListDer::from(data)]
        };

        // empty PEM file (no CRL blocks) means no revocations
        if der_crls.is_empty() {
            debug!(path = ?crl_path, "no crl blocks found, treating as no revocations");
            return Ok((Vec::new(), Vec::new()));
        }

        let mut validated_ders: Vec<CertificateRevocationListDer<'static>> =
            Vec::with_capacity(der_crls.len());
        let mut validated_crls: Vec<CertRevocationList<'static>> =
            Vec::with_capacity(der_crls.len());

        for (idx, crl_der) in der_crls.into_iter().enumerate() {
            // parse with webpki to catch errors early and to keep parsed form for new outbound and existing conns verifier hot path.
            // rustls with_crls() takes the pre-wrapped DER directly for new inbound connections.
            let owned = OwnedCertRevocationList::from_der(crl_der.as_ref()).map_err(|e| {
                CrlError::WebPkiError(format!("failed to parse crl {}: {:?}", idx + 1, e))
            })?;

            validated_ders.push(crl_der);
            // Owned variant borrows nothing, so the lifetime can be 'static
            validated_crls.push(CertRevocationList::from(owned));
        }

        debug!(
            path = ?crl_path,
            format = if is_pem { "PEM" } else { "DER" },
            count = validated_crls.len(),
            "crl loaded successfully"
        );
        Ok((validated_crls, validated_ders))
    }

    /// parses PEM-encoded CRL data that may contain multiple CRL blocks
    /// returns a Vec of DER-encoded CRLs (empty vec if no blocks found)
    fn parse_pem_crls(
        pem_data: &[u8],
    ) -> Result<Vec<CertificateRevocationListDer<'static>>, CrlError> {
        CertificateRevocationListDer::pem_slice_iter(pem_data)
            .map(|result| {
                result.map_err(|e| CrlError::ParseError(format!("failed to parse PEM: {}", e)))
            })
            .collect()
    }

    /// returns the pre-wrapped CRL DERs for rustls's with_crls().
    /// callers should `.iter().cloned()` to feed `WebPkiClientVerifier::builder().with_crls(...)`.
    /// if no CRLs are loaded, attempts to load them first.
    pub fn get_crl_ders(&self) -> Arc<Vec<CertificateRevocationListDer<'static>>> {
        let inner = self.inner.read().unwrap();
        if let Some(ref crl_ders) = inner.crl_ders {
            return crl_ders.clone();
        }
        drop(inner);
        debug!("crl not loaded, attempting to load now");
        if let Err(e) = self.reload_crl_data() {
            debug!(error = %e, "failed to load crl");
            return Arc::new(Vec::new());
        }
        let inner = self.inner.read().unwrap();
        if let Some(ref crl_ders) = inner.crl_ders {
            crl_ders.clone()
        } else {
            Arc::new(Vec::new())
        }
    }

    /// returns the pre-parsed CRLs for use by the webpki verifier.
    /// callers should `.iter().collect()` to get `Vec<&CertRevocationList>` for `RevocationOptionsBuilder::new.
    /// if no CRLs are loaded, attempts to load them first.
    pub fn get_crls(&self) -> Arc<Vec<CertRevocationList<'static>>> {
        let inner = self.inner.read().unwrap();
        if let Some(ref crls) = inner.crls {
            return crls.clone();
        }
        drop(inner);
        debug!("crl not loaded, attempting to load now");
        if let Err(e) = self.reload_crl_data() {
            debug!(error = %e, "failed to load crl");
            return Arc::new(Vec::new());
        }
        let inner = self.inner.read().unwrap();
        if let Some(ref crls) = inner.crls {
            crls.clone()
        } else {
            Arc::new(Vec::new())
        }
    }

    /// starts watching the CRL file for changes.
    /// uses debouncer to handle all file update patterns
    pub fn start_file_watcher(self: &Arc<Self>) -> Result<(), CrlError> {
        let crl_path = {
            let inner = self.inner.read().unwrap();
            inner.crl_path.clone()
        };

        // watch the parent directory to catch ConfigMap updates via symlinks
        let watch_path = crl_path
            .parent()
            .ok_or_else(|| CrlError::ParseError("crl path has no parent directory".to_string()))?;

        debug!(
            path = ?watch_path,
            debounce_secs = 2,
            "starting crl file watcher"
        );

        let manager = Arc::clone(self);

        // create debouncer with 2-second timeout
        // this collapses multiple events (CREATE/CHMOD/RENAME/REMOVE) into a single reload
        let mut debouncer = new_debouncer_opt(
            Duration::from_secs(2),
            None,
            move |result: DebounceEventResult| {
                match result {
                    Ok(events) => {
                        if !events.is_empty() {
                            debug!(event_count = events.len(), "crl directory events detected");

                            // reload CRL for any changes in the watched directory
                            // this handles Kubernetes ConfigMap updates (..data symlink changes)
                            // as well as direct file writes and text editor saves
                            debug!("crl directory changed, reloading");
                            match manager.load_crl() {
                                Ok(()) => {
                                    debug!("crl reloaded successfully after file change");
                                }
                                Err(e) => debug!(error = %e, "failed to reload crl"),
                            }
                        }
                    }
                    Err(errors) => {
                        for error in errors {
                            debug!(error = ?error, "crl watcher error");
                        }
                    }
                }
            },
            FileIdMap::new(),
            Config::default(),
        )
        .map_err(|e| CrlError::ParseError(format!("failed to create debouncer: {}", e)))?;

        // start watching the directory
        debouncer
            .watch(watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| CrlError::ParseError(format!("failed to watch directory: {}", e)))?;

        // store debouncer to keep it alive
        {
            let mut inner = self.inner.write().unwrap();
            inner._debouncer = Some(debouncer);
        }

        debug!("crl file watcher started successfully");
        Ok(())
    }

    /// Returns a receiver that fires after each successful CRL reload.
    /// The value is the CRL generation counter at the time of reload.
    pub fn subscribe_reloads(&self) -> watch::Receiver<u64> {
        self.crl_reload_rx.clone()
    }
}

/// Check whether a workload certificate chain is revoked in the currently loaded CRLs.
///
/// This is a diagnostic check: it emits a warning log and increments a metric
/// If the certificate (leaf or intermediate) appears in the CRL set.
pub fn check_own_cert_revocation(
    cert: &WorkloadCertificate,
    crl_manager: &CrlManager,
    metrics: &Metrics,
) {
    let crls = crl_manager.get_crls();
    if crls.is_empty() {
        return;
    }

    let chain_der = cert.cert_and_intermediates_der();
    let (end_entity, intermediates) = match chain_der.split_first() {
        Some((ee, inters)) => (ee, inters),
        None => return,
    };

    match verify_cert_chain(
        end_entity,
        intermediates,
        &cert.root_store(),
        UnixTime::now(),
        KeyUsage::server_auth(),
        &crls,
    ) {
        Err(webpki::Error::CertRevoked) => {
            let identity = cert
                .identity()
                .map(|id| id.to_string())
                .unwrap_or_else(|| "<unknown>".to_string());

            let serial = cert.cert.serial();
            warn!(
                %identity,
                %serial,
                "own workload certificate is revoked in loaded CRL; \
                peers with this CRL will reject connections from this identity"
            );
            metrics.record_own_cert_revoked();
        }
        Err(err) => {
            debug!(
                error = %err,
                "own certificate chain validation failed during CRL self-check \
                (non-revocation error, likely misconfigured roots or unrelated CRL)"
            );
        }
        Ok(_) => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        identity::Identity,
        test_helpers::helpers::test_proxy_metrics,
        tls::mock::{
            TEST_PKEY, TEST_ROOT, TEST_ROOT_KEY, TestIdentity, crl_pem_revoking_cert,
            generate_intermediate_ca, generate_test_certs_at,
        },
    };
    use rcgen::{
        BasicConstraints, CertificateParams, CertificateRevocationListParams, DistinguishedName,
        DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
        PKCS_ECDSA_P256_SHA256, RevocationReason, RevokedCertParams, SanType, SerialNumber, string,
    };
    use std::{io::Write, str::FromStr, time::SystemTime};
    use tempfile::NamedTempFile;
    use time::OffsetDateTime;

    /// A CA's key pair and certificate parameters, used to sign certs and CRLs in tests
    type CaMaterial = (rcgen::KeyPair, rcgen::CertificateParams);

    /// Creates a CA with the given CN and serial, capable of signing certs and CRLs.
    /// Returns the key pair and params ( not yet self-signed, pass to `self_signed`
    /// or use as issuer in `crl_pem_signed`)
    fn gen_ca(cn: &str, serial: u64) -> CaMaterial {
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

    /// Creates a PEM-encoded CRL signed by `issuer` that revokes the given serial numbers.
    /// Each revoked entry uses KeyCompromise as the reason.
    fn crl_pem_signed(issuer: &CaMaterial, crl_number: u64, revoked_serials: &[&[u8]]) -> String {
        let now = OffsetDateTime::now_utc();
        let revoked_certs = revoked_serials
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from_slice(s),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None,
            revoked_certs,
            key_identifier_method: KeyIdMethod::Sha256,
        };

        let iss = Issuer::from_params(&issuer.1, &issuer.0);
        params.signed_by(&iss).unwrap().pem().unwrap()
    }

    #[test]
    fn test_crl_manager_missing_file() {
        let result = CrlManager::new(
            PathBuf::from("/nonexistent/path/crl.pem"),
            test_proxy_metrics(),
        );
        assert!(result.is_ok(), "should handle missing CRL file gracefully");
    }

    #[test]
    fn test_crl_manager_invalid_file() {
        let mut file = NamedTempFile::new().expect("failed to create temporary test file");
        file.write_all(b"not a valid CRL")
            .expect("failed to write test data to temporary file");
        file.flush().expect("failed to flush temporary test file");

        let result = CrlManager::new(file.path().to_path_buf(), test_proxy_metrics());
        assert!(result.is_err(), "should fail on invalid CRL data");
    }

    #[test]
    fn test_crl_manager_empty_file() {
        let file = NamedTempFile::new().expect("failed to create temporary test file");
        // file is empty by default

        let result = CrlManager::new(file.path().to_path_buf(), test_proxy_metrics());
        assert!(result.is_ok(), "should handle empty CRL file gracefully");
    }

    #[test]
    fn test_crl_manager_valid_crl() {
        use rcgen::{
            CertificateParams, CertificateRevocationListParams, Issuer, KeyIdMethod, KeyPair,
            RevocationReason, RevokedCertParams, SerialNumber,
        };

        // generate a CA key pair
        let ca_key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("failed to generate CA key pair");

        // create CA certificate params
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        // create issuer from CA params and key
        let issuer = Issuer::from_params(&ca_params, &ca_key_pair);

        // create CRL with one revoked certificate
        let crl_params = CertificateRevocationListParams {
            this_update: time::OffsetDateTime::now_utc(),
            next_update: time::OffsetDateTime::now_utc() + time::Duration::days(30),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(12345u64),
                revocation_time: time::OffsetDateTime::now_utc(),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        };

        let crl = crl_params.signed_by(&issuer).expect("failed to sign CRL");
        let crl_pem = crl.pem().expect("failed to encode CRL as PEM");

        // write CRL to temp file
        let mut file = NamedTempFile::new().expect("failed to create temporary test file");
        file.write_all(crl_pem.as_bytes())
            .expect("failed to write CRL to temporary file");
        file.flush().expect("failed to flush temporary test file");

        // test that CrlManager can load it
        let manager = CrlManager::new(file.path().to_path_buf(), test_proxy_metrics())
            .expect("should successfully parse valid CRL");

        let ders = manager.get_crl_ders();
        assert_eq!(ders.len(), 1, "should have loaded one CRL DER");

        let crls = manager.get_crls();
        assert_eq!(crls.len(), 1, "should have loaded one CRL");
    }

    #[test]
    fn test_self_check_revoked_cert_detected() {
        let id = Identity::from_str("spiffe://cluster.local/ns/default/sa/test").unwrap();
        let now = SystemTime::now();
        let cert = generate_test_certs_at(
            &TestIdentity::Identity(id),
            now,
            now + Duration::from_secs(3600),
            None,
        );

        // Create CRL that revokes this cert's serial number by the same CA.
        let crl_pem = crl_pem_revoking_cert(&cert.cert.serial_bytes());

        // Write CRL to temp file and create CrlManager
        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        let metrics = test_proxy_metrics();
        let crl_manager = CrlManager::new(crl_file.path().to_path_buf(), metrics.clone()).unwrap();

        assert_eq!(metrics.own_cert_revoked.get(), 0);
        check_own_cert_revocation(&cert, &crl_manager, &metrics);
        assert_eq!(metrics.own_cert_revoked.get(), 1);
    }

    #[test]
    fn test_self_check_non_revoked_cert_passes() {
        let id = Identity::from_str("spiffe://cluster.local/ns/default/sa/test").unwrap();
        let now = SystemTime::now();
        let cert = generate_test_certs_at(
            &TestIdentity::Identity(id),
            now,
            now + Duration::from_secs(3600),
            None,
        );

        // Create CRL that revokes a different serial (all zeros, won't match random serial).
        let crl_pem = crl_pem_revoking_cert(&[0u8; 20]);

        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        let metrics = test_proxy_metrics();
        let crl_manager = CrlManager::new(crl_file.path().to_path_buf(), metrics.clone()).unwrap();

        check_own_cert_revocation(&cert, &crl_manager, &metrics);
        assert_eq!(metrics.own_cert_revoked.get(), 0);
    }

    #[test]
    fn test_self_check_cross_ca_no_false_positive() {
        // Cert issued by TEST_ROOT (CA-A)
        let id = Identity::from_str("spiffe://cluster.local/ns/default/sa/test").unwrap();
        let now = SystemTime::now();
        let cert = generate_test_certs_at(
            &TestIdentity::Identity(id),
            now,
            now + Duration::from_secs(3600),
            None,
        );
        let cert_serial = cert.cert.serial_bytes();

        // CRL signed by a different CA (CA-B), revoking the same serial
        let ca_b = gen_ca("CA-b", 999);
        let crl_pem = crl_pem_signed(&ca_b, 1, &[&cert_serial]);

        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        let metrics = test_proxy_metrics();
        let crl_manager = CrlManager::new(crl_file.path().to_path_buf(), metrics.clone()).unwrap();

        // Same serial, different issuer: webpki must NOT match
        check_own_cert_revocation(&cert, &crl_manager, &metrics);
        assert_eq!(metrics.own_cert_revoked.get(), 0);
    }

    #[test]
    fn test_self_check_no_crls_loaded() {
        let id = Identity::from_str("spiffe://cluster.local/ns/default/sa/test").unwrap();
        let now = SystemTime::now();
        let cert = generate_test_certs_at(
            &TestIdentity::Identity(id),
            now,
            now + Duration::from_secs(3600),
            None,
        );

        // empty crl_file
        let crl_file = NamedTempFile::new().unwrap();
        let metrics = test_proxy_metrics();
        let crl_manager = CrlManager::new(crl_file.path().to_path_buf(), metrics.clone()).unwrap();

        // get_crls() returns empty vec, function returns early
        check_own_cert_revocation(&cert, &crl_manager, &metrics);
        assert_eq!(metrics.own_cert_revoked.get(), 0);
    }

    #[test]
    fn test_self_check_intermediate_ca_revoked() {
        let now = SystemTime::now();

        // generate intermediate CA signed by TEST_ROOT
        let (ia_key_pem, ia_cert_pem, ia_serial) = generate_intermediate_ca(TEST_ROOT_KEY);

        // generate leaf cert signed by intermediate CA
        let leaf_kp = KeyPair::from_pem(str::from_utf8(TEST_PKEY).unwrap()).unwrap();
        let ia_kp = KeyPair::from_pem(&ia_key_pem).unwrap();

        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "cluster.local");

        let mut leaf_params = CertificateParams::default();
        leaf_params.not_before = now.into();
        leaf_params.not_after = (now + Duration::from_secs(3600)).into();
        leaf_params.serial_number = Some(SerialNumber::from(77777u64));
        leaf_params.distinguished_name = dn;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        leaf_params.subject_alt_names = vec![SanType::URI(
            string::Ia5String::try_from("spiffe://cluster.local/ns/default/sa/test".to_string())
                .unwrap(),
        )];

        // intermediate CA is the issuer
        let mut ia_dn = DistinguishedName::new();
        ia_dn.push(DnType::OrganizationName, "cluster.local");

        let mut ia_params = CertificateParams::default();
        ia_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ia_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ia_params.distinguished_name = ia_dn;

        let ia_issuer = Issuer::from_params(&ia_params, &ia_kp);

        let leaf_cert = leaf_params.signed_by(&leaf_kp, &ia_issuer).unwrap();
        let leaf_cert_pem = leaf_cert.pem();
        let leaf_key_pem = leaf_kp.serialize_pem();

        // build chain: leaf + intermediate, root in trust store
        let cert = WorkloadCertificate::new(
            leaf_key_pem.as_bytes(),
            leaf_cert_pem.as_bytes(),
            vec![ia_cert_pem.as_bytes(), TEST_ROOT],
        )
        .unwrap();

        // CRL that revokes the intermediate CA serial ( not the leaf)
        let crl_pem = crl_pem_revoking_cert(&ia_serial);

        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        let metrics = test_proxy_metrics();
        let crl_manager = CrlManager::new(crl_file.path().to_path_buf(), metrics.clone()).unwrap();

        check_own_cert_revocation(&cert, &crl_manager, &metrics);
        assert_eq!(
            metrics.own_cert_revoked.get(),
            1,
            "intermediate CA revocation should be detected via chain-level check"
        );
    }

    #[tokio::test]
    async fn test_crl_reload_notification() {
        // create a valid CRL to load
        let ca_kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let issuer = Issuer::from_params(&ca_params, &ca_kp);
        let now = time::OffsetDateTime::now_utc();

        let crl_params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + time::Duration::days(30),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![],
            key_identifier_method: KeyIdMethod::Sha256,
        };

        let crl_pem = crl_params.signed_by(&issuer).unwrap().pem().unwrap();

        // Write to CRL file
        let mut crl_file = NamedTempFile::new().unwrap();
        crl_file.write_all(crl_pem.as_bytes()).unwrap();
        crl_file.flush().unwrap();

        let metrics = test_proxy_metrics();
        let crl_manager = CrlManager::new(crl_file.path().to_path_buf(), metrics).unwrap();

        // Subscribe before reload.
        let mut rx = crl_manager.subscribe_reloads();

        let initial_gen = crl_manager.generation();

        // trigger a reload
        crl_manager.load_crl().unwrap();
        let next_gen = crl_manager.generation();
        assert!(
            next_gen > initial_gen,
            "generation should increment after reload"
        );

        // the channel should have received the next generation ( tea. earl grey. hot )
        rx.changed().await.expect("channel should not be closed");
        assert_eq!(
            *rx.borrow(),
            next_gen,
            "channel should carry the next generation"
        );
    }
}
