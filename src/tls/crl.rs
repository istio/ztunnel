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
use rustls::pki_types::CertificateRevocationListDer;
use rustls_pemfile::Item;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, warn};
use webpki::{CertRevocationList, OwnedCertRevocationList};

use crate::proxy::Metrics;
use crate::tls::revocation::{ConnRegistration, RevocationHandle, RevocationIndex};

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

        let manager = Self {
            inner: Arc::new(RwLock::new(CrlManagerInner {
                crls: None,
                crl_ders: None,
                crl_path: crl_path.clone(),
                _debouncer: None,
            })),
            index: RevocationIndex::new(metrics),
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
        Ok(())
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
        let mut reader = std::io::BufReader::new(Cursor::new(pem_data));

        rustls_pemfile::read_all(&mut reader)
            .filter_map(|result| match result {
                Ok(Item::Crl(crl)) => Some(Ok(crl)),
                Ok(_) => None, // skip non-CRL items
                Err(e) => Some(Err(CrlError::ParseError(format!(
                    "failed to parse PEM: {}",
                    e
                )))),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::helpers::test_proxy_metrics;
    use std::io::Write;
    use tempfile::NamedTempFile;

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
}
