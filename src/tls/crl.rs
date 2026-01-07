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

use notify::RecommendedWatcher;
use notify_debouncer_full::{
    DebounceEventResult, Debouncer, FileIdMap, new_debouncer,
    notify::{RecursiveMode, Watcher},
};
use rustls::pki_types::CertificateDer;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, info, warn};
use webpki::CertRevocationList;

// CrlManager handles certificate revocation list (CRL) validation.
//
// validation notes:
// - webpki's from_der() validates ASN.1 structure, CRL version (v2), and rejects
//   delta CRLs and indirect CRLs with unknown critical extensions
// - time bounds (thisUpdate/nextUpdate) are validated during load and at lookup time
// - signature verification is NOT performed during loading; this implementation
//   relies on the CRL being from a trusted source (e.g., mounted ConfigMap)
// - per RFC 5280 section 3.3, entries may be removed from CRLs after the
//   certificate's validity period expires

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("failed to read CRL file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("failed to parse CRL: {0}")]
    ParseError(String),

    #[error("failed to parse certificate: {0}")]
    CertificateParseError(String),

    #[error("CRL error: {0}")]
    WebPkiError(String),
}

#[derive(Clone)]
pub struct CrlManager {
    inner: Arc<RwLock<CrlManagerInner>>,
}

impl std::fmt::Debug for CrlManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlManager").finish_non_exhaustive()
    }
}

// stores both the webpki CRL and the original DER for time validation at lookup
struct CrlEntry {
    crl: CertRevocationList<'static>,
    der: Vec<u8>,
}

struct CrlManagerInner {
    crl_list: Vec<CrlEntry>,
    crl_path: PathBuf,
    _debouncer: Option<Debouncer<RecommendedWatcher, FileIdMap>>,
}

impl CrlManager {
    /// creates a new CRL manager
    pub fn new(crl_path: PathBuf) -> Result<Self, CrlError> {
        debug!(path = ?crl_path, "initializing crl manager");

        let manager = Self {
            inner: Arc::new(RwLock::new(CrlManagerInner {
                crl_list: Vec::new(),
                crl_path: crl_path.clone(),
                _debouncer: None,
            })),
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

    /// validates CRL time bounds: thisUpdate <= now <= nextUpdate
    /// returns true if valid, false if expired or not yet valid
    fn is_crl_time_valid(
        crl_info: &x509_parser::revocation_list::CertificateRevocationList,
        crl_index: usize,
    ) -> bool {
        use x509_parser::time::ASN1Time;

        let now = ASN1Time::now();
        let tbs = &crl_info.tbs_cert_list;

        // check thisUpdate <= now (CRL must be issued already)
        if tbs.this_update > now {
            warn!(
                crl = crl_index + 1,
                this_update = %tbs.this_update,
                "crl is not yet valid, skipping"
            );
            return false;
        }

        // check now <= nextUpdate (CRL must not be expired)
        if let Some(next_update) = tbs.next_update
            && now > next_update
        {
            warn!(
                crl = crl_index + 1,
                next_update = %next_update,
                "crl is expired, skipping"
            );
            return false;
        }
        // note: if nextUpdate is absent, we accept the CRL (per RFC 5280, nextUpdate is optional)

        true
    }

    pub fn load_crl(&self) -> Result<bool, CrlError> {
        let mut inner = self.inner.write().unwrap();

        debug!(path = ?inner.crl_path, "loading crl");
        let data = std::fs::read(&inner.crl_path)?;

        // empty file means no revocations - this is valid
        if data.is_empty() {
            debug!(path = ?inner.crl_path, "crl file is empty, treating as no revocations");
            let crl_count_changed = !inner.crl_list.is_empty();
            inner.crl_list.clear();
            return Ok(crl_count_changed);
        }

        debug!(bytes = data.len(), "read crl file");

        // parse all CRL blocks (handles concatenated CRLs)
        let der_crls = if data.starts_with(b"-----BEGIN") {
            debug!("crl is in PEM format, extracting all crl blocks");
            Self::parse_pem_crls(&data)?
        } else {
            debug!("crl is in DER format");
            // single DER-encoded CRL
            vec![data]
        };

        // empty PEM file (no CRL blocks) means no revocations
        if der_crls.is_empty() {
            debug!("no crl blocks found, treating as no revocations");
            let crl_count_changed = !inner.crl_list.is_empty();
            inner.crl_list.clear();
            return Ok(crl_count_changed);
        }

        debug!(count = der_crls.len(), "found crl block(s) in file");

        let mut parsed_crls = Vec::new();

        for (idx, der_data) in der_crls.iter().enumerate() {
            // parse with x509-parser for validation and logging
            use x509_parser::prelude::*;
            let (_, crl_info) = CertificateRevocationList::from_der(der_data).map_err(|e| {
                CrlError::ParseError(format!("failed to parse crl {}: {}", idx + 1, e))
            })?;

            let tbs = &crl_info.tbs_cert_list;

            // validate time bounds before accepting the CRL
            if !Self::is_crl_time_valid(&crl_info, idx) {
                // skip this CRL but continue processing others
                continue;
            }

            // parse with webpki for revocation checking
            let owned_crl = webpki::OwnedCertRevocationList::from_der(der_data).map_err(|e| {
                CrlError::WebPkiError(format!("failed to parse crl {}: {:?}", idx + 1, e))
            })?;

            let crl = CertRevocationList::from(owned_crl);

            debug!(
                crl = idx + 1,
                issuer = %tbs.issuer,
                this_update = %tbs.this_update,
                next_update = ?tbs.next_update,
                revoked = tbs.revoked_certificates.len(),
                "loaded crl"
            );

            parsed_crls.push(CrlEntry {
                crl,
                der: der_data.clone(),
            });
        }

        let crl_count_changed = parsed_crls.len() != inner.crl_list.len();

        if crl_count_changed {
            debug!(count = parsed_crls.len(), "crl file changed, reloaded");
        }

        // store parsed CRL objects
        inner.crl_list = parsed_crls;

        debug!(count = inner.crl_list.len(), "crl loaded successfully");
        Ok(crl_count_changed)
    }

    /// parses PEM-encoded CRL data that may contain multiple CRL blocks
    /// returns a Vec of DER-encoded CRLs (empty vec if no blocks found)
    fn parse_pem_crls(pem_data: &[u8]) -> Result<Vec<Vec<u8>>, CrlError> {
        let data_str = std::str::from_utf8(pem_data)
            .map_err(|e| CrlError::ParseError(format!("invalid UTF-8: {}", e)))?;

        let mut crls = Vec::new();
        let mut in_pem = false;
        let mut base64_data = String::new();

        for line in data_str.lines() {
            if line.starts_with("-----BEGIN") {
                in_pem = true;
                base64_data.clear(); // start new CRL block
                continue;
            }
            if line.starts_with("-----END") {
                if in_pem && !base64_data.is_empty() {
                    use base64::Engine;
                    let der = base64::engine::general_purpose::STANDARD
                        .decode(&base64_data)
                        .map_err(|e| {
                            CrlError::ParseError(format!("failed to decode base64: {}", e))
                        })?;
                    crls.push(der);
                    base64_data.clear();
                }
                in_pem = false;
                continue;
            }
            if in_pem {
                base64_data.push_str(line.trim());
            }
        }

        Ok(crls)
    }

    /// checks if a certificate is revoked.
    /// returns true if revoked, false otherwise (including on errors - fail-open policy)
    pub fn is_cert_revoked(&self, cert: &CertificateDer) -> bool {
        match self.check_cert_revocation(cert) {
            Ok(is_revoked) => is_revoked,
            Err(e) => {
                debug!(error = %e, "crl check failed, allowing connection (fail-open)");
                false
            }
        }
    }

    /// internal implementation that returns Result for error handling
    fn check_cert_revocation(&self, cert: &CertificateDer) -> Result<bool, CrlError> {
        use x509_parser::prelude::*;

        let inner = self.inner.read().unwrap();

        // if no CRLs are loaded, try to load them now
        if inner.crl_list.is_empty() {
            drop(inner);
            debug!("crl not loaded, attempting to load now");
            self.load_crl()?;
            // re-check after loading
            let inner = self.inner.read().unwrap();
            if inner.crl_list.is_empty() {
                debug!("no crls loaded, treating certificate as not revoked");
                return Ok(false);
            }
            drop(inner);
            return self.check_cert_revocation(cert);
        }

        // extract certificate serial number using x509-parser
        // webpki doesn't expose cert parsing publicly, so we use x509-parser for this
        let (_, parsed_cert) = X509Certificate::from_der(cert)
            .map_err(|e| CrlError::CertificateParseError(e.to_string()))?;

        let cert_serial = parsed_cert.serial.to_bytes_be();
        debug!(serial = ?cert_serial, "checking certificate");

        // check the certificate against all CRLs, skipping any that have expired since load
        for (idx, entry) in inner.crl_list.iter().enumerate() {
            // re-validate time bounds at lookup time (CRL may have expired since load)
            if let Ok((_, crl_info)) =
                x509_parser::revocation_list::CertificateRevocationList::from_der(&entry.der)
                && !Self::is_crl_time_valid(&crl_info, idx)
            {
                // skip expired CRL
                continue;
            }

            debug!(crl = idx + 1, "checking against crl");

            match entry.crl.find_serial(&cert_serial) {
                Ok(Some(revoked_cert)) => {
                    // note: RemoveFromCrl reason only appears in delta CRLs which webpki
                    // rejects, so we don't need to handle it specially here
                    debug!(
                        serial = ?cert_serial,
                        crl = idx + 1,
                        revocation_date = ?revoked_cert.revocation_date,
                        reason = ?revoked_cert.reason_code,
                        "certificate is revoked"
                    );
                    return Ok(true);
                }
                Ok(None) => {
                    // certificate isn't found in this CRL, continue checking others
                    debug!(crl = idx + 1, "certificate not found in crl");
                    continue;
                }
                Err(e) => {
                    // error during CRL lookup
                    debug!(crl = idx + 1, error = ?e, "error checking crl");
                    return Err(CrlError::WebPkiError(format!("crl lookup failed: {:?}", e)));
                }
            }
        }

        debug!(
            serial = ?cert_serial,
            crl_count = inner.crl_list.len(),
            "certificate is not revoked"
        );
        Ok(false)
    }

    /// checks if any certificate in the chain is revoked.
    /// returns true if any cert is revoked, false otherwise (including on errors - fail-open)
    pub fn is_revoked_chain(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
    ) -> bool {
        debug!(
            chain_length = 1 + intermediates.len(),
            "checking certificate chain against crl"
        );

        // check leaf certificate
        debug!("checking leaf certificate");
        if self.is_cert_revoked(end_entity) {
            debug!("leaf certificate is revoked");
            return true;
        }

        // check all intermediate certificates
        for (idx, intermediate) in intermediates.iter().enumerate() {
            debug!(position = idx, "checking intermediate certificate");
            if self.is_cert_revoked(intermediate) {
                debug!(position = idx, "intermediate certificate is revoked");
                return true;
            }
        }

        false
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
        let mut debouncer = new_debouncer(
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
                                Ok(crl_count_changed) => {
                                    debug!("crl reloaded successfully after file change");
                                    if crl_count_changed {
                                        info!("crl content changed");
                                    }
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
        )
        .map_err(|e| CrlError::ParseError(format!("failed to create debouncer: {}", e)))?;

        // start watching the directory
        debouncer
            .watcher()
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
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_crl_manager_missing_file() {
        let result = CrlManager::new(PathBuf::from("/nonexistent/path/crl.pem"));
        assert!(result.is_ok(), "should handle missing CRL file gracefully");
    }

    #[test]
    fn test_crl_manager_invalid_file() {
        let mut file = NamedTempFile::new().expect("failed to create temporary test file");
        file.write_all(b"not a valid CRL")
            .expect("failed to write test data to temporary file");
        file.flush().expect("failed to flush temporary test file");

        let result = CrlManager::new(file.path().to_path_buf());
        assert!(result.is_err(), "should fail on invalid CRL data");
    }

    #[test]
    fn test_crl_manager_empty_file() {
        let file = NamedTempFile::new().expect("failed to create temporary test file");
        // file is empty by default

        let result = CrlManager::new(file.path().to_path_buf());
        assert!(result.is_ok(), "should handle empty CRL file gracefully");
    }
}
