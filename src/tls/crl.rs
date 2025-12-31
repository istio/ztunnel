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
use tracing::{debug, error, info, warn};
use webpki::CertRevocationList;

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("failed to read CRL file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("failed to parse CRL: {0}")]
    ParseError(String),

    #[error("failed to parse certificate: {0}")]
    CertificateParseError(String),

    #[error("lock error: {0}")]
    LockError(String),

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

struct CrlManagerInner {
    crl_list: Vec<CertRevocationList<'static>>,
    crl_path: PathBuf,
    _debouncer: Option<Debouncer<RecommendedWatcher, FileIdMap>>,
}

impl CrlManager {
    /// Create a new CRL manager
    pub fn new(crl_path: PathBuf) -> Result<Self, CrlError> {
        debug!("initializing crl manager: path={:?}", crl_path);

        let manager = Self {
            inner: Arc::new(RwLock::new(CrlManagerInner {
                crl_list: Vec::new(),
                crl_path: crl_path.clone(),
                _debouncer: None,
            })),
        };

        // Try to load the CRL, but don't fail if the file doesn't exist yet
        // (it might be mounted later via ConfigMap)
        if let Err(e) = manager.load_crl() {
            match e {
                CrlError::IoError(ref io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                    warn!(
                        "CRL file not found at {:?}, will retry on first validation",
                        crl_path
                    );
                }
                _ => {
                    error!("failed to initialize CRL Manager: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(manager)
    }

    pub fn load_crl(&self) -> Result<bool, CrlError> {
        let mut inner = self
            .inner
            .write()
            .map_err(|e| CrlError::LockError(format!("failed to acquire write lock: {}", e)))?;

        debug!("loading CRL from {:?}", inner.crl_path);
        let data = std::fs::read(&inner.crl_path)?;

        if data.is_empty() {
            warn!("CRL file is empty at {:?}", inner.crl_path);
            return Err(CrlError::ParseError("CRL file is empty".to_string()));
        }

        debug!("read CRL file: {} bytes", data.len());

        // Parse all CRL blocks (handles concatenated CRLs)
        let der_crls = if data.starts_with(b"-----BEGIN") {
            debug!("CRL is in PEM format, extracting all CRL blocks");
            Self::parse_pem_crls(&data)?
        } else {
            debug!("CRL is in DER format");
            // Single DER-encoded CRL
            vec![data]
        };

        debug!("found {} CRL block(s) in file", der_crls.len());

        let mut parsed_crls = Vec::new();

        for (idx, der_data) in der_crls.iter().enumerate() {
            let owned_crl = webpki::OwnedCertRevocationList::from_der(der_data).map_err(|e| {
                CrlError::WebPkiError(format!("failed to parse CRL {}: {:?}", idx + 1, e))
            })?;

            let crl = CertRevocationList::from(owned_crl);

            // use x509-parser for detail logging
            use x509_parser::prelude::*;
            if let Ok((_, crl_info)) = CertificateRevocationList::from_der(der_data) {
                debug!("CRL {}:", idx + 1);
                debug!("  issuer: {}", crl_info.tbs_cert_list.issuer);
                debug!("  this update: {:?}", crl_info.tbs_cert_list.this_update);
                if let Some(next_update) = &crl_info.tbs_cert_list.next_update {
                    debug!("  next update: {:?}", next_update);
                }
                let revoked_count = crl_info.tbs_cert_list.revoked_certificates.len();
                debug!("  revoked certificates: {}", revoked_count);
            }

            parsed_crls.push(crl);
        }

        let has_new_revocations = parsed_crls.len() != inner.crl_list.len();

        if has_new_revocations {
            warn!(
                "CRL file changed - reloaded with {} CRL(s)",
                parsed_crls.len()
            );
        }

        // store parsed CRL objects
        inner.crl_list = parsed_crls;

        debug!("CRL loaded successfully ({} CRL(s))", inner.crl_list.len());
        Ok(has_new_revocations)
    }

    /// Parse PEM-encoded CRL data that may contain multiple CRL blocks
    /// Returns a Vec of DER-encoded CRLs
    fn parse_pem_crls(pem_data: &[u8]) -> Result<Vec<Vec<u8>>, CrlError> {
        let data_str = std::str::from_utf8(pem_data)
            .map_err(|e| CrlError::ParseError(format!("Invalid UTF-8: {}", e)))?;

        let mut crls = Vec::new();
        let mut in_pem = false;
        let mut base64_data = String::new();

        for line in data_str.lines() {
            if line.starts_with("-----BEGIN") {
                in_pem = true;
                base64_data.clear(); // Start new CRL block
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

        if crls.is_empty() {
            return Err(CrlError::ParseError(
                "no valid CRL blocks found in PEM data".to_string(),
            ));
        }

        Ok(crls)
    }

    /// Check if a certificate is revoked using webpki's native CRL API
    pub fn is_cert_revoked(&self, cert: &CertificateDer) -> Result<bool, CrlError> {
        use x509_parser::prelude::*;

        let inner = self
            .inner
            .read()
            .map_err(|e| CrlError::LockError(format!("failed to acquire read lock: {}", e)))?;

        // if no CRLs are loaded, try to load them now
        if inner.crl_list.is_empty() {
            drop(inner);
            debug!("crl not loaded, attempting to load now");
            self.load_crl()?;
            return self.is_cert_revoked(cert);
        }

        // extract certificate serial number using x509-parser
        // webpki doesn't expose cert parsing publicly, so we use x509-parser for this
        let (_, parsed_cert) = X509Certificate::from_der(cert)
            .map_err(|e| CrlError::CertificateParseError(e.to_string()))?;

        let cert_serial = parsed_cert.serial.to_bytes_be();
        debug!("checking certificate serial: {:?}", cert_serial);

        // check the certificate against ALL CRLs using webpki's native API
        for (idx, crl) in inner.crl_list.iter().enumerate() {
            debug!("checking against CRL {}", idx + 1);

            match crl.find_serial(&cert_serial) {
                Ok(Some(revoked_cert)) => {
                    error!(
                        "certificate with serial {:?} is REVOKED in CRL {}",
                        cert_serial,
                        idx + 1
                    );
                    error!("revocation date: {:?}", revoked_cert.revocation_date);
                    if let Some(reason) = revoked_cert.reason_code {
                        error!("revocation reason: {:?}", reason);
                    }
                    return Ok(true);
                }
                Ok(None) => {
                    // certificate isn't found in this CRL, continue checking others
                    debug!("certificate not found in CRL {}", idx + 1);
                    continue;
                }
                Err(e) => {
                    // error during CRL lookup
                    error!("error checking CRL {}: {:?}", idx + 1, e);
                    return Err(CrlError::WebPkiError(format!("CRL lookup failed: {:?}", e)));
                }
            }
        }

        debug!(
            "certificate serial {:?} is not revoked in any of the {} CRL(s)",
            cert_serial,
            inner.crl_list.len()
        );
        Ok(false)
    }

    /// Check if any certificate in the chain is revoked using webpki's native CRL API
    pub fn is_revoked_chain(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
    ) -> Result<bool, CrlError> {
        debug!(
            "checking certificate chain against CRL (chain length: {})",
            1 + intermediates.len()
        );

        // check leaf certificate
        debug!("checking leaf certificate");
        if self.is_cert_revoked(end_entity)? {
            error!("leaf certificate is REVOKED");
            return Ok(true);
        }

        // check all intermediate certificates
        for (idx, intermediate) in intermediates.iter().enumerate() {
            debug!("checking intermediate certificate {} in chain", idx);
            if self.is_cert_revoked(intermediate)? {
                error!("intermediate CA certificate at position {} is REVOKED", idx);
                return Ok(true);
            }
        }

        debug!("certificate chain validation passed - no revoked certificates found");
        Ok(false)
    }

    /// Start watching the CRL file for changes
    /// Uses debouncer to handle all file update patterns
    pub fn start_file_watcher(self: &Arc<Self>) -> Result<(), CrlError> {
        let crl_path = {
            let inner = self
                .inner
                .read()
                .map_err(|e| CrlError::LockError(format!("failed to acquire read lock: {}", e)))?;
            inner.crl_path.clone()
        };

        // watch the parent directory to catch ConfigMap updates via symlinks
        let watch_path = crl_path
            .parent()
            .ok_or_else(|| CrlError::ParseError("CRL path has no parent directory".to_string()))?;

        debug!(
            "starting CRL file watcher (debounced) for directory: {:?}",
            watch_path
        );
        debug!("  debounce timeout: 2 seconds");
        debug!("  watching for: Kubernetes ConfigMaps, direct writes, text editor saves");

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
                            // log all events for debugging
                            debug!("CRL directory events: {} event(s) detected", events.len());
                            for event in events.iter() {
                                debug!(
                                    "  Event: kind={:?}, paths={:?}",
                                    event.event.kind, event.event.paths
                                );
                            }

                            // reload CRL for any changes in the watched directory
                            // this handles Kubernetes ConfigMap updates (..data symlink changes)
                            // as well as direct file writes and text editor saves
                            debug!("CRL directory changed, reloading...");
                            match manager.load_crl() {
                                Ok(has_new_revocations) => {
                                    debug!("CRL reloaded successfully after file change");
                                    if has_new_revocations {
                                        info!("New revocation detected");
                                    }
                                }
                                Err(e) => error!("failed to reload CRL: {}", e),
                            }
                        }
                    }
                    Err(errors) => {
                        for error in errors {
                            error!("CRL watcher error: {:?}", error);
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

        // Store debouncer to keep it alive
        {
            let mut inner = self
                .inner
                .write()
                .map_err(|e| CrlError::LockError(format!("failed to acquire write lock: {}", e)))?;
            inner._debouncer = Some(debouncer);
        }

        debug!("CRL file watcher started successfully");
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
}
