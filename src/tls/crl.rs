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
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

#[derive(Debug, thiserror::Error)]
pub enum CrlError {
    #[error("failed to read CRL file: {0}")]
    IoError(#[from] std::io::Error),

    #[error("failed to parse CRL: {0}")]
    ParseError(String),

    #[error("CRL is expired")]
    ExpiredCrl,

    #[error("failed to parse certificate: {0}")]
    CertificateParseError(String),
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
    crl_data: Vec<Vec<u8>>,
    crl_path: PathBuf,
    allow_expired: bool,
    last_load_time: Option<SystemTime>,
    _debouncer: Option<Debouncer<RecommendedWatcher, FileIdMap>>,
    revoked_serials: HashSet<Vec<u8>>,
    pool_registry: Option<crate::proxy::pool::PoolRegistry>,
}

impl CrlManager {
    /// Create a new CRL manager
    pub fn new(crl_path: PathBuf, allow_expired: bool) -> Result<Self, CrlError> {
        debug!(
            "initializing CRL Manager: path={:?}, allow_expired={}",
            crl_path, allow_expired
        );

        let manager = Self {
            inner: Arc::new(RwLock::new(CrlManagerInner {
                crl_data: Vec::new(),
                crl_path: crl_path.clone(),
                allow_expired,
                last_load_time: None,
                _debouncer: None,
                revoked_serials: HashSet::new(),
                pool_registry: None,
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

    /// Register pool registry for draining HTTP/2 pools when CRL is reloaded with new revocations
    pub fn register_pool_registry(&self, registry: crate::proxy::pool::PoolRegistry) {
        let mut inner = self.inner.write().unwrap();
        inner.pool_registry = Some(registry);
        debug!("registered pool registry with CRL manager");
    }

    /// Load or reload the CRL from disk
    pub fn load_crl(&self) -> Result<bool, CrlError> {
        let mut inner = self.inner.write().unwrap();

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

        let mut total_revoked = 0;
        let mut new_revoked_serials = HashSet::new();

        for (idx, der_data) in der_crls.iter().enumerate() {
            use x509_parser::prelude::*;
            let (_, crl) = CertificateRevocationList::from_der(der_data).map_err(|e| {
                CrlError::ParseError(format!("Failed to parse CRL {}: {}", idx + 1, e))
            })?;

            debug!("CRL {}:", idx + 1);
            debug!("  Issuer: {}", crl.tbs_cert_list.issuer);
            debug!("  this update: {:?}", crl.tbs_cert_list.this_update);
            if let Some(next_update) = &crl.tbs_cert_list.next_update {
                debug!("  next update: {:?}", next_update);
            }
            let revoked_count = crl.tbs_cert_list.revoked_certificates.len();
            debug!("  revoked certificates: {}", revoked_count);
            total_revoked += revoked_count;

            for revoked in crl.tbs_cert_list.revoked_certificates.iter() {
                let serial = revoked.serial().to_bytes_be();
                new_revoked_serials.insert(serial);
            }

            // verify CRL validity
            Self::verify_crl_validity(&crl, inner.allow_expired)?;
        }

        // check if there are new revocations compared to previous load
        let has_new_revocations = !new_revoked_serials.is_subset(&inner.revoked_serials);

        if has_new_revocations {
            // calculate which serials are new
            let newly_revoked: HashSet<_> = new_revoked_serials
                .difference(&inner.revoked_serials)
                .collect();
            warn!(
                "detected {} NEW certificate revocation(s)",
                newly_revoked.len()
            );
            for serial in newly_revoked {
                warn!("  newly revoked serial: {:?}", serial);
            }
        }

        // store all CRL DER data and update revoked serials
        inner.crl_data = der_crls;
        inner.revoked_serials = new_revoked_serials;
        inner.last_load_time = Some(SystemTime::now());

        debug!(
            "CRL loaded successfully ({} CRL(s), {} total revoked certificate(s))",
            inner.crl_data.len(),
            total_revoked
        );
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

    /// Verify CRL validity period
    fn verify_crl_validity(
        crl: &x509_parser::revocation_list::CertificateRevocationList,
        allow_expired: bool,
    ) -> Result<(), CrlError> {
        let now = SystemTime::now();
        let unix_now = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64;

        // check thisUpdate (CRL issue time)
        if unix_now < crl.tbs_cert_list.this_update.timestamp() {
            warn!("CRL is not yet valid");
        }

        // check nextUpdate (CRL expiry)
        if let Some(next_update) = &crl.tbs_cert_list.next_update
            && unix_now > next_update.timestamp()
        {
            if !allow_expired {
                return Err(CrlError::ExpiredCrl);
            }
            warn!("CRL is expired but allow_expired_crl is enabled");
        }

        Ok(())
    }

    /// Check if any certificate in the chain is revoked
    pub fn is_revoked_chain(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
    ) -> Result<bool, CrlError> {
        debug!(
            "checking certificate chain against CRL (chain length: {})",
            1 + intermediates.len()
        );

        debug!("checking leaf certificate");
        if self.is_cert_revoked(end_entity)? {
            warn!("leaf certificate is REVOKED");
            return Ok(true);
        }

        // check all intermediate certificates
        for (idx, intermediate) in intermediates.iter().enumerate() {
            debug!("checking intermediate certificate {} in chain", idx);
            if self.is_cert_revoked(intermediate)? {
                warn!("intermediate CA certificate at position {} is REVOKED", idx);
                return Ok(true);
            }
        }

        debug!("certificate chain validation passed - no revoked certificates found");
        Ok(false)
    }

    /// Internal method to check if a single certificate is revoked
    /// Checks the certificate against ALL loaded CRLs
    fn is_cert_revoked(&self, cert: &CertificateDer) -> Result<bool, CrlError> {
        let inner = self.inner.read().unwrap();

        // if no CRLs are loaded, try to load them now
        if inner.crl_data.is_empty() {
            drop(inner);
            debug!("CRL not loaded, attempting to load now");
            self.load_crl()?;
            return self.is_cert_revoked(cert);
        }

        // parse the certificate to get its serial number
        use x509_parser::prelude::*;
        let (_, parsed_cert) = X509Certificate::from_der(cert)
            .map_err(|e| CrlError::CertificateParseError(e.to_string()))?;

        let cert_serial = &parsed_cert.serial;
        debug!("certificate serial number: {:?}", cert_serial);

        // check the certificate against ALL CRLs
        for (idx, crl_data) in inner.crl_data.iter().enumerate() {
            // Parse CRL from stored data
            let (_, crl) = CertificateRevocationList::from_der(crl_data).map_err(|e| {
                CrlError::ParseError(format!("failed to parse stored CRL {}: {}", idx + 1, e))
            })?;

            debug!(
                "checking against CRL {} (issuer: {})",
                idx + 1,
                crl.tbs_cert_list.issuer
            );

            // check if the certificate's serial number is in this CRL's revoked list
            for revoked_cert in &crl.tbs_cert_list.revoked_certificates {
                if revoked_cert.serial() == cert_serial {
                    warn!(
                        "certificate with serial {:?} is REVOKED in CRL {} (issuer: {})",
                        cert_serial,
                        idx + 1,
                        crl.tbs_cert_list.issuer
                    );
                    warn!("revocation date: {:?}", revoked_cert.revocation_date);
                    return Ok(true);
                }
            }
        }

        debug!(
            "certificate serial {:?} is not in any of the {} CRL(s)",
            cert_serial,
            inner.crl_data.len()
        );
        Ok(false)
    }

    /// Refresh the CRL from disk if needed
    pub fn refresh(&self) -> Result<(), CrlError> {
        self.load_crl().map(|_| ())
    }

    /// Start watching the CRL file for changes
    /// Uses debouncer to handle all file update patterns
    pub fn start_file_watcher(self: &Arc<Self>) -> Result<(), CrlError> {
        let crl_path = {
            let inner = self.inner.read().unwrap();
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
                                        warn!("NEW REVOCATIONS DETECTED - Closing all connections to force re-validation");
                                        manager.close_all_connections();
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
            let mut inner = self.inner.write().unwrap();
            inner._debouncer = Some(debouncer);
        }

        debug!("CRL file watcher started successfully");
        Ok(())
    }

    /// Close all connections when new certificate revocations are detected
    /// This drains HTTP/2 connection pools, forcing clients to reconnect and re-validate certificates
    fn close_all_connections(&self) {
        let inner = self.inner.read().unwrap();

        // drain HTTP/2 connection pools
        if let Some(ref registry) = inner.pool_registry {
            info!("draining HTTP/2 connection pools");
            registry.drain_all();
        } else {
            warn!("no pool registry registered - cannot drain HTTP/2 pools");
        }

        debug!("connection pools drained - clients will reconnect and re-validate certificates");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_crl_manager_missing_file() {
        let result = CrlManager::new(PathBuf::from("/nonexistent/path/crl.pem"), false);
        assert!(result.is_ok(), "should handle missing CRL file gracefully");
    }

    #[test]
    fn test_crl_manager_invalid_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(b"not a valid CRL").unwrap();
        file.flush().unwrap();

        let result = CrlManager::new(file.path().to_path_buf(), false);
        assert!(result.is_err(), "should fail on invalid CRL data");
    }
}
