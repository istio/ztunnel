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
use rustls::pki_types::CertificateRevocationListDer;
use rustls_pemfile::Item;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tracing::{debug, warn};

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
/// NOTE: CRL updates take effect when new ServerConfigs are created, which happens
/// on certificate refresh (~12hrs). For immediate CRL enforcement, a custom
/// ClientCertVerifier wrapper would be needed, but rustls doesn't provide a
/// built-in mechanism like `with_cert_resolver` for dynamic CRL updates.
pub struct CrlManager {
    inner: Arc<RwLock<CrlManagerInner>>,
}

impl std::fmt::Debug for CrlManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrlManager").finish_non_exhaustive()
    }
}

struct CrlManagerInner {
    crl_ders: Option<Vec<Vec<u8>>>, // None = not loaded, Some = loaded (may be empty)
    crl_path: PathBuf,
    _debouncer: Option<Debouncer<RecommendedWatcher, FileIdMap>>,
}

impl CrlManager {
    /// creates a new CRL manager
    pub fn new(crl_path: PathBuf) -> Result<Self, CrlError> {
        debug!(path = ?crl_path, "initializing crl manager");

        let manager = Self {
            inner: Arc::new(RwLock::new(CrlManagerInner {
                crl_ders: None,
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

    pub fn load_crl(&self) -> Result<(), CrlError> {
        let mut inner = self.inner.write().unwrap();

        debug!(path = ?inner.crl_path, "loading crl");
        let data = std::fs::read(&inner.crl_path)?;

        // empty file means no revocations - this is valid
        if data.is_empty() {
            debug!(path = ?inner.crl_path, "crl file is empty, treating as no revocations");
            inner.crl_ders = Some(Vec::new());
            return Ok(());
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
            inner.crl_ders = Some(Vec::new());
            return Ok(());
        }

        debug!(count = der_crls.len(), "found crl block(s) in file");

        let mut validated_ders = Vec::new();

        for (idx, der_data) in der_crls.into_iter().enumerate() {
            // validate with webpki to catch parse errors early
            // rustls will use the raw DER bytes directly
            webpki::OwnedCertRevocationList::from_der(&der_data).map_err(|e| {
                CrlError::WebPkiError(format!("failed to parse crl {}: {:?}", idx + 1, e))
            })?;

            debug!(crl = idx + 1, "loaded crl");

            validated_ders.push(der_data);
        }

        // store validated DER bytes
        inner.crl_ders = Some(validated_ders);

        debug!(
            count = inner.crl_ders.as_ref().map(|v| v.len()).unwrap_or(0),
            "crl loaded successfully"
        );
        Ok(())
    }

    /// parses PEM-encoded CRL data that may contain multiple CRL blocks
    /// returns a Vec of DER-encoded CRLs (empty vec if no blocks found)
    fn parse_pem_crls(pem_data: &[u8]) -> Result<Vec<Vec<u8>>, CrlError> {
        let mut reader = std::io::BufReader::new(Cursor::new(pem_data));

        rustls_pemfile::read_all(&mut reader)
            .filter_map(|result| match result {
                Ok(Item::Crl(crl)) => Some(Ok(crl.to_vec())),
                Ok(_) => None, // skip non-CRL items
                Err(e) => Some(Err(CrlError::ParseError(format!(
                    "failed to parse PEM: {}",
                    e
                )))),
            })
            .collect()
    }

    /// returns CRLs as DER bytes for rustls's with_crls().
    /// if no CRLs are loaded, attempts to load them first.
    pub fn get_crl_ders(&self) -> Vec<CertificateRevocationListDer<'static>> {
        let inner = self.inner.read().unwrap();
        if let Some(ref crl_ders) = inner.crl_ders {
            // already loaded, use existing lock directly
            crl_ders
                .iter()
                .map(|der| CertificateRevocationListDer::from(der.clone()))
                .collect()
        } else {
            // not loaded yet, drop lock to call load_crl()
            drop(inner);
            debug!("crl not loaded, attempting to load now");
            if let Err(e) = self.load_crl() {
                debug!(error = %e, "failed to load crl");
                return Vec::new();
            }
            // re-acquire after loading
            let inner = self.inner.read().unwrap();
            inner
                .crl_ders
                .as_ref()
                .map(|ders| {
                    ders.iter()
                        .map(|der| CertificateRevocationListDer::from(der.clone()))
                        .collect()
                })
                .unwrap_or_default()
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
