use std::sync::Arc;
use futures::StreamExt;
use spiffe::{TrustDomain};
use spire_api::{DelegateAttestationRequest, DelegatedIdentityClient, selectors::{K8s, Selector}};
use tonic::async_trait;
use crate::{config::{Config, SpireMode}, identity::{CompositeId, Error, Identity, PidClientTrait, RequestKeyEnum}, inpod::WorkloadUid, tls};

/// SPIRE client that fetches X.509 certificates for workload identities using
/// Kubernetes selectors (namespace + service account) rather than PIDs.
/// This approach works in environments where PID-based attestation is not feasible.
pub struct SpireClient {
    /// gRPC client for communicating with the SPIRE Delegated Identity API
    client: DelegatedIdentityClient,
    /// SPIFFE trust domain (e.g., "cluster.local") used for certificate validation
    trust_domain: String,
    pid: Option<Box<dyn PidClientTrait>>,
    cfg: Arc<Config>
}

impl SpireClient {
    /// Creates a new SPIRE client with the provided gRPC client and trust domain.
    /// 
    /// # Arguments
    /// * `client` - Configured DelegatedIdentityClient for SPIRE communication
    /// * `trust_domain` - SPIFFE trust domain string for this cluster
    pub fn new(client: DelegatedIdentityClient, trust_domain: String, pid: Option<Box<dyn PidClientTrait>>, cfg: Arc<Config>) -> Self {
        SpireClient { client, trust_domain, pid, cfg }
    }

    /// Fetches a workload certificate using Kubernetes selectors (namespace + service account).
    /// This method implements a streaming approach to handle SPIRE's async certificate delivery.
    /// 
    /// # Arguments
    /// * `id` - The SPIFFE identity containing namespace and service account information
    /// 
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    /// 
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn get_cert_by_selector(&self, id: &Identity) -> Result<tls::WorkloadCertificate, Error> {
        // Pre-allocate vector with exact capacity to avoid dynamic resizing
        // We always need exactly 2 selectors: namespace + service account
        let mut selectors = Vec::<Selector>::with_capacity(2);
        selectors.push(Selector::K8s(K8s::Namespace(id.ns().to_string())));
        selectors.push(Selector::K8s(K8s::ServiceAccount(id.sa().to_string())));

        Ok(self.get_cert_from_spire(DelegateAttestationRequest::Selectors(selectors)).await?)
    }

    /// Fetches a workload certificate using Kubernetes pid.
    /// This method implements a streaming approach to handle SPIRE's async certificate delivery.
    /// 
    /// # Arguments
    /// * `pid` - The container process ID for the workload
    /// 
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    /// 
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn get_cert_by_pid(&self, pid: i32, wl_uid: &WorkloadUid) -> Result<tls::WorkloadCertificate, Error> {
        let certs = self.get_cert_from_spire(DelegateAttestationRequest::Pid(pid)).await;

        match &self.pid {
            Some(pid_client) => {
               let pid_verify = pid_client.fetch_pid(wl_uid).await;

               match pid_verify {
                   Ok(fetched_pid) => {
                       if fetched_pid.into_i32() != pid {
                           return Err(Error::UnableToDeterminePidForWorkload(format!(
                               "PID mismatch for workload UID {}: expected {}, got {}",
                               wl_uid.clone().into_string(),
                               pid,
                               fetched_pid.into_i32()
                           )));
                       }
                   },
                   Err(e) => {
                       return Err(Error::UnableToDeterminePidForWorkload(format!(
                           "Failed to verify PID for workload UID {}: {}",
                           wl_uid.clone().into_string(),
                           e
                       )));
                   }
               }
            },
            None => {}
        }

        Ok(certs?)
    }

    async fn get_cert_by_workload_uid(&self, wl_uid: &WorkloadUid) -> Result<tls::WorkloadCertificate, Error> {
        match &self.pid {
            Some(pid_client) => {
                tracing::info!("Fetching PID for workload UID: {}", wl_uid.clone().into_string());
                let pid = pid_client.fetch_pid(wl_uid).await;
                match pid {
                    Ok(pid) => self.get_cert_by_pid(pid.into_i32(), wl_uid).await,
                    Err(e) => Err(Error::UnableToDeterminePidForWorkload(format!("Failed to fetch PID for workload UID {}: {}", wl_uid.clone().into_string(), e))),
                }
            },
            None => Err(Error::InvalidConfiguration("PID client not configured for workload UID attestation".to_string()))
        }
    }

    async fn get_cert_from_spire(&self, value: DelegateAttestationRequest) -> Result<tls::WorkloadCertificate, Error> {
        // Initiate streaming request to SPIRE server using Kubernetes selectors
        // clone() is cheap here as DelegatedIdentityClient uses Arc internally
        let mut stream = self.client.clone()
            .stream_x509_svids(value)
            .await
            .map_err(|e| Error::FailedToFetchCertificate(format!("Failed to stream X.509 SVIDs: {e}")))?;

        // Set reasonable timeout to prevent indefinite blocking on unresponsive SPIRE servers
        let time_out = std::time::Duration::from_secs(15);

        // Process the stream with timeout protection
        // SPIRE may deliver multiple responses, but we only need the first successful one
        let sf = tokio::time::timeout(time_out, async {
            while let Some(svid_response) = stream.next().await {
                match svid_response {
                    Ok(response) => {
                        // Successfully received a certificate - return immediately
                        return Ok(response);
                    }
                    Err(e) => {
                        // Log stream errors but continue waiting for subsequent responses
                        // Some responses may fail while others succeed
                        tracing::warn!("Error receiving SVID response: {}", e);
                    }
                }
            }
            // Stream ended without delivering any successful responses
            Err(Error::FailedToFetchCertificate("No SVIDs received in stream".to_string()))
        }).await;

        // Handle nested Result types from timeout + stream operations
        let svid_response = match sf {
            Ok(Ok(response)) => response,  // Successfully got certificate within timeout
            Ok(Err(e)) => return Err(e),   // Stream completed but no valid certificates
            Err(_) => {
                // Timeout expired before receiving any certificates
                return Err(Error::FailedToFetchCertificate("Timeout while waiting for SVID stream".to_string()));
            }
        };

        // Fetch the trust bundle containing CA certificates for validation
        let bundle = self.get_bundle().await?;

        // Construct the final WorkloadCertificate combining SVID and trust bundle
        let certs = tls::WorkloadCertificate::new_svid(&svid_response, &bundle)?;

        Ok(certs)
    }

    /// Fetches the X.509 trust bundle from SPIRE containing CA certificates
    /// for validating certificates within this trust domain.
    /// 
    /// # Returns
    /// Vector of CA certificates that can verify certificates in this trust domain
    /// 
    /// # Errors
    /// Returns error if bundle fetch fails, trust domain is invalid, or no bundle
    /// exists for the configured trust domain.
    async fn get_bundle(&self) -> Result<Vec<spiffe::cert::Certificate>, Error> {
        // Fetch all available trust bundles from SPIRE server
        let bundle_req = self.client.clone().fetch_x509_bundles()
        .await
        .map_err(|e| Error::FailedToFetchBundle(format!("Failed to fetch X.509 bundles: {}", e)))?;

        // Parse and validate the trust domain string
        let td = TrustDomain::new(&self.trust_domain).map_err(|e| Error::InvalidTrustDomain(format!("Invalid trust domain {}: {}", self.trust_domain, e)))?;
        tracing::debug!("Fetched bundle for trust domain: {}", td);

        // Extract CA certificates for our specific trust domain
        let bundles = match bundle_req.get_bundle(&td) {
            Some(b) => b.authorities(),  // Get the CA certificates
            None => {
                // No trust bundle available for this domain - configuration error
                return Err(Error::InvalidTrustDomain(format!("No bundle found for trust domain: {}", td)));
            }
        };

        // Clone the certificates to return owned values
        // This allows the bundle request to be dropped while keeping the certificates
        Ok(bundles.clone())
    }
}

/// Implementation of the CaClientTrait that integrates SPIRE with ztunnel's
/// certificate management system. This allows the SPIRE client to be used
/// interchangeably with other certificate authority implementations.
#[async_trait]
impl crate::identity::CaClientTrait for SpireClient {
    /// Fetches a certificate for the given identity using SPIRE's selector-based approach.
    /// This is the main integration point with ztunnel's certificate manager.
    /// 
    /// # Arguments
    /// * `id` - SPIFFE identity to fetch certificate for
    /// 
    /// # Returns
    /// WorkloadCertificate that can be used for TLS operations
    async fn fetch_certificate(&self, id: &CompositeId<RequestKeyEnum>) -> Result<tls::WorkloadCertificate, Error> {
        if self.cfg.spire_mode == SpireMode::ByPid {
            match id.key() {
                RequestKeyEnum::Workload(wl_uid) => {
                    self.get_cert_by_workload_uid(&wl_uid).await
                }
                _ => Err(Error::InvalidConfiguration("PID mode requires workload UID for attestation".to_string()))
            }
        } else {
            self.get_cert_by_selector(&id.id()).await
        }
    }
}
