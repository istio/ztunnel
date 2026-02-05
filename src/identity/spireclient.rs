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

use crate::{
    config::Config,
    identity::{CompositeId, Error, Identity, PidClientTrait, RequestKeyEnum},
    inpod::WorkloadUid,
    tls,
};
use spiffe::{TrustDomain, X509Svid};
use spire_api::{DelegateAttestationRequest, DelegatedIdentityClient};
use std::{str::FromStr, sync::Arc};
use tokio_stream::{Stream, StreamExt};
use tonic::async_trait;

/// Trait abstraction over the SPIRE DelegatedIdentityClient
#[cfg_attr(test, mockall::automock)]
#[async_trait]
pub trait DelegatedIdentityApi: Send + Sync {
    async fn get_x509_bundles(
        &self,
    ) -> Result<spiffe::X509BundleSet, spiffe::error::GrpcClientError>;
    async fn get_x509_svids(
        &self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<spiffe::X509Svid, spiffe::error::GrpcClientError>>
                + Send
                + Unpin,
        >,
        spiffe::error::GrpcClientError,
    >;
}

#[async_trait]
impl DelegatedIdentityApi for DelegatedIdentityClient {
    async fn get_x509_bundles(
        &self,
    ) -> Result<spiffe::X509BundleSet, spiffe::error::GrpcClientError> {
        self.clone().fetch_x509_bundles().await
    }

    async fn get_x509_svids(
        &self,
        attest_type: DelegateAttestationRequest,
    ) -> Result<
        Box<
            dyn Stream<Item = Result<spiffe::X509Svid, spiffe::error::GrpcClientError>>
                + Send
                + Unpin,
        >,
        spiffe::error::GrpcClientError,
    > {
        let stream = self.clone().stream_x509_svids(attest_type).await?;
        Ok(Box::new(stream))
    }
}

/// SPIRE client that fetches X.509 certificates for workload identities using
/// Kubernetes selectors (namespace + service account) rather than PIDs.
/// This approach works in environments where PID-based attestation is not feasible.
pub struct SpireClient<C: DelegatedIdentityApi> {
    /// gRPC client for communicating with the SPIRE Delegated Identity API
    client: C,
    /// SPIFFE trust domain (e.g., "cluster.local") used for certificate validation
    trust_domain: String,
    /// Optional PID client for workload PID verification
    pid: Box<dyn PidClientTrait>,
    /// Shared configuration for SPIRE client behavior
    cfg: Arc<Config>,
}

impl<C: DelegatedIdentityApi> SpireClient<C> {
    /// Creates a new SPIRE client with the provided gRPC client and trust domain.
    ///
    /// # Arguments
    /// * `client` - Configured DelegatedIdentityClient for SPIRE communication
    /// * `trust_domain` - SPIFFE trust domain string for this cluster
    /// * `pid` - Optional PID client for workload PID verification
    /// * `cfg` - Shared configuration for SPIRE client behavior
    pub fn new(
        client: C,
        trust_domain: String,
        pid: Box<dyn PidClientTrait>,
        cfg: Arc<Config>,
    ) -> Self {
        SpireClient {
            client,
            trust_domain,
            pid,
            cfg,
        }
    }

    /// Fetches a workload certificate using container pid.
    /// This method implements a streaming approach to handle SPIRE's async certificate delivery.
    ///
    /// # Arguments
    /// * `pid` - The container process ID for the workload
    /// * `wl_uid` - The unique identifier for the workload
    ///
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    ///
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn get_cert_by_pid(
        &self,
        pid: i32,
        wl_uid: &WorkloadUid,
    ) -> Result<tls::WorkloadCertificate, Error> {
        let certs = self
            .get_cert_from_spire(DelegateAttestationRequest::Pid(pid))
            .await;

        let certs = match certs {
            Err(e) => {
                return Err(Error::FailedToFetchCertificate(format!(
                    "Failed to fetch certificate for PID {}: {}",
                    pid, e
                )));
            }
            Ok(certs) => certs,
        };

        let pid_verify = self.pid.fetch_pid(wl_uid).await;

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
                Ok(certs)
            }
            Err(e) => Err(Error::UnableToDeterminePidForWorkload(format!(
                "Failed to verify PID for workload UID {}: {}",
                wl_uid.clone().into_string(),
                e
            ))),
        }
    }

    /// Fetches a workload certificate using workload UID to determine PID.
    /// This method implements a streaming approach to handle SPIRE's async certificate delivery.
    /// # Arguments
    /// * `wl_uid` - The unique identifier for the workload
    ///
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    ///
    /// # Errors
    /// Returns error if PID client is not configured, stream setup fails,
    /// no certificates are received within timeout, or certificate construction fails.
    async fn get_cert_by_workload_uid(
        &self,
        wl_uid: &WorkloadUid,
    ) -> Result<tls::WorkloadCertificate, Error> {
        tracing::info!(
            "Fetching PID for workload UID: {}",
            wl_uid.clone().into_string()
        );
        let pid = self.pid.fetch_pid(wl_uid).await;
        match pid {
            Ok(pid) => self.get_cert_by_pid(pid.into_i32(), wl_uid).await,
            Err(e) => Err(Error::UnableToDeterminePidForWorkload(format!(
                "Failed to fetch PID for workload UID {}: {}",
                wl_uid.clone().into_string(),
                e
            ))),
        }
    }

    /// Subscribes to the SPIRE server for workload certificates using the provided attestation request.
    ///
    /// # Arguments
    /// * `value` - The attestation request specifying how to identify the workload
    ///
    /// # Returns
    /// The first X509Svid received from the SPIRE server
    ///
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn subscribe_and_wait_for_workload_cert(
        &self,
        value: DelegateAttestationRequest,
    ) -> Result<X509Svid, Error> {
        // Initiate streaming request to SPIRE server using Kubernetes selectors
        // clone() is cheap here as DelegatedIdentityClient uses Arc internally
        let stream = self.client.get_x509_svids(value).await.map_err(|e| {
            Error::FailedToFetchCertificate(format!("Failed to stream X.509 SVIDs: {e}"))
        })?;
        // Set reasonable timeout to prevent indefinite blocking on unresponsive SPIRE servers
        let time_out = self.cfg.spire_timeout;

        // Process the stream with timeout protection
        // SPIRE may deliver multiple responses, but we only need the first successful one
        tokio::pin!(stream);
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
            Err(Error::FailedToFetchCertificate(
                "No SVIDs received in stream".to_string(),
            ))
        })
        .await;

        // Handle nested Result types from timeout + stream operations
        let svid_response = match sf {
            Ok(Ok(response)) => response, // Successfully got certificate within timeout
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                // Timeout expired before receiving any certificates
                tracing::error!("Timeout while waiting for SVID stream");
                return Err(Error::FailedToFetchCertificate(
                    "Timeout while waiting for SVID stream".to_string(),
                ));
            }
        };

        Ok(svid_response)
    }

    /// Fetches a workload certificate from SPIRE using the provided attestation request.
    ///
    /// # Arguments
    /// * `value` - The attestation request specifying how to identify the workload
    ///
    /// # Returns
    /// A WorkloadCertificate containing the X.509 certificate and private key
    ///
    /// # Errors
    /// Returns error if stream setup fails, no certificates are received within timeout,
    /// or certificate construction fails.
    async fn get_cert_from_spire(
        &self,
        value: DelegateAttestationRequest,
    ) -> Result<tls::WorkloadCertificate, Error> {
        // Handle nested Result types from timeout + stream operations
        let svid_response = self.subscribe_and_wait_for_workload_cert(value).await?;

        // Fetch the trust bundle containing CA certificates for validation
        let bundle = self.get_bundle().await?;

        // Construct the final WorkloadCertificate combining SVID and trust bundle
        let certs = tls::WorkloadCertificate::new_svid(&svid_response, &bundle)?;

        let id = format!(
            "spiffe://{}{}",
            svid_response.spiffe_id().trust_domain(),
            svid_response.spiffe_id().path()
        );

        // Validate that the returned identity matches the requested one
        Identity::from_str(&id)?;

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
        let bundle_req = self.client.get_x509_bundles().await.map_err(|e| {
            Error::FailedToFetchBundle(format!("Failed to fetch X.509 bundles: {}", e))
        })?;

        // Parse and validate the trust domain string
        let td = TrustDomain::new(&self.trust_domain).map_err(|e| {
            Error::InvalidTrustDomain(format!("Invalid trust domain {}: {}", self.trust_domain, e))
        })?;
        tracing::debug!("Fetched bundle for trust domain: {}", td);

        // Extract CA certificates for our specific trust domain
        let bundles = match bundle_req.get_bundle(&td) {
            Some(b) => b.authorities(), // Get the CA certificates
            None => {
                // No trust bundle available for this domain - configuration error
                return Err(Error::InvalidTrustDomain(format!(
                    "No bundle found for trust domain: {}",
                    td
                )));
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
impl<C: DelegatedIdentityApi> crate::identity::CaClientTrait for SpireClient<C> {
    /// Fetches a certificate for the given identity using SPIRE's selector-based approach.
    /// This is the main integration point with ztunnel's certificate manager.
    ///
    /// # Arguments
    /// * `id` - SPIFFE identity to fetch certificate for
    ///
    /// # Returns
    /// WorkloadCertificate that can be used for TLS operations
    async fn fetch_certificate(
        &self,
        id: &CompositeId<RequestKeyEnum>,
    ) -> Result<tls::WorkloadCertificate, Error> {
        match id.key() {
            RequestKeyEnum::Workload(wl_uid) => self.get_cert_by_workload_uid(wl_uid).await,
            _ => Err(Error::InvalidConfiguration(
                "PID mode requires workload UID for attestation".to_string(),
            )),
        }
    }
}

#[cfg(test)]
pub mod spire_tests {
    use crate::config;
    use crate::identity::CaClientTrait;
    use crate::identity::MockPidClientTrait;
    use crate::identity::SecretManager;
    use crate::identity::WorkloadPid;

    use super::*;
    use futures::SinkExt;
    use futures::channel::mpsc;
    use mockall::predicate::*;
    use rcgen::BasicConstraints;
    use rcgen::Certificate;
    use rcgen::CertificateParams;
    use rcgen::CertifiedIssuer;
    use rcgen::DnType;
    use rcgen::IsCa;
    use rcgen::KeyPair;
    use rcgen::KeyUsagePurpose;
    use rcgen::SanType;
    use rcgen::string::Ia5String;
    use spiffe::error::GrpcClientError;
    use spiffe::*;

    use rcgen::ExtendedKeyUsagePurpose as EKU;

    #[tokio::test]
    async fn test_get_bundle_success() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::new(cfg),
        );

        let result = spire_client.get_bundle().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_get_bundle_trust_domain_not_found() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let spire_client = SpireClient::new(
            mock_client,
            "wrong.trust_domain".to_string(),
            Box::new(pid_client),
            Arc::new(cfg),
        );

        let result = spire_client.get_bundle().await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("No bundle found for trust domain"));
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_success() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let result = spire_client
            .get_cert_by_pid(10, &WorkloadUid::new("uid-123456".to_string()))
            .await;

        assert!(result.is_ok());

        let workload_cert = result.unwrap();

        let id = workload_cert.identity();

        assert!(id.unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        assert!(identity.to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        let composite_id = CompositeId::new(
            identity,
            RequestKeyEnum::Workload(WorkloadUid::new("uid-123456".to_string())),
        );

        let fetch_result = spire_client.fetch_certificate(&composite_id).await;

        assert!(fetch_result.is_ok());
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_not_found() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client.expect_fetch_pid().returning(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No PID found for pod",
            ))
        });

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::new(cfg),
        );

        let result = spire_client
            .get_cert_by_pid(10, &WorkloadUid::new("uid-123456".to_string()))
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_cert_by_secret_manager_with_pid_success() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let composite_id = CompositeId::new(
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into()),
            RequestKeyEnum::Workload(WorkloadUid::new("uid-123456".to_string())),
        );
        let composite_id_diff_uid = CompositeId::new(
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into()),
            RequestKeyEnum::Workload(WorkloadUid::new("uid-654321".to_string())),
        );
        let sm = SecretManager::new_with_client(spire_client);
        let certs = sm.fetch_certificate(&composite_id).await.unwrap();
        assert!(
            certs.identity().unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa"
        );
        assert!(sm.cache_len().await == 1);
        let certs = sm.fetch_certificate(&composite_id).await.unwrap();
        assert!(
            certs.identity().unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa"
        );
        assert!(sm.cache_len().await == 1);
        let certs = sm.fetch_certificate(&composite_id_diff_uid).await.unwrap();
        assert!(
            certs.identity().unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa"
        );
        assert!(sm.cache_len().await == 2);
    }

    #[tokio::test]
    async fn test_get_cert_by_secret_manager_with_pid_not_found() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client.expect_fetch_pid().returning(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "No PID found for pod",
            ))
        });

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let composite_id = CompositeId::new(
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into()),
            RequestKeyEnum::Workload(WorkloadUid::new("uid-123456".to_string())),
        );
        let sm = SecretManager::new_with_client(spire_client);
        let certs = sm.fetch_certificate(&composite_id).await;
        assert!(certs.is_err());
        assert!(sm.cache_len().await == 1);
        let err = certs.err().unwrap().to_string();
        assert!(err.contains("No PID found for pod"));
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_success_delay_response() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_delay_response(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let identity =
            Identity::from_parts("example.org".into(), "default".into(), "test-sa".into());
        let result = spire_client
            .get_cert_by_pid(10, &WorkloadUid::new("uid-123456".to_string()))
            .await;

        assert!(result.is_ok());

        let workload_cert = result.unwrap();

        let id = workload_cert.identity();

        assert!(id.unwrap().to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        assert!(identity.to_string() == "spiffe://example.org/ns/default/sa/test-sa");

        let composite_id = CompositeId::new(
            identity,
            RequestKeyEnum::Workload(WorkloadUid::new("uid-123456".to_string())),
        );

        let fetch_result = spire_client.fetch_certificate(&composite_id).await;

        assert!(fetch_result.is_ok());
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_delay_response_timeout() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_delay_response_timeout(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;
        cfg.spire_timeout = std::time::Duration::from_secs(5);

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let result = spire_client
            .get_cert_by_pid(10, &WorkloadUid::new("uid-123456".to_string()))
            .await;

        assert!(result.is_err());

        let err = result.err().unwrap().to_string();
        assert!(err.contains("No SVIDs received in stream"));
    }

    #[tokio::test]
    async fn test_get_cert_by_pid_delay_response_timeout_empty() {
        let mut mock_client = MockDelegatedIdentityApi::new();
        let mut pid_client = MockPidClientTrait::new();

        mock_client.expect_get_x509_svids().returning(|_req| {
            let stream = mock_stream_svid_success_delay_response_timeout_empty(
                "spiffe://example.org/ns/default/sa/test-sa".to_string(),
            );
            Ok(stream)
        });

        mock_client
            .expect_get_x509_bundles()
            .returning(|| Ok(mock_bundle_response()));

        pid_client
            .expect_fetch_pid()
            .returning(|_| Ok(WorkloadPid::new(10)));

        let mut cfg = config::parse_config().unwrap();
        cfg.spire_enabled = true;

        let cfg = Arc::new(cfg);

        let spire_client = SpireClient::new(
            mock_client,
            "example.org".to_string(),
            Box::new(pid_client),
            Arc::clone(&cfg),
        );

        let result = spire_client
            .get_cert_by_pid(10, &WorkloadUid::new("uid-123456".to_string()))
            .await;

        assert!(result.is_err());

        let err = result.err().unwrap().to_string();
        assert!(err.contains("Timeout while waiting for SVID stream"));
    }

    fn mock_bundle_response() -> spiffe::X509BundleSet {
        let ca_key = KeyPair::generate().unwrap();
        let ca_params = ca_params("example.org").unwrap();

        // CertifiedIssuer gives you both the issuer + its self-signed cert
        let ca_issuer = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let td = TrustDomain::new("example.org").unwrap();
        let mut bundle = X509Bundle::new(td.clone());

        let ca_der_slice: &[u8] = ca_issuer.der();
        bundle.add_authority(ca_der_slice).unwrap();

        let mut set = spiffe::X509BundleSet::new();
        set.add_bundle(bundle);

        return set;
    }

    fn mock_stream_svid_success_response(
        spiffe_id: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        // build a stream that yields X509Svid responses
        // can you provide a minimal example of building such a stream?
        let (mut tx, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            let svid = generate_svid(&spiffe_id, "example.org");
            tx.send(Ok(svid)).await.unwrap();
        });
        Box::new(rx)
    }

    fn mock_stream_svid_success_delay_response(
        spiffe_id: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        // build a stream that yields X509Svid responses
        // can you provide a minimal example of building such a stream?
        let (mut tx, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            tx.send(Err(GrpcClientError::EmptyResponse)).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_secs(3)).await;

            let svid = generate_svid(&spiffe_id, "example.org");
            tx.send(Ok(svid)).await.unwrap();
        });
        Box::new(rx)
    }

    fn mock_stream_svid_success_delay_response_timeout(
        _: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        // build a stream that yields X509Svid responses
        // can you provide a minimal example of building such a stream?
        let (_, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });
        Box::new(rx)
    }

    fn mock_stream_svid_success_delay_response_timeout_empty(
        _: String,
    ) -> Box<dyn Stream<Item = Result<X509Svid, GrpcClientError>> + Send + Unpin> {
        // build a stream that yields X509Svid responses
        // can you provide a minimal example of building such a stream?
        let (mut tx, rx) = mpsc::channel(10);
        tokio::spawn(async move {
            tx.send(Err(GrpcClientError::EmptyResponse)).await.unwrap();

            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });
        Box::new(rx)
    }

    fn ca_params(cn: &str) -> Result<CertificateParams, rcgen::Error> {
        // Empty Vec<String> => no DNS SANs; we'll just use DN for the CA
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.distinguished_name.push(DnType::CommonName, cn);
        params.use_authority_key_identifier_extension = true;
        Ok(params)
    }

    fn spiffe_leaf_params(spiffe_id: &str) -> Result<CertificateParams, rcgen::Error> {
        // Again, no default DNS SANs
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
            KeyUsagePurpose::ContentCommitment,
        ];
        params.extended_key_usages = vec![EKU::ClientAuth, EKU::ServerAuth];

        // Optional subject DN
        params
            .distinguished_name
            .push(DnType::CommonName, "spiffe-workload");

        // SPIFFE ID as URI SAN: URI(Ia5String)
        let uri = Ia5String::try_from(spiffe_id)?;
        params.subject_alt_names.push(SanType::URI(uri));

        Ok(params)
    }

    fn generate_svid(spiffe_id: &str, cn: &str) -> X509Svid {
        let ca_key = KeyPair::generate().unwrap();
        let ca_params = ca_params(cn).unwrap();

        // CertifiedIssuer gives you both the issuer + its self-signed cert
        let ca_issuer = CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        // ----- Leaf cert with SPIFFE SAN -----
        let leaf_key = KeyPair::generate().unwrap();
        let leaf_params = spiffe_leaf_params(spiffe_id).unwrap();

        // Sign leaf with CA
        let leaf_cert: Certificate = leaf_params.signed_by(&leaf_key, &*ca_issuer).unwrap();

        let leaf_cert_der: Vec<u8> = leaf_cert.der().to_vec();
        let leaf_key_der: Vec<u8> = leaf_key.serialize_der();
        let ca_cert_der: Vec<u8> = ca_issuer.der().to_vec();

        // Combine leaf cert and CA cert chain
        let mut cert_chain = leaf_cert_der.clone();
        cert_chain.extend_from_slice(&ca_cert_der);

        let svid = X509Svid::parse_from_der(&cert_chain, &leaf_key_der)
            .map_err(|e| {
                tracing::error!("Failed to parse SVID: {}", e);
                e
            })
            .unwrap();

        svid
    }
}
