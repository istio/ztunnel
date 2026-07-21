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

//! Shared certificate-chain verification used by both inbound and outbound mesh TLS.
//!
//! Both directions validate the peer's certificate against the same trust anchors and the same
//! CRL revocation policy via `rustls-webpki`; they differ only in the [`KeyUsage`] required
//! (client vs server auth) and in the direction-specific identity check applied afterwards
//! (trust-domain match on inbound, exact SAN match on outbound).

use crate::tls::crl::CrlManager;
use crate::tls::lib::provider;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{CertRevocationListError, CertificateError, OtherError, RootCertStore};
use std::sync::Arc;
use webpki::{
    CertRevocationList, EndEntityCert, ExpirationPolicy, KeyUsage, RevocationCheckDepth,
    RevocationOptionsBuilder, UnknownStatusPolicy,
};

pub struct VerifiedChain {
    /// Verified intermediates, leaf-adjacent first. Excludes the end-entity and the trust anchor.
    pub intermediates: Vec<CertificateDer<'static>>,
}

/// Verifies the peer's certificate chains to a trusted root and, when CRLs are supplied, is not revoked.
/// Shared by inbound ([`KeyUsage::client_auth`]) and outbound ([`KeyUsage::server_auth`]) mesh TLS.
///
/// The CRL revocation policy is identical for both directions:
/// - [`RevocationCheckDepth::Chain`] — check the entire chain, not just the end-entity cert.
/// - [`UnknownStatusPolicy::Allow`] — fail open when a cert's revocation status is unknown.
/// - [`ExpirationPolicy::Ignore`] — do not reject solely because a CRL's `nextUpdate` has passed.
///
/// CRLs are read from `crl_manager` (when present) on every call, so CRL file updates take effect
/// on new connections immediately — both directions get identical snapshot semantics for free.
///
/// Does NOT perform any SAN / identity / hostname check — callers layer that on top.
pub fn verify_cert_chain(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    roots: &RootCertStore,
    now: UnixTime,
    key_usage: KeyUsage,
    crl_manager: &CrlManager,
) -> Result<VerifiedChain, rustls::Error> {
    let algs = provider().signature_verification_algorithms;
    let ee = EndEntityCert::try_from(end_entity).map_err(webpki_error_to_rustls)?;

    // get_crls() returns pre-parsed CRLs; the Arc must outlive the borrowed refs below.
    let crls = crl_manager.get_crls();
    let crl_refs: Vec<&CertRevocationList<'_>> = crls.iter().collect();

    let revocation = (!crl_refs.is_empty()).then(|| {
        RevocationOptionsBuilder::new(&crl_refs)
            .expect("non-empty CRL list")
            .with_depth(RevocationCheckDepth::Chain)
            .with_status_policy(UnknownStatusPolicy::Allow)
            .with_expiration_policy(ExpirationPolicy::Ignore)
            .build()
    });

    let path = ee
        .verify_for_usage(
            algs.all,
            &roots.roots,
            intermediates,
            now,
            key_usage,
            revocation,
            None,
        )
        .map_err(webpki_error_to_rustls)?;

    // webpki builds the path from the end-entity upward, so `intermediate_certificates()` yields
    // the used intermediates leaf-adjacent first — the order the CRL index expects.
    Ok(VerifiedChain {
        intermediates: path
            .intermediate_certificates()
            .map(|cert| cert.der().into_owned())
            .collect(),
    })
}

/// Maps `rustls-webpki` errors to `rustls::Error`.
///
/// We map the variants that carry structured `CertificateError` / CRL types used by rustls for
/// handshake reporting; everything else (signature-algorithm context, uncommon path failures, and
/// future `#[non_exhaustive]` variants) is wrapped in [`CertificateError::Other`] while preserving
/// the original `webpki::Error` for logs.
pub fn webpki_error_to_rustls(error: webpki::Error) -> rustls::Error {
    use webpki::Error;

    match error {
        Error::BadDer | Error::BadDerTime | Error::TrailingData(_) => {
            CertificateError::BadEncoding.into()
        }
        Error::CertNotValidYet { time, not_before } => {
            CertificateError::NotValidYetContext { time, not_before }.into()
        }
        Error::CertExpired { time, not_after } => {
            CertificateError::ExpiredContext { time, not_after }.into()
        }
        Error::UnknownIssuer => CertificateError::UnknownIssuer.into(),
        Error::CertNotValidForName(ctx) => CertificateError::NotValidForNameContext {
            expected: ctx.expected,
            presented: ctx.presented,
        }
        .into(),
        Error::CertRevoked => CertificateError::Revoked.into(),
        Error::UnknownRevocationStatus => CertificateError::UnknownRevocationStatus.into(),
        Error::CrlExpired { time, next_update } => {
            CertificateError::ExpiredRevocationListContext { time, next_update }.into()
        }
        Error::IssuerNotCrlSigner => CertRevocationListError::IssuerInvalidForCrl.into(),
        Error::InvalidSignatureForPublicKey => CertificateError::BadSignature.into(),
        #[allow(deprecated)]
        Error::RequiredEkuNotFound | Error::RequiredEkuNotFoundContext(_) => {
            CertificateError::InvalidPurpose.into()
        }
        e => CertificateError::Other(OtherError(Arc::new(e))).into(),
    }
}
