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

//! The [`WorkloadAttestor`] trait and its [`KubernetesObjectAttestor`]
//! implementation.
//!
//! An attestor turns a [`CertRequest`] into a `WorkloadReference` — the body
//! the SPIFFE Broker `SubscribeToX509SVID` RPC expects.
//!
//! [`WorkloadAttestor`] is the extension point for new attestation modes:
//! add a [`crate::config::BrokerAttestation`] variant, implement the trait,
//! and wire it into the dispatch in `SecretManager::new_spiffe_broker`. The
//! SPIFFE Broker spec we vendor at `proto/brokerapi.proto` defines other
//! reference variants too (for example a `WorkloadPIDReference` built from a
//! container PID), but only `KubernetesObject` is implemented today:
//!
//! - `KubernetesObject`: pass `(pods, core, namespace, name, uid)`. The
//!   broker server resolves the request against the Kubernetes API; no
//!   privileges beyond a UDS connection to the broker are required.

use prost::Message;
use prost_types::Any;

use crate::identity::Error;
use crate::identity::broker_proto::spiffe::broker as bpb;
use crate::identity::manager::CertRequest;

/// Fully-qualified protobuf type names used as `Any.type_url` prefixes per
/// google.protobuf.Any conventions.
const TYPE_URL_PREFIX: &str = "type.googleapis.com/";
// The reference messages live in the `spiffe.reference` proto package
// upstream (go-spiffe exp/proto/spiffe/reference). The SPIRE agent matches
// the incoming reference by its `google.protobuf.Any` type URL against that
// package name, so these MUST be `spiffe.reference.*` — even though our
// vendored `brokerapi.proto` declares the message bodies under the
// `spiffe.broker` package (the wire bytes are identical; only the type URL
// string is matched).
//
// Used by the bundle subscriber to attest ztunnel's *own* process by PID
// when calling `SubscribeToX509Bundles` (independent of how ztunnel attests
// the workloads it proxies for).
pub(super) const WORKLOAD_PID_REFERENCE_TYPE: &str = "spiffe.reference.WorkloadPIDReference";
const KUBERNETES_OBJECT_REFERENCE_TYPE: &str = "spiffe.reference.KubernetesObjectReference";

/// Build a `WorkloadReference` for the SPIFFE Broker
/// `SubscribeToX509SVID` RPC.
pub trait WorkloadAttestor: Send + Sync + std::fmt::Debug {
    /// Construct the reference identifying the requesting workload.
    fn attest(&self, req: &CertRequest) -> Result<bpb::WorkloadReference, Error>;
}

/// KubernetesObject attestor: builds a reference that names the pod by
/// `(plural=pods, group=core, namespace, name, uid)`. All inputs come from
/// data ztunnel already has in inpod mode (ZDS `AddWorkload.uid` plus the
/// pod's `WorkloadInfo`). No `/proc` access required.
#[derive(Debug, Default, Clone, Copy)]
pub struct KubernetesObjectAttestor;

impl WorkloadAttestor for KubernetesObjectAttestor {
    fn attest(&self, req: &CertRequest) -> Result<bpb::WorkloadReference, Error> {
        let wi = req.workload.as_ref().ok_or(Error::BrokerMissingWorkload)?;
        let uid = req.workload_uid.as_ref().ok_or(Error::BrokerMissingUid)?;
        let inner = bpb::KubernetesObjectReference {
            r#type: Some(bpb::KubernetesObjectType {
                plural: "pods".to_string(),
                group: "core".to_string(),
            }),
            key: Some(bpb::KubernetesObjectKey {
                namespace: wi.namespace.clone(),
                name: wi.name.clone(),
            }),
            uid: uid.to_string(),
        };
        let reference = pack_any(KUBERNETES_OBJECT_REFERENCE_TYPE, &inner);
        Ok(bpb::WorkloadReference {
            reference: Some(reference),
        })
    }
}

/// Encode `msg` and wrap in a `google.protobuf.Any` with the supplied
/// fully-qualified protobuf type name.
pub(super) fn pack_any<M: Message>(type_name: &str, msg: &M) -> Any {
    Any {
        type_url: format!("{TYPE_URL_PREFIX}{type_name}"),
        value: msg.encode_to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::state::WorkloadInfo;
    use crate::strng;
    use prost::Message;
    use std::sync::Arc;

    fn identity() -> Identity {
        Identity::Spiffe {
            trust_domain: "test".into(),
            namespace: "test".into(),
            service_account: "attestor-test".into(),
        }
    }

    fn workload() -> Arc<WorkloadInfo> {
        Arc::new(WorkloadInfo::new(
            "echo-7d8f9".to_string(),
            "demo".to_string(),
            "default".to_string(),
        ))
    }

    // --- KubernetesObjectAttestor ---------------------------------------

    #[test]
    fn k8s_attestor_missing_workload_errors() {
        let mut req = CertRequest::new(identity());
        req.workload_uid = Some(strng::new("pod-uid"));
        let err = KubernetesObjectAttestor
            .attest(&req)
            .expect_err("missing workload");
        assert!(matches!(err, Error::BrokerMissingWorkload), "got {err:?}");
    }

    #[test]
    fn k8s_attestor_missing_uid_errors() {
        let mut req = CertRequest::new(identity());
        req.workload = Some(workload());
        let err = KubernetesObjectAttestor
            .attest(&req)
            .expect_err("missing uid");
        assert!(matches!(err, Error::BrokerMissingUid), "got {err:?}");
    }

    #[test]
    fn k8s_attestor_builds_reference() {
        let mut req = CertRequest::new(identity());
        req.workload = Some(workload());
        req.workload_uid = Some(strng::new("0ae5c03d-5fb3-4eb9-9de8-2bd4b51606ba"));

        let ref_msg = KubernetesObjectAttestor.attest(&req).expect("attest");
        let any = ref_msg.reference.expect("Any present");
        assert_eq!(
            any.type_url,
            format!("{TYPE_URL_PREFIX}{KUBERNETES_OBJECT_REFERENCE_TYPE}")
        );
        let decoded = bpb::KubernetesObjectReference::decode(any.value.as_slice())
            .expect("decode KubernetesObjectReference");
        assert_eq!(decoded.uid, "0ae5c03d-5fb3-4eb9-9de8-2bd4b51606ba");
        let typ = decoded.r#type.expect("type present");
        assert_eq!(typ.plural, "pods");
        assert_eq!(typ.group, "core");
        let key = decoded.key.expect("key present");
        assert_eq!(key.namespace, "demo");
        assert_eq!(key.name, "echo-7d8f9");
    }
}
