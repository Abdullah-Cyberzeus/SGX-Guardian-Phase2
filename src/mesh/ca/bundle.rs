//! `EnrollmentBundle` (P4.5/P4.6) — what a joiner receives once its request
//! is approved. Signed as one unit (same `canonical_bytes_for_sign` +
//! `sign_in_place_generic`/`verify_with_document` shape as
//! [`crate::mesh::ca::descriptor::CaDescriptor`]) so tampering *any* field —
//! not just the ones the Nebula cert or the membership VC individually
//! cover, but `circle_name`, `overlay_ip`, the CA's own cert PEM too — is
//! caught by one verification, not a per-field patchwork. This is what
//! makes the plan's own exit criterion ("tampering any bundle field makes B
//! reject it") hold structurally rather than by convention.

use crate::did::document::{DidDocument, Proof};
use crate::did::{doc_sign, DidRecord};
use crate::vc::credential::{sort_json_keys, VerifiableCredential};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentBundle {
    pub request_id: String,
    pub circle_id: String,
    pub circle_name: String,
    pub ca_guardian_id: String,
    pub ca_cert_pem: String,
    pub ca_fingerprint: String,
    pub member_cert_pem: String,
    pub overlay_cidr: String,
    pub overlay_ip: String,
    pub member_vc: VerifiableCredential,
    pub issued_at: String,
    #[serde(default)]
    pub proof: Proof,
}

/// Same self-contained-verification shape as
/// [`crate::mesh::ca::descriptor::CaDescriptorBundle`] — the CA's own DID
/// document travels with the bundle, so a joiner that already trusts that
/// DID (via the `CaDescriptor` it verified during discovery, P3.3) can
/// verify this without a separate resolver hop either.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnrollmentBundle {
    pub bundle: EnrollmentBundle,
    pub ca_did_document: DidDocument,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("canonicalisation failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("missing or malformed proof")]
    InvalidProof,
    #[error("verification method {0} not found in the offered DID document")]
    VerificationMethodNotFound(String),
    #[error("bundle's ca_guardian_id does not match the offered DID document")]
    DidMismatch,
}

impl EnrollmentBundle {
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }

    pub fn sign(&mut self, guardian_id: &str) -> Result<(), BundleError> {
        let record = DidRecord::load(crate::did::DEFAULT_DID_PATH)
            .map_err(|e| BundleError::Sign(e.to_string()))?;
        let km = crate::vc::issue::load_runtime_key_manager(guardian_id)
            .map_err(|e| BundleError::Sign(e.to_string()))?;
        let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
        let canonical = self.canonical_bytes_for_sign()?;
        doc_sign::sign_in_place_generic(&mut self.proof, &canonical, &km, &vm_ref)
            .map_err(|e| BundleError::Sign(e.to_string()))?;
        Ok(())
    }
}

impl SignedEnrollmentBundle {
    pub fn build_and_sign(
        request_id: String,
        circle_id: String,
        circle_name: String,
        ca_guardian_id: String,
        ca_cert_pem: String,
        ca_fingerprint: String,
        member_cert_pem: String,
        overlay_cidr: String,
        overlay_ip: String,
        member_vc: VerifiableCredential,
    ) -> Result<Self, BundleError> {
        let mut bundle = EnrollmentBundle {
            request_id,
            circle_id,
            circle_name,
            ca_guardian_id: ca_guardian_id.clone(),
            ca_cert_pem,
            ca_fingerprint,
            member_cert_pem,
            overlay_cidr,
            overlay_ip,
            member_vc,
            issued_at: Utc::now().to_rfc3339(),
            proof: Proof::default(),
        };
        bundle.sign(&ca_guardian_id)?;
        let ca_did_document = crate::did::doc_persistence::load_self()
            .map_err(|e| BundleError::Sign(e.to_string()))?
            .ok_or_else(|| BundleError::Sign("no local DID document".into()))?;
        Ok(Self {
            bundle,
            ca_did_document,
        })
    }

    /// Verifies the whole bundle's signature against the CA's own DID
    /// document (bundled alongside it) — no separate resolver hop, same
    /// reasoning as `CaDescriptor::verify_with_document`.
    pub fn verify(&self) -> Result<(), BundleError> {
        if self.ca_did_document.id != self.bundle.member_vc.issuer {
            // The membership VC and the bundle must agree on who issued
            // them — a mismatch here means the two halves were assembled
            // from different CAs, deliberately or otherwise.
            return Err(BundleError::DidMismatch);
        }
        if self.bundle.proof.verification_method.trim().is_empty()
            || self.bundle.proof.proof_value.trim().is_empty()
        {
            return Err(BundleError::InvalidProof);
        }
        let vm = self
            .ca_did_document
            .verification_method
            .iter()
            .find(|vm| vm.id == self.bundle.proof.verification_method)
            .ok_or_else(|| {
                BundleError::VerificationMethodNotFound(
                    self.bundle.proof.verification_method.clone(),
                )
            })?;
        let public_key = crate::circle::model::public_key_from_vm(vm)
            .map_err(|_| BundleError::InvalidProof)?;
        let canonical = self.bundle.canonical_bytes_for_sign()?;
        let digest = Sha256::digest(&canonical);
        let signature = general_purpose::STANDARD
            .decode(&self.bundle.proof.proof_value)
            .map_err(|_| BundleError::InvalidProof)?;
        doc_sign::ecdsa_p256_verify_der_or_raw(&public_key, &digest, &signature)
            .map_err(|_| BundleError::InvalidProof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vc::credential::{CredentialStatus, CredentialSubject, MembershipStatus};

    fn sample_vc() -> VerifiableCredential {
        let now = Utc::now();
        VerifiableCredential {
            context: vec!["https://www.w3.org/2018/credentials/v1".into()],
            id: "urn:uuid:test".into(),
            vc_type: vec!["VerifiableCredential".into(), "CircleMembership".into()],
            issuer: "did:guardian:z6MkCa".into(),
            issuance_date: now.to_rfc3339(),
            expiration_date: (now + chrono::Duration::days(365)).to_rfc3339(),
            credential_subject: CredentialSubject::new(
                "did:guardian:z6MkJoiner".into(),
                crate::vc::credential::CredentialRole::Member,
                vec!["mesh:join".into()],
                now.to_rfc3339(),
                "circle-X".into(),
                Some("edge-7".into()),
                MembershipStatus::Active,
            ),
            credential_status: CredentialStatus {
                id: "status#0".into(),
                status_type: "StatusList2021Entry".into(),
                status_purpose: "revocation".into(),
                status_list_index: "0".into(),
                status_list_credential: "did:guardian:z6MkCa/status-list".into(),
            },
            proof: Proof::default(),
        }
    }

    #[test]
    fn tampering_any_field_after_signing_is_detected() {
        // `canonical_bytes_for_sign` covers the whole struct — a change to
        // any field, not just ones a nested VC/cert already covers,
        // changes the canonical bytes and so breaks the signature. This
        // asserts that structural property directly rather than the full
        // sign/verify round trip (which needs a real KeyManager + DID
        // record on disk — covered instead by `mesh::ca::server`'s
        // integration tests).
        let mut bundle = EnrollmentBundle {
            request_id: "req-1".into(),
            circle_id: "circle-X".into(),
            circle_name: "SGX-Alpha".into(),
            ca_guardian_id: "ca-1".into(),
            ca_cert_pem: "CERT".into(),
            ca_fingerprint: "sha256:aaaa".into(),
            member_cert_pem: "MEMBER-CERT".into(),
            overlay_cidr: "192.168.100.0/24".into(),
            overlay_ip: "192.168.100.5/24".into(),
            member_vc: sample_vc(),
            issued_at: Utc::now().to_rfc3339(),
            proof: Proof::default(),
        };
        let before = bundle.canonical_bytes_for_sign().unwrap();
        bundle.overlay_ip = "192.168.100.6/24".into();
        let after = bundle.canonical_bytes_for_sign().unwrap();
        assert_ne!(before, after);
    }
}
