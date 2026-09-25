//! `CaDescriptor` (P3.1) — the signed, self-describing "who is this CA"
//! document a joining Guardian fetches once it has *found* a candidate CA on
//! the LAN (via `mesh::discovery::browse`, which learns *where* to look from
//! mDNS or a `CaBeacon`, neither of which is itself authenticated — see that
//! module's doc comment for why that split is safe).
//!
//! Deliberately self-contained: the fetch response carries this descriptor
//! *and* the CA's own `DidDocument`, so [`CaDescriptor::verify_with_document`]
//! needs no separate DID resolution step. LAN discovery has to work with no
//! WAN reachable at all — a resolver hop that needs the internet would
//! silently break the one scenario this phase exists for.
//!
//! Signing follows the same `canonical_bytes_for_sign` + `sign_in_place_generic`
//! shape every other signed record in this codebase uses (`CircleRegistry`,
//! `NotificationPrefs`, `VerifiableCredential`) — nothing new to learn here if
//! you already know one of those.

use crate::did::document::{DidDocument, Proof};
use crate::did::{doc_sign, DidRecord};
use crate::mesh::ca::policy::{ApprovalMode, AttestationRequirement, CircleEnrollmentPolicy};
use crate::mesh::profile::MeshProfile;
use crate::vc::credential::sort_json_keys;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 12h refresh (P3.1) plus slack for a joiner mid-scan right before a
/// refresh tick, plus tolerance for modest clock drift between Guardians —
/// generous on purpose. This is a defence against replaying a *long*-stale
/// descriptor (an old CA state, a rotated fingerprint, a decommissioned
/// circle), not a tight anti-replay nonce; a signature only proves the CA
/// once produced these exact bytes, not that they are still current.
pub const FRESHNESS_WINDOW_SECS: i64 = 26 * 3600;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySummary {
    pub approval: ApprovalMode,
    pub attestation: AttestationRequirement,
}

impl From<&CircleEnrollmentPolicy> for PolicySummary {
    fn from(policy: &CircleEnrollmentPolicy) -> Self {
        Self {
            approval: policy.approval,
            attestation: policy.attestation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CaDescriptor {
    /// Bumped every time this Guardian regenerates its descriptor (on the
    /// 12h refresh tick or an endpoint change — see `mesh::discovery::advertise`).
    /// Exists purely so a future stale-replay defence has something to
    /// compare against; `generated_at` is what today's freshness check uses.
    pub version: u32,
    pub circle_id: String,
    pub circle_name: String,
    pub ca_guardian_id: String,
    pub ca_did: String,
    pub ca_fingerprint: String,
    pub overlay_cidr: String,
    /// `ip:port` of the descriptor/enrollment listener a joiner should talk
    /// to next — the same port this very descriptor was just fetched from.
    pub lan_endpoint: String,
    pub generated_at: String,
    pub policy_summary: PolicySummary,
    #[serde(default)]
    pub proof: Proof,
}

/// What [`serve_descriptor`]/`GetCaDescriptor` actually returns: the
/// descriptor plus the CA's own DID document, so the fetch is
/// self-verifying without a network round-trip to a resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaDescriptorBundle {
    pub descriptor: CaDescriptor,
    pub ca_did_document: DidDocument,
}

#[derive(Debug, thiserror::Error)]
pub enum DescriptorError {
    #[error("could not load own DID: {0}")]
    Did(String),
    #[error("could not load signing key: {0}")]
    Key(String),
    #[error("canonicalisation failed: {0}")]
    Canonical(#[from] serde_json::Error),
    #[error("signing failed: {0}")]
    Sign(String),
    #[error("missing or malformed proof")]
    InvalidProof,
    #[error("verification method {0} not found in the offered DID document")]
    VerificationMethodNotFound(String),
    #[error("descriptor's ca_did does not match the offered DID document's id")]
    DidMismatch,
    #[error("descriptor is outside the accepted freshness window")]
    Stale,
    #[error("descriptor has an unparseable generated_at timestamp: {0}")]
    BadTimestamp(String),
    #[error("network error: {0}")]
    Io(String),
}

impl CaDescriptor {
    /// Builds an unsigned descriptor from this Guardian's own `MeshProfile`
    /// and enrollment policy — call [`CaDescriptor::sign`] before handing it
    /// to anyone.
    pub fn build(
        profile: &MeshProfile,
        lan_endpoint: String,
        policy: &CircleEnrollmentPolicy,
        version: u32,
    ) -> Self {
        Self {
            version,
            circle_id: profile.circle_id.clone(),
            circle_name: profile.circle_name.clone(),
            ca_guardian_id: profile.guardian_id.clone(),
            ca_did: profile.ca_owner_did.clone(),
            ca_fingerprint: profile.ca_fingerprint.clone(),
            overlay_cidr: profile.overlay_cidr.clone(),
            lan_endpoint,
            generated_at: Utc::now().to_rfc3339(),
            policy_summary: PolicySummary::from(policy),
            proof: Proof::default(),
        }
    }

    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }

    pub fn sign(&mut self, node_id: &str) -> Result<(), DescriptorError> {
        let record = DidRecord::load(crate::did::DEFAULT_DID_PATH)
            .map_err(|e| DescriptorError::Did(e.to_string()))?;
        let km = crate::vc::issue::load_runtime_key_manager(node_id)
            .map_err(|e| DescriptorError::Key(e.to_string()))?;
        let vm_ref = format!(
            "{}#dkp-v{}",
            record.did,
            record.current_dkp_version.max(1)
        );
        let canonical = self.canonical_bytes_for_sign()?;
        doc_sign::sign_in_place_generic(&mut self.proof, &canonical, &km, &vm_ref)
            .map_err(|e| DescriptorError::Sign(e.to_string()))?;
        Ok(())
    }

    /// Verifies this descriptor's signature against the CA's own DID
    /// document (fetched alongside it — see the module doc), then checks
    /// `generated_at` is within [`FRESHNESS_WINDOW_SECS`] of `now`. Both
    /// checks must pass for a LAN entry to render as verified/selectable
    /// (P3.6); either failing alone is enough to reject it.
    pub fn verify_with_document(
        &self,
        ca_doc: &DidDocument,
        now: DateTime<Utc>,
    ) -> Result<(), DescriptorError> {
        if ca_doc.id != self.ca_did {
            return Err(DescriptorError::DidMismatch);
        }
        if self.proof.verification_method.trim().is_empty()
            || self.proof.proof_value.trim().is_empty()
        {
            return Err(DescriptorError::InvalidProof);
        }
        let vm = ca_doc
            .verification_method
            .iter()
            .find(|vm| vm.id == self.proof.verification_method)
            .ok_or_else(|| {
                DescriptorError::VerificationMethodNotFound(self.proof.verification_method.clone())
            })?;
        let public_key = crate::circle::model::public_key_from_vm(vm)
            .map_err(|_| DescriptorError::InvalidProof)?;
        let canonical = self.canonical_bytes_for_sign()?;
        let digest = Sha256::digest(&canonical);
        let signature = general_purpose::STANDARD
            .decode(&self.proof.proof_value)
            .map_err(|_| DescriptorError::InvalidProof)?;
        doc_sign::ecdsa_p256_verify_der_or_raw(&public_key, &digest, &signature)
            .map_err(|_| DescriptorError::InvalidProof)?;

        let generated_at = DateTime::parse_from_rfc3339(&self.generated_at)
            .map_err(|e| DescriptorError::BadTimestamp(e.to_string()))?
            .with_timezone(&Utc);
        let age_secs = (now - generated_at).num_seconds();
        if !(0..=FRESHNESS_WINDOW_SECS).contains(&age_secs) {
            return Err(DescriptorError::Stale);
        }
        Ok(())
    }
}

/// Builds a freshly signed [`CaDescriptorBundle`] for `profile`, advertised
/// at `advertise_addr` (the address a joiner should use). Called by
/// `mesh::ca::server::serve_forever` (P4.2), which owns the actual HTTP
/// listener and its 12h refresh loop — this function is the pure,
/// side-effect-free half, kept here next to the type it builds.
pub fn build_and_sign_bundle(
    profile: &MeshProfile,
    advertise_addr: &str,
    version: u32,
) -> Result<CaDescriptorBundle, DescriptorError> {
    let paths = crate::startup::GuardianPaths::production();
    let policy = crate::mesh::ca::policy::load(&paths)
        .map_err(|e| DescriptorError::Did(e.to_string()))?
        .unwrap_or_default();
    let mut descriptor = CaDescriptor::build(profile, advertise_addr.to_string(), &policy, version);
    descriptor.sign(&profile.guardian_id)?;
    let ca_did_document = crate::did::doc_persistence::load_self()
        .map_err(|e| DescriptorError::Did(e.to_string()))?
        .ok_or_else(|| DescriptorError::Did("no local DID document".into()))?;
    Ok(CaDescriptorBundle {
        descriptor,
        ca_did_document,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::profile::{EnrollChannel, MeshRole, PROFILE_SCHEMA_VERSION};

    fn sample_profile() -> MeshProfile {
        MeshProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            guardian_id: "p3-ca-1".into(),
            role: MeshRole::Ca,
            circle_id: "circle-ABCDEFGHJKMN".into(),
            circle_name: "SGX-Alpha".into(),
            ca_guardian_id: "p3-ca-1".into(),
            ca_fingerprint: "sha256:deadbeef".into(),
            ca_owner_did: "did:guardian:z6MkExampleOwner".into(),
            overlay_cidr: "192.168.101.0/24".into(),
            overlay_ip: "192.168.101.2/24".into(),
            lighthouses: Vec::new(),
            rendezvous_url: None,
            enrolled_via: EnrollChannel::Created,
            enrolled_at: Utc::now().to_rfc3339(),
        }
    }

    #[test]
    fn a_built_descriptor_carries_every_profile_field_it_should() {
        let profile = sample_profile();
        let policy = CircleEnrollmentPolicy::default();
        let descriptor =
            CaDescriptor::build(&profile, "192.168.101.2:50071".into(), &policy, 1);
        assert_eq!(descriptor.circle_id, profile.circle_id);
        assert_eq!(descriptor.circle_name, profile.circle_name);
        assert_eq!(descriptor.ca_did, profile.ca_owner_did);
        assert_eq!(descriptor.ca_fingerprint, profile.ca_fingerprint);
        assert_eq!(descriptor.lan_endpoint, "192.168.101.2:50071");
    }

    #[test]
    fn canonical_bytes_ignore_the_proof_field() {
        let profile = sample_profile();
        let policy = CircleEnrollmentPolicy::default();
        let mut descriptor =
            CaDescriptor::build(&profile, "192.168.101.2:50071".into(), &policy, 1);
        let before = descriptor.canonical_bytes_for_sign().unwrap();
        descriptor.proof.proof_value = "not-actually-signed-yet".into();
        let after = descriptor.canonical_bytes_for_sign().unwrap();
        assert_eq!(before, after);
    }

    fn minimal_doc(id: &str) -> DidDocument {
        DidDocument {
            context: vec![crate::did::document::CONTEXT_DID_V1.to_string()],
            id: id.to_string(),
            controller: id.to_string(),
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            service: Vec::new(),
            sgx_node_name: None,
            sgx_created: Utc::now().to_rfc3339(),
            sgx_updated: Utc::now().to_rfc3339(),
            sgx_version_id: 1,
            sgx_method_spec_version: "1".to_string(),
            sgx_status: None,
            sgx_revoked_vm: Vec::new(),
            proof: None,
        }
    }

    #[test]
    fn a_descriptor_whose_did_does_not_match_the_offered_document_is_rejected() {
        let profile = sample_profile();
        let policy = CircleEnrollmentPolicy::default();
        let descriptor = CaDescriptor::build(&profile, "x:1".into(), &policy, 1);
        let doc = minimal_doc("did:guardian:z6MkSomeoneElse");
        let err = descriptor
            .verify_with_document(&doc, Utc::now())
            .unwrap_err();
        assert!(matches!(err, DescriptorError::DidMismatch));
    }

    #[test]
    fn a_descriptor_with_no_verification_method_offered_is_rejected_before_any_signature_check() {
        let profile = sample_profile();
        let policy = CircleEnrollmentPolicy::default();
        let descriptor = CaDescriptor::build(&profile, "x:1".into(), &policy, 1);
        let doc = minimal_doc(&descriptor.ca_did);
        let err = descriptor
            .verify_with_document(&doc, Utc::now())
            .unwrap_err();
        assert!(matches!(err, DescriptorError::InvalidProof));
    }
}
