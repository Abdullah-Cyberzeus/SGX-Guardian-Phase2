//! P4.5 — turns an `Approved` [`crate::mesh::ca::requests::EnrollmentRequest`]
//! into a [`crate::mesh::ca::bundle::SignedEnrollmentBundle`]: allocate the
//! new member's overlay IP, sign its Nebula cert from its own public key
//! (never touching a private key — same `-in-pub` discipline every other
//! signing path in this codebase already follows), issue its membership VC,
//! and sign the whole bundle as one unit.

use crate::mesh::ca::bundle::{BundleError, SignedEnrollmentBundle};
use crate::mesh::ca::requests::{EnrollmentRequest, RequestState};
use crate::mesh::profile::MeshProfile;
use crate::nebula::ca::{CaIdentity, NebulaCA};
use crate::nebula::models::CircleMembership;
use crate::nebula::overlay_registry::OverlayRegistry;
use std::fs;

#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    #[error("request {0} is not approved")]
    NotApproved(String),
    #[error("overlay IP allocation failed: {0}")]
    Overlay(String),
    #[error("Nebula signing failed: {0}")]
    Nebula(#[from] std::io::Error),
    #[error("could not read the signed member certificate: {0}")]
    ReadCert(String),
    #[error("could not read the CA certificate: {0}")]
    ReadCaCert(String),
    #[error("could not read the CA fingerprint")]
    MissingFingerprint,
    #[error("VC issuance failed: {0}")]
    Vc(String),
    #[error("bundle signing failed: {0}")]
    Bundle(#[from] BundleError),
}

/// Issues the bundle for an already-`Approved` request. Idempotent in the
/// sense that matters for this codebase's crash-safety conventions: Nebula
/// cert signing itself is not staged/transactional (unlike `mesh::ca::create_circle`),
/// because — unlike creating a whole new CA tree — signing one more member
/// cert into the existing live `nodes/` directory has no partial-state
/// hazard to guard against: either the file gets written or it does not,
/// and a re-issue for the same `guardian_id` just re-signs and overwrites.
pub fn issue(
    paths: &crate::startup::GuardianPaths,
    profile: &MeshProfile,
    request: &EnrollmentRequest,
) -> Result<SignedEnrollmentBundle, IssueError> {
    if request.state != RequestState::Approved {
        return Err(IssueError::NotApproved(request.request_id.clone()));
    }

    let nebula_dir = paths.var_root.join("nebula");
    let nebula_dir_str = nebula_dir.display().to_string();
    let guardian_id = &request.submission.guardian_id;

    let mut overlay_registry = OverlayRegistry::load_or_create(
        &nebula_dir.join("overlay_registry.json").display().to_string(),
        &profile.circle_id,
        &overlay_prefix(&profile.overlay_cidr),
        &profile.guardian_id,
    );
    let overlay_ip = overlay_registry
        .assign_ip(guardian_id)
        .map_err(IssueError::Overlay)?;
    overlay_registry
        .save(&nebula_dir.join("overlay_registry.json").display().to_string())
        .map_err(IssueError::Overlay)?;

    let membership = CircleMembership {
        node_name: guardian_id.clone(),
        circle_id: profile.circle_id.clone(),
        vc_hash: request.request_id.clone(),
        is_valid: true,
    };
    let identity = CaIdentity::for_circle(&profile.circle_name);
    NebulaCA::issue_node_cert_from_pub_with(
        &nebula_dir_str,
        &membership,
        &overlay_ip,
        &request.submission.nebula_public_key_pem,
        &identity,
    )?;

    let member_cert_pem = fs::read_to_string(nebula_dir.join("nodes").join(format!("{guardian_id}.crt")))
        .map_err(|e| IssueError::ReadCert(e.to_string()))?;
    let ca_cert_pem = fs::read_to_string(nebula_dir.join("ca").join("ca.crt"))
        .map_err(|e| IssueError::ReadCaCert(e.to_string()))?;
    let ca_fingerprint =
        NebulaCA::ca_fingerprint(&nebula_dir_str).ok_or(IssueError::MissingFingerprint)?;

    let issuer_did = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
        .map_err(|e| IssueError::Vc(format!("load own DID: {e}")))?;
    let km = crate::vc::issue::load_runtime_key_manager(&profile.guardian_id)
        .map_err(|e| IssueError::Vc(format!("load signing key: {e}")))?;
    let role = crate::vc::credential::CredentialRole::Member;
    let member_vc = crate::vc::issue::issue_membership_vc(
        &issuer_did,
        &km,
        crate::vc::issue::IssueRequest {
            subject_did: &request.submission.did_document.id,
            role: role.clone(),
            permissions: crate::vc::issue::default_permissions_for_role(role),
            circle_id: &profile.circle_id,
            node_hint: Some(guardian_id.clone()),
            duration_days: None,
        },
    )
    .map_err(|e| IssueError::Vc(e.to_string()))?;

    SignedEnrollmentBundle::build_and_sign(
        request.request_id.clone(),
        profile.circle_id.clone(),
        profile.circle_name.clone(),
        profile.guardian_id.clone(),
        ca_cert_pem,
        ca_fingerprint,
        member_cert_pem,
        profile.overlay_cidr.clone(),
        overlay_ip,
        member_vc,
    )
    .map_err(IssueError::Bundle)
}

fn overlay_prefix(overlay_cidr: &str) -> String {
    overlay_cidr
        .split('/')
        .next()
        .and_then(|addr| {
            let octets: Vec<&str> = addr.split('.').collect();
            (octets.len() == 4).then(|| octets[..3].join("."))
        })
        .unwrap_or_else(|| crate::mesh::legacy::LEGACY_OVERLAY_PREFIX.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_prefix_extracts_the_first_three_octets() {
        assert_eq!(overlay_prefix("192.168.101.0/24"), "192.168.101");
    }

    #[test]
    fn overlay_prefix_falls_back_to_the_legacy_prefix_for_garbage_input() {
        assert_eq!(
            overlay_prefix("not-a-cidr"),
            crate::mesh::legacy::LEGACY_OVERLAY_PREFIX
        );
    }
}
