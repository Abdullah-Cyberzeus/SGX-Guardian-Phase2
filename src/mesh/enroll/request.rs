//! P4.6 — builds and signs this Guardian's own [`EnrollmentSubmission`].
//! Keygen (via [`super::keys::ensure_local_keypair`]) happens once and is
//! reused on every retry — the same keypair backs every submission for a
//! given `guardian_id` until it actually joins something, matching the
//! plan's own "keygen once, reused on retries."

use crate::mesh::ca::requests::EnrollmentSubmission;
use crate::mesh::enroll::keys::{self, KeygenError};
use crate::startup::GuardianPaths;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("local keygen failed: {0}")]
    Keygen(#[from] KeygenError),
    #[error("could not load own DID document: {0}")]
    Did(String),
    #[error("no local DID document yet — complete onboarding first")]
    NoDidDocument,
    #[error("could not sign the submission: {0}")]
    Sign(String),
}

/// Builds and signs a fresh [`EnrollmentSubmission`] for `circle_id`,
/// targeting whichever CA's `lan_endpoint` the caller already discovered
/// and verified (`mesh::discovery::browse`) — this function only builds the
/// request; `mesh::enroll::transport_lan` is what actually sends it.
pub fn build(
    paths: &GuardianPaths,
    guardian_id: &str,
    circle_id: &str,
    join_code: Option<String>,
) -> Result<EnrollmentSubmission, BuildError> {
    let nebula_dir = paths.var_root.join("nebula").display().to_string();
    let keypair = keys::ensure_local_keypair(&nebula_dir, guardian_id)?;

    let did_document = crate::did::doc_persistence::load_self()
        .map_err(|e| BuildError::Did(e.to_string()))?
        .ok_or(BuildError::NoDidDocument)?;

    let km = crate::vc::issue::load_runtime_key_manager(guardian_id)
        .map_err(|e| BuildError::Sign(e.to_string()))?;
    let hw_backend = km.backend_name().to_lowercase();

    let mut submission = EnrollmentSubmission {
        protocol_version: crate::mesh::ca::requests::PROTOCOL_VERSION,
        circle_id: circle_id.to_string(),
        guardian_id: guardian_id.to_string(),
        nonce: uuid::Uuid::new_v4().to_string(),
        nebula_public_key_pem: keypair.public_key_pem,
        hw_backend,
        join_code,
        did_document,
        proof: crate::did::document::Proof::default(),
    };
    submission
        .sign(guardian_id)
        .map_err(|e| BuildError::Sign(e.to_string()))?;
    Ok(submission)
}
