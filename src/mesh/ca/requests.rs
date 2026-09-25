//! P4.3/P4.4 — the persisted enrollment request store and verification
//! pipeline for circles created via `mesh::ca::create_circle` (Phase 2+).
//! Replaces YAML-polling for those circles only; the legacy hardcoded
//! nodeA/B/C cohort keeps using `cert_service.rs`'s YAML flow unchanged,
//! gated behind `SGX_LEGACY_ENROLL` (`src/server.rs`) — nothing here
//! touches that path.
//!
//! `SubmitEnrollment` (the HTTP handler in `mesh::ca::server`) returns a
//! request id immediately after storing a `Pending` request — no blocking
//! RPC waits on a human. The joiner polls `GET /enroll/{request_id}`
//! (`mesh::enroll::transport_lan`) until it sees `Approved`/`Rejected`.

use crate::did::document::{DidDocument, Proof};
use crate::did::doc_sign;
use crate::mesh::ca::policy::CircleEnrollmentPolicy;
use crate::vc::credential::sort_json_keys;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;

pub const PROTOCOL_VERSION: u32 = 1;
pub const NONCE_FRESHNESS_SECS: i64 = 5 * 60;
pub const DEFAULT_TTL_DAYS: i64 = 7;
pub const RATE_LIMIT_PER_SOURCE_PER_HOUR: usize = 10;

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),
    #[error("this CA serves circle {actual}, not {requested}")]
    WrongCircle { requested: String, actual: String },
    #[error("guardian_id {0} is already pending or a member under a different key")]
    GuardianIdCollision(String),
    #[error("nonce missing, already used, or outside the freshness window")]
    BadNonce,
    #[error("binding signature does not verify against the offered DID document: {0}")]
    BadBindingSignature(String),
    #[error("rate limit exceeded for this source")]
    RateLimited,
    #[error("guardian_id {0} is revoked")]
    Revoked(String),
    #[error("hardware backend {0} is not allowed for this circle")]
    HwBackendNotAllowed(String),
    #[error("circle already has {current}/{max} approved members")]
    MemberCapReached { current: u32, max: u32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("request {0} not found")]
    NotFound(String),
    #[error("request {0} is not pending")]
    NotPending(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Pending,
    Approved,
    Rejected,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyReport {
    pub checks: Vec<PolicyCheck>,
}

impl PolicyReport {
    fn push(&mut self, name: &str, passed: bool, detail: impl Into<String>) {
        self.checks.push(PolicyCheck {
            name: name.to_string(),
            passed,
            detail: detail.into(),
        });
    }

    pub fn all_passed(&self) -> bool {
        self.checks.iter().all(|c| c.passed)
    }
}

/// What a joiner submits (`POST /enroll`). `proof` signs
/// `canonical_bytes_for_sign` (this struct with `proof` defaulted) using the
/// joiner's own DKP key — verified against a verification method inside its
/// own `did_document`. That one signature does double duty for P4.4's
/// checks (2) and (3): a `nonce` the CA has not seen before, inside the
/// window, *and* signed by the key the DID document claims, together prove
/// this is a fresh request genuinely originated by the device holding that
/// key — not a captured-and-replayed older one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentSubmission {
    pub protocol_version: u32,
    pub circle_id: String,
    pub guardian_id: String,
    pub nonce: String,
    pub nebula_public_key_pem: String,
    pub hw_backend: String,
    #[serde(default)]
    pub join_code: Option<String>,
    pub did_document: DidDocument,
    #[serde(default)]
    pub proof: Proof,
}

impl EnrollmentSubmission {
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }

    /// Signs in place using the joiner's own runtime signing context —
    /// mirrors `CaDescriptor::sign`/`CircleRegistry::sign` exactly.
    pub fn sign(&mut self, guardian_id: &str) -> Result<(), RequestError> {
        let record = crate::did::DidRecord::load(crate::did::DEFAULT_DID_PATH)
            .map_err(|e| RequestError::BadBindingSignature(e.to_string()))?;
        let km = crate::vc::issue::load_runtime_key_manager(guardian_id)
            .map_err(|e| RequestError::BadBindingSignature(e.to_string()))?;
        let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
        let canonical = self.canonical_bytes_for_sign()?;
        doc_sign::sign_in_place_generic(&mut self.proof, &canonical, &km, &vm_ref)
            .map_err(|e| RequestError::BadBindingSignature(e.to_string()))?;
        Ok(())
    }

    /// Checks (2)+(3): the binding signature verifies against the offered
    /// `did_document`'s own verification method, and the DID document's
    /// `id` matches whichever DID that verification method actually belongs
    /// to (self-consistency — a document cannot vouch for a key it does not
    /// itself list).
    fn verify_binding(&self) -> Result<(), RequestError> {
        if self.proof.verification_method.trim().is_empty()
            || self.proof.proof_value.trim().is_empty()
        {
            return Err(RequestError::BadBindingSignature("missing proof".into()));
        }
        if !self
            .proof
            .verification_method
            .starts_with(&format!("{}#", self.did_document.id))
        {
            return Err(RequestError::BadBindingSignature(
                "proof's verification method does not belong to the offered DID document".into(),
            ));
        }
        let vm = self
            .did_document
            .verification_method
            .iter()
            .find(|vm| vm.id == self.proof.verification_method)
            .ok_or_else(|| {
                RequestError::BadBindingSignature("verification method not found".into())
            })?;
        let public_key = crate::circle::model::public_key_from_vm(vm)
            .map_err(|e| RequestError::BadBindingSignature(e.to_string()))?;
        let canonical = self
            .canonical_bytes_for_sign()
            .map_err(|e| RequestError::BadBindingSignature(e.to_string()))?;
        let digest = Sha256::digest(&canonical);
        let signature = general_purpose::STANDARD
            .decode(&self.proof.proof_value)
            .map_err(|e| RequestError::BadBindingSignature(e.to_string()))?;
        doc_sign::ecdsa_p256_verify_der_or_raw(&public_key, &digest, &signature)
            .map_err(|e| RequestError::BadBindingSignature(e.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentRequest {
    pub request_id: String,
    pub state: RequestState,
    pub submission: EnrollmentSubmission,
    pub policy_report: PolicyReport,
    pub auto_approved: bool,
    pub source_ip: String,
    pub created_at: String,
    pub expires_at: String,
    pub decided_at: Option<String>,
    pub decision_reason: Option<String>,
}

fn requests_dir(paths: &crate::startup::GuardianPaths) -> PathBuf {
    paths.var_root.join("mesh").join("ca").join("requests")
}

fn request_path(paths: &crate::startup::GuardianPaths, request_id: &str) -> PathBuf {
    requests_dir(paths).join(format!("{}.json", request_id))
}

// In-memory only, deliberately — see the module doc's reasoning for why a
// nonce/rate-limit window this short does not need to survive a restart.
static SEEN_NONCES: Lazy<StdMutex<HashMap<String, DateTime<Utc>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));
static RATE_LIMIT: Lazy<StdMutex<HashMap<String, Vec<DateTime<Utc>>>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

fn check_and_consume_nonce(nonce: &str, now: DateTime<Utc>) -> Result<(), RequestError> {
    if nonce.trim().is_empty() {
        return Err(RequestError::BadNonce);
    }
    let mut seen = SEEN_NONCES.lock().unwrap_or_else(|e| e.into_inner());
    seen.retain(|_, ts| now.signed_duration_since(*ts).num_seconds() < NONCE_FRESHNESS_SECS);
    if seen.contains_key(nonce) {
        return Err(RequestError::BadNonce);
    }
    seen.insert(nonce.to_string(), now);
    Ok(())
}

fn check_rate_limit(source_ip: &str, now: DateTime<Utc>) -> Result<(), RequestError> {
    let mut limits = RATE_LIMIT.lock().unwrap_or_else(|e| e.into_inner());
    let entry = limits.entry(source_ip.to_string()).or_default();
    entry.retain(|ts| now.signed_duration_since(*ts).num_seconds() < 3600);
    if entry.len() >= RATE_LIMIT_PER_SOURCE_PER_HOUR {
        return Err(RequestError::RateLimited);
    }
    entry.push(now);
    Ok(())
}

/// Runs P4.4 checks (1) protocol/circle_id, (2)+(3) nonce/binding (via
/// [`EnrollmentSubmission::verify_binding`]), (5) guardian_id collision and
/// (6) CRL revocation, and stores the result as a `Pending` (or
/// auto-rejected) [`EnrollmentRequest`]. Check (4), join-code HMAC, is
/// applied by the caller (`mesh::ca::server`) once a join code is present —
/// join codes are P4.8, built after this module, so it stays a hook here
/// rather than a hard dependency. Check (7), attestation, is Phase 5's; a
/// row is still added to the report so the UI has something to render, but
/// it always passes today.
pub fn submit(
    paths: &crate::startup::GuardianPaths,
    circle_id: &str,
    policy: &CircleEnrollmentPolicy,
    submission: EnrollmentSubmission,
    source_ip: String,
    join_code_check: Option<Result<(), String>>,
) -> Result<EnrollmentRequest, RequestError> {
    let now = Utc::now();
    check_rate_limit(&source_ip, now)?;

    let mut report = PolicyReport::default();

    if submission.protocol_version != PROTOCOL_VERSION {
        return Err(RequestError::UnsupportedVersion(submission.protocol_version));
    }
    if submission.circle_id != circle_id {
        return Err(RequestError::WrongCircle {
            requested: submission.circle_id.clone(),
            actual: circle_id.to_string(),
        });
    }
    report.push("protocol_version", true, "supported version, correct circle");

    check_and_consume_nonce(&submission.nonce, now)?;
    report.push("nonce", true, "fresh, single-use");

    submission
        .verify_binding()
        .map_err(|e| {
            report.push("binding_signature", false, e.to_string());
            e
        })?;
    report.push(
        "binding_signature",
        true,
        "signed by the key its own DID document names",
    );

    if existing_active_request_for_guardian(paths, &submission.guardian_id)?.is_some() {
        report.push(
            "guardian_id",
            false,
            "already pending or a member under a different key",
        );
        return Err(RequestError::GuardianIdCollision(submission.guardian_id.clone()));
    }
    report.push("guardian_id", true, "not already in use");

    if crate::crl::is_revoked(&submission.did_document.id) {
        report.push("revocation", false, "this DID is on the circle's CRL");
        return Err(RequestError::Revoked(submission.guardian_id.clone()));
    }
    report.push("revocation", true, "not revoked");

    let mut auto_approved = false;
    if let Some(check) = join_code_check {
        match check {
            Ok(()) => {
                report.push("join_code", true, "valid, single-use code");
                auto_approved = true;
            }
            Err(reason) => report.push("join_code", false, reason),
        }
    } else {
        report.push("join_code", true, "no code offered — manual approval required");
    }

    report.push(
        "attestation",
        true,
        "not enforced yet (Phase 5) — informational only",
    );

    if !policy.allowed_hw_backends.is_empty()
        && !policy
            .allowed_hw_backends
            .iter()
            .any(|b| b == &submission.hw_backend)
    {
        report.push(
            "hardware_backend",
            false,
            format!("{} is not an allowed backend for this circle", submission.hw_backend),
        );
        return Err(RequestError::HwBackendNotAllowed(submission.hw_backend));
    }
    report.push("hardware_backend", true, "allowed for this circle");

    if let Some(max) = policy.max_members {
        let current = list(paths)?
            .into_iter()
            .filter(|r| r.state == RequestState::Approved)
            .count() as u32;
        if current >= max {
            report.push(
                "max_members",
                false,
                format!("circle already has {current}/{max} approved members"),
            );
            return Err(RequestError::MemberCapReached { current, max });
        }
    }
    report.push("max_members", true, "under the circle's member cap");

    let request_id = uuid::Uuid::new_v4().to_string();
    let expires_at = now + Duration::days(DEFAULT_TTL_DAYS);
    let request = EnrollmentRequest {
        request_id: request_id.clone(),
        state: RequestState::Pending,
        submission,
        policy_report: report,
        auto_approved,
        source_ip,
        created_at: now.to_rfc3339(),
        expires_at: expires_at.to_rfc3339(),
        decided_at: None,
        decision_reason: None,
    };
    save(paths, &request)?;
    Ok(request)
}

fn save(paths: &crate::startup::GuardianPaths, request: &EnrollmentRequest) -> Result<(), RequestError> {
    let dir = requests_dir(paths);
    fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!("{}.json.tmp", request.request_id));
    fs::write(&tmp, serde_json::to_vec_pretty(request)?)?;
    fs::rename(&tmp, request_path(paths, &request.request_id))?;
    Ok(())
}

pub fn load(paths: &crate::startup::GuardianPaths, request_id: &str) -> Result<EnrollmentRequest, RequestError> {
    let path = request_path(paths, request_id);
    if !path.exists() {
        return Err(RequestError::NotFound(request_id.to_string()));
    }
    let bytes = fs::read(&path)?;
    let mut request: EnrollmentRequest = serde_json::from_slice(&bytes)?;
    if request.state == RequestState::Pending {
        let expires_at = DateTime::parse_from_rfc3339(&request.expires_at)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or(Utc::now());
        if Utc::now() > expires_at {
            request.state = RequestState::Expired;
            let _ = save(paths, &request);
        }
    }
    Ok(request)
}

pub fn list(paths: &crate::startup::GuardianPaths) -> Result<Vec<EnrollmentRequest>, RequestError> {
    let dir = requests_dir(paths);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        // `<id>.bundle.json` (see `save_bundle`) lives in the same
        // directory and also ends in `.json` — skip it explicitly rather
        // than relying on it merely failing to deserialize as a request.
        if !name.ends_with(".json") || name.ends_with(".bundle.json") {
            continue;
        }
        if let Ok(bytes) = fs::read(&path) {
            if let Ok(request) = serde_json::from_slice::<EnrollmentRequest>(&bytes) {
                out.push(request);
            }
        }
    }
    out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    Ok(out)
}

/// A `Pending`/`Approved` request for `guardian_id` under a *different*
/// request — used to reject a new submission that collides on the name
/// (P4.4 check 5's "rename is suggested if taken" is a UI-layer decision;
/// this layer only detects the collision).
fn existing_active_request_for_guardian(
    paths: &crate::startup::GuardianPaths,
    guardian_id: &str,
) -> Result<Option<EnrollmentRequest>, RequestError> {
    Ok(list(paths)?.into_iter().find(|r| {
        r.submission.guardian_id == guardian_id
            && matches!(r.state, RequestState::Pending | RequestState::Approved)
    }))
}

pub fn approve(
    paths: &crate::startup::GuardianPaths,
    request_id: &str,
) -> Result<EnrollmentRequest, RequestError> {
    let mut request = load(paths, request_id)?;
    if request.state != RequestState::Pending {
        return Err(RequestError::NotPending(request_id.to_string()));
    }
    request.state = RequestState::Approved;
    request.decided_at = Some(Utc::now().to_rfc3339());
    save(paths, &request)?;
    Ok(request)
}

fn bundle_path(paths: &crate::startup::GuardianPaths, request_id: &str) -> PathBuf {
    requests_dir(paths).join(format!("{}.bundle.json", request_id))
}

/// Persists the bundle issued for an `Approved` request, so
/// `mesh::ca::server`'s poll handler can hand it back on every subsequent
/// poll without re-issuing (re-signing, re-allocating an overlay IP) each
/// time — issuance happens exactly once, right after approval.
pub fn save_bundle(
    paths: &crate::startup::GuardianPaths,
    request_id: &str,
    bundle: &crate::mesh::ca::bundle::SignedEnrollmentBundle,
) -> Result<(), RequestError> {
    let dir = requests_dir(paths);
    fs::create_dir_all(&dir)?;
    fs::write(bundle_path(paths, request_id), serde_json::to_vec_pretty(bundle)?)?;
    Ok(())
}

pub fn load_bundle(
    paths: &crate::startup::GuardianPaths,
    request_id: &str,
) -> Result<Option<crate::mesh::ca::bundle::SignedEnrollmentBundle>, RequestError> {
    let path = bundle_path(paths, request_id);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(path)?)?))
}

pub fn reject(
    paths: &crate::startup::GuardianPaths,
    request_id: &str,
    reason: String,
) -> Result<EnrollmentRequest, RequestError> {
    let mut request = load(paths, request_id)?;
    if request.state != RequestState::Pending {
        return Err(RequestError::NotPending(request_id.to_string()));
    }
    request.state = RequestState::Rejected;
    request.decided_at = Some(Utc::now().to_rfc3339());
    request.decision_reason = Some(reason);
    save(paths, &request)?;
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::GuardianPaths;

    fn minimal_did_doc(id: &str, vm_id: &str) -> DidDocument {
        DidDocument {
            context: vec![crate::did::document::CONTEXT_DID_V1.to_string()],
            id: id.to_string(),
            controller: id.to_string(),
            verification_method: vec![crate::did::document::VerificationMethod {
                id: vm_id.to_string(),
                vm_type: "JsonWebKey2020".into(),
                controller: id.to_string(),
                public_key_jwk: crate::did::document::Jwk {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: "AAAA".into(),
                    y: "AAAA".into(),
                    kid: "k1".into(),
                },
            }],
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

    fn sample_submission() -> EnrollmentSubmission {
        let did = "did:guardian:z6MkJoiner";
        EnrollmentSubmission {
            protocol_version: PROTOCOL_VERSION,
            circle_id: "circle-ABCDEFGHJKMN".into(),
            guardian_id: "edge-7".into(),
            nonce: uuid::Uuid::new_v4().to_string(),
            nebula_public_key_pem: "-----BEGIN NEBULA X25519 PUBLIC KEY-----\nAAAA\n-----END NEBULA X25519 PUBLIC KEY-----\n".into(),
            hw_backend: "software".into(),
            join_code: None,
            did_document: minimal_did_doc(did, &format!("{did}#dkp-v1")),
            proof: Proof::default(),
        }
    }

    #[test]
    fn an_unsigned_submission_fails_binding_verification() {
        let submission = sample_submission();
        let err = submission.verify_binding().unwrap_err();
        assert!(matches!(err, RequestError::BadBindingSignature(_)));
    }

    #[test]
    fn a_proof_pointing_at_a_different_dids_verification_method_is_rejected() {
        let mut submission = sample_submission();
        submission.proof.verification_method = "did:guardian:z6MkSomeoneElse#dkp-v1".into();
        submission.proof.proof_value = "AAAA".into();
        let err = submission.verify_binding().unwrap_err();
        assert!(matches!(err, RequestError::BadBindingSignature(_)));
    }

    #[test]
    fn wrong_circle_id_is_rejected_before_touching_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let submission = sample_submission();
        let err = submit(
            &paths,
            "circle-OTHERCIRCLE",
            &CircleEnrollmentPolicy::default(),
            submission,
            "10.0.0.5".into(),
            None,
        )
        .unwrap_err();
        assert!(matches!(err, RequestError::WrongCircle { .. }));
        assert!(list(&paths).unwrap().is_empty());
    }

    #[test]
    fn a_reused_nonce_is_rejected_on_the_second_submission() {
        let nonce = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        assert!(check_and_consume_nonce(&nonce, now).is_ok());
        assert!(matches!(
            check_and_consume_nonce(&nonce, now),
            Err(RequestError::BadNonce)
        ));
    }

    #[test]
    fn approving_a_request_twice_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        let request = EnrollmentRequest {
            request_id: "req-1".into(),
            state: RequestState::Pending,
            submission: sample_submission(),
            policy_report: PolicyReport::default(),
            auto_approved: false,
            source_ip: "10.0.0.5".into(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: (Utc::now() + Duration::days(1)).to_rfc3339(),
            decided_at: None,
            decision_reason: None,
        };
        save(&paths, &request).unwrap();
        approve(&paths, "req-1").unwrap();
        assert!(matches!(
            approve(&paths, "req-1"),
            Err(RequestError::NotPending(_))
        ));
    }
}
