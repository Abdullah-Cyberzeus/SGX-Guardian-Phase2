use crate::circle::errors::CircleError;
use crate::circle::model::verify_signed_proof;
use crate::circle::persistence;
use crate::circle::store;
use crate::circle::Circle;
use crate::did::document::Proof;
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use crate::vc::credential::{
    sort_json_keys, CredentialRole, VC_CONTEXT_CORE, VC_CONTEXT_SGX_CIRCLE,
};
use crate::vc::issue::{default_permissions_for_role, validate_permissions_for_role};
use base64::{engine::general_purpose, Engine as _};
use chrono::{Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use uuid::Uuid;

pub const INVITE_CONTEXT: &str = "https://schemas.cyberzeus.io/sgx/v1/circle-invite";
pub const JOIN_REQUEST_CONTEXT: &str = "https://schemas.cyberzeus.io/sgx/v1/circle-join";
pub const DEFAULT_INVITE_TTL_MINUTES: i64 = 24 * 60;
pub const MIN_INVITE_TTL_MINUTES: i64 = 5;
pub const MAX_INVITE_TTL_MINUTES: i64 = 30 * 24 * 60;
pub const MAX_QR_PAYLOAD_SIZE: usize = 2048;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InviteToken {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    pub circle_id: String,
    pub circle_name: String,
    pub issuer_did: String,
    pub target_did: String,
    pub role: CredentialRole,
    pub permissions: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub max_uses: u32,
    pub nonce: String,
    #[serde(default)]
    pub proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct JoinRequest {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub invite_token: InviteToken,
    pub joiner_did: String,
    #[serde(default)]
    pub accepted: bool,
    pub nonce: String,
    pub issued_at: String,
    #[serde(default)]
    pub proof: Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InviteRedemption {
    pub redeemer_did: String,
    pub redeemed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceivedInviteState {
    Pending,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReceivedInvite {
    pub invite: InviteToken,
    pub received_at: String,
    pub state: ReceivedInviteState,
    #[serde(default)]
    pub updated_at: String,
}

pub fn mint_invite(
    circle: &Circle,
    issuer: &DidRecord,
    km: &KeyManager,
    target_did: &str,
    role: CredentialRole,
    ttl_minutes: Option<i64>,
    max_uses: Option<u32>,
) -> Result<InviteToken, CircleError> {
    let ttl = ttl_minutes.unwrap_or(DEFAULT_INVITE_TTL_MINUTES);
    let ttl = ttl.clamp(MIN_INVITE_TTL_MINUTES, MAX_INVITE_TTL_MINUTES);
    let now = Utc::now();
    let permissions = default_permissions_for_role(role.clone());
    validate_permissions_for_role(&role, &permissions)?;
    let mut token = InviteToken {
        context: vec![
            VC_CONTEXT_CORE.to_string(),
            VC_CONTEXT_SGX_CIRCLE.to_string(),
            INVITE_CONTEXT.to_string(),
        ],
        id: format!("urn:uuid:{}", Uuid::new_v4()),
        circle_id: circle.circle_id.clone(),
        circle_name: circle.name.clone(),
        issuer_did: issuer.did.clone(),
        target_did: target_did.to_string(),
        role,
        permissions,
        issued_at: now.to_rfc3339(),
        expires_at: (now + Duration::minutes(ttl)).to_rfc3339(),
        max_uses: max_uses.unwrap_or(1).max(1),
        nonce: random_nonce_b64(32),
        proof: Proof::default(),
    };
    let vm_ref = format!("{}#dkp-v{}", issuer.did, issuer.current_dkp_version.max(1));
    let canonical = token.canonical_bytes_for_sign()?;
    crate::did::doc_sign::sign_in_place_generic(&mut token.proof, &canonical, km, &vm_ref)?;
    save_invite(&token)?;
    Ok(token)
}

pub async fn verify_invite(token: &InviteToken, resolver: &Resolver) -> Result<(), CircleError> {
    if token.target_did.trim().is_empty() {
        return Err(CircleError::Invalid("invite target_did is required".into()));
    }
    validate_permissions_for_role(&token.role, &token.permissions)?;
    if token.max_uses == 0 {
        return Err(CircleError::Invalid(
            "invite max_uses must be at least 1".into(),
        ));
    }
    let expires_at = chrono::DateTime::parse_from_rfc3339(&token.expires_at)
        .map_err(|err| CircleError::Invalid(format!("invite expiry: {}", err)))?;
    if Utc::now() > expires_at.with_timezone(&Utc) {
        return Err(CircleError::InviteExpired(token.expires_at.clone()));
    }
    let resolved = resolver.resolve(&token.issuer_did).await?;
    let public_key = general_purpose::STANDARD.decode(resolved.public_key_der_b64)?;
    let canonical = token.canonical_bytes_for_sign()?;
    verify_signed_proof(&token.proof, &canonical, &public_key)
}

pub fn save_invite(token: &InviteToken) -> Result<(), CircleError> {
    persistence::write_atomic(
        &persistence::invite_path(&token.id),
        &serde_json::to_vec_pretty(token)?,
    )
}

pub fn load_invite(invite_id: &str) -> Result<InviteToken, CircleError> {
    let path = persistence::invite_path(invite_id);
    if !path.exists() {
        return Err(CircleError::NotFound(invite_id.to_string()));
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn list_invites(circle_id: &str) -> Result<Vec<InviteToken>, CircleError> {
    let dir = persistence::invites_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut invites = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file()
            || path.file_name().and_then(|name| name.to_str()) == Some("redeemed.json")
        {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(invite) = serde_json::from_slice::<InviteToken>(&bytes) else {
            continue;
        };
        if invite.circle_id == circle_id {
            invites.push(invite);
        }
    }
    invites.sort_by(|left, right| left.issued_at.cmp(&right.issued_at));
    Ok(invites)
}

pub fn list_received_invites() -> Result<Vec<ReceivedInvite>, CircleError> {
    let dir = persistence::received_invites_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut invites = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        let Ok(invite) = serde_json::from_slice::<ReceivedInvite>(&bytes) else {
            continue;
        };
        invites.push(invite);
    }
    invites.sort_by(|left, right| left.received_at.cmp(&right.received_at));
    Ok(invites)
}

pub fn save_received_invite(token: InviteToken) -> Result<ReceivedInvite, CircleError> {
    let now = Utc::now().to_rfc3339();
    let received = ReceivedInvite {
        invite: token,
        received_at: now.clone(),
        state: ReceivedInviteState::Pending,
        updated_at: now,
    };
    persistence::write_atomic(
        &persistence::received_invite_path(&received.invite.id),
        &serde_json::to_vec_pretty(&received)?,
    )?;
    Ok(received)
}

pub fn load_received_invite(invite_id: &str) -> Result<ReceivedInvite, CircleError> {
    let path = persistence::received_invite_path(invite_id);
    if !path.exists() {
        return Err(CircleError::NotFound(invite_id.to_string()));
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn set_received_invite_state(
    invite_id: &str,
    state: ReceivedInviteState,
) -> Result<ReceivedInvite, CircleError> {
    let mut invite = load_received_invite(invite_id)?;
    invite.state = state;
    invite.updated_at = Utc::now().to_rfc3339();
    persistence::write_atomic(
        &persistence::received_invite_path(invite_id),
        &serde_json::to_vec_pretty(&invite)?,
    )?;
    Ok(invite)
}

pub fn delete_invite(invite_id: &str) -> Result<(), CircleError> {
    let path = persistence::invite_path(invite_id);
    if !path.exists() {
        return Err(CircleError::NotFound(invite_id.to_string()));
    }
    fs::remove_file(path)?;
    Ok(())
}

pub fn encode_compact(token: &InviteToken) -> Result<String, CircleError> {
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(token)?))
}

pub fn decode_compact(value: &str) -> Result<InviteToken, CircleError> {
    let raw = general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|err| CircleError::Invalid(format!("invalid invite token: {}", err)))?;
    serde_json::from_slice(&raw)
        .map_err(|err| CircleError::Invalid(format!("invalid invite token: {}", err)))
}

pub fn build_share_link(token_b64: &str, owner_host: &str) -> Result<String, CircleError> {
    let payload = format!(
        "sgx-guardian://circle/join?owner_host={}&token={}",
        owner_host, token_b64
    );
    if payload.len() > MAX_QR_PAYLOAD_SIZE {
        return Err(CircleError::QrPayloadTooLarge {
            size: payload.len(),
            max: MAX_QR_PAYLOAD_SIZE,
        });
    }
    Ok(payload)
}

pub async fn resolve_circle_endpoint(
    did: &str,
    resolver: &Resolver,
) -> Result<String, CircleError> {
    let resolved = resolver.resolve(did).await.map_err(|err| {
        CircleError::Invalid(format!("DID resolution failed for {}: {}", did, err))
    })?;
    if crate::crl::is_revoked(did) {
        return Err(CircleError::Conflict(format!(
            "DID {} is revoked by CRL",
            did
        )));
    }
    let mut nebula_endpoint = None;
    for service in &resolved.services {
        let service_type = service.r#type.to_ascii_lowercase();
        if service_type.contains("circle") || service_type.contains("cot") {
            return normalize_service_endpoint(&service.endpoint);
        }
        if service_type.contains("nebula") || service.endpoint.starts_with("nebula://") {
            nebula_endpoint = Some(service.endpoint.clone());
        }
    }
    if let Some(endpoint) = nebula_endpoint {
        return normalize_service_endpoint(&endpoint);
    }
    Err(CircleError::Invalid(format!(
        "DID {} has no Circle/CoT/Nebula service endpoint",
        did
    )))
}

fn normalize_service_endpoint(endpoint: &str) -> Result<String, CircleError> {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(CircleError::Invalid("service endpoint is empty".into()));
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("nebula://") {
        let host = rest.split('/').next().unwrap_or(rest);
        if host.is_empty() {
            return Err(CircleError::Invalid(format!(
                "unreachable endpoint: {}",
                endpoint
            )));
        }
        return Ok(format!("http://{}:8443", host));
    }
    if let Some(rest) = trimmed.strip_prefix("tcp://") {
        let host = rest.split(':').next().unwrap_or(rest);
        if host.is_empty() {
            return Err(CircleError::Invalid(format!(
                "unreachable endpoint: {}",
                endpoint
            )));
        }
        return Ok(format!("http://{}:8443", host));
    }
    Err(CircleError::Invalid(format!(
        "unsupported DID service endpoint {}",
        endpoint
    )))
}

pub fn assert_redeemable(
    circle: &Circle,
    invite: &InviteToken,
    joiner_did: &str,
) -> Result<(), CircleError> {
    if circle.circle_id != invite.circle_id {
        return Err(CircleError::Invalid(format!(
            "invite {} targets circle {}, expected {}",
            invite.id, invite.circle_id, circle.circle_id
        )));
    }
    if circle.owner_did != invite.issuer_did {
        return Err(CircleError::Invalid(format!(
            "invite {} issuer {} is not the owner of {}",
            invite.id, invite.issuer_did, circle.circle_id
        )));
    }
    if invite.target_did != joiner_did {
        return Err(CircleError::Invalid(format!(
            "invite {} targets {}, not {}",
            invite.id, invite.target_did, joiner_did
        )));
    }
    let stored = load_invite(&invite.id)?;
    if stored != *invite {
        return Err(CircleError::InvalidProof(format!(
            "stored invite {} does not match presented token",
            invite.id
        )));
    }
    let ledger = load_redeemed()?;
    let redemptions = ledger.get(&invite.id).cloned().unwrap_or_default();
    if redemptions
        .iter()
        .any(|entry| entry.redeemer_did == joiner_did)
    {
        return Err(CircleError::InviteReplay(format!(
            "invite {} already redeemed by {}",
            invite.id, joiner_did
        )));
    }
    if redemptions.len() as u32 >= invite.max_uses {
        return Err(CircleError::InviteReplay(format!(
            "invite {} already reached max_uses={}",
            invite.id, invite.max_uses
        )));
    }
    Ok(())
}

pub fn record_redemption(invite_id: &str, joiner_did: &str) -> Result<(), CircleError> {
    let mut ledger = load_redeemed()?;
    ledger
        .entry(invite_id.to_string())
        .or_default()
        .push(InviteRedemption {
            redeemer_did: joiner_did.to_string(),
            redeemed_at: Utc::now().to_rfc3339(),
        });
    persistence::write_atomic(
        &persistence::redeemed_path(),
        &serde_json::to_vec_pretty(&ledger)?,
    )?;
    Ok(())
}

pub fn load_redeemed() -> Result<BTreeMap<String, Vec<InviteRedemption>>, CircleError> {
    let path = persistence::redeemed_path();
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn sign_join_request(
    joiner: &DidRecord,
    km: &KeyManager,
    invite_token: InviteToken,
) -> Result<JoinRequest, CircleError> {
    let mut request = JoinRequest {
        context: vec![
            VC_CONTEXT_CORE.to_string(),
            VC_CONTEXT_SGX_CIRCLE.to_string(),
            JOIN_REQUEST_CONTEXT.to_string(),
        ],
        invite_token,
        joiner_did: joiner.did.clone(),
        accepted: true,
        nonce: random_nonce_b64(32),
        issued_at: Utc::now().to_rfc3339(),
        proof: Proof::default(),
    };
    let vm_ref = format!("{}#dkp-v{}", joiner.did, joiner.current_dkp_version.max(1));
    let canonical = request.canonical_bytes_for_sign()?;
    crate::did::doc_sign::sign_in_place_generic(&mut request.proof, &canonical, km, &vm_ref)?;
    Ok(request)
}

pub async fn verify_join_request(
    request: &JoinRequest,
    resolver: &Resolver,
) -> Result<(), CircleError> {
    if !request.accepted {
        return Err(CircleError::Invalid(
            "join acceptance was not granted".into(),
        ));
    }
    if request.joiner_did != request.invite_token.target_did {
        return Err(CircleError::Invalid(format!(
            "acceptance DID {} does not match invite target {}",
            request.joiner_did, request.invite_token.target_did
        )));
    }
    let resolved = resolver.resolve(&request.joiner_did).await?;
    let public_key = general_purpose::STANDARD.decode(resolved.public_key_der_b64)?;
    let canonical = request.canonical_bytes_for_sign()?;
    verify_signed_proof(&request.proof, &canonical, &public_key)
}

pub fn save_joined_circle(
    node_id: &str,
    invite: &InviteToken,
) -> Result<crate::circle::model::Circle, CircleError> {
    let circle = crate::circle::model::Circle {
        circle_id: invite.circle_id.clone(),
        name: invite.circle_name.clone(),
        description: String::new(),
        owner_did: invite.issuer_did.clone(),
        kind: crate::circle::model::CircleKind::Comms,
        status: crate::circle::model::CircleStatus::Active,
        created_at: invite.issued_at.clone(),
        updated_at: invite.issued_at.clone(),
    };
    store::upsert_circle(node_id, circle)
}

impl InviteToken {
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }
}

impl JoinRequest {
    pub fn canonical_bytes_for_sign(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut copy = self.clone();
        copy.proof = Proof::default();
        let value = serde_json::to_value(&copy)?;
        serde_json::to_vec(&sort_json_keys(&value))
    }
}

fn random_nonce_b64(bytes: usize) -> String {
    let mut nonce = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    general_purpose::STANDARD.encode(nonce)
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::vc::credential::CredentialRole;

    fn sample_token() -> InviteToken {
        InviteToken {
            context: vec![INVITE_CONTEXT.to_string()],
            id: "urn:uuid:invite-1".to_string(),
            circle_id: "circle-1".to_string(),
            circle_name: "Test Circle".to_string(),
            issuer_did: "did:guardian:owner".to_string(),
            target_did: "did:guardian:joiner".to_string(),
            role: CredentialRole::Member,
            permissions: vec!["mesh:join".to_string()],
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2026-01-02T00:00:00Z".to_string(),
            max_uses: 1,
            nonce: "nonce".to_string(),
            proof: Proof::default(),
        }
    }

    #[test]
    fn invite_token_canonical_bytes_ignore_proof_but_detect_field_changes() {
        let mut token = sample_token();
        let baseline = token.canonical_bytes_for_sign().expect("canonical");

        token.proof = Proof {
            proof_type: "DataIntegrityProof".to_string(),
            cryptosuite: "ecdsa-2019".to_string(),
            verification_method: "did:guardian:owner#dkp-v1".to_string(),
            created: "2026-01-01T00:00:00Z".to_string(),
            proof_purpose: "assertionMethod".to_string(),
            proof_value: "signature".to_string(),
        };
        assert_eq!(
            baseline,
            token.canonical_bytes_for_sign().expect("canonical")
        );

        token.max_uses = 5;
        assert_ne!(
            baseline,
            token.canonical_bytes_for_sign().expect("canonical")
        );
    }

    #[test]
    fn join_request_canonical_bytes_ignore_proof_but_detect_field_changes() {
        let mut request = JoinRequest {
            context: vec![JOIN_REQUEST_CONTEXT.to_string()],
            invite_token: sample_token(),
            joiner_did: "did:guardian:joiner".to_string(),
            accepted: true,
            nonce: "nonce".to_string(),
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            proof: Proof::default(),
        };
        let baseline = request.canonical_bytes_for_sign().expect("canonical");

        request.proof = Proof {
            verification_method: "did:guardian:joiner#dkp-v1".to_string(),
            proof_value: "signature".to_string(),
            ..Proof::default()
        };
        assert_eq!(
            baseline,
            request.canonical_bytes_for_sign().expect("canonical")
        );

        request.joiner_did = "did:guardian:other".to_string();
        assert_ne!(
            baseline,
            request.canonical_bytes_for_sign().expect("canonical")
        );
    }

    #[test]
    fn build_share_link_accepts_payload_within_budget() {
        let link = build_share_link("dG9rZW4", "guardian.local:8443").expect("within budget");
        assert!(link.len() <= MAX_QR_PAYLOAD_SIZE);
        assert!(link.starts_with("sgx-guardian://circle/join?"));
    }

    #[test]
    fn build_share_link_rejects_oversized_payload() {
        let oversized_token = "a".repeat(MAX_QR_PAYLOAD_SIZE);
        let err = build_share_link(&oversized_token, "guardian.local:8443").unwrap_err();
        assert!(matches!(err, CircleError::QrPayloadTooLarge { .. }));
    }

    #[test]
    fn assert_redeemable_rejects_circle_mismatch_without_touching_disk() {
        let mut circle_owner_mismatch = Circle {
            circle_id: "circle-1".to_string(),
            name: "Test".to_string(),
            description: String::new(),
            owner_did: "did:guardian:owner".to_string(),
            kind: crate::circle::model::CircleKind::Comms,
            status: crate::circle::model::CircleStatus::Active,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let token = sample_token();

        // Wrong circle_id must be rejected before any persistence lookup runs.
        circle_owner_mismatch.circle_id = "other-circle".to_string();
        let err =
            assert_redeemable(&circle_owner_mismatch, &token, "did:guardian:joiner").unwrap_err();
        assert!(matches!(err, CircleError::Invalid(_)));

        // Wrong owner_did must likewise be rejected up front.
        circle_owner_mismatch.circle_id = token.circle_id.clone();
        circle_owner_mismatch.owner_did = "did:guardian:someone-else".to_string();
        let err =
            assert_redeemable(&circle_owner_mismatch, &token, "did:guardian:joiner").unwrap_err();
        assert!(matches!(err, CircleError::Invalid(_)));
    }
}
