use crate::circle::errors::CircleError;
use crate::circle::model::verify_signed_proof;
use crate::circle::persistence;
use crate::circle::store;
use crate::circle::Circle;
use crate::did::document::Proof;
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use crate::vc::credential::{sort_json_keys, CredentialRole, VC_CONTEXT_CORE, VC_CONTEXT_SGX_CIRCLE};
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

pub fn mint_invite(
    circle: &Circle,
    issuer: &DidRecord,
    km: &KeyManager,
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
    validate_permissions_for_role(&token.role, &token.permissions)?;
    if token.max_uses == 0 {
        return Err(CircleError::Invalid("invite max_uses must be at least 1".into()));
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
        if !path.is_file() || path.file_name().and_then(|name| name.to_str()) == Some("redeemed.json")
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
    Ok(serde_json::from_slice(
        &general_purpose::URL_SAFE_NO_PAD.decode(value)?,
    )?)
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
