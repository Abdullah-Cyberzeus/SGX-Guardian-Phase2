use crate::api::auth::{
    middleware::AuthenticatedSession,
    password, session,
    store::NewMemberRegistration,
};
use crate::api::{error::ApiError, handlers::peers, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::circle::{invite, store};
use axum::{extract::State, Extension, Json};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

static MEMBER_JOIN_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
const DEFAULT_REGISTRATION_DAYS: i64 = 30;

/// Communication-safe peer data for member sessions.
///
/// The administrative `/peers` response includes network addresses used for
/// topology and diagnostics. Member clients need only the attested identity,
/// presence, and call availability, so this endpoint deliberately omits IPs,
/// ports, policy data, and attestation internals.
#[derive(Debug, Serialize)]
pub struct PwaContact {
    #[serde(rename = "peerId")]
    pub peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub status: String,
    #[serde(rename = "lastSeen")]
    pub last_seen: String,
    pub online: bool,
    #[serde(rename = "callAvailable")]
    pub call_available: bool,
    #[serde(
        rename = "callUnavailableReason",
        skip_serializing_if = "Option::is_none"
    )]
    pub call_unavailable_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PwaContactsResponse {
    pub contacts: Vec<PwaContact>,
    pub total: usize,
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct PwaIdentityResponse {
    pub did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingCircleSummary {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OnboardingResponse {
    pub guardian_did: String,
    pub guardian_name: String,
    pub fingerprint: String,
    pub fingerprint_algorithm: &'static str,
    pub fingerprint_bits: u16,
    pub circles: Vec<OnboardingCircleSummary>,
    pub internet_required: bool,
    pub multiple_guardian_note: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInvitePreviewRequest {
    pub invite_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberInvitePreviewResponse {
    pub valid: bool,
    pub circle_id: String,
    pub circle_name: String,
    pub issuer_did: String,
    pub expires_at: String,
    pub role: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberJoinRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    pub invite_token: String,
    pub accepted_fingerprint: String,
    pub fingerprint_confirmed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberJoinResponse {
    pub token: String,
    pub user_id: String,
    pub email: String,
    pub role: &'static str,
    pub scopes: Vec<String>,
    pub guardian_did: String,
    pub guardian_fingerprint: String,
    pub circle_ids: Vec<String>,
    pub browser_registration_id: String,
    pub expires_at: i64,
    pub registration_expires_at: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationRemovalResponse {
    pub status: &'static str,
    pub revoked_sessions: usize,
}

/// Human-verifiable 80-bit prefix of SHA-256(device signing public key),
/// encoded with unambiguous Crockford Base32 and grouped 4-4-4-4. A changed
/// device identity necessarily changes the displayed value.
pub fn guardian_fingerprint(public_key: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let digest = Sha256::digest(public_key);
    let mut value = String::with_capacity(19);
    let mut buffer: u128 = 0;
    let mut bits = 0u8;
    let mut emitted = 0usize;
    for byte in digest.iter().take(10) {
        buffer = (buffer << 8) | u128::from(*byte);
        bits += 8;
        while bits >= 5 && emitted < 16 {
            bits -= 5;
            if emitted > 0 && emitted % 4 == 0 {
                value.push('-');
            }
            value.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
            emitted += 1;
        }
    }
    value
}

fn normalized_fingerprint(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect()
}

pub async fn onboarding(
    State(state): State<Arc<AppState>>,
) -> Result<Json<OnboardingResponse>, ApiError> {
    let registry = store::load_or_seed(&state.node_id)
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    let circles = registry
        .circles
        .into_iter()
        .filter(|circle| !circle.is_archived())
        .map(|circle| OnboardingCircleSummary {
            id: circle.circle_id,
            name: circle.name,
        })
        .collect();
    Ok(Json(OnboardingResponse {
        guardian_did: state.device_did.clone(),
        guardian_name: state.node_id.clone(),
        fingerprint: guardian_fingerprint(&state.device_pubkey_point),
        fingerprint_algorithm: "SHA-256 device-public-key / Crockford Base32",
        fingerprint_bits: 80,
        circles,
        internet_required: false,
        multiple_guardian_note: "If more than one Guardian is reachable, verify this fingerprint before continuing.",
    }))
}

pub async fn preview_member_invite(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MemberInvitePreviewRequest>,
) -> Result<Json<MemberInvitePreviewResponse>, ApiError> {
    rate_limit(&state, "member-invite-preview", &body.invite_token)?;
    let token = validate_local_member_invite(&state, &body.invite_token).await?;
    // A synthetic, non-persisted redeemer checks max-uses without consuming it.
    let circle = store::get_circle(&state.node_id, &token.circle_id).map_err(|error| match error {
        crate::circle::errors::CircleError::NotFound(_) => ApiError::Conflict(format!(
            "the invited Circle {} no longer exists on this Guardian; ask the administrator to create a new member invitation",
            token.circle_id
        )),
        other => ApiError::BadRequest(other.to_string()),
    })?;
    invite::assert_redeemable(&circle, &token, "browser:preview")
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    Ok(Json(MemberInvitePreviewResponse {
        valid: true,
        circle_id: token.circle_id,
        circle_name: token.circle_name,
        issuer_did: token.issuer_did,
        expires_at: token.expires_at,
        role: "member",
    }))
}

pub async fn join_member(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MemberJoinRequest>,
) -> Result<Json<MemberJoinResponse>, ApiError> {
    let email = body.email.trim().to_ascii_lowercase();
    let name = body.name.trim().to_string();
    if name.len() < 2 || !email.contains('@') {
        return Err(ApiError::BadRequest("valid name and email are required".into()));
    }
    rate_limit(&state, "member-credential-issue", &email)?;
    if !body.fingerprint_confirmed {
        audit_join_rejected(&state, &email, "fingerprint was not explicitly confirmed");
        return Err(ApiError::BadRequest(
            "explicit Guardian fingerprint confirmation is required".into(),
        ));
    }
    let current_fingerprint = guardian_fingerprint(&state.device_pubkey_point);
    if normalized_fingerprint(&body.accepted_fingerprint)
        != normalized_fingerprint(&current_fingerprint)
    {
        audit_join_rejected(&state, &email, "Guardian fingerprint mismatch");
        return Err(ApiError::Conflict(
            "Guardian fingerprint mismatch; do not continue until the physical Guardian is verified"
                .into(),
        ));
    }
    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!(
            "Guardian fingerprint explicitly confirmed actor={} fingerprint={}",
            email, current_fingerprint
        ),
    );
    let token = match validate_local_member_invite(&state, &body.invite_token).await {
        Ok(token) => token,
        Err(error) => {
            let audit_reason = format!("{:?}", error);
            audit_join_rejected(&state, &email, &audit_reason);
            return Err(error);
        }
    };
    let pw_hash = match password::hash_password(body.password).await {
        Ok(hash) => hash,
        Err(error) => {
            audit_join_rejected(&state, &email, "password policy rejected");
            return Err(ApiError::BadRequest(error.to_string()));
        }
    };
    let _join_guard = MEMBER_JOIN_LOCK.lock().await;
    let registration_id = Uuid::new_v4().to_string();
    let redeemer = format!("browser:{}", registration_id);
    let circle = store::get_circle(&state.node_id, &token.circle_id).map_err(|error| match error {
        crate::circle::errors::CircleError::NotFound(_) => ApiError::Conflict(format!(
            "the invited Circle {} no longer exists on this Guardian; ask the administrator to create a new member invitation",
            token.circle_id
        )),
        other => ApiError::BadRequest(other.to_string()),
    })?;
    invite::assert_redeemable(&circle, &token, &redeemer)
        .map_err(|error| ApiError::Conflict(error.to_string()))?;
    invite::record_redemption(&token.id, &redeemer)
        .map_err(|error| ApiError::Internal(error.to_string()))?;

    let registration_expires_at = chrono::Utc::now().timestamp()
        + registration_days().saturating_mul(24 * 60 * 60);
    let user = match state
        .admin
        .users
        .create_or_reactivate_member(NewMemberRegistration {
            name,
            email: email.clone(),
            pw_hash,
            circle_id: token.circle_id.clone(),
            browser_registration_id: registration_id.clone(),
            guardian_fingerprint: current_fingerprint.clone(),
            registration_expires_at,
            invite_id: token.id.clone(),
        })
        .await
    {
        Ok(user) => user,
        Err(error) => {
            let _ = invite::remove_redemption(&token.id, &redeemer);
            return Err(ApiError::Conflict(error.to_string()));
        }
    };

    // Rejoin/rotation invalidates every credential issued under the previous
    // browser registration before the replacement session is stored.
    state
        .admin
        .sessions
        .revoke_all_for_user(&user.user_id)
        .await?;

    let remaining_registration_secs = registration_expires_at
        .saturating_sub(chrono::Utc::now().timestamp())
        .max(1) as u64;
    let ttl = state.session_ttl_secs.min(remaining_registration_secs);
    let (session_token, claims, session_record) = session::issue(
        state.signer.clone(),
        &state.device_did,
        &user,
        Duration::from_secs(ttl.max(1)),
    )
    .await?;
    state.admin.sessions.put(session_record).await?;
    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Created,
        &format!(
            "member browser credential issued actor={} registration={} circle={} fingerprint={}",
            user.user_id, registration_id, token.circle_id, current_fingerprint
        ),
    );
    Ok(Json(MemberJoinResponse {
        token: session_token,
        user_id: user.user_id,
        email: user.email,
        role: "member",
        scopes: claims.scopes,
        guardian_did: state.device_did.clone(),
        guardian_fingerprint: current_fingerprint,
        circle_ids: claims.circle_ids,
        browser_registration_id: registration_id,
        expires_at: claims.exp,
        registration_expires_at,
    }))
}

pub async fn remove_registration(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedSession>,
) -> Result<Json<RegistrationRemovalResponse>, ApiError> {
    let registration_id = auth
        .claims
        .browser_registration_id
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("session has no browser registration".into()))?;
    state
        .admin
        .users
        .revoke_browser_registration(&auth.claims.sub, registration_id)
        .await?;
    let revoked_sessions = state
        .admin
        .sessions
        .revoke_all_for_user(&auth.claims.sub)
        .await?;
    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Warning,
        AuditAction::Revoked,
        &format!(
            "member browser registration removed actor={} registration={}",
            auth.claims.sub, registration_id
        ),
    );
    Ok(Json(RegistrationRemovalResponse {
        status: "registration_removed",
        revoked_sessions,
    }))
}

async fn validate_local_member_invite(
    state: &AppState,
    compact: &str,
) -> Result<invite::InviteToken, ApiError> {
    let token = invite::decode_compact(compact.trim())
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    invite::verify_invite(&token, &state.did_resolver)
        .await
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    if token.role != crate::vc::credential::CredentialRole::Member {
        return Err(ApiError::Forbidden(
            "only member invitations can create PWA accounts".into(),
        ));
    }
    if token.issuer_did != state.device_did {
        return Err(ApiError::Conflict(format!(
            "this invitation was issued by a different Guardian (issuer {}, current {}); open the link using the issuing Guardian address",
            token.issuer_did, state.device_did
        )));
    }
    let circle = store::get_circle(&state.node_id, &token.circle_id).map_err(|error| match error {
        crate::circle::errors::CircleError::NotFound(_) => ApiError::Conflict(format!(
            "the invited Circle {} no longer exists on this Guardian; ask the administrator to create a new member invitation",
            token.circle_id
        )),
        other => ApiError::BadRequest(other.to_string()),
    })?;
    if circle.owner_did != state.device_did {
        return Err(ApiError::Forbidden(
            "member invitation must be issued by this Guardian".into(),
        ));
    }
    Ok(token)
}

fn rate_limit(state: &AppState, action: &str, subject: &str) -> Result<(), ApiError> {
    let digest = hex::encode(Sha256::digest(subject.as_bytes()));
    let now = chrono::Utc::now().timestamp();
    let global_allowed = state.login_rate_limiter.check_and_record(
        &format!("{}:global", action),
        now,
        state.auth_rate_limit,
    );
    let subject_allowed = state.login_rate_limiter.check_and_record(
        &format!("{}:{}", action, &digest[..16]),
        now,
        state.auth_rate_limit,
    );
    if global_allowed && subject_allowed {
        Ok(())
    } else {
        Err(ApiError::TooManyRequests(
            "too many onboarding attempts; try again later".into(),
        ))
    }
}

fn registration_days() -> i64 {
    std::env::var("SGX_PWA_REGISTRATION_DAYS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_REGISTRATION_DAYS)
}

fn audit_join_rejected(state: &AppState, actor: &str, reason: &str) {
    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Warning,
        AuditAction::Rejected,
        &format!("member browser credential rejected actor={} reason={}", actor, reason),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_human_readable_and_eighty_bits() {
        let fingerprint = guardian_fingerprint(b"guardian-public-key");
        assert_eq!(fingerprint.len(), 19);
        assert_eq!(fingerprint.chars().filter(|value| *value == '-').count(), 3);
        assert_eq!(normalized_fingerprint(&fingerprint).len(), 16);
        assert_eq!(fingerprint, guardian_fingerprint(b"guardian-public-key"));
        assert_ne!(fingerprint, guardian_fingerprint(b"rotated-public-key"));
    }
}

pub async fn identity(State(state): State<Arc<AppState>>) -> Json<PwaIdentityResponse> {
    Json(PwaIdentityResponse {
        did: state.device_did.clone(),
    })
}

pub async fn contacts(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedSession>,
) -> Result<Json<PwaContactsResponse>, ApiError> {
    let allowed_dids = crate::api::auth::authorization::scoped_circle_contact_dids(
        &state.node_id,
        &state.device_did,
        &auth.claims.circle_ids,
    )
    .map_err(ApiError::Internal)?;
    let Json(response) = peers::list(State(state)).await?;
    let contacts = response
        .peers
        .into_iter()
        .filter(|peer| {
            peer.did.is_some()
                && peer.did.as_ref().is_some_and(|did| allowed_dids.contains(did))
                && matches!(peer.status.as_str(), "verified" | "trusted" | "success")
        })
        .map(|peer| PwaContact {
            peer_id: peer.peer_id,
            did: peer.did,
            status: peer.status,
            last_seen: peer.last_seen,
            online: peer.online,
            call_available: peer.call_available,
            call_unavailable_reason: peer.call_unavailable_reason,
        })
        .collect::<Vec<_>>();
    let total = contacts.len();

    Ok(Json(PwaContactsResponse {
        contacts,
        total,
        timestamp: response.timestamp,
    }))
}
