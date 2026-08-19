use crate::api::auth::{
    middleware::AuthenticatedSession, password, session, store::NewMemberRegistration,
};
use crate::api::{error::ApiError, handlers::peers, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::circle::{invite, store};
use axum::{extract::State, Extension, Json};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

static MEMBER_JOIN_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
const DEFAULT_REGISTRATION_DAYS: i64 = 30;
const CONTACT_PRESENCE_HEARTBEAT_SECONDS: u64 = 30;
const CONTACT_PRESENCE_EXPIRY_SECONDS: u64 = 90;

#[derive(Debug, Clone, Default)]
struct ContactMetadata {
    display_name: Option<String>,
    full_name: Option<String>,
    device_name: Option<String>,
    role: Option<String>,
    member_type: Option<String>,
    join_date: Option<String>,
    active_browser_member: bool,
}

fn role_label(role: &crate::vc::credential::CredentialRole) -> &'static str {
    match role {
        crate::vc::credential::CredentialRole::Owner => "owner",
        crate::vc::credential::CredentialRole::Member => "member",
    }
}

fn display_name_from(did: &str, metadata: Option<&ContactMetadata>, fallback: &str) -> String {
    metadata
        .and_then(|meta| meta.display_name.as_deref())
        .filter(|value| !value.trim().is_empty())
        .or_else(|| metadata.and_then(|meta| meta.full_name.as_deref()))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            if fallback.trim().is_empty() {
                did
            } else {
                fallback
            }
        })
        .to_string()
}

fn presence_expiry_from(last_seen: &str) -> Option<String> {
    chrono::DateTime::parse_from_rfc3339(last_seen)
        .ok()
        .map(|seen| {
            (seen.with_timezone(&chrono::Utc)
                + chrono::Duration::seconds(CONTACT_PRESENCE_EXPIRY_SECONDS as i64))
            .to_rfc3339()
        })
}

fn presence_status(online: bool, stale: bool) -> String {
    if stale {
        "stale".to_string()
    } else if online {
        "online".to_string()
    } else {
        "offline".to_string()
    }
}

async fn contact_metadata(
    state: &AppState,
    allowed_circle_ids: &[String],
) -> Result<BTreeMap<String, ContactMetadata>, ApiError> {
    let allowed = allowed_circle_ids.iter().cloned().collect::<HashSet<_>>();
    let local_circle_ids =
        crate::api::auth::authorization::local_active_circle_ids(&state.node_id, &state.device_did)
            .map_err(ApiError::Internal)?;
    let scoped_circle_ids = if allowed.is_empty() {
        local_circle_ids
    } else {
        local_circle_ids
            .into_iter()
            .filter(|circle_id| allowed.contains(circle_id))
            .collect()
    };

    let mut metadata = BTreeMap::<String, ContactMetadata>::new();
    for circle_id in &scoped_circle_ids {
        let Ok(members) = crate::circle::members::list_members(&state.node_id, circle_id) else {
            continue;
        };
        for member in members
            .into_iter()
            .filter(|member| {
                matches!(
                    member.lifecycle_state,
                    crate::circle::members::MemberLifecycleState::Active
                )
            })
            .filter(|member| member.did != state.device_did)
        {
            let entry = metadata.entry(member.did.clone()).or_default();
            if entry.role.is_none() {
                entry.role = Some(role_label(&member.role).to_string());
            }
            if entry.join_date.is_none() {
                entry.join_date = Some(member.join_date);
            }
            if entry.device_name.is_none() {
                entry.device_name = member.node_hint.clone();
            }
            if entry.member_type.is_none() {
                entry.member_type = member
                    .member_type
                    .clone()
                    .or_else(|| Some("guardian".to_string()));
            }
            if entry.display_name.is_none() {
                entry.display_name = member
                    .name
                    .clone()
                    .or(member.email.clone())
                    .or(member.node_hint.clone());
            }
            if entry.full_name.is_none() {
                entry.full_name = member.name;
            }
        }
    }

    let now = chrono::Utc::now().timestamp();
    for user in state.admin.users.list().await? {
        if user.role != crate::api::auth::store::UserRole::Member
            || user.status != "active"
            || user
                .registration_expires_at
                .is_some_and(|expiry| expiry <= now)
            || !user
                .circle_ids
                .iter()
                .any(|circle_id| scoped_circle_ids.contains(circle_id))
        {
            continue;
        }
        let Some(registration_id) = user.browser_registration_id.as_deref() else {
            continue;
        };
        let did = crate::api::handlers::browser_member::did_for_registration(registration_id);
        let entry = metadata.entry(did).or_default();
        entry.display_name = Some(user.name.clone());
        entry.full_name = Some(user.name);
        entry.device_name = Some("Browser".to_string());
        entry.role.get_or_insert_with(|| "member".to_string());
        entry.member_type = Some("browser".to_string());
        entry.join_date.get_or_insert(user.created_at);
        entry.active_browser_member = true;
    }

    Ok(metadata)
}

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
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "fullName", skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(rename = "deviceName")]
    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub status: String,
    pub role: String,
    #[serde(rename = "memberType")]
    pub member_type: String,
    #[serde(rename = "joinDate", skip_serializing_if = "Option::is_none")]
    pub join_date: Option<String>,
    #[serde(rename = "lastSeen")]
    pub last_seen: String,
    pub online: bool,
    #[serde(rename = "presenceStatus")]
    pub presence_status: String,
    #[serde(rename = "presenceStale")]
    pub presence_stale: bool,
    #[serde(rename = "presenceExpiresAt", skip_serializing_if = "Option::is_none")]
    pub presence_expires_at: Option<String>,
    #[serde(rename = "heartbeatIntervalSeconds")]
    pub heartbeat_interval_seconds: u64,
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
    #[serde(rename = "presenceHeartbeatSeconds")]
    pub presence_heartbeat_seconds: u64,
    #[serde(rename = "presenceExpirySeconds")]
    pub presence_expiry_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct PwaIdentityResponse {
    pub did: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PwaHealthResponse {
    pub status: &'static str,
    pub guardian_did: String,
    pub actor_id: String,
    pub role: String,
    pub circle_ids: Vec<String>,
    pub server_time: i64,
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
    #[serde(default)]
    pub owner_host: Option<String>,
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
    #[serde(default)]
    pub owner_host: Option<String>,
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
    pub browser_member_did: String,
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
            if emitted > 0 && emitted.is_multiple_of(4) {
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
        multiple_guardian_note:
            "If more than one Guardian is reachable, verify this fingerprint before continuing.",
    }))
}

pub async fn preview_member_invite(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MemberInvitePreviewRequest>,
) -> Result<Json<MemberInvitePreviewResponse>, ApiError> {
    rate_limit(&state, "member-invite-preview", &body.invite_token)?;
    let token = validate_member_invite(&state, &body.invite_token).await?;
    if token.issuer_did == state.device_did {
        // A synthetic, non-persisted redeemer checks max-uses without consuming it.
        let circle = local_invite_circle(&state, &token)?;
        let preview_did = crate::api::handlers::browser_member::did_for_registration("preview");
        invite::assert_redeemable(&circle, &token, &preview_did)
            .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    } else {
        // A foreign issuer is valid for portable onboarding, but its address
        // must travel separately so this Guardian can redeem server-to-server.
        crate::api::handlers::circle::normalize_owner_url(
            body.owner_host.as_deref().unwrap_or_default(),
        )?;
    }
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
        return Err(ApiError::BadRequest(
            "valid name and email are required".into(),
        ));
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
    let token = match validate_member_invite(&state, &body.invite_token).await {
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
    let redeemer = crate::api::handlers::browser_member::did_for_registration(&registration_id);
    let locally_issued = token.issuer_did == state.device_did;
    if locally_issued {
        let circle = local_invite_circle(&state, &token)?;
        invite::assert_redeemable(&circle, &token, &redeemer)
            .map_err(|error| ApiError::Conflict(error.to_string()))?;
        invite::record_redemption(&token.id, &redeemer)
            .map_err(|error| ApiError::Internal(error.to_string()))?;
    } else {
        let owner_host = body.owner_host.as_deref().unwrap_or_default();
        crate::api::handlers::circle::join_remote_circle(&state, token.clone(), owner_host).await?;
    }

    let registration_expires_at =
        chrono::Utc::now().timestamp() + registration_days().saturating_mul(24 * 60 * 60);
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
            if locally_issued {
                let _ = invite::remove_redemption(&token.id, &redeemer);
            }
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
        browser_member_did: crate::api::handlers::browser_member::did_for_registration(
            &registration_id,
        ),
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

async fn validate_member_invite(
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
    Ok(token)
}

fn local_invite_circle(
    state: &AppState,
    token: &invite::InviteToken,
) -> Result<crate::circle::Circle, ApiError> {
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
    Ok(circle)
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
        &format!(
            "member browser credential rejected actor={} reason={}",
            actor, reason
        ),
    );
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
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

    #[test]
    fn pwa_contact_contract_omits_network_address_and_includes_profile_presence() {
        let contact = PwaContact {
            peer_id: "nodeB".into(),
            display_name: "Node B".into(),
            full_name: Some("Node B Guardian".into()),
            device_name: "nodeB".into(),
            did: Some("did:guardian:b".into()),
            status: "verified".into(),
            role: "member".into(),
            member_type: "guardian".into(),
            join_date: Some("2026-08-17T00:00:00Z".into()),
            last_seen: "2026-08-17T12:00:00Z".into(),
            online: true,
            presence_status: presence_status(true, false),
            presence_stale: false,
            presence_expires_at: presence_expiry_from("2026-08-17T12:00:00Z"),
            heartbeat_interval_seconds: CONTACT_PRESENCE_HEARTBEAT_SECONDS,
            call_available: true,
            call_unavailable_reason: None,
        };
        let json = serde_json::to_value(contact).expect("serialize contact");
        assert_eq!(json["displayName"], "Node B");
        assert_eq!(json["deviceName"], "nodeB");
        assert_eq!(json["presenceStatus"], "online");
        assert!(json.get("ip").is_none());
        assert!(json.get("port").is_none());
    }

    #[test]
    fn stale_presence_takes_precedence_over_online() {
        assert_eq!(presence_status(true, true), "stale");
        assert_eq!(presence_status(false, false), "offline");
    }
}

pub async fn identity(State(state): State<Arc<AppState>>) -> Json<PwaIdentityResponse> {
    Json(PwaIdentityResponse {
        did: state.device_did.clone(),
    })
}

pub async fn health(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedSession>,
) -> Json<PwaHealthResponse> {
    Json(PwaHealthResponse {
        status: "guardian_connected",
        guardian_did: state.device_did.clone(),
        actor_id: auth.claims.sub,
        role: auth.claims.role,
        circle_ids: auth.claims.circle_ids,
        server_time: chrono::Utc::now().timestamp(),
    })
}

pub async fn contacts(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedSession>,
) -> Result<Json<PwaContactsResponse>, ApiError> {
    let mut allowed_dids = crate::api::auth::authorization::scoped_circle_contact_dids(
        &state.node_id,
        &state.device_did,
        &auth.claims.circle_ids,
    )
    .map_err(ApiError::Internal)?;
    let local_circle_ids =
        crate::api::auth::authorization::local_active_circle_ids(&state.node_id, &state.device_did)
            .map_err(ApiError::Internal)?;
    let scoped_circle_ids = if auth.claims.circle_ids.is_empty() {
        local_circle_ids
    } else {
        local_circle_ids
            .into_iter()
            .filter(|circle_id| auth.claims.circle_ids.contains(circle_id))
            .collect()
    };
    allowed_dids.extend(
        crate::api::handlers::browser_member::dids_for_circles(&state, &scoped_circle_ids).await?,
    );
    let metadata = contact_metadata(&state, &auth.claims.circle_ids).await?;
    let Json(response) = peers::list(State(state.clone())).await?;
    let now = chrono::Utc::now().to_rfc3339();
    let guardian_presence_expires_at = Some(
        (chrono::Utc::now() + chrono::Duration::seconds(CONTACT_PRESENCE_EXPIRY_SECONDS as i64))
            .to_rfc3339(),
    );
    let mut contacts = vec![PwaContact {
        peer_id: state.node_id.clone(),
        display_name: state.node_id.clone(),
        full_name: Some("This Guardian".to_string()),
        device_name: state.node_id.clone(),
        did: Some(state.device_did.clone()),
        status: "verified".to_string(),
        role: "owner".to_string(),
        member_type: "guardian".to_string(),
        join_date: None,
        last_seen: now,
        online: true,
        presence_status: "online".to_string(),
        presence_stale: false,
        presence_expires_at: guardian_presence_expires_at,
        heartbeat_interval_seconds: CONTACT_PRESENCE_HEARTBEAT_SECONDS,
        call_available: true,
        call_unavailable_reason: None,
    }];
    let mut included_dids = HashSet::from([state.device_did.clone()]);
    contacts.extend(
        response
            .peers
            .into_iter()
            .filter(|peer| {
                peer.did.is_some()
                    && peer
                        .did
                        .as_ref()
                        .is_some_and(|did| allowed_dids.contains(did))
                    && matches!(peer.status.as_str(), "verified" | "trusted" | "success")
            })
            .filter_map(|peer| {
                let did = peer.did.clone()?;
                included_dids.insert(did.clone());
                let meta = metadata.get(&did);
                let display_name = display_name_from(&did, meta, &peer.peer_id);
                let device_name = meta
                    .and_then(|item| item.device_name.clone())
                    .unwrap_or_else(|| peer.peer_id.clone());
                Some(PwaContact {
                    peer_id: peer.peer_id,
                    display_name,
                    full_name: meta.and_then(|item| item.full_name.clone()),
                    device_name,
                    did: Some(did),
                    status: peer.status,
                    role: meta
                        .and_then(|item| item.role.clone())
                        .unwrap_or_else(|| "member".to_string()),
                    member_type: meta
                        .and_then(|item| item.member_type.clone())
                        .unwrap_or_else(|| "guardian".to_string()),
                    join_date: meta.and_then(|item| item.join_date.clone()),
                    last_seen: peer.last_seen.clone(),
                    online: peer.online,
                    presence_status: presence_status(peer.online, false),
                    presence_stale: false,
                    presence_expires_at: presence_expiry_from(&peer.last_seen),
                    heartbeat_interval_seconds: CONTACT_PRESENCE_HEARTBEAT_SECONDS,
                    call_available: peer.call_available,
                    call_unavailable_reason: peer.call_unavailable_reason,
                })
            })
            .collect::<Vec<_>>(),
    );
    for (did, meta) in metadata {
        if included_dids.contains(&did) || !allowed_dids.contains(&did) {
            continue;
        }
        let active = meta.active_browser_member;
        let display_name = display_name_from(&did, Some(&meta), &did);
        contacts.push(PwaContact {
            peer_id: did.clone(),
            display_name,
            full_name: meta.full_name,
            device_name: meta.device_name.unwrap_or_else(|| "Browser".to_string()),
            did: Some(did),
            status: if active { "verified" } else { "inactive" }.to_string(),
            role: meta.role.unwrap_or_else(|| "member".to_string()),
            member_type: meta.member_type.unwrap_or_else(|| "browser".to_string()),
            join_date: meta.join_date,
            last_seen: String::new(),
            online: active,
            presence_status: presence_status(active, false),
            presence_stale: false,
            presence_expires_at: None,
            heartbeat_interval_seconds: CONTACT_PRESENCE_HEARTBEAT_SECONDS,
            call_available: active,
            call_unavailable_reason: (!active)
                .then(|| "The member browser is inactive.".to_string()),
        });
    }
    contacts.sort_by(|left, right| left.display_name.cmp(&right.display_name));
    let total = contacts.len();

    Ok(Json(PwaContactsResponse {
        contacts,
        total,
        timestamp: response.timestamp,
        presence_heartbeat_seconds: CONTACT_PRESENCE_HEARTBEAT_SECONDS,
        presence_expiry_seconds: CONTACT_PRESENCE_EXPIRY_SECONDS,
    }))
}
