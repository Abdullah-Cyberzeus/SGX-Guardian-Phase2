use crate::api::auth::{
    middleware::AuthenticatedSession,
    oidc::{CyleniumOidcClient, CyleniumOidcConfig, IdTokenClaims},
    password,
    provider::Credentials,
    session,
    store::{NewUser, OidcTransactionRecord, User, UserRole},
};
use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use axum::{extract::State, Extension, Json};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use std::sync::Arc;
use std::time::Duration;

const OIDC_TRANSACTION_TTL_SECS: i64 = 300;

#[derive(Debug, serde::Deserialize)]
pub struct SignupRequest {
    pub name: String,
    pub email: String,
    pub password: String,
    /// The requested application role. The backend validates this value and
    /// derives its fixed scopes; caller-provided scopes are never accepted.
    #[serde(default = "default_signup_role")]
    pub role: String,
}

fn default_signup_role() -> String {
    "admin".to_string()
}

#[derive(Debug, serde::Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct CyleniumCallbackRequest {
    pub code: String,
    pub state: String,
    #[serde(default, rename = "codeVerifier")]
    pub code_verifier: Option<String>,
}

#[derive(Debug, serde::Serialize)]
pub struct CyleniumAuthorizeStartResponse {
    pub state: String,
    pub nonce: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct SignupResponse {
    #[serde(rename = "userId")]
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub scopes: Vec<String>,
    #[serde(rename = "guardianDid")]
    pub guardian_did: String,
    pub token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct LoginUserResponse {
    pub id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub scopes: Vec<String>,
    #[serde(rename = "hidePresence")]
    pub hide_presence: bool,
    #[serde(rename = "hideReadReceipts")]
    pub hide_read_receipts: bool,
    #[serde(rename = "hideTyping")]
    pub hide_typing: bool,
    #[serde(rename = "circleIds")]
    pub circle_ids: Vec<String>,
    #[serde(
        rename = "browserRegistrationId",
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_registration_id: Option<String>,
    #[serde(rename = "browserMemberDid", skip_serializing_if = "Option::is_none")]
    pub browser_member_did: Option<String>,
    #[serde(
        rename = "guardianFingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub guardian_fingerprint: Option<String>,
    #[serde(
        rename = "registrationExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub registration_expires_at: Option<i64>,
}

#[derive(Debug, serde::Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: LoginUserResponse,
    #[serde(rename = "guardianDid")]
    pub guardian_did: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct LogoutResponse {
    pub status: String,
}

#[derive(Debug, serde::Serialize)]
pub struct RevokeAllResponse {
    pub status: String,
    #[serde(rename = "revokedSessions")]
    pub revoked_sessions: usize,
}

#[derive(Debug, serde::Serialize)]
pub struct SessionResponse {
    pub valid: bool,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub name: String,
    pub email: String,
    pub role: String,
    pub scopes: Vec<String>,
    #[serde(rename = "hidePresence")]
    pub hide_presence: bool,
    #[serde(rename = "hideReadReceipts")]
    pub hide_read_receipts: bool,
    #[serde(rename = "hideTyping")]
    pub hide_typing: bool,
    #[serde(rename = "circleIds")]
    pub circle_ids: Vec<String>,
    #[serde(
        rename = "browserRegistrationId",
        skip_serializing_if = "Option::is_none"
    )]
    pub browser_registration_id: Option<String>,
    #[serde(rename = "browserMemberDid", skip_serializing_if = "Option::is_none")]
    pub browser_member_did: Option<String>,
    #[serde(
        rename = "guardianFingerprint",
        skip_serializing_if = "Option::is_none"
    )]
    pub guardian_fingerprint: Option<String>,
    #[serde(
        rename = "registrationExpiresAt",
        skip_serializing_if = "Option::is_none"
    )]
    pub registration_expires_at: Option<i64>,
    #[serde(rename = "guardianDid")]
    pub guardian_did: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

pub async fn signup(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SignupRequest>,
) -> Result<Json<SignupResponse>, ApiError> {
    let name = body.name.trim();
    let email = body.email.trim();
    if name.is_empty() || email.is_empty() {
        return Err(ApiError::BadRequest(
            "name and email are required".to_string(),
        ));
    }
    let role = match UserRole::parse(&body.role) {
        Some(UserRole::Admin) => UserRole::Admin,
        Some(UserRole::Member) => {
            return Err(ApiError::Forbidden(
                "member accounts require the verified Guardian invitation workflow".into(),
            ))
        }
        _ => {
            return Err(ApiError::BadRequest(
                "role must be admin or member".to_string(),
            ))
        }
    };

    let pw_hash = password::hash_password(body.password)
        .await
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let user = state
        .admin
        .users
        .create_initial_owner(NewUser {
            name: name.to_string(),
            email: email.to_string(),
            pw_hash,
            role,
            oidc_sub: None,
        })
        .await
        .map_err(|e| {
            let message = e.to_string();
            if message.contains("signup is only allowed before the first user is created") {
                ApiError::Forbidden(message)
            } else {
                ApiError::Conflict(message)
            }
        })?;

    let (token, claims, session_rec) = session::issue(
        state.signer.clone(),
        &state.device_did,
        &user,
        Duration::from_secs(state.session_ttl_secs),
    )
    .await?;
    state.admin.sessions.put(session_rec).await?;

    Ok(Json(SignupResponse {
        user_id: user.user_id,
        email: user.email,
        role: claims.role,
        scopes: claims.scopes,
        guardian_did: state.device_did.clone(),
        token,
        expires_at: claims.exp,
    }))
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let provider = state
        .auth_providers
        .local()
        .ok_or_else(|| ApiError::Internal("local auth provider missing".into()))?;
    let user = provider
        .authenticate(
            state.as_ref(),
            Credentials {
                email: body.email,
                password: body.password,
            },
        )
        .await?;
    validate_member_registration(&state, &user)?;
    let ttl = member_session_ttl(&state, &user);

    let (token, claims, session_rec) = session::issue(
        state.signer.clone(),
        &state.device_did,
        &user,
        Duration::from_secs(ttl),
    )
    .await?;
    state.admin.sessions.put(session_rec).await?;

    Ok(Json(LoginResponse {
        token,
        user: LoginUserResponse {
            id: user.user_id,
            name: user.name,
            email: user.email,
            role: claims.role,
            scopes: claims.scopes,
            hide_presence: user.hide_presence,
            hide_read_receipts: user.hide_read_receipts,
            hide_typing: user.hide_typing,
            circle_ids: claims.circle_ids,
            browser_member_did: claims
                .browser_registration_id
                .as_deref()
                .map(crate::api::handlers::browser_member::did_for_registration),
            browser_registration_id: claims.browser_registration_id,
            guardian_fingerprint: claims.guardian_fingerprint,
            registration_expires_at: user.registration_expires_at,
        },
        guardian_did: state.device_did.clone(),
        expires_at: claims.exp,
    }))
}

pub async fn cylenium_authorize_start(
    State(state): State<Arc<AppState>>,
) -> Result<Json<CyleniumAuthorizeStartResponse>, ApiError> {
    let provider = state
        .auth_providers
        .cylenium()
        .ok_or_else(|| ApiError::Internal("cylenium auth provider missing".into()))?;
    if !provider.enabled() {
        return Err(ApiError::Forbidden(
            "cylenium SSO provider is disabled".into(),
        ));
    }

    let config = cylenium_oidc_config_from_env()?;
    let now = chrono::Utc::now().timestamp();
    let record = OidcTransactionRecord {
        state: random_url_safe(32),
        nonce: random_url_safe(32),
        client_id: config.client_id,
        redirect_uri: config.redirect_uri,
        created_at: now,
        expires_at: now + OIDC_TRANSACTION_TTL_SECS,
        used: false,
    };
    state.admin.oidc_transactions.put(record.clone()).await?;

    Ok(Json(CyleniumAuthorizeStartResponse {
        state: record.state,
        nonce: record.nonce,
        expires_at: record.expires_at,
    }))
}

pub async fn cylenium_callback(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CyleniumCallbackRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let provider = state
        .auth_providers
        .cylenium()
        .ok_or_else(|| ApiError::Internal("cylenium auth provider missing".into()))?;
    if !provider.enabled() {
        return Err(ApiError::Forbidden(
            "cylenium SSO provider is disabled".into(),
        ));
    }

    let transaction_state = body.state.trim();
    if transaction_state.is_empty() {
        return Err(ApiError::Unauthorized(
            "cylenium callback missing state".into(),
        ));
    }
    let transaction = state
        .admin
        .oidc_transactions
        .consume(transaction_state)
        .await?
        .ok_or_else(|| {
            ApiError::Unauthorized("unknown, expired, or already used oidc transaction".into())
        })?;

    let config = cylenium_oidc_config_from_env()?;
    let client = CyleniumOidcClient::new(config);
    let (_, claims) = client
        .exchange_code_and_verify(
            &body.code,
            body.code_verifier.as_deref(),
            transaction.nonce.as_str(),
        )
        .await
        .map_err(|e| ApiError::Unauthorized(format!("cylenium OIDC login failed: {}", e)))?;
    let user = resolve_cylenium_user(&state, &claims).await?;

    let (token, claims, session_rec) = session::issue(
        state.signer.clone(),
        &state.device_did,
        &user,
        Duration::from_secs(state.session_ttl_secs),
    )
    .await?;
    state.admin.sessions.put(session_rec).await?;

    Ok(Json(LoginResponse {
        token,
        user: LoginUserResponse {
            id: user.user_id,
            name: user.name,
            email: user.email,
            role: claims.role,
            scopes: claims.scopes,
            hide_presence: user.hide_presence,
            hide_read_receipts: user.hide_read_receipts,
            hide_typing: user.hide_typing,
            circle_ids: claims.circle_ids,
            browser_member_did: claims
                .browser_registration_id
                .as_deref()
                .map(crate::api::handlers::browser_member::did_for_registration),
            browser_registration_id: claims.browser_registration_id,
            guardian_fingerprint: claims.guardian_fingerprint,
            registration_expires_at: user.registration_expires_at,
        },
        guardian_did: state.device_did.clone(),
        expires_at: claims.exp,
    }))
}

async fn resolve_cylenium_user(state: &AppState, claims: &IdTokenClaims) -> Result<User, ApiError> {
    // The OIDC `sub` claim, not email, is the durable identity key: email
    // can change or be reassigned at the IdP, but `sub` is permanent for a
    // given Cylenium user.
    let sub = claims.sub.trim();
    if sub.is_empty() {
        return Err(ApiError::Unauthorized(
            "cylenium ID token missing subject claim".into(),
        ));
    }
    let email = claims
        .email
        .as_deref()
        .map(str::trim)
        .filter(|email| !email.is_empty())
        .ok_or_else(|| ApiError::Unauthorized("cylenium ID token missing email claim".into()))?;
    Ok(match state.admin.users.find_by_oidc_sub(sub).await? {
        Some(user) => user,
        None => match state.admin.users.find_by_email(email).await? {
            // A local/password account already owns this email: link it to
            // this Cylenium subject so future logins resolve by sub.
            Some(existing) => {
                state
                    .admin
                    .users
                    .link_oidc_sub(&existing.user_id, sub)
                    .await?
            }
            None => {
                let name = claims
                    .name
                    .as_deref()
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .unwrap_or(email)
                    .to_string();
                state
                    .admin
                    .users
                    .create(NewUser {
                        name,
                        email: email.to_string(),
                        pw_hash: password::random_unusable_hash().await?,
                        role: UserRole::Admin,
                        oidc_sub: Some(sub.to_string()),
                    })
                    .await?
            }
        },
    })
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<LogoutResponse>, ApiError> {
    let Some(Extension(session)) = session else {
        return Err(ApiError::Unauthorized(
            "logout requires authentication".to_string(),
        ));
    };
    state.admin.sessions.revoke(&session.claims.jti).await?;
    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Revoked,
        &format!("browser session revoked actor={}", session.claims.sub),
    );
    Ok(Json(LogoutResponse {
        status: "logged_out".into(),
    }))
}

pub async fn revoke_all_sessions(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<RevokeAllResponse>, ApiError> {
    let revoked_sessions = state
        .admin
        .sessions
        .revoke_all_for_user(&session.claims.sub)
        .await?;
    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Revoked,
        &format!(
            "all browser sessions revoked actor={} count={}",
            session.claims.sub, revoked_sessions
        ),
    );
    Ok(Json(RevokeAllResponse {
        status: "all_sessions_revoked".into(),
        revoked_sessions,
    }))
}

pub async fn refresh_session(
    State(state): State<Arc<AppState>>,
    Extension(auth): Extension<AuthenticatedSession>,
) -> Result<Json<LoginResponse>, ApiError> {
    let user = state
        .admin
        .users
        .find_by_id(&auth.claims.sub)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("session user not found".into()))?;
    validate_member_registration(&state, &user)?;
    let ttl = member_session_ttl(&state, &user);
    let (token, claims, record) = session::issue(
        state.signer.clone(),
        &state.device_did,
        &user,
        Duration::from_secs(ttl),
    )
    .await?;
    state.admin.sessions.put(record).await?;
    state.admin.sessions.revoke(&auth.claims.jti).await?;
    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!("browser session refreshed actor={}", auth.claims.sub),
    );
    Ok(Json(LoginResponse {
        token,
        user: LoginUserResponse {
            id: user.user_id,
            name: user.name,
            email: user.email,
            role: claims.role,
            scopes: claims.scopes,
            hide_presence: user.hide_presence,
            hide_read_receipts: user.hide_read_receipts,
            hide_typing: user.hide_typing,
            circle_ids: claims.circle_ids,
            browser_member_did: claims
                .browser_registration_id
                .as_deref()
                .map(crate::api::handlers::browser_member::did_for_registration),
            browser_registration_id: claims.browser_registration_id,
            guardian_fingerprint: claims.guardian_fingerprint,
            registration_expires_at: user.registration_expires_at,
        },
        guardian_did: state.device_did.clone(),
        expires_at: claims.exp,
    }))
}

pub async fn session(
    State(state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<SessionResponse>, ApiError> {
    let Some(Extension(session)) = session else {
        return Err(ApiError::Unauthorized(
            "session requires authentication".to_string(),
        ));
    };
    let user = state
        .admin
        .users
        .find_by_id(&session.claims.sub)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("session user not found".into()))?;

    let browser_registration_id = user.browser_registration_id;
    let browser_member_did = browser_registration_id
        .as_deref()
        .map(crate::api::handlers::browser_member::did_for_registration);

    Ok(Json(SessionResponse {
        valid: true,
        user_id: session.claims.sub,
        name: user.name,
        email: user.email,
        role: user.role.as_str().to_string(),
        scopes: crate::api::auth::authorization::effective_scopes(user.role.as_str(), &user.scopes),
        hide_presence: user.hide_presence,
        hide_read_receipts: user.hide_read_receipts,
        hide_typing: user.hide_typing,
        circle_ids: user.circle_ids,
        browser_registration_id,
        browser_member_did,
        guardian_fingerprint: user.guardian_fingerprint,
        registration_expires_at: user.registration_expires_at,
        guardian_did: state.device_did.clone(),
        expires_at: session.claims.exp,
    }))
}

#[derive(serde::Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub hide_presence: Option<bool>,
    #[serde(default)]
    pub hide_read_receipts: Option<bool>,
    #[serde(default)]
    pub hide_typing: Option<bool>,
}

#[derive(serde::Serialize)]
pub struct ProfileResponse {
    pub user_id: String,
    pub name: String,
    pub email: String,
    pub hide_presence: bool,
    pub hide_read_receipts: bool,
    pub hide_typing: bool,
}

/// Self-service profile update — display name, email, and Guardian-enforced
/// privacy toggles (hide presence / read receipts / typing). Always acts on the
/// caller's own account (`claims.sub`); there is no target-user parameter.
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<ProfileResponse>, ApiError> {
    let patch = crate::api::auth::store::ProfilePatch {
        name: req.name,
        email: req.email,
        hide_presence: req.hide_presence,
        hide_read_receipts: req.hide_read_receipts,
        hide_typing: req.hide_typing,
    };
    let user = state
        .admin
        .users
        .update_profile(&session.claims.sub, patch)
        .await
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    log_audit(
        &state.node_id,
        AuditCategory::Identity,
        AuditSeverity::Info,
        AuditAction::Updated,
        &format!("profile updated actor={}", session.claims.sub),
    );

    Ok(Json(ProfileResponse {
        user_id: user.user_id,
        name: user.name,
        email: user.email,
        hide_presence: user.hide_presence,
        hide_read_receipts: user.hide_read_receipts,
        hide_typing: user.hide_typing,
    }))
}

fn validate_member_registration(
    state: &AppState,
    user: &crate::api::auth::store::User,
) -> Result<(), ApiError> {
    if user.role != UserRole::Member {
        return Ok(());
    }
    if user.status != "active"
        || user.browser_registration_id.is_none()
        || user.circle_ids.is_empty()
        || user
            .registration_expires_at
            .is_none_or(|expiry| expiry <= chrono::Utc::now().timestamp())
    {
        return Err(ApiError::Unauthorized(
            "member browser registration is inactive or expired; rejoin this Guardian".into(),
        ));
    }
    let current = crate::api::handlers::pwa::guardian_fingerprint(&state.device_pubkey_point);
    if user.guardian_fingerprint.as_deref() != Some(current.as_str()) {
        return Err(ApiError::Conflict(
            "Guardian fingerprint changed; explicit verification and rejoin are required".into(),
        ));
    }
    Ok(())
}

fn member_session_ttl(state: &AppState, user: &crate::api::auth::store::User) -> u64 {
    if user.role != UserRole::Member {
        return state.session_ttl_secs;
    }
    let remaining = user
        .registration_expires_at
        .unwrap_or_default()
        .saturating_sub(chrono::Utc::now().timestamp())
        .max(1) as u64;
    state.session_ttl_secs.min(remaining)
}

fn cylenium_oidc_config_from_env() -> Result<CyleniumOidcConfig, ApiError> {
    Ok(CyleniumOidcConfig {
        issuer: required_env("SGX_CYLENIUM_OIDC_ISSUER")?,
        token_endpoint: required_env("SGX_CYLENIUM_OIDC_TOKEN_ENDPOINT")?,
        jwks_uri: required_env("SGX_CYLENIUM_OIDC_JWKS_URI")?,
        client_id: required_env("SGX_CYLENIUM_OIDC_CLIENT_ID")?,
        client_secret: optional_env("SGX_CYLENIUM_OIDC_CLIENT_SECRET"),
        redirect_uri: required_env("SGX_CYLENIUM_OIDC_REDIRECT_URI")?,
    })
}

fn required_env(key: &str) -> Result<String, ApiError> {
    optional_env(key).ok_or_else(|| ApiError::Internal(format!("missing required env {}", key)))
}

fn optional_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn random_url_safe(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::oidc::Audience;
    use tempfile::TempDir;

    fn claims(sub: &str, email: Option<&str>, name: Option<&str>) -> IdTokenClaims {
        let now = chrono::Utc::now().timestamp();
        IdTokenClaims {
            iss: "https://login.cylenium.example".into(),
            sub: sub.into(),
            aud: Audience::One("sgx-client".into()),
            exp: now + 300,
            iat: Some(now),
            nbf: None,
            email: email.map(str::to_string),
            name: name.map(str::to_string),
            nonce: Some("nonce".into()),
        }
    }

    fn test_state(td: &TempDir) -> Arc<AppState> {
        AppState::for_tests(
            td.path(),
            "nodeA",
            td.path().join("config").to_string_lossy().to_string(),
        )
    }

    #[tokio::test]
    async fn cylenium_resolves_an_existing_account_by_durable_subject() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);
        let existing = state
            .admin
            .users
            .create(NewUser {
                name: "Existing Owner".into(),
                email: "old-address@example.com".into(),
                pw_hash: "unusable".into(),
                role: UserRole::Admin,
                oidc_sub: Some("subject-1".into()),
            })
            .await
            .expect("create existing account");

        let resolved = resolve_cylenium_user(
            state.as_ref(),
            &claims(
                "subject-1",
                Some("new-address@example.com"),
                Some("Changed Name"),
            ),
        )
        .await
        .expect("resolve by subject");
        assert_eq!(resolved.user_id, existing.user_id);
        assert_eq!(resolved.email, "old-address@example.com");
    }

    #[tokio::test]
    async fn cylenium_links_a_matching_local_email_on_first_login() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);
        let existing = state
            .admin
            .users
            .create(NewUser {
                name: "Local Owner".into(),
                email: "owner@example.com".into(),
                pw_hash: "local-password-hash".into(),
                role: UserRole::Admin,
                oidc_sub: None,
            })
            .await
            .expect("create local account");

        let resolved = resolve_cylenium_user(
            state.as_ref(),
            &claims("subject-linked", Some(" OWNER@example.com "), None),
        )
        .await
        .expect("link local account");
        assert_eq!(resolved.user_id, existing.user_id);
        assert_eq!(resolved.oidc_sub.as_deref(), Some("subject-linked"));
        assert_eq!(state.admin.users.count().await.expect("count"), 1);
    }

    #[tokio::test]
    async fn cylenium_creates_a_new_owner_and_uses_email_when_name_is_blank() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);
        let resolved = resolve_cylenium_user(
            state.as_ref(),
            &claims("subject-new", Some("new@example.com"), Some("   ")),
        )
        .await
        .expect("create Cylenium account");

        assert_eq!(resolved.name, "new@example.com");
        assert_eq!(resolved.email, "new@example.com");
        assert_eq!(resolved.role, UserRole::Admin);
        assert_eq!(resolved.oidc_sub.as_deref(), Some("subject-new"));
        assert_eq!(state.admin.users.count().await.expect("count"), 1);
    }

    #[tokio::test]
    async fn cylenium_rejects_missing_subject_or_email_claims() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        for invalid in [
            claims("  ", Some("owner@example.com"), None),
            claims("subject", None, None),
            claims("subject", Some("   "), None),
        ] {
            let error = resolve_cylenium_user(state.as_ref(), &invalid)
                .await
                .expect_err("missing identity claim");
            assert!(matches!(error, ApiError::Unauthorized(_)));
        }
        assert_eq!(state.admin.users.count().await.expect("count"), 0);
    }

    #[test]
    fn cylenium_state_and_nonce_are_url_safe_and_have_expected_entropy_length() {
        let value = random_url_safe(32);
        assert_eq!(URL_SAFE_NO_PAD.decode(value).expect("decode").len(), 32);
    }

    /// The six OIDC settings `cylenium_oidc_config_from_env` reads, plus the
    /// provider flag, which `ProviderRegistry::from_env` reads when the
    /// `AppState` is built — so it must be set before `test_state`.
    const OIDC_ENV: &[(&str, &str)] = &[
        ("SGX_SSO_CYLENIUM_ENABLED", "1"),
        ("SGX_CYLENIUM_OIDC_ISSUER", "https://login.cylenium.example"),
        // Port 1 is reserved and never listening, so the token exchange fails
        // fast and deterministically instead of reaching a real IdP.
        (
            "SGX_CYLENIUM_OIDC_TOKEN_ENDPOINT",
            "http://127.0.0.1:1/token",
        ),
        ("SGX_CYLENIUM_OIDC_JWKS_URI", "http://127.0.0.1:1/jwks"),
        ("SGX_CYLENIUM_OIDC_CLIENT_ID", "sgx-client"),
        (
            "SGX_CYLENIUM_OIDC_REDIRECT_URI",
            "https://guardian.local/callback",
        ),
    ];

    struct OidcEnv {
        previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl OidcEnv {
        /// Sets every OIDC variable except those named in `omit`, remembering
        /// the prior values so the process environment is restored on drop.
        fn set(omit: &[&str]) -> Self {
            let mut previous = Vec::new();
            for (key, value) in OIDC_ENV {
                previous.push((*key, std::env::var_os(key)));
                if omit.contains(key) {
                    std::env::remove_var(key);
                } else {
                    std::env::set_var(key, value);
                }
            }
            Self { previous }
        }
    }

    impl Drop for OidcEnv {
        fn drop(&mut self) {
            for (key, value) in self.previous.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[tokio::test]
    async fn cylenium_endpoints_are_forbidden_while_the_provider_is_disabled() {
        let _lock = crate::test_support::async_env_lock().await;
        let previous = std::env::var_os("SGX_SSO_CYLENIUM_ENABLED");
        std::env::remove_var("SGX_SSO_CYLENIUM_ENABLED");
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        let error = cylenium_authorize_start(State(state.clone()))
            .await
            .err()
            .expect("disabled provider");
        assert!(matches!(error, ApiError::Forbidden(_)), "{error:?}");

        let error = cylenium_callback(
            State(state),
            Json(CyleniumCallbackRequest {
                code: "code".into(),
                state: "state".into(),
                code_verifier: None,
            }),
        )
        .await
        .err()
        .expect("disabled provider");
        assert!(matches!(error, ApiError::Forbidden(_)), "{error:?}");

        if let Some(value) = previous {
            std::env::set_var("SGX_SSO_CYLENIUM_ENABLED", value);
        }
    }

    #[tokio::test]
    async fn cylenium_authorize_start_issues_and_persists_a_transaction() {
        let _lock = crate::test_support::async_env_lock().await;
        let _env = OidcEnv::set(&[]);
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        let started = cylenium_authorize_start(State(state.clone()))
            .await
            .expect("authorize start succeeds");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&started.0.state)
                .expect("decode state")
                .len(),
            32
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&started.0.nonce)
                .expect("decode nonce")
                .len(),
            32
        );
        assert!(started.0.expires_at > chrono::Utc::now().timestamp());

        // The transaction is single-use: consuming it once yields the record
        // with the matching nonce, and a second consume yields nothing.
        let consumed = state
            .admin
            .oidc_transactions
            .consume(&started.0.state)
            .await
            .expect("consume")
            .expect("transaction present");
        assert_eq!(consumed.nonce, started.0.nonce);
        assert_eq!(consumed.client_id, "sgx-client");
        assert!(state
            .admin
            .oidc_transactions
            .consume(&started.0.state)
            .await
            .expect("consume")
            .is_none());
    }

    #[tokio::test]
    async fn cylenium_authorize_start_reports_a_missing_oidc_setting() {
        let _lock = crate::test_support::async_env_lock().await;
        let _env = OidcEnv::set(&["SGX_CYLENIUM_OIDC_ISSUER"]);
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        let error = cylenium_authorize_start(State(state))
            .await
            .err()
            .expect("incomplete OIDC configuration");
        assert!(
            matches!(&error, ApiError::Internal(message) if message.contains("SGX_CYLENIUM_OIDC_ISSUER")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn cylenium_callback_rejects_missing_unknown_and_replayed_transactions() {
        let _lock = crate::test_support::async_env_lock().await;
        let _env = OidcEnv::set(&[]);
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        for (label, transaction_state) in [("blank", "   "), ("unknown", "no-such-state")] {
            let error = cylenium_callback(
                State(state.clone()),
                Json(CyleniumCallbackRequest {
                    code: "code".into(),
                    state: transaction_state.into(),
                    code_verifier: None,
                }),
            )
            .await
            .err()
            .unwrap_or_else(|| panic!("{label} state must be rejected"));
            assert!(
                matches!(error, ApiError::Unauthorized(_)),
                "{label}: {error:?}"
            );
        }

        // A real, unconsumed transaction gets past the state check and fails at
        // the token exchange instead — the IdP endpoint is a dead port.
        let started = cylenium_authorize_start(State(state.clone()))
            .await
            .expect("authorize start succeeds");
        let error = cylenium_callback(
            State(state.clone()),
            Json(CyleniumCallbackRequest {
                code: "code".into(),
                state: started.0.state.clone(),
                code_verifier: None,
            }),
        )
        .await
        .err()
        .expect("token exchange cannot reach the IdP");
        assert!(
            matches!(&error, ApiError::Unauthorized(message) if message.contains("cylenium OIDC login failed")),
            "{error:?}"
        );

        // ...and that attempt consumed it, so replaying the same state fails
        // at the transaction check rather than reaching the IdP again.
        let error = cylenium_callback(
            State(state),
            Json(CyleniumCallbackRequest {
                code: "code".into(),
                state: started.0.state,
                code_verifier: None,
            }),
        )
        .await
        .err()
        .expect("a consumed transaction cannot be replayed");
        assert!(
            matches!(&error, ApiError::Unauthorized(message) if message.contains("oidc transaction")),
            "{error:?}"
        );
    }

    #[test]
    fn optional_and_required_env_trim_values_and_treat_blank_as_absent() {
        let _previous = std::env::var_os("SGX_TEST_AUTH_ENV_PROBE");

        std::env::set_var("SGX_TEST_AUTH_ENV_PROBE", "  value  ");
        assert_eq!(
            optional_env("SGX_TEST_AUTH_ENV_PROBE").as_deref(),
            Some("value")
        );
        assert_eq!(
            required_env("SGX_TEST_AUTH_ENV_PROBE").expect("present"),
            "value"
        );

        std::env::set_var("SGX_TEST_AUTH_ENV_PROBE", "   ");
        assert_eq!(optional_env("SGX_TEST_AUTH_ENV_PROBE"), None);
        assert!(required_env("SGX_TEST_AUTH_ENV_PROBE").is_err());

        std::env::remove_var("SGX_TEST_AUTH_ENV_PROBE");
        assert_eq!(optional_env("SGX_TEST_AUTH_ENV_PROBE"), None);
        assert!(matches!(
            required_env("SGX_TEST_AUTH_ENV_PROBE"),
            Err(ApiError::Internal(message)) if message.contains("SGX_TEST_AUTH_ENV_PROBE")
        ));
    }

    /// The serde default applied when a signup request omits `role`. It is
    /// `admin` because the signup route only accepts `admin` or `member` (see
    /// `signup`'s own "role must be admin or member" rejection), so this is the
    /// administrative default for first-boot onboarding rather than a
    /// least-privilege fallback.
    #[test]
    fn default_signup_role_is_admin() {
        assert_eq!(default_signup_role(), "admin");
        assert!(
            UserRole::parse(&default_signup_role()).is_some(),
            "the default must be a role the signup route actually accepts"
        );
    }

    fn member_user(state: &AppState) -> crate::api::auth::store::User {
        crate::api::auth::store::User {
            user_id: "user-1".into(),
            name: "Member".into(),
            email: "member@example.test".into(),
            pw_hash: "unusable".into(),
            role: UserRole::Member,
            scopes: Vec::new(),
            circle_ids: vec!["circle-1".into()],
            browser_registration_id: Some("registration-1".into()),
            guardian_fingerprint: Some(crate::api::handlers::pwa::guardian_fingerprint(
                &state.device_pubkey_point,
            )),
            registration_expires_at: Some(chrono::Utc::now().timestamp() + 3_600),
            invite_id: None,
            created_at: "2026-07-24T00:00:00Z".into(),
            status: "active".into(),
            failed_attempts: 0,
            locked_until: None,
            last_failed_at: None,
            oidc_sub: None,
            hide_presence: false,
            hide_read_receipts: false,
            hide_typing: false,
        }
    }

    /// Every reason a member browser registration stops being accepted. Each
    /// case starts from a valid member and breaks exactly one precondition.
    #[test]
    fn validate_member_registration_rejects_each_broken_precondition() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);
        let valid = member_user(&state);
        validate_member_registration(&state, &valid).expect("a complete member is accepted");

        // Non-member accounts are not subject to any of these checks.
        let mut owner = valid.clone();
        owner.role = UserRole::Owner;
        owner.status = "inactive".into();
        owner.circle_ids.clear();
        owner.browser_registration_id = None;
        owner.registration_expires_at = None;
        owner.guardian_fingerprint = None;
        validate_member_registration(&state, &owner).expect("non-members are exempt");

        let mut inactive = valid.clone();
        inactive.status = "inactive".into();
        let mut no_registration = valid.clone();
        no_registration.browser_registration_id = None;
        let mut no_circles = valid.clone();
        no_circles.circle_ids.clear();
        let mut no_expiry = valid.clone();
        no_expiry.registration_expires_at = None;
        let mut expired = valid.clone();
        expired.registration_expires_at = Some(chrono::Utc::now().timestamp() - 1);

        for (label, user) in [
            ("inactive", inactive),
            ("no registration id", no_registration),
            ("no circles", no_circles),
            ("no expiry", no_expiry),
            ("expired", expired),
        ] {
            let error = validate_member_registration(&state, &user)
                .err()
                .unwrap_or_else(|| panic!("{label} must be rejected"));
            assert!(
                matches!(error, ApiError::Unauthorized(_)),
                "{label}: {error:?}"
            );
        }

        // A changed Guardian fingerprint is a conflict, not an expiry — it
        // needs explicit re-verification rather than a silent refresh.
        let mut rotated = valid;
        rotated.guardian_fingerprint = Some("0000-0000-0000-0000".into());
        let error = validate_member_registration(&state, &rotated)
            .err()
            .expect("a rotated Guardian identity must be caught");
        assert!(matches!(error, ApiError::Conflict(_)), "{error:?}");
    }

    #[test]
    fn member_session_ttl_is_capped_by_the_remaining_registration_window() {
        let td = TempDir::new().expect("tempdir");
        let state = test_state(&td);

        // Non-members always get the full session TTL.
        let mut owner = member_user(&state);
        owner.role = UserRole::Owner;
        owner.registration_expires_at = Some(chrono::Utc::now().timestamp() + 1);
        assert_eq!(member_session_ttl(&state, &owner), state.session_ttl_secs);

        // A member whose registration outlives the session TTL gets the TTL.
        let mut long_lived = member_user(&state);
        long_lived.registration_expires_at =
            Some(chrono::Utc::now().timestamp() + state.session_ttl_secs as i64 * 10);
        assert_eq!(
            member_session_ttl(&state, &long_lived),
            state.session_ttl_secs
        );

        // A member whose registration expires sooner is clamped to it.
        let mut short_lived = member_user(&state);
        short_lived.registration_expires_at = Some(chrono::Utc::now().timestamp() + 30);
        let ttl = member_session_ttl(&state, &short_lived);
        assert!(ttl <= 30 && ttl > 0, "expected a clamped ttl, got {ttl}");

        // An already-expired or missing registration still yields at least 1s
        // rather than underflowing.
        let mut expired = member_user(&state);
        expired.registration_expires_at = Some(chrono::Utc::now().timestamp() - 10_000);
        assert_eq!(member_session_ttl(&state, &expired), 1);
        let mut missing = member_user(&state);
        missing.registration_expires_at = None;
        assert_eq!(member_session_ttl(&state, &missing), 1);
    }
}
