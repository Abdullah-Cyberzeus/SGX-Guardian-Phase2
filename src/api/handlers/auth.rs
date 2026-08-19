use crate::api::auth::{
    middleware::AuthenticatedSession,
    oidc::{CyleniumOidcClient, CyleniumOidcConfig},
    password,
    provider::Credentials,
    session,
    store::{NewUser, OidcTransactionRecord, UserRole},
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
    pub email: String,
    pub role: String,
    pub scopes: Vec<String>,
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
    pub email: String,
    pub role: String,
    pub scopes: Vec<String>,
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
            email: user.email,
            role: claims.role,
            scopes: claims.scopes,
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
    let user = match state.admin.users.find_by_oidc_sub(sub).await? {
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
    };

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
            email: user.email,
            role: claims.role,
            scopes: claims.scopes,
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
            email: user.email,
            role: claims.role,
            scopes: claims.scopes,
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
        email: user.email,
        role: user.role.as_str().to_string(),
        scopes: if user.scopes.is_empty() {
            crate::api::auth::authorization::default_scopes(user.role.as_str())
        } else {
            user.scopes
        },
        circle_ids: user.circle_ids,
        browser_registration_id,
        browser_member_did,
        guardian_fingerprint: user.guardian_fingerprint,
        registration_expires_at: user.registration_expires_at,
        guardian_did: state.device_did.clone(),
        expires_at: session.claims.exp,
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
