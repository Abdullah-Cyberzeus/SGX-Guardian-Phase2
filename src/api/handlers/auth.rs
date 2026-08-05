use crate::api::auth::{
    middleware::AuthenticatedSession,
    oidc::{CyleniumOidcClient, CyleniumOidcConfig},
    password,
    provider::Credentials,
    session,
    store::{NewUser, OidcTransactionRecord, UserRole},
};
use crate::api::{error::ApiError, state::AppState};
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
    pub token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct LoginUserResponse {
    pub id: String,
    pub email: String,
    pub role: String,
}

#[derive(Debug, serde::Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: LoginUserResponse,
    #[serde(rename = "expiresAt")]
    pub expires_at: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct LogoutResponse {
    pub status: String,
}

#[derive(Debug, serde::Serialize)]
pub struct SessionResponse {
    pub valid: bool,
    #[serde(rename = "userId")]
    pub user_id: String,
    pub email: String,
    pub role: String,
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
            role: UserRole::Owner,
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
        },
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
    let sub = claims
        .sub
        .trim();
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
            Some(existing) => state.admin.users.link_oidc_sub(&existing.user_id, sub).await?,
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
        },
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
    Ok(Json(LogoutResponse {
        status: "logged_out".into(),
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

    Ok(Json(SessionResponse {
        valid: true,
        user_id: session.claims.sub,
        email: user.email,
        role: user.role.as_str().to_string(),
        expires_at: session.claims.exp,
    }))
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
