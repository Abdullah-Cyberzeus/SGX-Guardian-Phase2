use crate::api::auth::{
    middleware::AuthenticatedSession,
    password,
    provider::Credentials,
    session,
    store::{NewUser, UserRole},
};
use crate::api::{error::ApiError, state::AppState};
use axum::{extract::State, Extension, Json};
use std::sync::Arc;
use std::time::Duration;

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

pub async fn logout(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<LogoutResponse>, ApiError> {
    state.admin.sessions.revoke(&session.claims.jti).await?;
    Ok(Json(LogoutResponse {
        status: "logged_out".into(),
    }))
}

pub async fn session(
    State(state): State<Arc<AppState>>,
    Extension(session): Extension<AuthenticatedSession>,
) -> Result<Json<SessionResponse>, ApiError> {
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
