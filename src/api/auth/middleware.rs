use crate::api::auth::session::{self, Claims};
use crate::api::state::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, Method, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AuthenticatedSession {
    pub claims: Claims,
    pub token: String,
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if is_public_route(req.method(), req.uri().path()) || is_cors_preflight(req.headers()) {
        return next.run(req).await;
    }

    let Some(value) = req.headers().get(header::AUTHORIZATION) else {
        return unauthorized("missing bearer token");
    };
    let Ok(value) = value.to_str() else {
        return unauthorized("invalid authorization header");
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return unauthorized("missing bearer token");
    };
    let token = token.to_string();

    let claims = match session::verify(&state.device_pubkey_point, &token) {
        Ok(claims) => claims,
        Err(_) => return unauthorized("invalid bearer token"),
    };
    if claims.iss != state.device_did {
        return unauthorized("token issuer mismatch");
    }
    if claims.exp <= Utc::now().timestamp() {
        return unauthorized("token expired");
    }
    let stored_session = match state.admin.sessions.get(&claims.jti).await {
        Ok(session) => session,
        Err(_) => return unauthorized("invalid session"),
    };
    let Some(stored_session) = stored_session else {
        return unauthorized("unknown session");
    };
    if stored_session.revoked || stored_session.expires_at <= Utc::now().timestamp() {
        return unauthorized("session revoked");
    }

    req.extensions_mut()
        .insert(AuthenticatedSession { claims, token });
    next.run(req).await
}

fn is_public_route(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::POST, "/api/v1/auth/signup")
            | (&Method::POST, "/api/v1/auth/login")
            | (&Method::GET, "/api/v1/health")
    )
}

fn is_cors_preflight(headers: &HeaderMap) -> bool {
    headers.contains_key(header::ORIGIN)
        && headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

fn unauthorized(message: &str) -> Response {
    crate::api::error::ApiError::Unauthorized(message.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::{
        session,
        store::{NewUser, UserRole},
    };
    use crate::api::state::AppState;
    use axum::{routing::get, Json, Router};
    use reqwest::StatusCode;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    async fn spawn_secured_app() -> (String, String, tokio::task::JoinHandle<()>) {
        let td = TempDir::new().expect("tempdir");
        let base = td.path().to_path_buf();
        let state = AppState::for_tests(
            &base,
            "nodeA",
            base.join("config").to_string_lossy().to_string(),
        );
        let user = state
            .admin
            .users
            .create(NewUser {
                name: "Admin".into(),
                email: "admin@example.com".into(),
                pw_hash: "hash".into(),
                role: UserRole::Owner,
            })
            .await
            .expect("seed user");
        let (token, _, session_rec) = session::issue(
            state.signer.clone(),
            &state.device_did,
            &user,
            std::time::Duration::from_secs(300),
        )
        .await
        .expect("issue token");
        state
            .admin
            .sessions
            .put(session_rec)
            .await
            .expect("save session");

        let app = Router::new()
            .route("/api/v1/health", get(|| async { "ok" }))
            .route(
                "/api/v1/private",
                get(|| async { Json(json!({ "ok": true })) }),
            )
            .with_state(state.clone())
            .layer(axum::middleware::from_fn_with_state(state, require_auth));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("local addr");
        let handle = tokio::spawn(async move {
            let _td = td;
            let _ = axum::serve(listener, app.into_make_service()).await;
        });
        (format!("http://{}", addr), token, handle)
    }

    #[tokio::test]
    async fn public_health_route_is_open() {
        let (base_url, _token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .get(format!("{}/api/v1/health", base_url))
            .send()
            .await
            .expect("health");
        handle.abort();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn private_route_requires_bearer_token() {
        let (base_url, _token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .get(format!("{}/api/v1/private", base_url))
            .send()
            .await
            .expect("private route");
        handle.abort();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn private_route_accepts_valid_bearer_token() {
        let (base_url, token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .get(format!("{}/api/v1/private", base_url))
            .bearer_auth(token)
            .send()
            .await
            .expect("authorized private route");
        handle.abort();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cors_preflight_is_allowed_without_bearer_token() {
        let (base_url, _token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .request(
                reqwest::Method::OPTIONS,
                format!("{}/api/v1/private", base_url),
            )
            .header(reqwest::header::ORIGIN, "http://localhost:3000")
            .header(reqwest::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .send()
            .await
            .expect("preflight route");
        handle.abort();
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
