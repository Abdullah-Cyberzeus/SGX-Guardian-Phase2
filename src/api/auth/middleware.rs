use crate::api::auth::authorization::{self, AccessDecision};
use crate::api::auth::session::{self, Claims};
use crate::api::state::AppState;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use axum::{
    extract::State,
    http::{header, HeaderMap, Method, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
#[cfg(test)]
use std::sync::atomic::{AtomicI8, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AuthenticatedSession {
    pub claims: Claims,
    pub token: String,
}

#[cfg(test)]
static TEST_DISABLE_LOGIN_OVERRIDE: AtomicI8 = AtomicI8::new(-1);

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if login_disabled() {
        return next.run(req).await;
    }
    if is_public_route(req.method(), req.uri().path())
        || is_cors_preflight(req.method(), req.headers())
    {
        return next.run(req).await;
    }

    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
        .or_else(|| {
            ((req.uri().path().starts_with("/api/v1/group-call/")
                && req.uri().path().ends_with("/ws"))
                || (req.uri().path().starts_with("/api/v1/call/")
                    && req.uri().path().ends_with("/ws"))
                || req.uri().path() == "/api/v1/chat/ws"
                || req.uri().path() == "/api/v1/cert/requests/ws"
                || req.uri().path() == "/api/v1/ha/ws")
                .then(|| query_parameter(req.uri().query(), "access_token"))
                .flatten()
        });
    let Some(token) = token else {
        tracing::warn!(
            "operator auth failed path={} reason=missing bearer token",
            req.uri().path()
        );
        return unauthorized("missing bearer token");
    };

    let claims = match session::verify(&state.device_pubkey_point, &token) {
        Ok(claims) => claims,
        Err(_) => {
            tracing::warn!(
                "operator auth failed path={} reason=invalid bearer token",
                req.uri().path()
            );
            return unauthorized("invalid bearer token");
        }
    };
    if claims.iss != state.device_did {
        tracing::warn!(
            "operator auth failed path={} reason=token issuer mismatch",
            req.uri().path()
        );
        return unauthorized("token issuer mismatch");
    }
    if claims.exp <= Utc::now().timestamp() {
        tracing::warn!(
            "operator auth failed path={} reason=token expired",
            req.uri().path()
        );
        return unauthorized("token expired");
    }
    let stored_session = match state.admin.sessions.get(&claims.jti).await {
        Ok(session) => session,
        Err(_) => {
            tracing::warn!(
                "operator auth failed path={} reason=session store error",
                req.uri().path()
            );
            return unauthorized("invalid session");
        }
    };
    let Some(stored_session) = stored_session else {
        tracing::warn!(
            "operator auth failed path={} reason=unknown session",
            req.uri().path()
        );
        return unauthorized("unknown session");
    };
    if stored_session.revoked || stored_session.expires_at <= Utc::now().timestamp() {
        tracing::warn!(
            "operator auth failed path={} reason=session revoked",
            req.uri().path()
        );
        return unauthorized("session revoked");
    }

    let user = match state.admin.users.find_by_id(&claims.sub).await {
        Ok(Some(user)) => user,
        _ => return unauthorized("session user not found"),
    };
    if user.status != "active" {
        return unauthorized("session user is inactive");
    }
    if claims.role != user.role.as_str() {
        return unauthorized("session role changed; sign in again");
    }
    let current_scopes = if user.scopes.is_empty() {
        authorization::default_scopes(user.role.as_str())
    } else {
        user.scopes
    };
    // Tokens issued before scopes were introduced remain valid for existing
    // owner/admin accounts. New scoped sessions fail closed when permissions
    // change in the account record and must be re-issued by signing in.
    if !claims.scopes.is_empty() && claims.scopes != current_scopes {
        return unauthorized("session permissions changed; sign in again");
    }
    if claims.role == "member" {
        if user
            .registration_expires_at
            .is_none_or(|expiry| expiry <= Utc::now().timestamp())
        {
            log_audit(
                &state.node_id,
                AuditCategory::Identity,
                AuditSeverity::Warning,
                AuditAction::Rejected,
                &format!("member browser registration expired actor={}", claims.sub),
            );
            return unauthorized("browser registration expired; rejoin this Guardian");
        }
        if claims.circle_ids != user.circle_ids
            || claims.browser_registration_id != user.browser_registration_id
            || claims.guardian_fingerprint != user.guardian_fingerprint
        {
            return unauthorized("browser registration changed; sign in again");
        }
        let current_fingerprint =
            crate::api::handlers::pwa::guardian_fingerprint(&state.device_pubkey_point);
        if claims.guardian_fingerprint.as_deref() != Some(current_fingerprint.as_str()) {
            log_audit(
                &state.node_id,
                AuditCategory::Identity,
                AuditSeverity::Warning,
                AuditAction::Rejected,
                &format!("Guardian fingerprint rotation requires member re-verification actor={}", claims.sub),
            );
            return unauthorized("Guardian fingerprint changed; verification is required");
        }
    }

    match authorization::authorize(&claims.role, &current_scopes, req.method(), req.uri().path()) {
        AccessDecision::Allowed => {
            if claims.role == "member" {
                audit_access_decision(
                    &state.node_id,
                    &claims,
                    req.method(),
                    req.uri().path(),
                    true,
                    None,
                );
            }
        }
        AccessDecision::Denied { required_scope } => {
            audit_access_decision(
                &state.node_id,
                &claims,
                req.method(),
                req.uri().path(),
                false,
                Some(required_scope),
            );
            return forbidden("insufficient role or scope for this operation");
        }
    }

    req.extensions_mut()
        .insert(AuthenticatedSession { claims, token });
    next.run(req).await
}

fn login_disabled() -> bool {
    #[cfg(test)]
    match TEST_DISABLE_LOGIN_OVERRIDE.load(Ordering::Relaxed) {
        0 => return false,
        1 => return true,
        _ => {}
    }

    crate::runtime_gates::login_disabled()
}

fn query_parameter(query: Option<&str>, name: &str) -> Option<String> {
    query?
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(key, value)| (key == name).then(|| value.to_string()))
}

fn is_public_route(method: &Method, path: &str) -> bool {
    let public_frontend = method == Method::GET && !path.starts_with("/api/");
    let circle_snapshot_pull =
        method == Method::GET && path.starts_with("/api/v1/circles/") && path.ends_with("/members/snapshot");

    matches!(
        (method, path),
        (&Method::POST, "/api/v1/auth/signup")
            | (&Method::POST, "/api/v1/auth/login")
            | (&Method::POST, "/api/v1/auth/oidc/cylenium/start")
            | (&Method::POST, "/api/v1/auth/oidc/cylenium/callback")
            | (&Method::GET, "/api/v1/pwa/onboarding")
            | (&Method::POST, "/api/v1/pwa/onboarding/invite-preview")
            | (&Method::POST, "/api/v1/pwa/onboarding/join")
            | (&Method::POST, "/api/v1/circles/redeem")
            // Service-authenticated in handlers::circle::receive_invite.
            | (&Method::POST, "/api/v1/circles/invites/inbox")
            // Service-authenticated in handlers::circle::receive_member_snapshot.
            | (&Method::POST, "/api/v1/circles/snapshots/inbox")
            | (&Method::POST, "/api/v1/restore/validate")
            | (&Method::GET, "/api/v1/restore/status")
            | (&Method::GET, "/api/v1/health")
    ) || circle_snapshot_pull
        || public_frontend
}

fn is_cors_preflight(method: &Method, headers: &HeaderMap) -> bool {
    method == Method::OPTIONS
        && headers.contains_key(header::ORIGIN)
        && headers.contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
}

fn unauthorized(message: &str) -> Response {
    crate::api::error::ApiError::Unauthorized(message.to_string()).into_response()
}

fn forbidden(message: &str) -> Response {
    crate::api::error::ApiError::Forbidden(message.to_string()).into_response()
}

fn audit_access_decision(
    node_id: &str,
    claims: &Claims,
    method: &Method,
    path: &str,
    allowed: bool,
    required_scope: Option<&str>,
) {
    let message = format!(
        "API authorization {} actor={} role={} method={} path={} required_scope={}",
        if allowed { "allowed" } else { "denied" },
        claims.sub,
        claims.role,
        method,
        path,
        required_scope.unwrap_or("role-default")
    );
    log_audit(
        node_id,
        AuditCategory::Identity,
        if allowed {
            AuditSeverity::Info
        } else {
            AuditSeverity::Warning
        },
        if allowed {
            AuditAction::Succeeded
        } else {
            AuditAction::Rejected
        },
        &message,
    );
}

#[cfg(test)]
pub(crate) struct TestDisableLoginGuard {
    previous: i8,
}

#[cfg(test)]
pub(crate) fn test_force_disable_login(disabled: bool) -> TestDisableLoginGuard {
    let next = if disabled { 1 } else { 0 };
    let previous = TEST_DISABLE_LOGIN_OVERRIDE.swap(next, Ordering::Relaxed);
    TestDisableLoginGuard { previous }
}

#[cfg(test)]
impl Drop for TestDisableLoginGuard {
    fn drop(&mut self) {
        TEST_DISABLE_LOGIN_OVERRIDE.store(self.previous, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::{
        session,
        store::{NewMemberRegistration, NewUser, UserRole},
    };
    use crate::api::state::AppState;
    use crate::test_support::async_env_lock;
    use axum::{routing::get, Json, Router};
    use reqwest::StatusCode;
    use serde_json::json;
    use tempfile::TempDir;
    use tokio::net::TcpListener;

    async fn spawn_secured_app_for_role(
        role: UserRole,
    ) -> (String, String, tokio::task::JoinHandle<()>) {
        let td = TempDir::new().expect("tempdir");
        let base = td.path().to_path_buf();
        let state = AppState::for_tests(
            &base,
            "nodeA",
            base.join("config").to_string_lossy().to_string(),
        );
        let user = if role == UserRole::Member {
            state
                .admin
                .users
                .create_or_reactivate_member(NewMemberRegistration {
                    name: "Member".into(),
                    email: "member@example.com".into(),
                    pw_hash: "hash".into(),
                    circle_id: "test-circle".into(),
                    browser_registration_id: "test-browser".into(),
                    guardian_fingerprint: crate::api::handlers::pwa::guardian_fingerprint(
                        &state.device_pubkey_point,
                    ),
                    registration_expires_at: Utc::now().timestamp() + 300,
                    invite_id: "test-invite".into(),
                })
                .await
                .expect("seed member")
        } else {
            state
                .admin
                .users
                .create(NewUser {
                    name: "Admin".into(),
                    email: "admin@example.com".into(),
                    pw_hash: "hash".into(),
                    role,
                    oidc_sub: None,
                })
                .await
                .expect("seed user")
        };
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
            .route(
                "/api/v1/chat/history",
                get(|| async { Json(json!({ "messages": [] })) }),
            )
            .route(
                "/api/v1/policy/sign",
                axum::routing::post(|| async { Json(json!({ "ok": true })) }),
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

    async fn spawn_secured_app() -> (String, String, tokio::task::JoinHandle<()>) {
        spawn_secured_app_for_role(UserRole::Owner).await
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
    async fn member_can_read_messages_but_cannot_sign_policy() {
        let (base_url, token, handle) = spawn_secured_app_for_role(UserRole::Member).await;
        let client = reqwest::Client::new();

        let messages = client
            .get(format!("{}/api/v1/chat/history", base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("member message history");
        assert_eq!(messages.status(), StatusCode::OK);

        let policy = client
            .post(format!("{}/api/v1/policy/sign", base_url))
            .bearer_auth(&token)
            .send()
            .await
            .expect("member policy sign");
        handle.abort();
        assert_eq!(policy.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cors_preflight_is_allowed_without_bearer_token() {
        let (base_url, _token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .request(
                reqwest::Method::OPTIONS,
                format!("{}/api/v1/private", base_url),
            )
            .header(reqwest::header::ORIGIN, "http://localhost:3001")
            .header(reqwest::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .send()
            .await
            .expect("preflight route");
        handle.abort();
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn forged_preflight_headers_do_not_bypass_auth_on_get() {
        let (base_url, _token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .get(format!("{}/api/v1/private", base_url))
            .header(reqwest::header::ORIGIN, "http://localhost:3001")
            .header(reqwest::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .send()
            .await
            .expect("forged preflight request");
        handle.abort();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn private_route_allows_requests_when_login_is_disabled() {
        let _test_lock = async_env_lock().await;
        let _guard = test_force_disable_login(true);
        let (base_url, _token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .get(format!("{}/api/v1/private", base_url))
            .send()
            .await
            .expect("private route with login disabled");
        handle.abort();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn call_and_websocket_routes_now_require_auth() {
        // These used to be blanket-public (a bearer-less bypass that also let
        // unauthenticated clients read/join call and group-call websockets).
        // They now go through the normal bearer-token check, falling back to
        // the `access_token` query param specifically for the `/ws` upgrade
        // paths (browsers can't set custom headers on a WebSocket handshake).
        assert!(!is_public_route(&Method::POST, "/api/v1/group-calls"));
        assert!(!is_public_route(
            &Method::GET,
            "/api/v1/group-call/group-1/ws"
        ));
        assert!(!is_public_route(&Method::GET, "/api/v1/call/session-1/ws"));
    }

    #[tokio::test]
    async fn websocket_route_accepts_access_token_query_param() {
        let (base_url, token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .get(format!(
                "{}/api/v1/call/session-1/ws?access_token={}",
                base_url, token
            ))
            .send()
            .await
            .expect("ws route with query token");
        handle.abort();
        // No matching route in this minimal test app (so not 200), but the
        // auth layer must accept the query-param token rather than reject it.
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn websocket_route_rejects_missing_token() {
        let (base_url, _token, handle) = spawn_secured_app().await;
        let response = reqwest::Client::new()
            .get(format!("{}/api/v1/call/session-1/ws", base_url))
            .send()
            .await
            .expect("ws route without token");
        handle.abort();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn circle_redeem_route_is_public() {
        assert!(is_public_route(&Method::POST, "/api/v1/circles/redeem"));
    }
}
