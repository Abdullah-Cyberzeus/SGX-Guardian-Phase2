use axum::body::to_bytes;
use axum::http::{header, Method, StatusCode};
use axum::response::IntoResponse;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use sgx_guardian_client::api::auth::authorization::{
    authorize, default_scopes, effective_scopes, scope, AccessDecision,
};
use sgx_guardian_client::api::auth::command_auth::CommandAuthError;
use sgx_guardian_client::api::auth::provider::{
    AuthProvider, Credentials, CyleniumProvider, LocalAuthProvider, ProviderRegistry,
    CYLENIUM_PROVIDER_NAME, LOCAL_PROVIDER_NAME,
};
use sgx_guardian_client::api::auth::rate_limiter::DeviceRateLimiter;
use sgx_guardian_client::api::auth::session::{self, Claims};
use sgx_guardian_client::api::frontend;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct ProviderEnv {
    original: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl ProviderEnv {
    fn set(value: Option<&str>) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let original = std::env::var("SGX_SSO_CYLENIUM_ENABLED").ok();
        match value {
            Some(value) => std::env::set_var("SGX_SSO_CYLENIUM_ENABLED", value),
            None => std::env::remove_var("SGX_SSO_CYLENIUM_ENABLED"),
        }
        Self {
            original,
            _lock: lock,
        }
    }
}

impl Drop for ProviderEnv {
    fn drop(&mut self) {
        match &self.original {
            Some(value) => std::env::set_var("SGX_SSO_CYLENIUM_ENABLED", value),
            None => std::env::remove_var("SGX_SSO_CYLENIUM_ENABLED"),
        }
    }
}

fn decision_with_scope(method: Method, path: &str, required: &'static str) {
    assert_eq!(
        authorize("member", &[required.to_string()], &method, path),
        AccessDecision::Allowed,
        "expected member access for {method} {path}"
    );
    assert_eq!(
        authorize("member", &[], &method, path),
        AccessDecision::Denied {
            required_scope: required
        },
        "expected missing-scope denial for {method} {path}"
    );
}

fn encoded_json(value: serde_json::Value) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap())
}

#[test]
fn default_and_effective_scopes_cover_roles_empty_legacy_duplicates_and_custom_values() {
    for role in ["owner", "admin"] {
        assert_eq!(default_scopes(role), vec![scope::ADMIN_ALL]);
    }
    let member = default_scopes("member");
    assert_eq!(member.len(), 12);
    for required in [
        scope::GUARDIAN_READ,
        scope::CIRCLES_READ,
        scope::MESSAGES_READ,
        scope::MESSAGES_SEND,
        scope::CALLS_USE,
        scope::CONTACTS_READ,
        scope::CONTACTS_MANAGE,
        scope::FILES_READ,
        scope::FILES_UPLOAD,
        scope::NOTIFICATIONS_READ,
        scope::NOTIFICATIONS_MANAGE,
        scope::SETTINGS_OWN,
    ] {
        assert!(member.contains(&required.to_string()));
    }
    assert!(default_scopes("guest").is_empty());

    assert_eq!(effective_scopes("member", &[]), member);
    let healed = effective_scopes(
        "member",
        &[scope::MESSAGES_READ.into(), "custom:retained".into()],
    );
    assert_eq!(healed[0], scope::MESSAGES_READ);
    assert_eq!(healed[1], "custom:retained");
    assert_eq!(
        healed
            .iter()
            .filter(|item| item.as_str() == scope::MESSAGES_READ)
            .count(),
        1
    );
    assert!(healed.contains(&scope::FILES_UPLOAD.to_string()));
    assert_eq!(
        effective_scopes("guest", &["custom".into()]),
        vec!["custom"]
    );
}

#[test]
fn authorization_allows_admin_roles_and_rejects_unknown_roles_and_routes() {
    for role in ["owner", "admin"] {
        for method in [Method::GET, Method::POST, Method::PATCH, Method::DELETE] {
            assert_eq!(
                authorize(role, &[], &method, "/api/v1/admin/anything"),
                AccessDecision::Allowed
            );
        }
    }
    assert_eq!(
        authorize(
            "guest",
            &[scope::ADMIN_ALL.into()],
            &Method::GET,
            "/api/v1/node/status"
        ),
        AccessDecision::Denied {
            required_scope: scope::ADMIN_ALL
        }
    );
    assert_eq!(
        authorize(
            "member",
            &[scope::ADMIN_ALL.into()],
            &Method::GET,
            "/api/v1/unknown"
        ),
        AccessDecision::Denied {
            required_scope: scope::ADMIN_ALL
        }
    );
    assert!(format!("{:?}", AccessDecision::Allowed).contains("Allowed"));
}

#[test]
fn authorization_maps_session_identity_contact_and_circle_routes() {
    for (method, path, required) in [
        (Method::GET, "/api/v1/auth/session", scope::SETTINGS_OWN),
        (Method::POST, "/api/v1/auth/logout", scope::SETTINGS_OWN),
        (
            Method::DELETE,
            "/api/v1/auth/sessions/revoke-all",
            scope::SETTINGS_OWN,
        ),
        (
            Method::POST,
            "/api/v1/auth/session/refresh",
            scope::SETTINGS_OWN,
        ),
        (Method::PATCH, "/api/v1/auth/profile", scope::SETTINGS_OWN),
        (
            Method::DELETE,
            "/api/v1/pwa/registration",
            scope::SETTINGS_OWN,
        ),
        (
            Method::POST,
            "/api/v1/pwa/circles/join",
            scope::CIRCLES_READ,
        ),
        (Method::GET, "/api/v1/node/status", scope::GUARDIAN_READ),
        (Method::PATCH, "/api/v1/node/status", scope::SETTINGS_OWN),
        (Method::GET, "/api/v1/pwa/identity", scope::GUARDIAN_READ),
        (Method::GET, "/api/v1/pwa/health", scope::GUARDIAN_READ),
        (Method::GET, "/api/v1/pwa/contacts", scope::CONTACTS_READ),
        (Method::GET, "/api/v1/contacts", scope::CONTACTS_READ),
        (Method::POST, "/api/v1/contacts", scope::CONTACTS_MANAGE),
        (
            Method::GET,
            "/api/v1/contacts/did:test",
            scope::CONTACTS_READ,
        ),
        (
            Method::PATCH,
            "/api/v1/contacts/did:test",
            scope::CONTACTS_MANAGE,
        ),
        (
            Method::DELETE,
            "/api/v1/contacts/did:test",
            scope::CONTACTS_MANAGE,
        ),
        (Method::GET, "/api/v1/circles", scope::CIRCLES_READ),
        (Method::GET, "/api/v1/circles/circle-a", scope::CIRCLES_READ),
        (
            Method::GET,
            "/api/v1/circles/circle-a/members",
            scope::CONTACTS_READ,
        ),
        (
            Method::POST,
            "/api/v1/circles/join/preview",
            scope::CIRCLES_READ,
        ),
        (Method::POST, "/api/v1/circles/join", scope::CIRCLES_READ),
    ] {
        decision_with_scope(method, path, required);
    }
}

#[test]
fn authorization_maps_chat_call_vault_transfer_and_notification_routes() {
    for (method, path, required) in [
        (Method::GET, "/api/v1/chat/history", scope::MESSAGES_READ),
        (Method::GET, "/api/v1/chat/ws", scope::MESSAGES_READ),
        (Method::POST, "/api/v1/chat/send", scope::MESSAGES_SEND),
        (Method::POST, "/api/v1/chat/read", scope::MESSAGES_SEND),
        (Method::POST, "/api/v1/chat/upload", scope::FILES_UPLOAD),
        (
            Method::GET,
            "/api/v1/chat/download/file-a",
            scope::FILES_READ,
        ),
        (Method::GET, "/api/v1/calls", scope::CALLS_USE),
        (Method::POST, "/api/v1/calls/initiate", scope::CALLS_USE),
        (
            Method::POST,
            "/api/v1/call/browser-action",
            scope::CALLS_USE,
        ),
        (Method::GET, "/api/v1/group-calls", scope::CALLS_USE),
        (Method::POST, "/api/v1/group-calls/start", scope::CALLS_USE),
        (Method::POST, "/api/v1/group-call/end", scope::CALLS_USE),
        (Method::GET, "/api/v1/vault/files", scope::FILES_READ),
        (Method::POST, "/api/v1/vault/upload", scope::FILES_UPLOAD),
        (
            Method::POST,
            "/api/v1/vault/files/file-a/revoke",
            scope::FILES_UPLOAD,
        ),
        (
            Method::PATCH,
            "/api/v1/vault/files/file-a/expiry",
            scope::FILES_UPLOAD,
        ),
        (Method::GET, "/api/v1/xfer/jobs", scope::FILES_READ),
        (Method::POST, "/api/v1/xfer/send", scope::FILES_UPLOAD),
        (
            Method::POST,
            "/api/v1/xfer/job-a/cancel",
            scope::FILES_UPLOAD,
        ),
        (
            Method::GET,
            "/api/v1/notifications",
            scope::NOTIFICATIONS_READ,
        ),
        (
            Method::GET,
            "/api/v1/notifications/stream",
            scope::NOTIFICATIONS_READ,
        ),
        (
            Method::GET,
            "/api/v1/notifications/unread-count",
            scope::NOTIFICATIONS_READ,
        ),
        (
            Method::GET,
            "/api/v1/notifications/item-a",
            scope::NOTIFICATIONS_READ,
        ),
        (
            Method::POST,
            "/api/v1/notifications/read-all",
            scope::NOTIFICATIONS_MANAGE,
        ),
        (
            Method::POST,
            "/api/v1/notifications/item-a/read",
            scope::NOTIFICATIONS_MANAGE,
        ),
    ] {
        decision_with_scope(method, path, required);
    }
}

#[test]
fn authorization_denies_unsafe_methods_shapes_and_legacy_call_routes() {
    let scopes = default_scopes("member");
    for (method, path) in [
        (Method::PUT, "/api/v1/contacts"),
        (Method::POST, "/api/v1/contacts/did:test"),
        (Method::POST, "/api/v1/circles/circle-a"),
        (Method::GET, "/api/v1/circles/a/members/extra"),
        (Method::DELETE, "/api/v1/circles/a"),
        (Method::DELETE, "/api/v1/chat/history"),
        (Method::POST, "/api/v1/chat/download/file-a"),
        (Method::POST, "/api/v1/call/initiate"),
        (Method::POST, "/api/v1/call/accept"),
        (Method::POST, "/api/v1/call/reject"),
        (Method::POST, "/api/v1/call/end"),
        (Method::POST, "/api/v1/call/policy-check"),
        (Method::DELETE, "/api/v1/vault/files"),
        (Method::POST, "/api/v1/vault/folders"),
        (Method::PATCH, "/api/v1/xfer/jobs"),
        (Method::POST, "/api/v1/notifications"),
        (Method::PUT, "/api/v1/notifications/item/read"),
    ] {
        assert!(matches!(
            authorize("member", &scopes, &method, path),
            AccessDecision::Denied {
                required_scope: scope::ADMIN_ALL
            }
        ));
    }
}

#[tokio::test]
async fn rate_limiter_isolated_devices_expiry_zero_limit_and_default() {
    let limiter = DeviceRateLimiter::new(2, Duration::from_secs(60));
    limiter.check_rate_limit("device-a").await.unwrap();
    limiter.check_rate_limit("device-a").await.unwrap();
    assert!(matches!(
        limiter.check_rate_limit("device-a").await,
        Err(CommandAuthError::RateLimitExceeded(message)) if message.contains("device-a") && message.contains("Max 2")
    ));
    limiter.check_rate_limit("device-b").await.unwrap();

    let zero = DeviceRateLimiter::new(0, Duration::from_secs(60));
    assert!(matches!(
        zero.check_rate_limit("blocked").await,
        Err(CommandAuthError::RateLimitExceeded(_))
    ));
    let expiring = DeviceRateLimiter::new(1, Duration::from_millis(5));
    expiring.check_rate_limit("device").await.unwrap();
    tokio::time::sleep(Duration::from_millis(8)).await;
    expiring.check_rate_limit("device").await.unwrap();
    let default = DeviceRateLimiter::default();
    default.check_rate_limit("device").await.unwrap();
}

#[test]
fn command_auth_errors_format_every_variant() {
    let cases = [
        (
            CommandAuthError::InvalidSchema("bad field".into()),
            "Invalid schema: bad field",
        ),
        (
            CommandAuthError::RateLimitExceeded("slow down".into()),
            "Rate limit exceeded: slow down",
        ),
        (
            CommandAuthError::NoOp("unchanged".into()),
            "No-op command: unchanged",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
        assert!(format!("{error:?}").contains(expected.split(": ").last().unwrap()));
    }
}

#[test]
fn providers_expose_names_enabled_flags_registry_lookup_and_credentials() {
    let _env = ProviderEnv::set(Some("true"));
    let local = LocalAuthProvider;
    assert_eq!(local.name(), LOCAL_PROVIDER_NAME);
    assert!(local.enabled());
    let cylenium = CyleniumProvider::new(false);
    assert_eq!(cylenium.name(), CYLENIUM_PROVIDER_NAME);
    assert!(!cylenium.enabled());
    assert!(CyleniumProvider::new(true).enabled());

    let registry = ProviderRegistry::from_env();
    assert!(registry.local().unwrap().enabled());
    assert!(registry.cylenium().unwrap().enabled());
    assert!(registry.get("unknown").is_none());
    let credentials = Credentials {
        email: "User@Example.com".into(),
        password: "secret".into(),
    };
    assert_eq!(credentials.email, "User@Example.com");
    assert_eq!(credentials.password, "secret");
    assert!(format!("{credentials:?}").contains("User@Example.com"));
}

#[test]
fn provider_registry_environment_flag_accepts_only_one_or_true() {
    for (raw, expected) in [
        (None, false),
        (Some("0"), false),
        (Some("yes"), false),
        (Some("1"), true),
        (Some("TRUE"), true),
    ] {
        let _env = ProviderEnv::set(raw);
        assert_eq!(
            ProviderRegistry::from_env().cylenium().unwrap().enabled(),
            expected
        );
    }
}

#[test]
fn jwt_verify_rejects_missing_extra_malformed_header_algorithm_type_and_signature() {
    for (token, expected) in [
        ("", "missing jwt claims"),
        ("a", "missing jwt claims"),
        ("a.b", "missing jwt signature"),
        ("a.b.c.d", "too many segments"),
        ("!.b.c", "jwt header decode"),
    ] {
        assert!(session::verify(&[], token)
            .unwrap_err()
            .to_string()
            .contains(expected));
    }

    let invalid_json = format!("{}.e30.AA", URL_SAFE_NO_PAD.encode("not-json"));
    assert!(session::verify(&[], &invalid_json)
        .unwrap_err()
        .to_string()
        .contains("jwt header json"));
    let wrong_alg = format!(
        "{}.e30.AA",
        encoded_json(json!({"alg":"HS256","typ":"JWT"}))
    );
    assert!(session::verify(&[], &wrong_alg)
        .unwrap_err()
        .to_string()
        .contains("unsupported jwt alg HS256"));
    let wrong_type = format!(
        "{}.e30.AA",
        encoded_json(json!({"alg":"ES256","typ":"JWS"}))
    );
    assert!(session::verify(&[], &wrong_type)
        .unwrap_err()
        .to_string()
        .contains("unsupported jwt typ JWS"));
    let bad_signature = format!("{}.e30.!", encoded_json(json!({"alg":"ES256"})));
    assert!(session::verify(&[], &bad_signature)
        .unwrap_err()
        .to_string()
        .contains("jwt signature decode"));
    let failed_verify = format!("{}.e30.AA", encoded_json(json!({"alg":"ES256","typ":""})));
    assert!(session::verify(&[], &failed_verify)
        .unwrap_err()
        .to_string()
        .contains("jwt signature verification failed"));
}

#[test]
fn claims_deserialize_defaults_optional_fields_and_round_trip() {
    let value = json!({
        "sub": "user-1",
        "role": "member",
        "iss": "did:guardian:node",
        "iat": 100,
        "exp": 200,
        "jti": "session-1"
    });
    let claims: Claims = serde_json::from_value(value).unwrap();
    assert!(claims.scopes.is_empty());
    assert!(claims.circle_ids.is_empty());
    assert_eq!(claims.browser_registration_id, None);
    assert_eq!(claims.guardian_fingerprint, None);
    let round_trip: Claims =
        serde_json::from_str(&serde_json::to_string(&claims).unwrap()).unwrap();
    assert_eq!(round_trip, claims);
}

#[tokio::test]
async fn embedded_frontend_serves_redirect_api_404_spa_assets_and_cache_headers() {
    let redirect = frontend::captive_portal().await.into_response();
    assert_eq!(redirect.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(redirect.headers()[header::LOCATION], "/join");

    for path in ["/api", "/api/unknown"] {
        assert_eq!(
            frontend::serve(path.parse().unwrap()).await.status(),
            StatusCode::NOT_FOUND
        );
    }
    let root = frontend::serve("/".parse().unwrap()).await;
    assert_eq!(root.status(), StatusCode::OK);
    assert_eq!(
        root.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );
    assert_eq!(root.headers()[header::CACHE_CONTROL], "no-cache");
    let body = to_bytes(root.into_body(), usize::MAX).await.unwrap();
    assert!(body.windows(13).any(|window| window == b"<div id=\"root"));

    let fallback = frontend::serve("/deep/react/route".parse().unwrap()).await;
    assert_eq!(fallback.status(), StatusCode::OK);
    assert_eq!(fallback.headers()[header::CACHE_CONTROL], "no-cache");
    assert_eq!(
        fallback.headers()[header::CONTENT_TYPE],
        "text/html; charset=utf-8"
    );

    let worker = frontend::serve("/sw.js".parse().unwrap()).await;
    assert_eq!(
        worker.headers()[header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
    assert_eq!(worker.headers()[header::CACHE_CONTROL], "no-cache");
    assert_eq!(worker.headers()["service-worker-allowed"], "/");

    let manifest = frontend::serve("/manifest.json".parse().unwrap()).await;
    assert_eq!(
        manifest.headers()[header::CONTENT_TYPE],
        "application/json; charset=utf-8"
    );
    assert_eq!(manifest.headers()[header::CACHE_CONTROL], "no-cache");
    let asset = frontend::serve("/asset-manifest.json".parse().unwrap()).await;
    assert_eq!(
        asset.headers()[header::CACHE_CONTROL],
        "public, max-age=31536000, immutable"
    );
}
