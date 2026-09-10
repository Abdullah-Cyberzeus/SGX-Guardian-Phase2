// Integration tests for the call API handlers (src/api/handlers/call.rs).
// Uses tower::ServiceExt::oneshot against the real router + AppState, no
// mocked HTTP layer. Local (same-node) browser-member calls are used for the
// success paths because they never touch the real Nebula overlay, which is
// unavailable in this sandbox; the legacy `/api/v1/call/*` endpoints are
// exercised for their Nebula-unavailable and not-found/forbidden branches,
// which are deterministic without a real overlay. Every `/api/v1/call*`
// route requires a bearer token (none of them are in the auth middleware's
// public-route allowlist), so every request below carries one.

#[path = "wave_b_support/mod.rs"]
mod support;

use serde_json::json;

#[tokio::test]
async fn legacy_initiate_call_fails_when_nebula_overlay_unavailable() {
    let env = support::Env::new();
    let owner_token = env.owner_token().await;
    // Valid device ids, but there is no real Nebula overlay in this sandbox,
    // so `get_local_nebula_ip` deterministically fails.
    let (status, body) = support::call(
        env.router(),
        "POST",
        "/api/v1/call/initiate",
        Some(&owner_token),
        Some(json!({
            "initiator_device_id": "device-1",
            "initiator_virtual_id": "v1",
            "receiver_device_id": "device-2",
            "receiver_virtual_id": "v2",
            "receiver_nebula_ip": "192.168.100.2",
            "requested_media": ["audio"],
        })),
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "{body}"
    );
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("Nebula overlay unavailable"));
}
