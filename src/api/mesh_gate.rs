//! API gating middleware (P1.5) — blocks `MeshRequired` routes until the
//! Guardian's lifecycle reaches `ONLINE`.
//!
//! Before Phase 1 this question did not exist: the REST API did not bind
//! until enrollment had already finished (or the process had `exit(1)`'d), so
//! every route was implicitly mesh-required. Once `boot_local()` binds the API
//! immediately (P1.2), some routes must keep working for an unenrolled
//! Guardian — the setup UI has to be able to check status, read logs, and
//! drive the Create/Join flow — while everything that assumes a circle
//! (peers, chat, calls, CRL, transport…) must not be reachable until the mesh
//! subsystem is actually up.
//!
//! ## Allow-list, not a per-route tag
//!
//! The plan's own framing is "tag every route Provisioning or MeshRequired."
//! With 321 `.route()` calls across `api/mod.rs` and `api/routes.rs`, tagging
//! each one individually is both a large amount of busywork and an easy place
//! to introduce a silent mistake (a route nobody tagged defaults to whichever
//! behaviour the mistake produces). Inverting it — a short, explicit allow-list
//! of what stays reachable pre-enrollment, with everything else defaulting to
//! `MeshRequired` — means a newly added route is gated by default, and staying
//! reachable pre-enrollment is an opt-in a reviewer can see in one place.
//!
//! This mirrors `auth::middleware::is_public_route`'s existing shape
//! (`api/auth/middleware.rs:242`) deliberately, so both gates read the same
//! way and stay easy to audit side by side.

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

use crate::api::state::AppState;
use crate::mesh::lifecycle::{current, LifecycleState};

/// Routes that must keep working for a Guardian that is not yet `ONLINE`.
///
/// Kept intentionally small and named for what each group is, matching the
/// plan's own list: auth, this node's own status/boot-status/restart, the
/// mesh lifecycle API itself, logs, PCR, and *this Guardian's own* DID
/// (not peer resolution, which inherently needs a circle to have peers in).
fn is_provisioning_route(method: &Method, path: &str) -> bool {
    if path.starts_with("/api/v1/mesh/") {
        return true;
    }
    if path.starts_with("/api/v1/auth/") {
        return true;
    }
    if path.starts_with("/api/v1/pcr/") {
        return true;
    }
    if path == "/api/v1/logs" {
        return true;
    }
    if path == "/api/v1/health" {
        return true;
    }
    if matches!(
        path,
        "/api/v1/node/status" | "/api/v1/node/boot-status" | "/api/v1/node/restart"
    ) {
        return true;
    }
    // "DID self" — this Guardian's own document, not peer resolution
    // (`/did/resolve`, `/did/document/peers`, `/did/document/peer`), which
    // has nothing to resolve before this Guardian has any peers.
    if matches!(
        path,
        "/api/v1/did/status"
            | "/api/v1/did/document"
            | "/api/v1/did/document/raw"
            | "/api/v1/did/document/verify"
            | "/api/v1/did/document/publish"
            | "/api/v1/did/deactivate"
            | "/api/v1/did/reactivate"
    ) {
        return true;
    }
    let _ = method; // reserved: no current Provisioning route needs a method check
    false
}

/// `axum::middleware::from_fn_with_state` handler. Layered inside `require_auth`
/// (auth still runs first — an unenrolled Guardian's API is not an
/// unauthenticated one) and only over the routes defined in `build_router`,
/// never over `/api/v1/wifi/*` (a separately nested sub-router) or the
/// embedded frontend fallback, both of which must always be reachable.
pub async fn gate(
    State(_state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if is_provisioning_route(req.method(), req.uri().path()) {
        return next.run(req).await;
    }

    let snapshot = current();
    if snapshot.state.is_online() {
        return next.run(req).await;
    }

    not_enrolled_response(snapshot.state)
}

fn not_enrolled_response(state: LifecycleState) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "code": "GUARDIAN_NOT_ENROLLED",
            "lifecycle": state,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_and_provisioning_routes_stay_open() {
        for (method, path) in [
            (Method::GET, "/api/v1/mesh/lifecycle"),
            (Method::GET, "/api/v1/mesh/lifecycle/ws"),
            (Method::POST, "/api/v1/mesh/reset"),
            (Method::POST, "/api/v1/auth/login"),
            (Method::GET, "/api/v1/node/status"),
            (Method::GET, "/api/v1/node/boot-status"),
            (Method::GET, "/api/v1/logs"),
            (Method::GET, "/api/v1/pcr/status"),
            (Method::GET, "/api/v1/did/status"),
            (Method::GET, "/api/v1/health"),
        ] {
            assert!(
                is_provisioning_route(&method, path),
                "{path} must stay reachable before enrollment"
            );
        }
    }

    #[test]
    fn peer_dependent_did_routes_are_not_provisioning() {
        // An unenrolled Guardian has no peers to resolve — these must gate.
        for path in [
            "/api/v1/did/resolve",
            "/api/v1/did/document/peers",
            "/api/v1/did/document/peer",
        ] {
            assert!(
                !is_provisioning_route(&Method::GET, path),
                "{path} depends on circle peers and must not be Provisioning"
            );
        }
    }

    #[test]
    fn mesh_dependent_routes_default_to_gated() {
        for (method, path) in [
            (Method::GET, "/api/v1/peers"),
            (Method::POST, "/api/v1/chat/send"),
            (Method::POST, "/api/v1/call/start"),
            (Method::GET, "/api/v1/crl/list"),
            (Method::GET, "/api/v1/vc/list"),
            (Method::POST, "/api/v1/xfer/send"),
        ] {
            assert!(
                !is_provisioning_route(&method, path),
                "{path} must default to MeshRequired, not be silently allow-listed"
            );
        }
    }

    #[test]
    fn a_route_this_gate_has_never_seen_defaults_to_gated() {
        // The whole point of the allow-list design: an unrecognised route is
        // gated by default, not open by default.
        assert!(!is_provisioning_route(
            &Method::GET,
            "/api/v1/some/brand/new/endpoint"
        ));
    }

    #[test]
    fn the_rejection_body_matches_the_documented_contract() {
        let response = not_enrolled_response(LifecycleState::Unenrolled);
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }
}
