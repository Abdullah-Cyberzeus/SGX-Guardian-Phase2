//! `/api/v1/mesh/*` — the lifecycle API (P1.6).
//!
//! These are the only routes an unenrolled Guardian's frontend can call
//! (`mesh_gate` allow-lists `/api/v1/mesh/*` unconditionally — see
//! `api/mesh_gate.rs`), so this is how the setup UI (P1.7/P1.8) learns what
//! state the Guardian is in and drives it forward.

use crate::api::auth::middleware::AuthenticatedSession;
use crate::api::{error::ApiError, state::AppState};
use crate::mesh::ca::{self, policy::CircleEnrollmentPolicy};
use crate::mesh::lifecycle::{self, LifecycleSnapshot, LifecycleState};
use crate::mesh::profile;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// The circle-membership facts the setup UI shows once they exist. `None`
/// fields (or the whole `profile`) are the normal, expected shape for a
/// Guardian that has not enrolled yet — never an error condition.
#[derive(Debug, Clone, Serialize)]
pub struct LifecycleProfileView {
    pub circle_name: String,
    pub role: String,
    pub ca_fingerprint: String,
    pub overlay_ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LifecycleView {
    pub state: LifecycleState,
    pub since: String,
    pub detail: Option<String>,
    pub profile: Option<LifecycleProfileView>,
}

impl From<LifecycleSnapshot> for LifecycleView {
    fn from(snapshot: LifecycleSnapshot) -> Self {
        let profile = profile::current().map(|p| LifecycleProfileView {
            circle_name: p.circle_name.clone(),
            role: format!("{:?}", p.role),
            ca_fingerprint: p.ca_fingerprint.clone(),
            overlay_ip: p.overlay_ip.clone(),
        });
        Self {
            state: snapshot.state,
            since: snapshot.since,
            detail: snapshot.detail,
            profile,
        }
    }
}

/// GET /api/v1/mesh/lifecycle
pub async fn lifecycle_status(State(_state): State<Arc<AppState>>) -> Json<LifecycleView> {
    Json(lifecycle::current().into())
}

/// GET /api/v1/mesh/lifecycle/ws — pushes a snapshot on every transition.
///
/// Unlike `cert.rs`'s `requests_socket` (which polls YAML files on disk every
/// 2s, since there is nothing to await there), lifecycle transitions already
/// go through a `tokio::sync::watch` channel (`mesh::lifecycle::subscribe`),
/// so this pushes immediately on change rather than polling.
pub async fn lifecycle_socket(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(run_lifecycle_socket)
}

async fn run_lifecycle_socket(socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = lifecycle::subscribe();

    // Send the current state immediately — a client that connects mid-boot
    // should not have to wait for the *next* transition to learn where things
    // stand right now.
    let initial: LifecycleView = rx.borrow().clone().into();
    let Ok(payload) = serde_json::to_string(&serde_json::json!({
        "type": "mesh.lifecycle.snapshot",
        "lifecycle": initial,
    })) else {
        return;
    };
    if sender.send(Message::Text(payload.into())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    // The sender half only drops if the process is shutting
                    // down; nothing more to push.
                    break;
                }
                let view: LifecycleView = rx.borrow().clone().into();
                let Ok(payload) = serde_json::to_string(&serde_json::json!({
                    "type": "mesh.lifecycle.snapshot",
                    "lifecycle": view,
                })) else { continue };
                if sender.send(Message::Text(payload.into())).await.is_err() { break; }
            }
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Ping(bytes))) => {
                    if sender.send(Message::Pong(bytes)).await.is_err() { break; }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                _ => {}
            }
        }
    }
}

/// The Guardian device itself (admin/owner session, or no session when login
/// is disabled) may drive mesh enrollment. A browser member session may not —
/// mirrors `vault.rs`'s `is_admin_caller` precedent exactly.
fn is_admin(session: &Option<Extension<AuthenticatedSession>>) -> bool {
    session
        .as_ref()
        .map(|Extension(session)| session.claims.role != "member")
        .unwrap_or_else(crate::runtime_gates::login_disabled)
}

#[derive(Debug, Deserialize)]
pub struct ResetRequest {
    /// Must equal this Guardian's own id — a lightweight, deliberate
    /// confirmation rather than a bare `POST` with no body, since this
    /// discards enrollment progress. Mirrors the "type the resource name to
    /// confirm" pattern used for other irreversible actions in this product.
    pub confirm_guardian_id: String,
}

/// POST /api/v1/mesh/reset — REJECTED/ERROR/PENDING_APPROVAL → UNENROLLED.
///
/// Admin-only (a browser member session, `role == "member"`, must not be able
/// to discard the device's own enrollment attempt) and requires the caller to
/// echo this Guardian's id back, so a stray or scripted `POST` with no
/// awareness of what it is confirming cannot silently wipe pending progress.
pub async fn reset(
    State(_state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(payload): Json<ResetRequest>,
) -> Result<Json<LifecycleView>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may reset mesh enrollment".into(),
        ));
    }

    let expected_id = crate::mesh::local_guardian_id();
    if payload.confirm_guardian_id.trim() != expected_id {
        return Err(ApiError::BadRequest(format!(
            "confirm_guardian_id must equal '{expected_id}'"
        )));
    }

    let current = lifecycle::current().state;
    if !current.can_transition_to(LifecycleState::Unenrolled) {
        return Err(ApiError::Conflict(format!(
            "cannot reset from lifecycle state {current:?} — only REJECTED, ERROR and \
             PENDING_APPROVAL may be reset"
        )));
    }

    let snapshot = lifecycle::transition_to(LifecycleState::Unenrolled, None)
        .map_err(|e| ApiError::Conflict(e.to_string()))?;
    Ok(Json(snapshot.into()))
}

#[derive(Debug, Deserialize)]
pub struct CreateCircleRequest {
    pub name: String,
    #[serde(default)]
    pub overlay_cidr: Option<String>,
    #[serde(default)]
    pub policy: Option<CircleEnrollmentPolicy>,
}

#[derive(Debug, Serialize)]
pub struct CreateCircleResponse {
    pub circle_id: String,
    pub circle_name: String,
    pub ca_fingerprint: String,
    pub overlay_cidr: String,
    pub overlay_ip: String,
    /// Tells SU02 (P2.5) to show "restarting…" rather than treating this as
    /// done — `nebula` does not actually come up until the restart this
    /// response triggers completes (see the module-level note on why).
    pub restarting: bool,
}

impl From<ca::CreatedCircle> for CreateCircleResponse {
    fn from(created: ca::CreatedCircle) -> Self {
        Self {
            circle_id: created.circle_id,
            circle_name: created.circle_name,
            ca_fingerprint: created.ca_fingerprint,
            overlay_cidr: created.overlay_cidr,
            overlay_ip: created.overlay_ip,
            restarting: true,
        }
    }
}

impl From<&ca::CreateCircleError> for ApiError {
    fn from(error: &ca::CreateCircleError) -> Self {
        use ca::CreateCircleError::*;
        match error {
            AlreadyEnrolled | NebulaMaterialExists => {
                ApiError::Conflict(error.to_string())
            }
            UnsupportedCidr(_) | InvalidName(_) => ApiError::BadRequest(error.to_string()),
            Staging(_) | Nebula(_) | Keygen(_) | MissingFingerprint | Profile(_)
            | Lifecycle(_) | Policy(_) | CircleStore(_) | Vc(_) | Commit(_) => {
                ApiError::Internal(error.to_string())
            }
        }
    }
}

/// The exit code [`schedule_restart_after_response`] uses. Not a standard
/// `sysexits.h` value — just distinctive enough to `grep` for in logs and
/// tell apart from an actual crash. Both `docker-compose.dev.yml`
/// (`restart: unless-stopped`) and the systemd unit (`Restart=on-failure`)
/// already restart on any non-zero exit, so no packaging change was needed
/// to make this work.
const RESTART_FOR_MESH_ACTIVATION_EXIT_CODE: i32 = 90;

/// Ends the process shortly after this call, once the caller has had a
/// chance to send its response — see the `mesh::ca` module doc comment for
/// why a restart, rather than live activation, is how a freshly created
/// circle's Nebula material actually starts running.
fn schedule_restart_after_response() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        println!(
            "🔁 Restarting to activate the mesh circle just created (exit {RESTART_FOR_MESH_ACTIVATION_EXIT_CODE})"
        );
        std::process::exit(RESTART_FOR_MESH_ACTIVATION_EXIT_CODE);
    });
}

/// POST /api/v1/mesh/circles (P2.1/P2.2/P2.4) — make this Guardian the CA of
/// a brand-new circle.
///
/// Admin-only, same reasoning as `reset`. Responds `202` (the circle is
/// created, but is not yet ONLINE — that needs the restart this triggers to
/// complete) rather than `201`, since the created resource is not fully
/// usable at the moment this returns.
pub async fn create_circle(
    State(_state): State<Arc<AppState>>,
    session: Option<Extension<AuthenticatedSession>>,
    Json(payload): Json<CreateCircleRequest>,
) -> Result<(StatusCode, Json<CreateCircleResponse>), ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may create a mesh circle".into(),
        ));
    }

    let paths = crate::startup::GuardianPaths::production();
    let guardian_id = crate::mesh::local_guardian_id();
    let created = ca::create_circle(
        &paths,
        &guardian_id,
        payload.name,
        ca::CreateCircleOptions {
            overlay_cidr: payload.overlay_cidr,
            policy: payload.policy,
        },
    )
    .await
    .map_err(|e| ApiError::from(&e))?;

    schedule_restart_after_response();
    Ok((StatusCode::ACCEPTED, Json(created.into())))
}

/// The circle-membership facts for whichever circle this Guardian belongs
/// to, for both roles — CA and Member read the same `MeshProfile` fields.
#[derive(Debug, Serialize)]
pub struct CircleView {
    pub circle_id: String,
    pub circle_name: String,
    pub role: String,
    pub ca_guardian_id: String,
    pub ca_fingerprint: String,
    pub overlay_cidr: String,
    pub overlay_ip: String,
    pub enrolled_via: String,
    pub enrolled_at: String,
}

/// GET /api/v1/mesh/circle — the current circle, or 404 while unenrolled.
pub async fn get_circle(State(_state): State<Arc<AppState>>) -> Result<Json<CircleView>, ApiError> {
    let profile = profile::current().ok_or_else(|| {
        ApiError::NotFound("this Guardian has not created or joined a circle yet".into())
    })?;
    Ok(Json(CircleView {
        circle_id: profile.circle_id.clone(),
        circle_name: profile.circle_name.clone(),
        role: format!("{:?}", profile.role),
        ca_guardian_id: profile.ca_guardian_id.clone(),
        ca_fingerprint: profile.ca_fingerprint.clone(),
        overlay_cidr: profile.overlay_cidr.clone(),
        overlay_ip: profile.overlay_ip.clone(),
        enrolled_via: format!("{:?}", profile.enrolled_via),
        enrolled_at: profile.enrolled_at.clone(),
    }))
}

// ── P3.4: LAN CA discovery API ──────────────────────────────────────────
//
// A scan is a background job, not a single request/response — P3.3's own
// 5s collection window plus a parallel fetch-and-verify round trip per
// candidate makes it too slow to hold a connection open for. `POST .../lan`
// starts one and returns immediately with an id; `GET .../lan/{scan_id}`
// polls it. In-memory only, deliberately: a scan's results are only ever
// useful to the operator who is mid-setup in that same session, and nothing
// here needs to survive a restart.

use crate::mesh::discovery::{self, DiscoveredCa};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex as StdMutex;

enum LanScanState {
    Running,
    Done(Vec<DiscoveredCa>),
}

static LAN_SCANS: Lazy<StdMutex<HashMap<String, LanScanState>>> =
    Lazy::new(|| StdMutex::new(HashMap::new()));

#[derive(Debug, Serialize)]
pub struct StartScanResponse {
    pub scan_id: String,
}

/// POST /api/v1/mesh/discovery/lan — starts a scan, returns `{scan_id}`.
pub async fn start_lan_discovery(
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<(StatusCode, Json<StartScanResponse>), ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may scan for mesh circles".into(),
        ));
    }
    let scan_id = uuid::Uuid::new_v4().to_string();
    {
        let mut scans = LAN_SCANS.lock().unwrap_or_else(|e| e.into_inner());
        scans.insert(scan_id.clone(), LanScanState::Running);
    }
    let scan_id_for_task = scan_id.clone();
    tokio::spawn(async move {
        let results = discovery::browse::scan().await;
        let mut scans = LAN_SCANS.lock().unwrap_or_else(|e| e.into_inner());
        scans.insert(scan_id_for_task, LanScanState::Done(results));
    });
    Ok((StatusCode::ACCEPTED, Json(StartScanResponse { scan_id })))
}

#[derive(Debug, Serialize)]
pub struct LanScanStatusResponse {
    pub status: &'static str,
    pub results: Vec<DiscoveredCa>,
}

/// GET /api/v1/mesh/discovery/lan/{scan_id} — poll a scan started above.
/// 404 once the id no longer maps to any tracked scan (never started, or —
/// out of scope for now — evicted; nothing prunes `LAN_SCANS` yet, since a
/// setup session realistically starts a handful of scans, not thousands).
pub async fn get_lan_discovery(
    session: Option<Extension<AuthenticatedSession>>,
    axum::extract::Path(scan_id): axum::extract::Path<String>,
) -> Result<Json<LanScanStatusResponse>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may read a mesh circle scan".into(),
        ));
    }
    let scans = LAN_SCANS.lock().unwrap_or_else(|e| e.into_inner());
    match scans.get(&scan_id) {
        None => Err(ApiError::NotFound(format!("no scan {scan_id}"))),
        Some(LanScanState::Running) => Ok(Json(LanScanStatusResponse {
            status: "running",
            results: Vec::new(),
        })),
        Some(LanScanState::Done(results)) => Ok(Json(LanScanStatusResponse {
            status: "done",
            results: results.clone(),
        })),
    }
}

#[derive(Debug, Deserialize)]
pub struct ProbeRequest {
    pub host: String,
    pub port: u16,
}

/// POST /api/v1/mesh/discovery/probe {host, port} — fetch and verify one
/// operator-supplied endpoint directly, bypassing beacon discovery (for a
/// LAN that blocks UDP broadcast/multicast but still routes plain TCP).
pub async fn probe_ca(
    session: Option<Extension<AuthenticatedSession>>,
    Json(payload): Json<ProbeRequest>,
) -> Result<Json<DiscoveredCa>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may probe for a mesh circle".into(),
        ));
    }
    let endpoint = format!("{}:{}", payload.host, payload.port);
    discovery::browse::probe(&endpoint)
        .await
        .map(Json)
        .ok_or_else(|| {
            ApiError::NotFound(format!("no CA descriptor answered at {endpoint}"))
        })
}

// ── P4.9: joiner-triggered enrollment ───────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JoinRequest {
    /// `host:port` of the CA's descriptor/enrollment listener — exactly
    /// `DiscoveredCa.lan_endpoint` (P3.3), so the frontend passes through
    /// whatever the LAN scan already found and the operator selected.
    pub lan_endpoint: String,
    pub circle_id: String,
    #[serde(default)]
    pub join_code: Option<String>,
}

/// POST /api/v1/mesh/join — starts joining a circle discovered on the LAN.
/// Fire-and-forget by design, same shape as `create_circle`: the actual
/// submit/poll/install sequence runs in the background
/// (`mesh::enroll::start_join`) and the frontend watches
/// `GET /api/v1/mesh/lifecycle` for progress, exactly as `SU02CreateCircle`
/// already does through its own restart.
pub async fn join_circle(
    session: Option<Extension<AuthenticatedSession>>,
    Json(payload): Json<JoinRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may join a mesh circle".into(),
        ));
    }
    if profile::current().is_some() {
        return Err(ApiError::Conflict(
            "this Guardian already has a circle profile — reset it before joining another".into(),
        ));
    }
    let guardian_id = crate::mesh::local_guardian_id();
    let paths = crate::startup::GuardianPaths::production();
    tokio::spawn(async move {
        match crate::mesh::enroll::start_join(
            &paths,
            &guardian_id,
            &payload.lan_endpoint,
            &payload.circle_id,
            payload.join_code,
        )
        .await
        {
            Ok(()) => schedule_restart_after_response(),
            Err(e) => {
                eprintln!("❌ Join failed: {e}");
                let _ = lifecycle::transition_to(LifecycleState::Error, Some(e));
            }
        }
    });
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "starting": true }))))
}

// ── P4.7: enrollment approval API (the P4.3 request store's own requests —
// separate from the legacy YAML-backed `/api/v1/cert/requests`, which keeps
// working unchanged for the hardcoded nodeA/B/C cohort) ────────────────

/// GET /api/v1/mesh/enroll-requests — every request this CA has ever seen,
/// newest last, each carrying its own `PolicyReport` for the UI to render
/// per-check ✔/✖ (P4.7).
pub async fn list_enroll_requests(
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<Vec<crate::mesh::ca::requests::EnrollmentRequest>>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may list enrollment requests".into(),
        ));
    }
    let paths = crate::startup::GuardianPaths::production();
    crate::mesh::ca::requests::list(&paths)
        .map(Json)
        .map_err(|e| ApiError::Internal(e.to_string()))
}

#[derive(Debug, Deserialize)]
pub struct RejectRequestPayload {
    #[serde(default)]
    pub reason: Option<String>,
}

/// POST /api/v1/mesh/enroll-requests/{request_id}/approve — approves and
/// immediately issues the bundle (so the joiner's very next poll receives
/// it), matching `mesh::ca::server`'s own auto-approve path.
pub async fn approve_enroll_request(
    session: Option<Extension<AuthenticatedSession>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may approve an enrollment request".into(),
        ));
    }
    let paths = crate::startup::GuardianPaths::production();
    let approved = crate::mesh::ca::requests::approve(&paths, &request_id)
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let profile = profile::current()
        .ok_or_else(|| ApiError::Conflict("this Guardian has no circle profile".into()))?;
    let bundle = crate::mesh::ca::issuer::issue(&paths, &profile, &approved)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    crate::mesh::ca::requests::save_bundle(&paths, &request_id, &bundle)
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(serde_json::json!({ "approved": true })))
}

/// POST /api/v1/mesh/enroll-requests/{request_id}/reject
pub async fn reject_enroll_request(
    session: Option<Extension<AuthenticatedSession>>,
    axum::extract::Path(request_id): axum::extract::Path<String>,
    Json(payload): Json<RejectRequestPayload>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may reject an enrollment request".into(),
        ));
    }
    let paths = crate::startup::GuardianPaths::production();
    crate::mesh::ca::requests::reject(
        &paths,
        &request_id,
        payload.reason.unwrap_or_else(|| "rejected by admin".to_string()),
    )
    .map_err(|e| ApiError::BadRequest(e.to_string()))?;
    Ok(Json(serde_json::json!({ "rejected": true })))
}

// ── P4.8: join codes ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateJoinCodePayload {
    #[serde(default = "default_join_code_ttl_minutes")]
    pub ttl_minutes: i64,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub auto_approve_role: Option<String>,
}

fn default_join_code_ttl_minutes() -> i64 {
    60
}

#[derive(Debug, Serialize)]
pub struct JoinCodeResponse {
    pub id: String,
    pub code: String,
    pub expires_at: String,
}

/// POST /api/v1/mesh/join-codes {ttl_minutes?, note?, auto_approve_role?} —
/// the plaintext code is returned exactly once, here; the stored record
/// never carries it (see `mesh::joincode`'s module doc).
pub async fn create_join_code(
    session: Option<Extension<AuthenticatedSession>>,
    Json(payload): Json<CreateJoinCodePayload>,
) -> Result<(StatusCode, Json<JoinCodeResponse>), ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may invite a Guardian".into(),
        ));
    }
    let profile = profile::current()
        .ok_or_else(|| ApiError::Conflict("this Guardian has no circle profile".into()))?;
    let paths = crate::startup::GuardianPaths::production();
    let (stored, code) = crate::mesh::joincode::create(
        &paths,
        &profile.circle_id,
        payload.ttl_minutes,
        payload.note,
        payload.auto_approve_role,
    )
    .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(JoinCodeResponse {
            id: stored.id,
            code,
            expires_at: stored.expires_at,
        }),
    ))
}

/// GET /api/v1/mesh/join-codes — listing never includes the plaintext code
/// (it was never stored — see `mesh::joincode`).
pub async fn list_join_codes(
    session: Option<Extension<AuthenticatedSession>>,
) -> Result<Json<Vec<crate::mesh::joincode::StoredJoinCode>>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may list join codes".into(),
        ));
    }
    let paths = crate::startup::GuardianPaths::production();
    crate::mesh::joincode::list(&paths)
        .map(Json)
        .map_err(|e| ApiError::Internal(e.to_string()))
}

/// DELETE /api/v1/mesh/join-codes/{id}
pub async fn revoke_join_code(
    session: Option<Extension<AuthenticatedSession>>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !is_admin(&session) {
        return Err(ApiError::Forbidden(
            "only an admin session may revoke a join code".into(),
        ));
    }
    let paths = crate::startup::GuardianPaths::production();
    crate::mesh::joincode::revoke(&paths, &id)
        .map(|()| Json(serde_json::json!({ "revoked": true })))
        .map_err(|_| ApiError::NotFound(format!("no join code {id}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_view_is_only_built_when_a_profile_exists() {
        // Exercises the `LifecycleView::from` conversion directly, without
        // touching the process-wide profile cache (which other tests in this
        // binary also read/write).
        let snapshot = LifecycleSnapshot {
            state: LifecycleState::Unenrolled,
            since: "2026-09-24T00:00:00Z".to_string(),
            detail: None,
        };
        let view: LifecycleView = snapshot.into();
        assert_eq!(view.state, LifecycleState::Unenrolled);
    }
}
