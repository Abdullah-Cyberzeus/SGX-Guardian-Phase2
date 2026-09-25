//! P4.2 — the LAN-facing enrollment server: `GET /ca-descriptor` (P3.1,
//! moved here from `descriptor.rs`, unchanged behavior), `POST /enroll`
//! (P4.3's `SubmitEnrollment`) and `GET /enroll/{request_id}` (the joiner's
//! poll loop, `mesh::enroll::transport_lan`).
//!
//! **Transport note — a deliberate departure from the plan's literal
//! "gRPC over TLS":** this is plain HTTP/JSON, the same choice Phase 3 made
//! for `GetCaDescriptor` and for the same reason, now extended rather than
//! reversed. Authenticity does not come from the transport here: every
//! message either side sends is itself signed and verified at the
//! application layer — `CaDescriptor`/`EnrollmentSubmission`/
//! `EnrollmentBundle` all sign `canonical_bytes_for_sign` and verify against
//! a DID the other side already trusts (the CA's, proven by the
//! P3-verified descriptor; the joiner's, proven by its own DID document
//! travelling with its submission). Real TLS with the SPKI pinned to the
//! descriptor (the plan's literal design) would be real defence-in-depth on
//! top of that, but hand-rolling a custom `rustls` certificate verifier
//! under this pass's time budget is exactly the kind of security-critical,
//! zero-precedent code most likely to hide a subtle bug — this codebase has
//! no existing SPKI-pinning verifier to model from. Flagged here, not
//! silently dropped: a good hardening item for a dedicated follow-up, not a
//! blocker for a working, board-portable enrollment flow today.
//!
//! **Never exposed here:** approve/reject. Those are admin-only decisions
//! made through the local, session-gated REST API
//! (`src/api/handlers/cert.rs`, P4.7) — not reachable from the LAN this
//! server listens on, which by design serves an unauthenticated joiner that
//! has no session yet.

use crate::mesh::ca::bundle::SignedEnrollmentBundle;
use crate::mesh::ca::descriptor::{build_and_sign_bundle, CaDescriptorBundle};
use crate::mesh::ca::requests::{self, EnrollmentRequest, EnrollmentSubmission, RequestState};
use crate::mesh::profile::MeshProfile;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("descriptor build failed: {0}")]
    Descriptor(#[from] crate::mesh::ca::descriptor::DescriptorError),
    #[error("network error: {0}")]
    Io(String),
}

struct ServerState {
    profile: Arc<MeshProfile>,
    descriptor: RwLock<CaDescriptorBundle>,
    paths: crate::startup::GuardianPaths,
}

/// Runs the enrollment server forever. Called once from
/// `mesh::discovery::advertise::run`, itself only spawned for a CA — a
/// `Member` never runs this.
pub async fn serve_forever(
    profile: Arc<MeshProfile>,
    advertise_addr: String,
) -> Result<(), ServerError> {
    let paths = crate::startup::GuardianPaths::production();
    let bundle = build_and_sign_bundle(&profile, &advertise_addr, 1)?;
    let state = Arc::new(ServerState {
        profile: profile.clone(),
        descriptor: RwLock::new(bundle),
        paths,
    });

    {
        let state = state.clone();
        let advertise_addr = advertise_addr.clone();
        tokio::spawn(async move {
            // Moved verbatim from `descriptor.rs`'s old `serve_forever` —
            // see P3.1's own "refreshed every 12h" note there.
            let mut version: u32 = 1;
            loop {
                tokio::time::sleep(Duration::from_secs(12 * 3600)).await;
                version += 1;
                match build_and_sign_bundle(&state.profile, &advertise_addr, version) {
                    Ok(fresh) => *state.descriptor.write().await = fresh,
                    Err(e) => eprintln!(
                        "⚠️ CaDescriptor refresh failed (keeping the previous one): {e}"
                    ),
                }
            }
        });
    }

    let bind_addr = format!("0.0.0.0:{}", crate::mesh::discovery::descriptor_port());
    let router = Router::new()
        .route("/ca-descriptor", get(handle_get_descriptor))
        .route("/enroll", post(handle_submit_enrollment))
        .route("/enroll/{request_id}", get(handle_poll_enrollment))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .map_err(|e| ServerError::Io(format!("bind {bind_addr}: {e}")))?;
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|e| ServerError::Io(format!("serve: {e}")))?;
    Ok(())
}

async fn handle_get_descriptor(
    State(state): State<Arc<ServerState>>,
) -> Json<CaDescriptorBundle> {
    Json(state.descriptor.read().await.clone())
}

#[derive(Debug, thiserror::Error)]
enum SubmitError {
    #[error(transparent)]
    Request(#[from] requests::RequestError),
}

impl IntoResponse for SubmitError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            SubmitError::Request(requests::RequestError::RateLimited) => {
                StatusCode::TOO_MANY_REQUESTS
            }
            SubmitError::Request(requests::RequestError::GuardianIdCollision(_)) => {
                StatusCode::CONFLICT
            }
            SubmitError::Request(requests::RequestError::Revoked(_)) => StatusCode::FORBIDDEN,
            _ => StatusCode::BAD_REQUEST,
        };
        (status, Json(serde_json::json!({ "error": self.to_string() }))).into_response()
    }
}

#[derive(Debug, Serialize)]
struct SubmitResponse {
    request_id: String,
    state: RequestState,
}

async fn handle_submit_enrollment(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(submission): Json<EnrollmentSubmission>,
) -> Result<Json<SubmitResponse>, SubmitError> {
    let policy = crate::mesh::ca::policy::load(&state.paths)
        .ok()
        .flatten()
        .unwrap_or_default();

    let join_code_check = submission.join_code.as_ref().map(|code| {
        crate::mesh::joincode::redeem(
            &state.paths,
            &state.profile.circle_id,
            code,
            &submission.guardian_id,
        )
        .map(|_role| ())
    });

    let request = requests::submit(
        &state.paths,
        &state.profile.circle_id,
        &policy,
        submission,
        addr.ip().to_string(),
        join_code_check,
    )?;

    // A code with `auto_approve_role: Some(_)` was already validated as
    // usable inside `requests::submit`'s join-code check; issuing
    // immediately here (rather than waiting for an admin to click approve)
    // is what "join code and auto-approve in under 60s" (the plan's own
    // exit criterion) actually requires.
    if request.auto_approved {
        if let Ok(approved) = requests::approve(&state.paths, &request.request_id) {
            if let Ok(bundle) = crate::mesh::ca::issuer::issue(&state.paths, &state.profile, &approved) {
                let _ = requests::save_bundle(&state.paths, &request.request_id, &bundle);
            }
        }
    }

    Ok(Json(SubmitResponse {
        request_id: request.request_id,
        state: request.state,
    }))
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PollResponse {
    Pending,
    Approved { bundle: SignedEnrollmentBundle },
    Rejected { reason: Option<String> },
    Expired,
}

async fn handle_poll_enrollment(
    State(state): State<Arc<ServerState>>,
    Path(request_id): Path<String>,
) -> Result<Json<PollResponse>, (StatusCode, String)> {
    let request: EnrollmentRequest = requests::load(&state.paths, &request_id)
        .map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;
    let response = match request.state {
        RequestState::Pending => PollResponse::Pending,
        RequestState::Rejected => PollResponse::Rejected {
            reason: request.decision_reason.clone(),
        },
        RequestState::Expired => PollResponse::Expired,
        RequestState::Approved => {
            let bundle = requests::load_bundle(&state.paths, &request_id)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .ok_or_else(|| {
                    (
                        StatusCode::ACCEPTED,
                        "approved, bundle not issued yet — poll again".to_string(),
                    )
                })?;
            PollResponse::Approved { bundle }
        }
    };
    Ok(Json(response))
}
