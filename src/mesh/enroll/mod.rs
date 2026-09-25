//! Joiner-side enrollment.
//!
//! Phase 0 lands only [`keys`], the local Nebula key generation that stops
//! private keys being minted on — and shipped from — the CA (blocker B1).
//! Phase 4 adds `request`, `transport_lan` and `install`; `transport_wan`
//! stays unbuilt for now — Phase 4 is LAN-only by its own title, and no
//! later phase in the plan names it either, so it is deferred rather than
//! stubbed. See `docs/Guardian_Mesh_Enrollment_Complete_Plan.md` §4.1.

pub mod install;
pub mod keys;
pub mod request;
pub mod transport_lan;

use crate::startup::GuardianPaths;

/// Starts (or resumes) a join end to end: if this Guardian already has a
/// `(lan_endpoint, request_id)` persisted from an earlier call — a prior
/// click that actually succeeded server-side even if the browser never saw
/// the response, a remounted progress screen, anything — resumes polling
/// that *same* request instead of submitting a second one. Submitting
/// unconditionally every call used to mean a harmless double-click or a
/// remounted `SU06` could 409 against its own still-pending first attempt
/// and show a confusing "declined or expired" error for a request that was
/// neither — this is what closes that gap. Only builds and sends a fresh
/// submission when there is genuinely nothing pending yet. The one caller
/// is the `POST /api/v1/mesh/join` handler (P4.9's SU05→SU06 screens drive
/// it by watching `GET /api/v1/mesh/lifecycle`, the same way P2.5's Create
/// Circle screen already watches it through its own restart).
pub async fn start_join(
    paths: &GuardianPaths,
    guardian_id: &str,
    lan_endpoint: &str,
    circle_id: &str,
    join_code: Option<String>,
) -> Result<(), String> {
    if let Some((pending_endpoint, pending_request_id)) = transport_lan::load_pending(paths) {
        return finish_join(paths, guardian_id, &pending_endpoint, &pending_request_id).await;
    }

    let _ = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::Enrolling,
        None,
    );
    let submission = request::build(paths, guardian_id, circle_id, join_code)
        .map_err(|e| e.to_string())?;
    let request_id = transport_lan::submit(lan_endpoint, &submission)
        .await
        .map_err(|e| e.to_string())?;
    let _ = transport_lan::save_pending(paths, lan_endpoint, &request_id);
    finish_join(paths, guardian_id, lan_endpoint, &request_id).await
}

/// Boot-time resume: if this Guardian is still `UNENROLLED` and a pending
/// join is persisted from before the last restart, resumes polling that
/// same request instead of ever re-submitting — the plan's own "B restarts
/// while PENDING and resumes" exit criterion. A no-op (and self-clearing)
/// if this Guardian already has a profile by the time this runs, which can
/// happen if the join actually finished right before a second restart.
pub async fn resume_pending_join_if_any(paths: &GuardianPaths, guardian_id: &str) {
    let Some((lan_endpoint, request_id)) = transport_lan::load_pending(paths) else {
        return;
    };
    if crate::mesh::profile::current().is_some() {
        transport_lan::clear_pending(paths);
        return;
    }
    let paths = paths.clone();
    let guardian_id = guardian_id.to_string();
    tokio::spawn(async move {
        println!("🔁 Resuming a pending mesh join from before the last restart…");
        if let Err(e) = finish_join(&paths, &guardian_id, &lan_endpoint, &request_id).await {
            eprintln!("❌ Resumed join failed: {e}");
            let _ = crate::mesh::lifecycle::transition_to(
                crate::mesh::lifecycle::LifecycleState::Error,
                Some(e),
            );
        }
    });
}

/// The shared poll → verify → install tail for both a fresh join
/// ([`start_join`]) and a resumed one ([`resume_pending_join_if_any`]).
/// Polls for up to the request store's own TTL (P4.3's 7-day default) —
/// long enough for a human to get around to manual approval, short enough
/// that an abandoned request eventually stops being retried forever.
async fn finish_join(
    paths: &GuardianPaths,
    guardian_id: &str,
    lan_endpoint: &str,
    request_id: &str,
) -> Result<(), String> {
    let _ = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::PendingApproval,
        None,
    );
    let bundle = transport_lan::poll_until_decided(
        lan_endpoint,
        request_id,
        std::time::Duration::from_secs(
            crate::mesh::ca::requests::DEFAULT_TTL_DAYS as u64 * 24 * 3600,
        ),
    )
    .await
    .map_err(|e| e.to_string())?;
    let _ = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::CertificateReceived,
        None,
    );
    bundle.verify().map_err(|e| e.to_string())?;
    let _ = crate::mesh::lifecycle::transition_to(
        crate::mesh::lifecycle::LifecycleState::CertificateValidated,
        None,
    );
    install::install(paths, guardian_id, &bundle).map_err(|e| e.to_string())?;
    transport_lan::clear_pending(paths);
    Ok(())
}
