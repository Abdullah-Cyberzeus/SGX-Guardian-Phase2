//! `GuardianLifecycle` — the boot → enrollment → online state machine (§4.3).
//!
//! Before Phase 1, "am I ready to serve the API" and "am I enrolled" were the
//! same question, answered inline in `main()`: enrollment ran to completion (or
//! `exit(1)`) before the REST API ever bound. This module gives that question
//! its own persisted, observable state, so `startup::local::boot_local()` can
//! bind the API immediately and `mesh::activation` can drive enrollment in the
//! background while the UI watches transitions over `/api/v1/mesh/lifecycle/ws`.
//!
//! ```text
//! BOOT → INITIALIZING → UNENROLLED ─┬─ CREATING_CIRCLE ───────────────────────────┐
//!                                   └─ DISCOVERING_CA (LAN)                        │
//!                                         ├─ WAITING_FOR_CA_SELECTION              │
//!                                         └─ CONNECTING_TO_REMOTE_CA (WAN)         │
//!                                                ↓                                 │
//!                                         ENROLLING → PENDING_APPROVAL             │
//!                                                ↓           ↓ (reject)            │
//!                                    CERTIFICATE_RECEIVED   REJECTED → UNENROLLED  │
//!                                                ↓                                 │
//!                                    CERTIFICATE_VALIDATED                         │
//!                                                ↓                                 ↓
//!                                         CIRCLE_MEMBER  ←─────────────────────────┘
//!                                                ↓ activate_mesh()
//!                                             ONLINE   (ERROR reachable from any state)
//! ```
//!
//! Phase 1 only drives the boot-time transitions (`resolve_boot_state`) and
//! `CIRCLE_MEMBER → ONLINE` (from `mesh::activation`); the Create/Join/LAN/WAN
//! states in the middle are wired up by Phases 2–7. The full state set and
//! transition table are defined now so later phases only ever call
//! [`transition_to`], never invent a new ad hoc status field.

use chrono::Utc;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::RwLock;
use tokio::sync::watch;

use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::startup::GuardianPaths;

use super::profile::MeshProfile;

/// Every state a Guardian's enrollment can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Boot,
    Initializing,
    Unenrolled,
    CreatingCircle,
    DiscoveringCa,
    WaitingForCaSelection,
    ConnectingToRemoteCa,
    Enrolling,
    PendingApproval,
    CertificateReceived,
    CertificateValidated,
    CircleMember,
    Online,
    Rejected,
    Error,
}

impl LifecycleState {
    /// Whether `self → to` is a legal transition.
    ///
    /// `Error` is reachable from every state (the diagram's explicit rule —
    /// any failure anywhere must be representable without inventing a new
    /// terminal state), and a state transitioning to itself is always legal
    /// (idempotent re-announcement, e.g. two callers both detecting `Online`).
    pub fn can_transition_to(self, to: LifecycleState) -> bool {
        use LifecycleState::*;
        if to == Error || to == self {
            return true;
        }
        matches!(
            (self, to),
            (Boot, Initializing)
                | (Initializing, Unenrolled)
                | (Initializing, CircleMember)
                | (Unenrolled, CreatingCircle)
                | (Unenrolled, DiscoveringCa)
                | (Unenrolled, ConnectingToRemoteCa)
                | (CreatingCircle, CircleMember)
                | (DiscoveringCa, WaitingForCaSelection)
                | (WaitingForCaSelection, Enrolling)
                | (ConnectingToRemoteCa, Enrolling)
                | (Enrolling, PendingApproval)
                | (Enrolling, CertificateReceived)
                | (PendingApproval, CertificateReceived)
                | (PendingApproval, Rejected)
                | (Rejected, Unenrolled)
                | (CertificateReceived, CertificateValidated)
                | (CertificateValidated, CircleMember)
                | (CircleMember, Online)
                // The reset action (P1.6): only from the three states the plan
                // names. `Online` and `CircleMember` are deliberately excluded —
                // resetting an active circle membership is a distinct, more
                // consequential operation than clearing a failed attempt, and
                // isn't part of this endpoint's contract.
                | (PendingApproval, Unenrolled)
                | (Error, Unenrolled)
                // P1.2 step 6: Phases 2-7 (the Create/Join UI, the states in
                // the middle of the diagram) are not built yet, so
                // `mesh::activation::activate_mesh` still self-bootstraps a
                // fresh Guardian the way it always has — LAN/WAN discovery and
                // enrollment run inline, unconditionally, exactly as before
                // Phase 1. Its own successful completion is the only proof of
                // membership that exists until those phases wire up the
                // intermediate states, so it is allowed to close the gap
                // directly from `Unenrolled` (first attempt) or `Error` (a
                // retry that this time succeeded) — never from a state that
                // implies a human or a timer is mid-decision
                // (`PendingApproval`, `Rejected`, the LAN/WAN discovery
                // states), which activate_mesh reaching `CircleMember` would
                // silently steamroll.
                | (Unenrolled, CircleMember)
                | (Error, CircleMember)
        )
    }

    /// Whether this state means "stop retrying automatically" — the UI should
    /// offer Retry/Reset rather than a spinner.
    pub fn is_terminal_failure(self) -> bool {
        matches!(self, LifecycleState::Error | LifecycleState::Rejected)
    }

    /// Whether this state means the Guardian is fully up: mesh active, API
    /// unrestricted. This is what [`crate::api::mesh_gate`] gates on.
    pub fn is_online(self) -> bool {
        self == LifecycleState::Online
    }
}

/// The persisted + broadcast record: state plus context for the UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LifecycleSnapshot {
    pub state: LifecycleState,
    /// RFC3339 timestamp of the last transition.
    pub since: String,
    /// Human-readable context: an error reason, a pending request id, etc.
    /// Cleared on every transition unless the transition explicitly sets one.
    #[serde(default)]
    pub detail: Option<String>,
}

impl LifecycleSnapshot {
    fn new(state: LifecycleState, detail: Option<String>) -> Self {
        Self {
            state,
            since: Utc::now().to_rfc3339(),
            detail,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    #[error("illegal lifecycle transition {from:?} → {to:?}")]
    IllegalTransition {
        from: LifecycleState,
        to: LifecycleState,
    },
    #[error("lifecycle state at {path} is unreadable: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("lifecycle state at {path} is not valid JSON: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

fn path_for(paths: &GuardianPaths) -> PathBuf {
    paths.var_root.join("mesh").join("lifecycle.json")
}

fn load(paths: &GuardianPaths) -> Result<Option<LifecycleSnapshot>, LifecycleError> {
    let path = path_for(paths);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .map(Some)
            .map_err(|source| LifecycleError::Parse {
                path: path.display().to_string(),
                source,
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(LifecycleError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Atomic write, mirroring [`MeshProfile::save`]'s temp-file-then-rename.
fn save(paths: &GuardianPaths, snapshot: &LifecycleSnapshot) -> Result<(), LifecycleError> {
    let path = path_for(paths);
    let dir = path.parent().expect("lifecycle path always has a parent");
    let io_err = |source: std::io::Error| LifecycleError::Io {
        path: path.display().to_string(),
        source,
    };
    std::fs::create_dir_all(dir).map_err(io_err)?;

    let body = serde_json::to_vec_pretty(snapshot).map_err(|source| LifecycleError::Parse {
        path: path.display().to_string(),
        source,
    })?;
    let tmp = dir.join(format!(".lifecycle.json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, &body).map_err(io_err)?;
    std::fs::rename(&tmp, &path).map_err(io_err)?;
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// Process-wide state
// ────────────────────────────────────────────────────────────────────
//
// A `watch` channel rather than a plain lock: the API's WebSocket handler and
// `mesh::activation`'s background tasks both need to *await* the next
// transition, not just read the current one. `RwLock` guards the paths used
// for persistence, mirroring `mesh::profile`'s `install_paths` pattern so
// tests can sandbox both modules the same way.

static PATHS: Lazy<RwLock<GuardianPaths>> = Lazy::new(|| RwLock::new(GuardianPaths::production()));

static CHANNEL: Lazy<(watch::Sender<LifecycleSnapshot>, watch::Receiver<LifecycleSnapshot>)> =
    Lazy::new(|| watch::channel(LifecycleSnapshot::new(LifecycleState::Boot, None)));

fn active_paths() -> GuardianPaths {
    PATHS.read().expect("lifecycle paths poisoned").clone()
}

/// Redirects the module at a sandbox root. Tests only.
pub fn install_paths(paths: GuardianPaths) {
    *PATHS.write().expect("lifecycle paths poisoned") = paths;
}

/// The current snapshot. Cheap: reading a `watch` channel never blocks.
pub fn current() -> LifecycleSnapshot {
    CHANNEL.1.clone().borrow_and_update().clone()
}

/// A receiver for transitions from `current()` onward. Used by the lifecycle
/// WebSocket handler (P1.6) and by anything in `mesh::activation` that waits
/// on a state it did not itself just set.
pub fn subscribe() -> watch::Receiver<LifecycleSnapshot> {
    CHANNEL.1.clone()
}

/// Moves to `to`, validating the transition, persisting it, broadcasting it,
/// and writing an audit entry. This is the **only** way lifecycle state
/// should change — no call site should write `mesh/lifecycle.json` directly.
pub fn transition_to(
    to: LifecycleState,
    detail: Option<String>,
) -> Result<LifecycleSnapshot, LifecycleError> {
    let from = current().state;
    if !from.can_transition_to(to) {
        log_audit(
            &super::local_guardian_id(),
            AuditCategory::Node,
            AuditSeverity::Warning,
            AuditAction::Failed,
            &format!("Rejected illegal lifecycle transition {from:?} → {to:?}"),
        );
        return Err(LifecycleError::IllegalTransition { from, to });
    }

    let snapshot = LifecycleSnapshot::new(to, detail);
    save(&active_paths(), &snapshot)?;
    // `send` only errors when every receiver has been dropped, which cannot
    // happen here — this module holds one itself in `CHANNEL`.
    let _ = CHANNEL.0.send(snapshot.clone());

    log_audit(
        &super::local_guardian_id(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!("Lifecycle transition {from:?} → {to:?}"),
    );
    Ok(snapshot)
}

/// Convenience for the common failure path: any state → [`LifecycleState::Error`]
/// with a human-readable reason. Never panics, never exits — this is the
/// direct replacement for the `std::process::exit(1)` calls P1.3 removes.
pub fn fail(reason: impl Into<String>) -> LifecycleSnapshot {
    let reason = reason.into();
    eprintln!("❌ Guardian lifecycle error: {reason}");
    // `can_transition_to` always permits `Error`, so this cannot fail; a
    // persistence error here would itself be unrecoverable, and the process
    // is already reporting a failure, so it is logged rather than escalated.
    transition_to(LifecycleState::Error, Some(reason.clone())).unwrap_or_else(|e| {
        eprintln!("⚠️ Failed to persist lifecycle error state: {e}");
        LifecycleSnapshot::new(LifecycleState::Error, Some(reason))
    })
}

/// Whether a valid, usable certificate is already on disk for `profile`.
///
/// Mirrors the ad hoc checks `main.rs` scattered before Phase 1 — a CA needs
/// its own CA cert, a member needs its own cert plus the CA cert it trusts.
fn has_valid_circle_credentials(paths: &GuardianPaths, profile: &MeshProfile) -> bool {
    let nebula_base = paths.var_root.join("nebula").display().to_string();
    if !crate::nebula::ca::NebulaCA::ca_cert_exists(&nebula_base) {
        return false;
    }
    if profile.is_ca() {
        return true;
    }
    std::path::Path::new(&nebula_base)
        .join("nodes")
        .join(format!("{}.crt", profile.guardian_id))
        .exists()
}

/// Boot entry point (§4.3's rules): resolve where the state machine should
/// start, from the mesh profile (already loaded by `mesh::legacy::migrate_and_initialize`)
/// and whatever was persisted from the previous run.
///
/// - A valid profile with a usable certificate goes straight to `CIRCLE_MEMBER`
///   (`mesh::activation` takes it to `ONLINE`).
/// - A persisted in-progress or failed enrollment state (`PENDING_APPROVAL`,
///   `REJECTED`, `ERROR`, or any of the LAN/WAN discovery states) resumes
///   exactly where it left off — restarting mid-enrollment must not discard
///   progress a human or a timer is waiting on.
/// - Anything else — including a first boot with no persisted state at all —
///   becomes `UNENROLLED`.
pub fn resolve_boot_state(
    paths: &GuardianPaths,
    profile: Option<&MeshProfile>,
) -> Result<LifecycleSnapshot, LifecycleError> {
    let _ = transition_to(LifecycleState::Initializing, None);

    if let Some(profile) = profile {
        if has_valid_circle_credentials(paths, profile) {
            return transition_to(LifecycleState::CircleMember, None);
        }
    }

    let persisted = load(paths)?;
    let resume_state = persisted.as_ref().map(|s| s.state).filter(|s| {
        matches!(
            s,
            LifecycleState::CreatingCircle
                | LifecycleState::DiscoveringCa
                | LifecycleState::WaitingForCaSelection
                | LifecycleState::ConnectingToRemoteCa
                | LifecycleState::Enrolling
                | LifecycleState::PendingApproval
                | LifecycleState::CertificateReceived
                | LifecycleState::CertificateValidated
                | LifecycleState::Rejected
                | LifecycleState::Error
        )
    });

    match resume_state {
        // Resuming into anything other than Unenrolled from Initializing must
        // go through Unenrolled first: most of these states are only reachable
        // from Unenrolled or from each other, never directly from Initializing.
        // The transition graph is deliberately strict about this, so the resume
        // path walks it exactly like a fresh enrollment would, then immediately
        // continues to the persisted state.
        Some(state) if state != LifecycleState::Unenrolled => {
            transition_to(LifecycleState::Unenrolled, None)?;
            let detail = persisted.and_then(|s| s.detail);
            transition_to_resuming(state, detail)
        }
        _ => transition_to(LifecycleState::Unenrolled, None),
    }
}

/// Walks from `UNENROLLED` to `target` along the one legal path the resume
/// states allow, so a persisted `PENDING_APPROVAL` (for example) is restored
/// without replaying a transition that never actually happened (no LAN
/// discovery UI event occurred this boot — the daemon is simply resuming).
///
/// This is intentionally permissive relative to [`LifecycleState::can_transition_to`]:
/// resume is reconstructing history, not making a fresh decision, so it walks
/// directly to `target` for states that ordinarily require an intermediate hop,
/// logging the resume rather than the (synthetic) intermediate steps.
fn transition_to_resuming(
    target: LifecycleState,
    detail: Option<String>,
) -> Result<LifecycleSnapshot, LifecycleError> {
    let snapshot = LifecycleSnapshot::new(target, detail);
    save(&active_paths(), &snapshot)?;
    let _ = CHANNEL.0.send(snapshot.clone());
    log_audit(
        &super::local_guardian_id(),
        AuditCategory::Node,
        AuditSeverity::Info,
        AuditAction::Succeeded,
        &format!("Resumed lifecycle state {target:?} after restart"),
    );
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::profile::{EnrollChannel, MeshRole, PROFILE_SCHEMA_VERSION};
    use std::sync::Mutex as StdMutex;

    /// `CHANNEL`/`PATHS` are process-wide, so tests that touch lifecycle state
    /// must not run concurrently with each other in this binary.
    static TEST_LOCK: Lazy<StdMutex<()>> = Lazy::new(|| StdMutex::new(()));

    fn reset(paths: &GuardianPaths) {
        install_paths(paths.clone());
        let _ = CHANNEL
            .0
            .send(LifecycleSnapshot::new(LifecycleState::Boot, None));
    }

    fn member_profile(guardian_id: &str) -> MeshProfile {
        MeshProfile {
            schema_version: PROFILE_SCHEMA_VERSION,
            guardian_id: guardian_id.to_string(),
            role: MeshRole::Member,
            circle_id: "circle-7f3c1a".to_string(),
            circle_name: "SGX-Alpha".to_string(),
            ca_guardian_id: "us-hq-01".to_string(),
            ca_fingerprint: "sha256:abc".to_string(),
            ca_owner_did: "did:guardian:xyz".to_string(),
            overlay_cidr: "192.168.100.0/24".to_string(),
            overlay_ip: "192.168.100.5/24".to_string(),
            lighthouses: vec![],
            rendezvous_url: None,
            enrolled_via: EnrollChannel::Lan,
            enrolled_at: "2026-09-24T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn boot_can_only_go_to_initializing() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert!(LifecycleState::Boot.can_transition_to(LifecycleState::Initializing));
        assert!(!LifecycleState::Boot.can_transition_to(LifecycleState::Online));
    }

    #[test]
    fn error_is_reachable_from_every_state() {
        let _guard = TEST_LOCK.lock().unwrap();
        for state in [
            LifecycleState::Boot,
            LifecycleState::Initializing,
            LifecycleState::Unenrolled,
            LifecycleState::CreatingCircle,
            LifecycleState::DiscoveringCa,
            LifecycleState::WaitingForCaSelection,
            LifecycleState::ConnectingToRemoteCa,
            LifecycleState::Enrolling,
            LifecycleState::PendingApproval,
            LifecycleState::CertificateReceived,
            LifecycleState::CertificateValidated,
            LifecycleState::CircleMember,
            LifecycleState::Online,
            LifecycleState::Rejected,
            LifecycleState::Error,
        ] {
            assert!(
                state.can_transition_to(LifecycleState::Error),
                "{state:?} → Error must always be legal"
            );
        }
    }

    #[test]
    fn online_cannot_be_reached_directly_from_unenrolled() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Guards the whole point of the state machine: nothing may skip
        // enrollment and land on Online.
        assert!(!LifecycleState::Unenrolled.can_transition_to(LifecycleState::Online));
    }

    #[test]
    fn reset_is_only_legal_from_the_three_named_states() {
        let _guard = TEST_LOCK.lock().unwrap();
        assert!(LifecycleState::PendingApproval.can_transition_to(LifecycleState::Unenrolled));
        assert!(LifecycleState::Rejected.can_transition_to(LifecycleState::Unenrolled));
        assert!(LifecycleState::Error.can_transition_to(LifecycleState::Unenrolled));
        // Online and CircleMember are deliberately excluded — resetting an
        // active membership is not this endpoint's job.
        assert!(!LifecycleState::Online.can_transition_to(LifecycleState::Unenrolled));
        assert!(!LifecycleState::CircleMember.can_transition_to(LifecycleState::Unenrolled));
    }

    #[test]
    fn activate_mesh_may_close_the_gap_to_circle_member_from_unenrolled_or_error() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Phases 2-7's intermediate states are not wired up yet, so
        // mesh::activation::activate_mesh's own successful completion is
        // still what proves membership for a fresh (or previously failed)
        // Guardian — see the transition table's comment on these two arms.
        assert!(LifecycleState::Unenrolled.can_transition_to(LifecycleState::CircleMember));
        assert!(LifecycleState::Error.can_transition_to(LifecycleState::CircleMember));
    }

    #[test]
    fn activate_mesh_may_not_steamroll_a_state_a_human_or_timer_is_mid_decision_on() {
        let _guard = TEST_LOCK.lock().unwrap();
        // These states mean an operator is waiting on an approval, a timer is
        // mid-discovery, or a request was explicitly rejected — a background
        // task reaching CIRCLE_MEMBER must not silently skip past any of them.
        // (CreatingCircle and CertificateValidated are deliberately not in
        // this list — reaching CircleMember from either is already the
        // diagram's own legitimate Phase 2/4 endpoint, not something to guard
        // against.)
        for state in [
            LifecycleState::PendingApproval,
            LifecycleState::Rejected,
            LifecycleState::DiscoveringCa,
            LifecycleState::WaitingForCaSelection,
            LifecycleState::ConnectingToRemoteCa,
            LifecycleState::Enrolling,
            LifecycleState::CertificateReceived,
        ] {
            assert!(
                !state.can_transition_to(LifecycleState::CircleMember),
                "{state:?} → CircleMember must not be a direct jump"
            );
        }
    }

    #[test]
    fn an_illegal_transition_is_rejected_and_leaves_state_unchanged() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        reset(&GuardianPaths::rooted_at(dir.path()));
        transition_to(LifecycleState::Initializing, None).unwrap();
        transition_to(LifecycleState::Unenrolled, None).unwrap();

        let err = transition_to(LifecycleState::Online, None).unwrap_err();
        assert!(matches!(err, LifecycleError::IllegalTransition { .. }));
        assert_eq!(current().state, LifecycleState::Unenrolled);
    }

    #[test]
    fn fail_always_succeeds_and_carries_the_reason() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        reset(&GuardianPaths::rooted_at(dir.path()));
        transition_to(LifecycleState::Initializing, None).unwrap();
        transition_to(LifecycleState::CreatingCircle, None).unwrap_or_else(|_| {
            transition_to(LifecycleState::Unenrolled, None).unwrap();
            transition_to(LifecycleState::CreatingCircle, None).unwrap()
        });

        let snapshot = fail("nebula-cert binary missing");
        assert_eq!(snapshot.state, LifecycleState::Error);
        assert_eq!(snapshot.detail.as_deref(), Some("nebula-cert binary missing"));
        assert_eq!(current().state, LifecycleState::Error);
    }

    #[test]
    fn a_transition_is_persisted_and_survives_a_reload() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        reset(&paths);
        transition_to(LifecycleState::Initializing, None).unwrap();
        transition_to(LifecycleState::Unenrolled, None).unwrap();

        let loaded = load(&paths).unwrap().expect("a snapshot must be on disk");
        assert_eq!(loaded.state, LifecycleState::Unenrolled);
    }

    #[test]
    fn an_enrolled_guardian_with_a_valid_cert_boots_straight_to_circle_member() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        reset(&paths);

        let profile = member_profile("edge-7");
        let nebula = paths.var_root.join("nebula");
        std::fs::create_dir_all(nebula.join("ca")).unwrap();
        std::fs::create_dir_all(nebula.join("nodes")).unwrap();
        std::fs::write(nebula.join("ca/ca.crt"), "CA CERT").unwrap();
        std::fs::write(nebula.join("nodes/edge-7.crt"), "MEMBER CERT").unwrap();

        let snapshot = resolve_boot_state(&paths, Some(&profile)).unwrap();
        assert_eq!(snapshot.state, LifecycleState::CircleMember);
    }

    #[test]
    fn an_unenrolled_guardian_with_no_profile_boots_to_unenrolled() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        reset(&paths);

        let snapshot = resolve_boot_state(&paths, None).unwrap();
        assert_eq!(snapshot.state, LifecycleState::Unenrolled);
    }

    #[test]
    fn a_profile_without_a_matching_certificate_on_disk_does_not_boot_to_circle_member() {
        // Guards against a copied/corrupted profile.json claiming membership
        // the certificate material does not back up.
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        reset(&paths);

        let profile = member_profile("edge-7");
        let snapshot = resolve_boot_state(&paths, Some(&profile)).unwrap();
        assert_ne!(snapshot.state, LifecycleState::CircleMember);
    }

    #[test]
    fn a_pending_approval_persisted_from_a_previous_run_resumes_rather_than_resetting() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        reset(&paths);

        // Simulate a previous run that got as far as PendingApproval before the
        // process restarted.
        save(
            &paths,
            &LifecycleSnapshot::new(
                LifecycleState::PendingApproval,
                Some("request-id-abc123".to_string()),
            ),
        )
        .unwrap();

        let snapshot = resolve_boot_state(&paths, None).unwrap();
        assert_eq!(snapshot.state, LifecycleState::PendingApproval);
        assert_eq!(snapshot.detail.as_deref(), Some("request-id-abc123"));
    }

    #[test]
    fn a_persisted_error_resumes_as_error_not_unenrolled() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = GuardianPaths::rooted_at(dir.path());
        reset(&paths);
        save(
            &paths,
            &LifecycleSnapshot::new(LifecycleState::Error, Some("boom".to_string())),
        )
        .unwrap();

        let snapshot = resolve_boot_state(&paths, None).unwrap();
        assert_eq!(snapshot.state, LifecycleState::Error);
    }

    #[tokio::test]
    async fn subscribers_see_transitions_that_happen_after_they_subscribed() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        reset(&GuardianPaths::rooted_at(dir.path()));
        transition_to(LifecycleState::Initializing, None).unwrap();

        let mut rx = subscribe();
        transition_to(LifecycleState::Unenrolled, None).unwrap();

        // `changed()` resolves once the sender has published something new
        // since this receiver's last observed value.
        rx.changed().await.unwrap();
        assert_eq!(rx.borrow().state, LifecycleState::Unenrolled);
    }

    #[test]
    fn is_terminal_failure_and_is_online_classify_states_correctly() {
        assert!(LifecycleState::Error.is_terminal_failure());
        assert!(LifecycleState::Rejected.is_terminal_failure());
        assert!(!LifecycleState::PendingApproval.is_terminal_failure());
        assert!(LifecycleState::Online.is_online());
        assert!(!LifecycleState::CircleMember.is_online());
    }
}
