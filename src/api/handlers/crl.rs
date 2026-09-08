use super::dkp::{ActionResponse, run_cli, run_cli_with_env};
use crate::api::error::ApiError;
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::crl::entry::CrlEntry;
use crate::crl::persistence;
use axum::{
    Json,
    extract::{Query, State},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Deserialize, Default)]
pub struct RevokeCrlRequest {
    pub did: String,
    pub reason: String,
    pub severity: String,
    pub device_id: Option<String>,
    pub user_id: Option<String>,
    pub note: Option<String>,
    pub audit_ref: Option<String>,
    pub attestation_ref: Option<String>,
    pub evidence_digest: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RevokeCrlResponse {
    pub status: String,
    pub message: String,
    pub entry: CrlEntry,
    pub sequence: u64,
    pub merkle_root: String,
}

#[derive(Debug, Deserialize)]
pub struct UnrevokeCrlRequest {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct UnrevokeCrlResponse {
    pub status: String,
    pub message: String,
    pub did: String,
    pub sequence: u64,
    pub merkle_root: String,
}

#[derive(Debug, Deserialize)]
pub struct EntryQuery {
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct CheckQuery {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct CrlListResponse {
    pub status: String,
    pub count: usize,
    pub entries: Vec<CrlEntry>,
}

#[derive(Debug, Serialize)]
pub struct CrlCheckResponse {
    pub status: String,
    pub did: String,
    pub revoked: bool,
    pub entry: Option<CrlEntry>,
}

#[derive(Debug, Serialize)]
pub struct CrlVerifyResponse {
    pub ok: bool,
    pub errors: Vec<String>,
    pub sequence: Option<u64>,
    pub merkle_root: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrlRootResponse {
    pub sequence: u64,
    pub merkle_root: String,
}

#[derive(Debug, Serialize)]
pub struct GossipStatusResponse {
    pub enabled: bool,
    pub port: u16,
    pub interval_secs: u64,
    pub threshold_pct: u8,
    pub self_did: String,
    pub circle_id: String,
    pub other_members: usize,
    pub threshold_count: usize,
    pub sequence: u64,
    pub merkle_root: String,
    pub entries: usize,
    pub propagated: usize,
    pub rounds_initiated: u64,
    pub rounds_served: u64,
    pub entries_merged: u64,
    pub last_round: Option<crate::crl::gossip::engine::LastRound>,
}

#[derive(Debug, Serialize)]
pub struct GossipTriggerResponse {
    pub success: bool,
    pub peer_did: String,
    pub peer_node: String,
    pub merged: usize,
    pub pushed: usize,
    pub peer_merged: usize,
    pub merkle_root: String,
    pub newly_propagated: Vec<String>,
    pub message: String,
}

/// GET /api/v1/crl/gossip/status - gossip engine observability.
pub async fn gossip_status(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<GossipStatusResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    let self_did = crate::did::DidRecord::load(&crate::crl::gossip::engine::did_record_path())
        .map(|record| record.did)
        .unwrap_or_default();
    let circle_id = crate::crl::issue::current_circle_id()
        .unwrap_or_else(|_| crate::crl::issue::DEFAULT_CIRCLE_ID.to_string());
    let other_members = crate::crl::gossip::engine::active_gossip_peers(&self_did).len();
    let threshold_count =
        crate::crl::gossip::engine::threshold_count(other_members, config.threshold_pct);
    let (sequence, merkle_root, entries, propagated) =
        match persistence::load_crl().map_err(|error| ApiError::Internal(error.to_string()))? {
            Some(crl) => (
                crl.sequence,
                crl.merkle_root.clone(),
                crl.entries.len(),
                crl.entries.iter().filter(|entry| entry.propagated).count(),
            ),
            None => (0, String::new(), 0, 0),
        };
    Ok(Json(GossipStatusResponse {
        enabled: config.enabled,
        port: config.port,
        interval_secs: config.interval_secs,
        threshold_pct: config.threshold_pct,
        self_did,
        circle_id,
        other_members,
        threshold_count,
        sequence,
        merkle_root,
        entries,
        propagated,
        rounds_initiated: crate::crl::gossip::engine::rounds_initiated(),
        rounds_served: crate::crl::gossip::engine::rounds_served(),
        entries_merged: crate::crl::gossip::engine::entries_merged_total(),
        last_round: crate::crl::gossip::engine::last_round(),
    }))
}

/// POST /api/v1/crl/gossip/trigger - run ONE gossip round immediately with
/// a random active peer. Deterministic board-testing hook; the periodic
/// loop keeps running untouched.
pub async fn gossip_trigger(
    State(state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<GossipTriggerResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    let report =
        crate::crl::gossip::engine::run_round_once(&state.node_id, &state.did_resolver, &config)
            .await
            .map_err(ApiError::Internal)?;
    Ok(Json(GossipTriggerResponse {
        success: true,
        peer_did: report.peer_did,
        peer_node: report.peer_node,
        merged: report.merged + report.replaced,
        pushed: report.pushed,
        peer_merged: report.peer_merged,
        merkle_root: report.merkle_root,
        newly_propagated: report.newly_propagated,
        message: "gossip round completed".to_string(),
    }))
}

#[derive(Debug, Serialize)]
pub struct EmergencyStatusResponse {
    pub enabled: bool,
    pub port: u16,
    pub ttl: u8,
    pub notices_sent: u64,
    pub notices_received: u64,
    pub notices_merged: u64,
    pub notices_rebroadcast: u64,
    pub sessions_terminated: u64,
    pub last_notice: Option<crate::crl::gossip::emergency::LastNotice>,
}

#[derive(Debug, Serialize)]
pub struct EmergencyBroadcastResponse {
    pub success: bool,
    pub revoked_did: String,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct EmergencySessionDebugSeedRequest {
    pub did: String,
    pub transport: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct EmergencySessionDebugStatusQuery {
    pub did: String,
}

#[derive(Debug, Serialize)]
pub struct EmergencySessionDebugResponse {
    pub node_id: String,
    pub did: String,
    pub remote_device_id: String,
    pub exists: bool,
    pub total_sessions: usize,
    pub active_sessions: usize,
    pub session: Option<crate::cot::session_manager::Session>,
    pub message: String,
}

/// GET /api/v1/crl/emergency/status — emergency channel observability.
pub async fn emergency_status(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<EmergencyStatusResponse>, ApiError> {
    let config = crate::crl::gossip::GossipConfig::from_env();
    Ok(Json(EmergencyStatusResponse {
        enabled: config.emergency_enabled,
        port: config.emergency_port,
        ttl: config.emergency_ttl,
        notices_sent: crate::crl::gossip::emergency::notices_sent(),
        notices_received: crate::crl::gossip::emergency::notices_received(),
        notices_merged: crate::crl::gossip::emergency::notices_merged(),
        notices_rebroadcast: crate::crl::gossip::emergency::notices_rebroadcast(),
        sessions_terminated: crate::crl::gossip::emergency::sessions_terminated_total(),
        last_notice: crate::crl::gossip::emergency::last_notice(),
    }))
}

/// POST /api/v1/crl/emergency/debug/session — seed a live CoT session for a
/// peer DID so CRL-029 can verify that emergency revocation drops it.
pub async fn emergency_debug_session_seed(
    State(state): State<Arc<crate::api::state::AppState>>,
    Json(body): Json<EmergencySessionDebugSeedRequest>,
) -> Result<Json<EmergencySessionDebugResponse>, ApiError> {
    let did = normalize_debug_did(&body.did)?;
    let transport = parse_debug_transport(body.transport.as_deref())?;
    let remote_device_id = resolve_device_id_for_did(&did)?;
    let local_device_id = resolve_local_device_id()?;
    let manager = session_manager_handle()?;

    let session = manager
        .get_or_create(&local_device_id, &remote_device_id, transport)
        .await;
    let total_sessions = manager.total_count().await;
    let active_sessions = manager.active_count().await;

    Ok(Json(EmergencySessionDebugResponse {
        node_id: state.node_id.clone(),
        did,
        remote_device_id,
        exists: true,
        total_sessions,
        active_sessions,
        session: Some(session),
        message: format!("debug CoT session seeded via {}", transport),
    }))
}

/// GET /api/v1/crl/emergency/debug/session?did=... — inspect whether a live
/// CoT session still exists for the DID under test.
pub async fn emergency_debug_session_status(
    State(state): State<Arc<crate::api::state::AppState>>,
    Query(query): Query<EmergencySessionDebugStatusQuery>,
) -> Result<Json<EmergencySessionDebugResponse>, ApiError> {
    let did = normalize_debug_did(&query.did)?;
    let remote_device_id = resolve_device_id_for_did(&did)?;
    let manager = session_manager_handle()?;
    let session = manager.get_session(&remote_device_id).await;
    let total_sessions = manager.total_count().await;
    let active_sessions = manager.active_count().await;
    let exists = session.is_some();

    Ok(Json(EmergencySessionDebugResponse {
        node_id: state.node_id.clone(),
        did,
        remote_device_id,
        exists,
        total_sessions,
        active_sessions,
        session,
        message: if exists {
            "debug CoT session exists".to_string()
        } else {
            "debug CoT session not present".to_string()
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct EmergencyBroadcastQuery {
    pub did: String,
}

pub async fn emergency_broadcast(
    State(state): State<Arc<crate::api::state::AppState>>,
    axum::extract::Query(q): axum::extract::Query<EmergencyBroadcastQuery>,
) -> Result<Json<EmergencyBroadcastResponse>, ApiError> {
    if q.did.trim().is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".into()));
    }
    let crl = persistence::load_crl()
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .ok_or_else(|| ApiError::NotFound("no local CRL".into()))?;
    let entry = crl
        .entries
        .iter()
        .find(|entry| entry.revoked_did == q.did)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("{} is not revoked", q.did)))?;
    if !matches!(entry.severity, crate::crl::entry::Severity::Critical) {
        return Err(ApiError::BadRequest(
            "emergency broadcast is only for critical revocations".into(),
        ));
    }
    crate::crl::gossip::emergency::broadcast_for_entry(state.node_id.clone(), entry);
    Ok(Json(EmergencyBroadcastResponse {
        success: true,
        revoked_did: q.did,
        message: "emergency broadcast dispatched".to_string(),
    }))
}

/// GET /api/v1/crl/emergency/notifications — durable feed the mobile app
/// polls to raise user push notifications for critical revocations.
pub async fn emergency_notifications(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<Vec<crate::crl::gossip::notifications::EmergencyNotification>>, ApiError> {
    Ok(Json(crate::crl::gossip::notifications::recent(
        crate::crl::gossip::notifications::MAX_FEED_RETURN,
    )))
}

#[derive(Debug, Serialize)]
pub struct OfflineStatusResponse {
    pub enabled: bool,
    pub online: bool,
    pub sync_interval_secs: u64,
    pub flush_rounds: u32,
    pub max_retries: u32,
    pub pending: usize,
    pub sync_cycles: u64,
    pub reconnects: u64,
    pub entries_delivered: u64,
    pub entries_fetched: u64,
    pub peer_sync_state:
        std::collections::HashMap<String, crate::crl::offline::sync::PeerSyncState>,
}

/// GET /api/v1/crl/offline/status - offline sync observability.
pub async fn offline_status(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<OfflineStatusResponse>, ApiError> {
    let config = crate::crl::offline::OfflineConfig::from_env();
    Ok(Json(OfflineStatusResponse {
        enabled: config.enabled,
        online: crate::crl::offline::sync::is_online(),
        sync_interval_secs: config.sync_interval_secs,
        flush_rounds: config.flush_rounds,
        max_retries: config.max_retries,
        pending: crate::crl::offline::queue::count(),
        sync_cycles: crate::crl::offline::sync::sync_cycles(),
        reconnects: crate::crl::offline::sync::reconnects(),
        entries_delivered: crate::crl::offline::sync::entries_delivered(),
        entries_fetched: crate::crl::offline::sync::entries_fetched(),
        peer_sync_state: crate::crl::offline::sync::sync_state_snapshot(),
    }))
}

/// GET /api/v1/crl/offline/pending - list queued (undelivered) revocations.
pub async fn offline_pending(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pending = crate::crl::offline::queue::list()
        .map_err(|error| ApiError::Internal(error.to_string()))?;
    let items: Vec<serde_json::Value> = pending
        .into_iter()
        .map(|item| {
            serde_json::json!({
                "id": item.entry.id,
                "revoked_did": item.entry.revoked_did,
                "reason": item.entry.reason.as_str(),
                "severity": item.entry.severity.as_str(),
                "attempts": item.attempts,
                "queued_at": item.queued_at,
                "last_attempt_at": item.last_attempt_at,
                "last_error": item.last_error,
                "parked": item.parked,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "status": "success",
        "count": items.len(),
        "pending": items,
    })))
}

/// POST /api/v1/crl/offline/sync - run one sync cycle now (deterministic hook).
pub async fn offline_sync(
    State(state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<crate::crl::offline::sync::CycleReport>, ApiError> {
    let config = crate::crl::offline::OfflineConfig::from_env();
    let report = crate::crl::offline::sync::run_cycle(&state.node_id, &state.did_resolver, &config)
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(report))
}

pub async fn revoke(
    State(state): State<Arc<crate::api::state::AppState>>,
    Json(body): Json<RevokeCrlRequest>,
) -> Result<Json<RevokeCrlResponse>, ApiError> {
    if body.did.trim().is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".to_string()));
    }

    let mut args = vec![
        "crl".to_string(),
        "revoke".to_string(),
        "--did".to_string(),
        body.did.clone(),
        "--reason".to_string(),
        body.reason.clone(),
        "--severity".to_string(),
        body.severity.clone(),
    ];
    push_optional_arg(&mut args, "--device-id", body.device_id.as_deref());
    push_optional_arg(&mut args, "--user-id", body.user_id.as_deref());
    push_optional_arg(&mut args, "--note", body.note.as_deref());

    let response =
        run_owned_cli_with_env(args, &[("SGX_CRL_SKIP_EMERGENCY_BROADCAST", "1")]).await?;
    ensure_cli_success(response)?;

    let crl = persistence::load_crl()
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .ok_or_else(|| ApiError::NotFound("CRL not found after revoke".to_string()))?;
    let entry = crl
        .entries
        .iter()
        .find(|entry| entry.revoked_did == body.did)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("CRL entry not found for DID {}", body.did)))?;
    // Emergency Revocation: critical revocations fire the priority UDP
    // broadcast at once (daemon tokio runtime; fire-and-forget).
    if matches!(entry.severity, crate::crl::entry::Severity::Critical) {
        crate::crl::gossip::emergency::broadcast_for_entry(state.node_id.clone(), entry.clone());
    }

    // Track the just-issued revocation in the offline queue so it is
    // guaranteed to reach peers even if connectivity is currently down.
    crate::crl::offline::queue_pending(&state.node_id, &entry);

    // Feed the alert-rules engine. issue_revocation() itself runs inside the
    // separate sgx-pa-cli subprocess (see run_owned_cli_with_env above), so a
    // publish() there would be lost with that process — this in-daemon handler
    // is the only point that can actually reach the running rules::spawn() listener.
    crate::rules::publish(crate::rules::RuleEvent::CrlRevocation {
        node_id: state.node_id.clone(),
        revoked_did: entry.revoked_did.clone(),
        reason: entry.reason.as_str().to_string(),
        severity: entry.severity.as_str().to_string(),
    });

    log_audit(
        &state.node_id,
        AuditCategory::Crl,
        AuditSeverity::Critical,
        AuditAction::Revoked,
        &format!(
            "CRL entry issued: {} (reason: {}, severity: {})",
            entry.revoked_did,
            entry.reason.as_str(),
            entry.severity.as_str()
        ),
    );

    Ok(Json(RevokeCrlResponse {
        status: "success".to_string(),
        message: "CRL entry issued".to_string(),
        entry,
        sequence: crl.sequence,
        merkle_root: crl.merkle_root,
    }))
}

pub async fn unrevoke(
    State(state): State<Arc<crate::api::state::AppState>>,
    Json(body): Json<UnrevokeCrlRequest>,
) -> Result<Json<UnrevokeCrlResponse>, ApiError> {
    if body.did.trim().is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".to_string()));
    }

    let response = run_owned_cli(vec![
        "crl".to_string(),
        "unrevoke".to_string(),
        "--did".to_string(),
        body.did.clone(),
    ])
    .await?;
    ensure_cli_success(response)?;

    let crl = persistence::load_crl()
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .ok_or_else(|| ApiError::NotFound("CRL not found after unrevoke".to_string()))?;

    log_audit(
        &state.node_id,
        AuditCategory::Crl,
        AuditSeverity::Warning,
        AuditAction::Updated,
        &format!("CRL entry unrevoked: {}", body.did),
    );

    Ok(Json(UnrevokeCrlResponse {
        status: "success".to_string(),
        message: "CRL entry unrevoked".to_string(),
        did: body.did,
        sequence: crl.sequence,
        merkle_root: crl.merkle_root,
    }))
}

pub async fn list(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<CrlListResponse>, ApiError> {
    let response = run_owned_cli(vec!["crl".to_string(), "list".to_string()]).await?;
    ensure_cli_success(response)?;

    let crl = persistence::load_crl().map_err(|error| ApiError::Internal(error.to_string()))?;
    let entries = crl.map(|crl| crl.entries).unwrap_or_default();
    Ok(Json(CrlListResponse {
        status: "success".to_string(),
        count: entries.len(),
        entries,
    }))
}

pub async fn entry(
    State(_state): State<Arc<crate::api::state::AppState>>,
    Query(query): Query<EntryQuery>,
) -> Result<Json<CrlEntry>, ApiError> {
    let id = query.id.trim();
    if id.is_empty() {
        return Err(ApiError::BadRequest("id must not be empty".to_string()));
    }

    let response = run_owned_cli(vec![
        "crl".to_string(),
        "show".to_string(),
        "--id".to_string(),
        id.to_string(),
    ])
    .await?;
    let response = ensure_cli_success(response)?;
    let entry: CrlEntry = serde_json::from_str(&response.stdout)?;
    Ok(Json(entry))
}

pub async fn check(
    State(_state): State<Arc<crate::api::state::AppState>>,
    Query(query): Query<CheckQuery>,
) -> Result<Json<CrlCheckResponse>, ApiError> {
    let did = query.did.trim();
    if did.is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".to_string()));
    }

    let response = run_owned_cli(vec![
        "crl".to_string(),
        "check".to_string(),
        "--did".to_string(),
        did.to_string(),
    ])
    .await?;
    let response = ensure_cli_success(response)?;
    let value: serde_json::Value = serde_json::from_str(&response.stdout)?;
    let entry = value
        .get("entry")
        .filter(|entry| !entry.is_null())
        .map(|entry| serde_json::from_value(entry.clone()))
        .transpose()?;

    Ok(Json(CrlCheckResponse {
        status: "success".to_string(),
        did: did.to_string(),
        revoked: value
            .get("revoked")
            .and_then(|revoked| revoked.as_bool())
            .unwrap_or(false),
        entry,
    }))
}

pub async fn verify(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<CrlVerifyResponse>, ApiError> {
    let response = run_owned_cli(vec!["crl".to_string(), "verify".to_string()]).await?;
    let root = persistence::load_crl()
        .map_err(|error| ApiError::Internal(error.to_string()))?
        .map(|crl| (crl.sequence, crl.merkle_root));
    if response.success {
        Ok(Json(CrlVerifyResponse {
            ok: true,
            errors: Vec::new(),
            sequence: root.as_ref().map(|(sequence, _)| *sequence),
            merkle_root: root.map(|(_, merkle_root)| merkle_root),
        }))
    } else {
        Ok(Json(CrlVerifyResponse {
            ok: false,
            errors: vec![cli_message(&response)],
            sequence: root.as_ref().map(|(sequence, _)| *sequence),
            merkle_root: root.map(|(_, merkle_root)| merkle_root),
        }))
    }
}

pub async fn root(
    State(_state): State<Arc<crate::api::state::AppState>>,
) -> Result<Json<CrlRootResponse>, ApiError> {
    let response = run_owned_cli(vec!["crl".to_string(), "root".to_string()]).await?;
    let response = ensure_cli_success(response)?;
    let root: CrlRootResponse = serde_json::from_str(&response.stdout)?;
    Ok(Json(root))
}

async fn run_owned_cli(args: Vec<String>) -> Result<ActionResponse, ApiError> {
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    run_cli(&refs).await
}

async fn run_owned_cli_with_env(
    args: Vec<String>,
    envs: &[(&str, &str)],
) -> Result<ActionResponse, ApiError> {
    let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    run_cli_with_env(&refs, envs).await
}

fn push_optional_arg(args: &mut Vec<String>, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        args.push(name.to_string());
        args.push(value.to_string());
    }
}

fn ensure_cli_success(response: ActionResponse) -> Result<ActionResponse, ApiError> {
    if response.success {
        Ok(response)
    } else {
        Err(map_cli_failure(&response))
    }
}

fn map_cli_failure(response: &ActionResponse) -> ApiError {
    let message = cli_message(response);
    let lower = message.to_ascii_lowercase();
    if lower.contains("already revoked") {
        ApiError::Conflict(message)
    } else if lower.contains("self")
        || lower.contains("member-issued")
        || lower.contains("invalid signature")
        || lower.contains("only the circle owner")
        || lower.contains("revoke the circle owner")
    {
        ApiError::Forbidden(message)
    } else if lower.contains("not found") || lower.contains("not currently revoked") {
        ApiError::NotFound(message)
    } else {
        ApiError::BadRequest(message)
    }
}

fn cli_message(response: &ActionResponse) -> String {
    let stderr = response.stderr.trim();
    if !stderr.is_empty() {
        return stderr.to_string();
    }
    let stdout = response.stdout.trim();
    if !stdout.is_empty() {
        return stdout.to_string();
    }
    "sgx-pa-cli crl command failed".to_string()
}

fn normalize_debug_did(did: &str) -> Result<String, ApiError> {
    let did = did.trim();
    if did.is_empty() {
        return Err(ApiError::BadRequest("did must not be empty".into()));
    }
    Ok(did.to_string())
}

fn parse_debug_transport(raw: Option<&str>) -> Result<crate::cot::types::TransportType, ApiError> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(crate::cot::types::TransportType::Ethernet);
    };

    let lowered = raw.to_ascii_lowercase();
    match lowered.as_str() {
        "ethernet" | "eth" => Ok(crate::cot::types::TransportType::Ethernet),
        "wifi" | "wi-fi" | "wlan" => Ok(crate::cot::types::TransportType::WiFi),
        "bluetooth" | "bt" => Ok(crate::cot::types::TransportType::Bluetooth),
        "cellular" | "lte" | "5g" => Ok(crate::cot::types::TransportType::Cellular),
        "satellite" | "sat" => Ok(crate::cot::types::TransportType::Satellite),
        _ => Err(ApiError::BadRequest(format!(
            "unsupported transport '{}' (expected Ethernet, WiFi, Bluetooth, Cellular, or Satellite)",
            raw
        ))),
    }
}

fn session_manager_handle(
) -> Result<std::sync::Arc<crate::cot::session_manager::SessionManager>, ApiError> {
    crate::cot::session_manager::global_session_manager().ok_or_else(|| {
        ApiError::Internal("CoT session manager is not initialized on this node".into())
    })
}

fn resolve_local_device_id() -> Result<String, ApiError> {
    let doc = crate::did::doc_persistence::load_self()
        .map_err(|error| ApiError::Internal(format!("load self DID document: {}", error)))?
        .ok_or_else(|| ApiError::NotFound("self DID document not found".into()))?;
    device_id_from_document(&doc).map_err(ApiError::Internal)
}

fn resolve_device_id_for_did(did: &str) -> Result<String, ApiError> {
    if let Some(doc) = crate::did::doc_persistence::load_self()
        .map_err(|error| ApiError::Internal(format!("load self DID document: {}", error)))?
        .filter(|doc| doc.id == did)
    {
        return device_id_from_document(&doc).map_err(ApiError::Internal);
    }

    let docs = crate::did::doc_persistence::list_peer_docs()
        .map_err(|error| ApiError::Internal(format!("list peer DID documents: {}", error)))?;
    let doc = docs
        .into_iter()
        .find(|doc| doc.id == did)
        .ok_or_else(|| ApiError::NotFound(format!("peer DID document not found for {}", did)))?;
    device_id_from_document(&doc).map_err(ApiError::Internal)
}

fn device_id_from_document(doc: &crate::did::document::DidDocument) -> Result<String, String> {
    let pubkey = doc
        .primary_public_key_bytes()
        .ok_or_else(|| format!("primary public key missing for {}", doc.id))?;
    crate::cot::identity::DeviceIdentity::from_public_key(&pubkey)
        .map(|identity| identity.device_id().to_string())
        .map_err(|error| format!("derive device id for {}: {}", doc.id, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cot::types::TransportType;

    #[test]
    fn parse_debug_transport_defaults_to_ethernet() {
        assert_eq!(
            parse_debug_transport(None).unwrap(),
            TransportType::Ethernet
        );
        assert_eq!(
            parse_debug_transport(Some("")).unwrap(),
            TransportType::Ethernet
        );
    }

    #[test]
    fn parse_debug_transport_accepts_aliases() {
        assert_eq!(
            parse_debug_transport(Some("wifi")).unwrap(),
            TransportType::WiFi
        );
        assert_eq!(
            parse_debug_transport(Some("bt")).unwrap(),
            TransportType::Bluetooth
        );
        assert_eq!(
            parse_debug_transport(Some("5g")).unwrap(),
            TransportType::Cellular
        );
    }

    #[test]
    fn parse_debug_transport_rejects_unknown_value() {
        let err = parse_debug_transport(Some("carrier-pigeon")).unwrap_err();
        let message = match err {
            ApiError::BadRequest(message) => message,
            other => panic!("unexpected error: {:?}", other),
        };
        assert!(message.contains("unsupported transport"));
    }

    fn test_state(temp: &tempfile::TempDir) -> Arc<crate::api::state::AppState> {
        crate::api::state::AppState::for_tests(
            temp.path(),
            "nodeA",
            temp.path().join("config").to_string_lossy().to_string(),
        )
    }

    #[tokio::test]
    async fn gossip_status_reports_defaults_with_no_local_crl() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let response = gossip_status(State(test_state(&temp)))
            .await
            .expect("gossip_status succeeds");
        assert_eq!(response.0.entries, 0);
        assert_eq!(response.0.propagated, 0);
        assert_eq!(response.0.sequence, 0);
    }

    #[tokio::test]
    async fn emergency_status_reports_defaults() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let response = emergency_status(State(test_state(&temp)))
            .await
            .expect("emergency_status succeeds");
        assert!(response.0.last_notice.is_none());
    }

    #[tokio::test]
    async fn emergency_notifications_returns_empty_feed() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let response = emergency_notifications(State(test_state(&temp)))
            .await
            .expect("emergency_notifications succeeds");
        assert!(response.0.is_empty());
    }

    #[tokio::test]
    async fn offline_status_reports_defaults() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let response = offline_status(State(test_state(&temp)))
            .await
            .expect("offline_status succeeds");
        assert_eq!(response.0.pending, 0);
    }

    #[tokio::test]
    async fn offline_pending_returns_empty_list_with_no_queue() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let response = offline_pending(State(test_state(&temp)))
            .await
            .expect("offline_pending succeeds");
        assert_eq!(response.0["count"], 0);
    }

    #[tokio::test]
    async fn emergency_broadcast_rejects_empty_did() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let error = emergency_broadcast(
            State(test_state(&temp)),
            axum::extract::Query(EmergencyBroadcastQuery { did: "  ".into() }),
        )
        .await
        .expect_err("empty did is rejected");
        assert!(matches!(error, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn emergency_broadcast_returns_404_with_no_local_crl() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let error = emergency_broadcast(
            State(test_state(&temp)),
            axum::extract::Query(EmergencyBroadcastQuery {
                did: "did:guardian:someone".into(),
            }),
        )
        .await
        .expect_err("no local CRL yet");
        assert!(matches!(error, ApiError::NotFound(_)));
    }

    #[tokio::test]
    async fn entry_and_check_reject_empty_query_values() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let entry_error = entry(
            State(test_state(&temp)),
            Query(EntryQuery { id: "  ".into() }),
        )
        .await
        .expect_err("empty id is rejected");
        assert!(matches!(entry_error, ApiError::BadRequest(_)));

        let check_error = check(
            State(test_state(&temp)),
            Query(CheckQuery { did: "  ".into() }),
        )
        .await
        .expect_err("empty did is rejected");
        assert!(matches!(check_error, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn revoke_and_unrevoke_reject_empty_did_before_shelling_out() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let revoke_error = revoke(
            State(test_state(&temp)),
            Json(RevokeCrlRequest {
                did: "   ".into(),
                reason: "test".into(),
                severity: "low".into(),
                device_id: None,
                user_id: None,
                note: None,
                audit_ref: None,
                attestation_ref: None,
                evidence_digest: None,
            }),
        )
        .await
        .expect_err("empty did is rejected");
        assert!(matches!(revoke_error, ApiError::BadRequest(_)));

        let unrevoke_error = unrevoke(
            State(test_state(&temp)),
            Json(UnrevokeCrlRequest { did: "   ".into() }),
        )
        .await
        .expect_err("empty did is rejected");
        assert!(matches!(unrevoke_error, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn list_entry_check_verify_and_root_surface_missing_cli_as_internal_error() {
        // No `sgx-pa-cli` binary is built/reachable in this sandbox (and no
        // `SGX_PA_CLI_PATH` override is set), so every handler that shells
        // out to it deterministically fails the same way
        // (`ApiError::Internal`) rather than ever reaching CRL logic.
        let temp = tempfile::TempDir::new().expect("tempdir");

        let list_error = list(State(test_state(&temp))).await.expect_err("no CLI");
        assert!(matches!(list_error, ApiError::Internal(_)));

        let entry_error = entry(
            State(test_state(&temp)),
            Query(EntryQuery { id: "abc".into() }),
        )
        .await
        .expect_err("no CLI");
        assert!(matches!(entry_error, ApiError::Internal(_)));

        let check_error = check(
            State(test_state(&temp)),
            Query(CheckQuery {
                did: "did:guardian:someone".into(),
            }),
        )
        .await
        .expect_err("no CLI");
        assert!(matches!(check_error, ApiError::Internal(_)));

        let verify_error = verify(State(test_state(&temp))).await.expect_err("no CLI");
        assert!(matches!(verify_error, ApiError::Internal(_)));

        let root_error = root(State(test_state(&temp))).await.expect_err("no CLI");
        assert!(matches!(root_error, ApiError::Internal(_)));
    }

    fn cli_response(success: bool, stdout: &str, stderr: &str) -> ActionResponse {
        ActionResponse {
            success,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            restart_required: false,
            timestamp: "2026-09-03T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn push_optional_arg_appends_a_flag_and_value_only_when_present() {
        let mut args = vec!["crl".to_string()];
        push_optional_arg(&mut args, "--reason", Some("compromised"));
        push_optional_arg(&mut args, "--circle", None);
        assert_eq!(args, vec!["crl", "--reason", "compromised"]);
    }

    #[test]
    fn cli_message_prefers_stderr_then_stdout_then_a_default() {
        assert_eq!(
            cli_message(&cli_response(false, "out", "  the real error  ")),
            "the real error"
        );
        assert_eq!(cli_message(&cli_response(false, "  out  ", "   ")), "out");
        assert_eq!(
            cli_message(&cli_response(false, "  ", "")),
            "sgx-pa-cli crl command failed"
        );
    }

    #[test]
    fn ensure_cli_success_passes_a_successful_response_through_untouched() {
        let response = ensure_cli_success(cli_response(true, "done", ""))
            .expect("a successful CLI response is returned as-is");
        assert_eq!(response.stdout, "done");

        assert!(ensure_cli_success(cli_response(false, "", "boom")).is_err());
    }

    /// `map_cli_failure` is what turns the CLI's free-text stderr into an HTTP
    /// status, so each phrase it keys on gets its own case here.
    #[test]
    fn map_cli_failure_classifies_each_known_cli_message() {
        let cases: &[(&str, fn(&ApiError) -> bool)] = &[
            ("DID is already revoked", |e| {
                matches!(e, ApiError::Conflict(_))
            }),
            ("cannot revoke self", |e| {
                matches!(e, ApiError::Forbidden(_))
            }),
            ("member-issued credential", |e| {
                matches!(e, ApiError::Forbidden(_))
            }),
            ("invalid signature on entry", |e| {
                matches!(e, ApiError::Forbidden(_))
            }),
            ("only the circle owner may do this", |e| {
                matches!(e, ApiError::Forbidden(_))
            }),
            ("cannot revoke the circle owner", |e| {
                matches!(e, ApiError::Forbidden(_))
            }),
            ("entry not found", |e| matches!(e, ApiError::NotFound(_))),
            ("DID is not currently revoked", |e| {
                matches!(e, ApiError::NotFound(_))
            }),
            ("something else entirely", |e| {
                matches!(e, ApiError::BadRequest(_))
            }),
        ];

        for (message, expected) in cases {
            let error = map_cli_failure(&cli_response(false, "", message));
            assert!(expected(&error), "message {message:?} produced {error:?}");
        }

        // Classification is case-insensitive and reads stdout when stderr is
        // empty, so an uppercase message on stdout still classifies.
        assert!(matches!(
            map_cli_failure(&cli_response(false, "ALREADY REVOKED", "")),
            ApiError::Conflict(_)
        ));

        // With nothing to go on at all it falls through to a bad request.
        assert!(matches!(
            map_cli_failure(&cli_response(false, "", "")),
            ApiError::BadRequest(_)
        ));
    }

    #[test]
    fn normalize_debug_did_trims_and_rejects_blanks() {
        assert_eq!(
            normalize_debug_did("  did:guardian:abc  ").expect("valid"),
            "did:guardian:abc"
        );
        for blank in ["", "   ", "\t"] {
            assert!(
                matches!(normalize_debug_did(blank), Err(ApiError::BadRequest(_))),
                "{blank:?} must be rejected"
            );
        }
    }

    #[test]
    fn parse_debug_transport_accepts_every_alias_and_defaults_to_ethernet() {
        use crate::cot::types::TransportType;

        // Absent and blank both default.
        assert_eq!(
            parse_debug_transport(None).expect("default"),
            TransportType::Ethernet
        );
        assert_eq!(
            parse_debug_transport(Some("   ")).expect("default"),
            TransportType::Ethernet
        );

        for (raw, expected) in [
            ("ethernet", TransportType::Ethernet),
            ("ETH", TransportType::Ethernet),
            ("wifi", TransportType::WiFi),
            ("Wi-Fi", TransportType::WiFi),
            ("wlan", TransportType::WiFi),
            ("bluetooth", TransportType::Bluetooth),
            ("BT", TransportType::Bluetooth),
            ("cellular", TransportType::Cellular),
            ("lte", TransportType::Cellular),
            ("5G", TransportType::Cellular),
            ("satellite", TransportType::Satellite),
            ("sat", TransportType::Satellite),
        ] {
            assert_eq!(
                parse_debug_transport(Some(raw)).unwrap_or_else(|e| panic!("{raw}: {e:?}")),
                expected,
                "input {raw}"
            );
        }

        let error = parse_debug_transport(Some("carrier-pigeon"))
            .err()
            .expect("an unknown transport is rejected");
        assert!(
            matches!(&error, ApiError::BadRequest(message)
                if message.contains("carrier-pigeon") && message.contains("Ethernet")),
            "{error:?}"
        );
    }

    #[test]
    fn session_manager_handle_reports_an_uninitialized_cot_stack() {
        // `global_session_manager()` is only installed by the running daemon,
        // so under test it is always absent — the deterministic outcome this
        // helper exists to translate.
        let error = session_manager_handle()
            .err()
            .expect("no CoT session manager under test");
        assert!(
            matches!(&error, ApiError::Internal(message) if message.contains("not initialized")),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn device_id_resolution_reports_a_missing_self_document() {
        let _lock = crate::test_utils::TEST_ENV_LOCK.lock().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let previous_self = std::env::var_os(crate::did::doc_persistence::SELF_DOC_PATH_ENV);
        let previous_peers = std::env::var_os(crate::did::doc_persistence::PEERS_DOC_DIR_ENV);
        let peers = temp.path().join("peers");
        std::fs::create_dir_all(&peers).expect("peers dir");
        std::env::set_var(
            crate::did::doc_persistence::SELF_DOC_PATH_ENV,
            temp.path().join("did_doc.json"),
        );
        std::env::set_var(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, &peers);

        let error = resolve_local_device_id()
            .err()
            .expect("no self DID document exists");
        assert!(matches!(error, ApiError::NotFound(_)), "{error:?}");

        // ...and neither self nor any peer document matches an arbitrary DID.
        let error = resolve_device_id_for_did("did:guardian:nobody")
            .err()
            .expect("no matching document");
        assert!(
            matches!(&error, ApiError::NotFound(message) if message.contains("did:guardian:nobody")),
            "{error:?}"
        );

        match previous_self {
            Some(value) => std::env::set_var(crate::did::doc_persistence::SELF_DOC_PATH_ENV, value),
            None => std::env::remove_var(crate::did::doc_persistence::SELF_DOC_PATH_ENV),
        }
        match previous_peers {
            Some(value) => std::env::set_var(crate::did::doc_persistence::PEERS_DOC_DIR_ENV, value),
            None => std::env::remove_var(crate::did::doc_persistence::PEERS_DOC_DIR_ENV),
        }
    }
}
