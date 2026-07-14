use super::dkp::{run_cli, run_cli_with_env, ActionResponse};
use crate::api::error::ApiError;
use crate::crl::entry::CrlEntry;
use crate::crl::persistence;
use axum::{
    extract::{Query, State},
    Json,
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

    Ok(Json(RevokeCrlResponse {
        status: "success".to_string(),
        message: "CRL entry issued".to_string(),
        entry,
        sequence: crl.sequence,
        merkle_root: crl.merkle_root,
    }))
}

pub async fn unrevoke(
    State(_state): State<Arc<crate::api::state::AppState>>,
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
    if response.success {
        Ok(Json(CrlVerifyResponse {
            ok: true,
            errors: Vec::new(),
        }))
    } else {
        Ok(Json(CrlVerifyResponse {
            ok: false,
            errors: vec![cli_message(&response)],
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
