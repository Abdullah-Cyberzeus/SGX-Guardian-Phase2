use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::{
    advisory::{AdvisoryStatus, SecurityAdvisory},
    blocker::load_block_records,
    config::{BlockMode, SuricataConfig},
    threat_alert::{Severity, ThreatAlert},
};
use axum::{
    extract::{Path as AxumPath, Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
    pub severity: Option<String>,
}

pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AlertsQuery>,
) -> Result<Json<Vec<ThreatAlert>>, ApiError> {
    let mut alerts = load_alerts(&state).await?;

    if let Some(severity) = query.severity.as_deref() {
        alerts.retain(|alert| severity_matches(alert.severity, severity));
    }

    let limit = query.limit.unwrap_or(500).min(10_000);
    if alerts.len() > limit {
        alerts.drain(..alerts.len() - limit);
    }

    Ok(Json(alerts))
}

#[derive(Serialize)]
pub struct ModbusAlertsResponse {
    pub total_matches: usize,
    pub rules: Vec<ModbusRuleSummary>,
}

#[derive(Serialize)]
pub struct ModbusRuleSummary {
    pub rule_id: u8,
    pub name: &'static str,
    pub function_codes: &'static [&'static str],
    pub matched: bool,
    pub match_count: usize,
    pub matched_signatures: Vec<String>,
    pub recent_alerts: Vec<ThreatAlert>,
}

pub async fn modbus_alerts(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ModbusAlertsResponse>, ApiError> {
    let alerts = match load_alerts(&state).await {
        Ok(alerts) => alerts,
        Err(ApiError::NotFound(_)) => Vec::new(),
        Err(err) => return Err(err),
    };

    let mut total_matches = 0usize;
    let mut rules = Vec::with_capacity(MODBUS_RULES.len());

    for spec in MODBUS_RULES {
        let matches: Vec<ThreatAlert> = alerts
            .iter()
            .filter(|alert| modbus_rule_matches(spec, alert))
            .cloned()
            .collect();

        total_matches += matches.len();

        let mut matched_signatures = Vec::new();
        for alert in &matches {
            if !matched_signatures.iter().any(|sig| sig == &alert.signature) {
                matched_signatures.push(alert.signature.clone());
            }
        }

        let recent_start = matches.len().saturating_sub(5);
        rules.push(ModbusRuleSummary {
            rule_id: spec.rule_id,
            name: spec.name,
            function_codes: spec.function_codes,
            matched: !matches.is_empty(),
            match_count: matches.len(),
            matched_signatures,
            recent_alerts: matches[recent_start..].to_vec(),
        });
    }

    Ok(Json(ModbusAlertsResponse {
        total_matches,
        rules,
    }))
}

#[derive(Serialize)]
pub struct BlocksResponse {
    pub blocked: Vec<String>,
}

pub async fn list_blocks(
    State(state): State<Arc<AppState>>,
) -> Result<Json<BlocksResponse>, ApiError> {
    let mut blocked = nft_blocked_ips().await.unwrap_or_default();
    if blocked.is_empty() {
        let path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
        blocked = load_block_records(&path)
            .unwrap_or_default()
            .into_iter()
            .map(|record| record.ip)
            .collect();
    }
    blocked.sort();
    blocked.dedup();
    Ok(Json(BlocksResponse { blocked }))
}

#[derive(Deserialize)]
pub struct UnblockReq {
    pub ip: String,
}

pub async fn unblock(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<UnblockReq>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "unblock", &body.ip]).await?))
}

pub async fn update_rules(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "rules-update"]).await?))
}

pub async fn validate_config(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "validate"]).await?))
}

// ── New endpoints ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ThreatStatusResponse {
    pub suricata: String,
    pub enabled: bool,
    pub block_mode: String,
    pub alert_count: usize,
    pub block_count: usize,
}

pub async fn status(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ThreatStatusResponse>, ApiError> {
    let cfg = SuricataConfig::load(Path::new(&state.threat_config_path)).unwrap_or_default();

    let suricata = tokio::process::Command::new("systemctl")
        .args(["is-active", "suricata"])
        .output()
        .await
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let alerts_path = PathBuf::from(&state.threat_state_dir).join("alerts.jsonl");
    let alert_count = tokio::fs::read_to_string(&alerts_path)
        .await
        .map(|text| text.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);

    let blocks_path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
    let block_count = load_block_records(&blocks_path).unwrap_or_default().len();

    Ok(Json(ThreatStatusResponse {
        suricata,
        enabled: cfg.enabled,
        block_mode: cfg.block_mode.as_str().to_string(),
        alert_count,
        block_count,
    }))
}

pub async fn get_config(
    State(state): State<Arc<AppState>>,
) -> Result<Json<SuricataConfig>, ApiError> {
    let cfg = SuricataConfig::load(Path::new(&state.threat_config_path))
        .map_err(|e| ApiError::Internal(e.to_string()))?;
    Ok(Json(cfg))
}

#[derive(Deserialize)]
pub struct ThreatConfigPatch {
    pub enabled: Option<bool>,
    pub block_mode: Option<BlockMode>,
    pub rule_update_hours: Option<u64>,
    pub block_ttl_secs: Option<u64>,
    pub block_exempt: Option<Vec<String>>,
}

pub async fn set_config(
    State(state): State<Arc<AppState>>,
    Json(patch): Json<ThreatConfigPatch>,
) -> Result<Json<ActionResponse>, ApiError> {
    let config_path = Path::new(&state.threat_config_path);
    let mut cfg = SuricataConfig::load(config_path).unwrap_or_default();

    if let Some(v) = patch.enabled {
        cfg.enabled = v;
    }
    if let Some(v) = patch.block_mode {
        cfg.block_mode = v;
    }
    if let Some(v) = patch.rule_update_hours {
        cfg.rule_update_hours = v;
    }
    if let Some(v) = patch.block_ttl_secs {
        cfg.block_ttl_secs = v;
    }
    if let Some(v) = patch.block_exempt {
        cfg.block_exempt = v;
    }

    cfg.validate()
        .map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let yaml = serde_yaml::to_string(&cfg).map_err(|e| ApiError::Internal(e.to_string()))?;
    tokio::fs::write(&state.threat_config_path, yaml)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(ActionResponse {
        success: true,
        stdout: "config updated — effective within 5 seconds".into(),
        stderr: String::new(),
        restart_required: false,
        timestamp: Utc::now().to_rfc3339(),
    }))
}

#[derive(Deserialize)]
pub struct BlockReq {
    pub ip: String,
}

pub async fn block_ip(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<BlockReq>,
) -> Result<Json<ActionResponse>, ApiError> {
    Ok(Json(run_cli(&["threat", "block", &body.ip]).await?))
}

pub async fn start(State(_state): State<Arc<AppState>>) -> Result<Json<ActionResponse>, ApiError> {
    let output = tokio::process::Command::new("systemctl")
        .args(["start", "suricata"])
        .output()
        .await
        .map_err(|e| ApiError::Internal(format!("systemctl: {}", e)))?;

    let success = output.status.success();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok(Json(ActionResponse {
        success,
        stdout: if success {
            "suricata started".into()
        } else {
            String::new()
        },
        stderr,
        restart_required: false,
        timestamp: Utc::now().to_rfc3339(),
    }))
}

fn severity_matches(actual: Severity, expected: &str) -> bool {
    actual.as_str().eq_ignore_ascii_case(expected)
        || format!("{:?}", actual).eq_ignore_ascii_case(expected)
}

async fn load_alerts(state: &AppState) -> Result<Vec<ThreatAlert>, ApiError> {
    let path = PathBuf::from(&state.threat_state_dir).join("alerts.jsonl");
    let bytes = tokio::fs::read(&path).await.map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            ApiError::NotFound("no alerts yet - has Suricata produced events?".into())
        } else {
            ApiError::Internal(format!("failed to read {}: {}", path.display(), err))
        }
    })?;

    Ok(bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect())
}

struct ModbusRuleSpec {
    rule_id: u8,
    name: &'static str,
    function_codes: &'static [&'static str],
    signature_ids: &'static [u32],
    signatures: &'static [&'static str],
}

const MODBUS_RULE_1_SIGNATURE_IDS: &[u32] = &[10000201, 10000202];
const MODBUS_RULE_2_SIGNATURE_IDS: &[u32] = &[10000203, 10000204];
const MODBUS_RULE_3_SIGNATURE_IDS: &[u32] = &[10000205, 10000206, 10000207, 10000208];
const MODBUS_RULE_4_SIGNATURE_IDS: &[u32] = &[10000209];
const MODBUS_RULE_5_SIGNATURE_IDS: &[u32] = &[10000210];

const MODBUS_RULE_1_SIGNATURES: &[&str] = &[
    "SGX OT Modbus Unauthorized Write Single Coil FC5",
    "SGX OT Modbus Unauthorized Write Multiple Coils FC15",
];
const MODBUS_RULE_2_SIGNATURES: &[&str] = &[
    "SGX OT Modbus Write Safety Critical Register FC6",
    "SGX OT Modbus Write Safety Critical Registers FC16",
];
const MODBUS_RULE_3_SIGNATURES: &[&str] = &[
    "SGX OT Modbus PLC Program Upload FC65",
    "SGX OT Modbus PLC Program Upload FC66",
    "SGX OT Modbus PLC Firmware Upload FC67",
    "SGX OT Modbus PLC Firmware Upload FC68",
];
const MODBUS_RULE_4_SIGNATURES: &[&str] = &["SGX OT Modbus Exception Response Detected"];
const MODBUS_RULE_5_SIGNATURES: &[&str] = &["SGX OT Modbus Write Command Time Audit"];

const MODBUS_RULES: &[ModbusRuleSpec] = &[
    ModbusRuleSpec {
        rule_id: 1,
        name: "Unauthorized Write to PLC Coils",
        function_codes: &["FC5", "FC15"],
        signature_ids: MODBUS_RULE_1_SIGNATURE_IDS,
        signatures: MODBUS_RULE_1_SIGNATURES,
    },
    ModbusRuleSpec {
        rule_id: 2,
        name: "Write to Safety-Critical Holding Registers",
        function_codes: &["FC6", "FC16"],
        signature_ids: MODBUS_RULE_2_SIGNATURE_IDS,
        signatures: MODBUS_RULE_2_SIGNATURES,
    },
    ModbusRuleSpec {
        rule_id: 3,
        name: "PLC Firmware/Program Upload",
        function_codes: &["FC65", "FC66", "FC67", "FC68"],
        signature_ids: MODBUS_RULE_3_SIGNATURE_IDS,
        signatures: MODBUS_RULE_3_SIGNATURES,
    },
    ModbusRuleSpec {
        rule_id: 4,
        name: "Modbus Exception Response Detection",
        function_codes: &["FC129"],
        signature_ids: MODBUS_RULE_4_SIGNATURE_IDS,
        signatures: MODBUS_RULE_4_SIGNATURES,
    },
    ModbusRuleSpec {
        rule_id: 5,
        name: "Write Command Time Audit",
        function_codes: &["FC5"],
        signature_ids: MODBUS_RULE_5_SIGNATURE_IDS,
        signatures: MODBUS_RULE_5_SIGNATURES,
    },
];

fn modbus_rule_matches(spec: &ModbusRuleSpec, alert: &ThreatAlert) -> bool {
    spec.signature_ids.contains(&alert.signature_id)
        || spec
            .signatures
            .iter()
            .any(|signature| *signature == alert.signature)
}

async fn nft_blocked_ips() -> Result<Vec<String>, ApiError> {
    let output = tokio::process::Command::new("nft")
        .args(["-a", "list", "chain", "inet", "sgx_threat", "input"])
        .output()
        .await
        .map_err(|err| ApiError::Internal(format!("nft list: {}", err)))?;

    if !output.status.success() {
        return Ok(Vec::new());
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(text
        .lines()
        .filter_map(parse_nft_block_ip)
        .collect::<Vec<_>>())
}

fn parse_nft_block_ip(line: &str) -> Option<String> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    tokens
        .windows(3)
        .find(|window| (window[0] == "ip" || window[0] == "ip6") && window[1] == "saddr")
        .map(|window| window[2].trim_end_matches(',').to_string())
}

#[derive(Deserialize)]
pub struct AdvisoryQuery {
    pub status: Option<String>,
}

pub async fn list_advisories(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AdvisoryQuery>,
) -> Result<Json<Vec<SecurityAdvisory>>, ApiError> {
    let store = state.advisory_store.lock().await;
    let filter = query.status.as_deref().and_then(|s| match s {
        "pending" => Some(AdvisoryStatus::Pending),
        "auto_executed" => Some(AdvisoryStatus::AutoExecuted),
        "approved" => Some(AdvisoryStatus::Approved),
        "rejected" => Some(AdvisoryStatus::Rejected),
        _ => None,
    });
    Ok(Json(store.list(filter)))
}

pub async fn get_advisory(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SecurityAdvisory>, ApiError> {
    let store = state.advisory_store.lock().await;
    match store.get_by_id(&id) {
        Some(advisory) => Ok(Json(advisory.clone())),
        None => Err(ApiError::NotFound(format!("Advisory {} not found", id))),
    }
}

pub async fn approve_advisory(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SecurityAdvisory>, ApiError> {
    let mut store = state.advisory_store.lock().await;
    match store.approve(&id) {
        Some(advisory) => {
            log_audit(
                &state.node_id,
                AuditCategory::Network,
                AuditSeverity::Info,
                AuditAction::Applied,
                &format!("advisory {} approved by admin: {}", id, advisory.title),
            );
            Ok(Json(advisory))
        }
        None => Err(ApiError::NotFound(format!(
            "Pending advisory {} not found",
            id
        ))),
    }
}

pub async fn reject_advisory(
    State(state): State<Arc<AppState>>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<SecurityAdvisory>, ApiError> {
    let mut store = state.advisory_store.lock().await;
    match store.reject(&id) {
        Some(advisory) => {
            log_audit(
                &state.node_id,
                AuditCategory::Network,
                AuditSeverity::Info,
                AuditAction::Rejected,
                &format!("advisory {} rejected by admin: {}", id, advisory.title),
            );
            Ok(Json(advisory))
        }
        None => Err(ApiError::NotFound(format!(
            "Pending advisory {} not found",
            id
        ))),
    }
}
