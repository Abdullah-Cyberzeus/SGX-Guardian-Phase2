use super::dkp::{ActionResponse, run_cli};
use crate::api::{error::ApiError, state::AppState};
use crate::threat::{
    blocker::load_block_records,
    config::{BlockMode, SuricataConfig},
    threat_alert::{Severity, ThreatAlert},
};
use axum::{
    Json,
    extract::{Path as AxumPath, Query, State},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
    pub severity: Option<String>,
}

#[derive(Serialize)]
pub struct ThreatAlertView {
    #[serde(flatten)]
    pub alert: ThreatAlert,
    pub archived: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct AlertStateFile {
    #[serde(default)]
    archived: BTreeSet<String>,
}

#[derive(Serialize)]
pub struct AlertActionResponse {
    pub success: bool,
    pub alert_id: String,
    pub archived: bool,
}

pub async fn list_alerts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AlertsQuery>,
) -> Result<Json<Vec<ThreatAlertView>>, ApiError> {
    let mut alerts = load_alerts(&state).await?;
    let alert_state = load_alert_state(&state).await?;

    if let Some(severity) = query.severity.as_deref() {
        alerts.retain(|alert| severity_matches(alert.severity, severity));
    }

    let limit = query.limit.unwrap_or(500).min(10_000);
    if alerts.len() > limit {
        alerts.drain(..alerts.len() - limit);
    }

    Ok(Json(
        alerts
            .into_iter()
            .map(|mut alert| {
                let event_alert_id = event_alert_id(&alert);
                alert.alert_id = event_alert_id.clone();

                ThreatAlertView {
                    archived: alert_state.archived.contains(&event_alert_id),
                    alert,
                }
            })
            .collect(),
    ))
}

pub async fn archive_alert(
    State(state): State<Arc<AppState>>,
    AxumPath(alert_id): AxumPath<String>,
) -> Result<Json<AlertActionResponse>, ApiError> {
    ensure_alert_exists(&state, &alert_id).await?;
    let mut alert_state = load_alert_state(&state).await?;
    alert_state.archived.insert(alert_id.clone());
    save_alert_state(&state, &alert_state).await?;
    Ok(Json(AlertActionResponse {
        success: true,
        alert_id,
        archived: true,
    }))
}

pub async fn restore_alert(
    State(state): State<Arc<AppState>>,
    AxumPath(alert_id): AxumPath<String>,
) -> Result<Json<AlertActionResponse>, ApiError> {
    ensure_alert_exists(&state, &alert_id).await?;
    let mut alert_state = load_alert_state(&state).await?;
    alert_state.archived.remove(&alert_id);
    save_alert_state(&state, &alert_state).await?;
    Ok(Json(AlertActionResponse {
        success: true,
        alert_id,
        archived: false,
    }))
}

pub async fn delete_alert(
    State(state): State<Arc<AppState>>,
    AxumPath(alert_id): AxumPath<String>,
) -> Result<Json<AlertActionResponse>, ApiError> {
    let mut alerts = load_alerts(&state).await?;
    let before = alerts.len();
    alerts.retain(|alert| !alert_id_matches(alert, &alert_id));
    if alerts.len() == before {
        return Err(ApiError::NotFound("alert not found".into()));
    }

    let path = alerts_path(&state);
    let content = alerts
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| ApiError::Internal(format!("failed to serialize alerts: {err}")))?
        .join("\n");
    tokio::fs::write(
        &path,
        if content.is_empty() {
            content
        } else {
            format!("{content}\n")
        },
    )
    .await
    .map_err(|err| ApiError::Internal(format!("failed to write {}: {err}", path.display())))?;

    let mut alert_state = load_alert_state(&state).await?;
    alert_state.archived.remove(&alert_id);
    save_alert_state(&state, &alert_state).await?;
    Ok(Json(AlertActionResponse {
        success: true,
        alert_id,
        archived: false,
    }))
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

/// Live threat summary consumed by the dashboard.
///
/// The score is deliberately derived only from persisted alerts rather than
/// synthetic/demo values. Recent unblocked alerts carry their full severity
/// weight; an alert that Guardian blocked still carries a smaller residual
/// weight so a mitigated incident remains visible in the health score.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ThreatIntelResponse {
    pub score: u8,
    pub threats_24h: usize,
    pub blocked: usize,
    pub last_updated: String,
}

pub async fn threat_intel(
    State(state): State<Arc<AppState>>,
) -> Result<Json<ThreatIntelResponse>, ApiError> {
    let now = Utc::now();
    let alerts = load_alerts(&state).await?;
    let blocked = active_block_count(&state).await;

    Ok(Json(summarize_threat_intel(&alerts, blocked, now)))
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
    let path = alerts_path(state);
    let bytes = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(ApiError::Internal(format!(
                "failed to read {}: {}",
                path.display(),
                err
            )));
        }
    };

    Ok(bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .filter_map(|line| serde_json::from_slice(line).ok())
        .collect())
}

fn alerts_path(state: &AppState) -> PathBuf {
    PathBuf::from(&state.threat_state_dir).join("alerts.jsonl")
}

fn alert_state_path(state: &AppState) -> PathBuf {
    PathBuf::from(&state.threat_state_dir).join("alert_state.json")
}

fn event_alert_id(alert: &ThreatAlert) -> String {
    format!("{}-{}", alert.alert_id, alert.timestamp.timestamp_millis())
}

fn alert_id_matches(alert: &ThreatAlert, candidate: &str) -> bool {
    alert.alert_id == candidate || event_alert_id(alert) == candidate
}

async fn ensure_alert_exists(state: &AppState, alert_id: &str) -> Result<(), ApiError> {
    if load_alerts(state)
        .await?
        .iter()
        .any(|alert| alert_id_matches(alert, alert_id))
    {
        Ok(())
    } else {
        Err(ApiError::NotFound("alert not found".into()))
    }
}

async fn load_alert_state(state: &AppState) -> Result<AlertStateFile, ApiError> {
    let path = alert_state_path(state);
    match tokio::fs::read(&path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|err| {
            ApiError::Internal(format!("failed to parse {}: {err}", path.display()))
        }),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(AlertStateFile::default()),
        Err(err) => Err(ApiError::Internal(format!(
            "failed to read {}: {err}",
            path.display()
        ))),
    }
}

async fn save_alert_state(state: &AppState, alert_state: &AlertStateFile) -> Result<(), ApiError> {
    let path = alert_state_path(state);
    tokio::fs::create_dir_all(&state.threat_state_dir)
        .await
        .map_err(|err| {
            ApiError::Internal(format!("failed to create threat state directory: {err}"))
        })?;
    let contents = serde_json::to_vec_pretty(alert_state)
        .map_err(|err| ApiError::Internal(format!("failed to serialize alert state: {err}")))?;
    tokio::fs::write(&path, contents)
        .await
        .map_err(|err| ApiError::Internal(format!("failed to write {}: {err}", path.display())))
}

async fn active_block_count(state: &AppState) -> usize {
    let mut blocked = nft_blocked_ips().await.unwrap_or_default();
    if blocked.is_empty() {
        let now = Utc::now().timestamp();
        let path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
        blocked = load_block_records(&path)
            .unwrap_or_default()
            .into_iter()
            .filter(|record| record.expires_at > now)
            .map(|record| record.ip)
            .collect();
    }
    blocked.sort();
    blocked.dedup();
    blocked.len()
}

fn summarize_threat_intel(
    alerts: &[ThreatAlert],
    blocked: usize,
    now: chrono::DateTime<Utc>,
) -> ThreatIntelResponse {
    let cutoff = now - chrono::Duration::hours(24);
    let recent = alerts
        .iter()
        .filter(|alert| alert.timestamp >= cutoff && alert.timestamp <= now)
        .collect::<Vec<_>>();

    let penalty = recent.iter().fold(0u32, |total, alert| {
        let weight = match (alert.severity, alert.blocked) {
            (Severity::Critical, false) => 25,
            (Severity::High, false) => 15,
            (Severity::Medium, false) => 8,
            (Severity::Low, false) => 3,
            (Severity::Info, false) => 1,
            (Severity::Critical, true) => 5,
            (Severity::High, true) => 3,
            (Severity::Medium, true) => 2,
            (Severity::Low, true) => 1,
            (Severity::Info, true) => 0,
        };
        total.saturating_add(weight)
    });

    ThreatIntelResponse {
        score: 100u8.saturating_sub(penalty.min(100) as u8),
        threats_24h: recent.len(),
        blocked,
        last_updated: now.to_rfc3339(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::threat_alert::ThreatCategory;

    fn alert_at(
        severity: Severity,
        blocked: bool,
        timestamp: chrono::DateTime<Utc>,
    ) -> ThreatAlert {
        ThreatAlert {
            alert_id: format!("{:?}-{}", severity, timestamp.timestamp()),
            timestamp,
            src_ip: "198.51.100.10".into(),
            src_port: 1234,
            dst_ip: "192.0.2.10".into(),
            dst_port: 443,
            protocol: "TCP".into(),
            signature_id: 1,
            signature: "test threat".into(),
            category: ThreatCategory::Other,
            severity,
            rev: 1,
            gid: 1,
            event_type: "alert".into(),
            blocked,
        }
    }

    #[test]
    fn threat_intel_uses_only_last_24_hours_and_real_block_count() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-19T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let alerts = vec![
            alert_at(Severity::Critical, false, now - chrono::Duration::hours(1)),
            alert_at(Severity::High, true, now - chrono::Duration::hours(2)),
            alert_at(Severity::Critical, false, now - chrono::Duration::hours(25)),
            alert_at(
                Severity::Critical,
                false,
                now + chrono::Duration::minutes(1),
            ),
        ];

        let summary = summarize_threat_intel(&alerts, 4, now);

        assert_eq!(summary.score, 72);
        assert_eq!(summary.threats_24h, 2);
        assert_eq!(summary.blocked, 4);
        assert_eq!(summary.last_updated, "2026-08-19T12:00:00+00:00");
    }

    #[test]
    fn threat_intel_score_is_bounded_at_zero() {
        let now = Utc::now();
        let alerts = (0..5)
            .map(|_| alert_at(Severity::Critical, false, now))
            .collect::<Vec<_>>();

        assert_eq!(summarize_threat_intel(&alerts, 0, now).score, 0);
    }

    #[test]
    fn threat_intel_serializes_frontend_field_names() {
        let now = Utc::now();
        let value = serde_json::to_value(summarize_threat_intel(&[], 0, now)).unwrap();

        assert_eq!(value["score"], 100);
        assert_eq!(value["threats24h"], 0);
        assert_eq!(value["blocked"], 0);
        assert!(value.get("lastUpdated").is_some());
    }

    #[test]
    fn event_alert_ids_are_unique_per_alert_timestamp() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-08-19T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let first = alert_at(Severity::High, false, now);
        let second = alert_at(
            Severity::High,
            false,
            now + chrono::Duration::milliseconds(1),
        );

        assert_eq!(first.alert_id, second.alert_id);
        assert_ne!(event_alert_id(&first), event_alert_id(&second));
        assert!(alert_id_matches(&first, &first.alert_id));
        assert!(alert_id_matches(&first, &event_alert_id(&first)));
        assert!(!alert_id_matches(&first, &event_alert_id(&second)));
    }
}
