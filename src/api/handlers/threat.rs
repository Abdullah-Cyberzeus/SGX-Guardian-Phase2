use super::dkp::{run_cli, ActionResponse};
use crate::api::{error::ApiError, state::AppState};
use crate::threat::{
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
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct AlertsQuery {
    pub limit: Option<usize>,
    pub severity: Option<String>,
}

#[derive(Debug, Serialize)]
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
    let now = Utc::now().timestamp();
    let path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
    blocked.extend(
        load_block_records(&path)
            .unwrap_or_default()
            .into_iter()
            .filter(|record| record.expires_at > now)
            .map(|record| record.ip),
    );
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
    let now = Utc::now().timestamp();
    let path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
    blocked.extend(
        load_block_records(&path)
            .unwrap_or_default()
            .into_iter()
            .filter(|record| record.expires_at > now)
            .map(|record| record.ip),
    );
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

    // ── severity_matches ────────────────────────────────────────────────────

    #[test]
    fn severity_matches_is_case_insensitive_on_as_str() {
        assert!(severity_matches(Severity::Critical, "critical"));
        assert!(severity_matches(Severity::Critical, "CRITICAL"));
        assert!(severity_matches(Severity::Critical, "Critical"));
    }

    #[test]
    fn severity_matches_also_accepts_debug_repr() {
        // as_str() gives "high"; Debug gives "High" — both should match.
        assert!(severity_matches(Severity::High, "High"));
    }

    #[test]
    fn severity_matches_rejects_unrelated_severity() {
        assert!(!severity_matches(Severity::Low, "high"));
        assert!(!severity_matches(Severity::Info, "critical"));
    }

    // ── modbus_rule_matches ─────────────────────────────────────────────────

    #[test]
    fn modbus_rule_matches_by_signature_id() {
        let alert = ThreatAlert {
            signature_id: 10000201,
            signature: "unrelated text".into(),
            ..alert_at(Severity::High, false, Utc::now())
        };
        assert!(modbus_rule_matches(&MODBUS_RULES[0], &alert));
    }

    #[test]
    fn modbus_rule_matches_by_signature_text() {
        let alert = ThreatAlert {
            signature_id: 0,
            signature: MODBUS_RULE_1_SIGNATURES[1].to_string(),
            ..alert_at(Severity::High, false, Utc::now())
        };
        assert!(modbus_rule_matches(&MODBUS_RULES[0], &alert));
    }

    #[test]
    fn modbus_rule_does_not_match_unrelated_alert() {
        let alert = ThreatAlert {
            signature_id: 99,
            signature: "totally unrelated".into(),
            ..alert_at(Severity::High, false, Utc::now())
        };
        assert!(!modbus_rule_matches(&MODBUS_RULES[0], &alert));
    }

    // ── parse_nft_block_ip ──────────────────────────────────────────────────

    #[test]
    fn parse_nft_block_ip_extracts_ipv4_saddr() {
        let line = "        ip saddr 203.0.113.5 counter packets 1 bytes 60 drop # handle 4";
        assert_eq!(parse_nft_block_ip(line), Some("203.0.113.5".to_string()));
    }

    #[test]
    fn parse_nft_block_ip_extracts_ipv6_saddr_and_strips_trailing_comma() {
        let line = "ip6 saddr fe80::1, drop # handle 9";
        assert_eq!(parse_nft_block_ip(line), Some("fe80::1".to_string()));
    }

    #[test]
    fn parse_nft_block_ip_returns_none_when_no_saddr_present() {
        let line = "chain input { type filter hook input priority -10; }";
        assert_eq!(parse_nft_block_ip(line), None);
    }

    // ── load_alerts / list_alerts / modbus_alerts (filesystem-backed) ───────

    fn test_state(temp: &tempfile::TempDir) -> Arc<AppState> {
        let config_dir = temp.path().join("config");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        AppState::for_tests(temp.path(), "nodeA", config_dir.display().to_string())
    }

    fn write_alerts_jsonl(state: &AppState, alerts: &[ThreatAlert]) {
        let path = PathBuf::from(&state.threat_state_dir).join("alerts.jsonl");
        let mut body = String::new();
        for alert in alerts {
            body.push_str(&serde_json::to_string(alert).unwrap());
            body.push('\n');
        }
        std::fs::write(path, body).expect("write alerts.jsonl");
    }

    #[tokio::test]
    async fn load_alerts_returns_empty_vec_when_file_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        let alerts = load_alerts(&state).await.expect("load_alerts");
        assert!(alerts.is_empty());
    }

    #[tokio::test]
    async fn load_alerts_skips_malformed_json_lines() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        let good = alert_at(Severity::High, false, Utc::now());
        let path = PathBuf::from(&state.threat_state_dir).join("alerts.jsonl");
        let body = format!(
            "{}\nnot valid json\n\n{}\n",
            serde_json::to_string(&good).unwrap(),
            serde_json::to_string(&good).unwrap()
        );
        std::fs::write(path, body).expect("write alerts.jsonl");

        let alerts = load_alerts(&state).await.expect("load_alerts");
        assert_eq!(alerts.len(), 2);
    }

    #[tokio::test]
    async fn list_alerts_filters_by_severity_and_honors_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        let now = Utc::now();
        let alerts = vec![
            alert_at(Severity::Critical, false, now),
            alert_at(Severity::Low, false, now),
            alert_at(Severity::Critical, true, now),
        ];
        write_alerts_jsonl(&state, &alerts);

        let axum::Json(all) = list_alerts(
            State(state.clone()),
            Query(AlertsQuery {
                limit: None,
                severity: None,
            }),
        )
        .await
        .expect("list_alerts");
        assert_eq!(all.len(), 3);

        let axum::Json(critical_only) = list_alerts(
            State(state.clone()),
            Query(AlertsQuery {
                limit: None,
                severity: Some("critical".into()),
            }),
        )
        .await
        .expect("list_alerts filtered");
        assert_eq!(critical_only.len(), 2);
        assert!(critical_only
            .iter()
            .all(|a| matches!(a.alert.severity, Severity::Critical)));

        let axum::Json(limited) = list_alerts(
            State(state.clone()),
            Query(AlertsQuery {
                limit: Some(1),
                severity: None,
            }),
        )
        .await
        .expect("list_alerts limited");
        assert_eq!(limited.len(), 1);
    }

    #[tokio::test]
    async fn modbus_alerts_groups_matches_per_rule_and_dedups_signatures() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        let now = Utc::now();
        let mut matching = alert_at(Severity::High, false, now);
        matching.signature_id = MODBUS_RULE_1_SIGNATURE_IDS[0];
        matching.signature = MODBUS_RULE_1_SIGNATURES[0].to_string();
        let mut matching2 = matching.clone();
        matching2.alert_id = "second".into();
        let mut unrelated = alert_at(Severity::Low, false, now);
        unrelated.signature_id = 42;
        unrelated.signature = "unrelated".into();

        write_alerts_jsonl(&state, &[matching, matching2, unrelated]);

        let axum::Json(response) = modbus_alerts(State(state)).await.expect("modbus_alerts");

        assert_eq!(response.total_matches, 2);
        let rule1 = response
            .rules
            .iter()
            .find(|r| r.rule_id == 1)
            .expect("rule 1 present");
        assert!(rule1.matched);
        assert_eq!(rule1.match_count, 2);
        assert_eq!(rule1.matched_signatures.len(), 1);

        let rule2 = response
            .rules
            .iter()
            .find(|r| r.rule_id == 2)
            .expect("rule 2 present");
        assert!(!rule2.matched);
        assert_eq!(rule2.match_count, 0);
    }

    #[tokio::test]
    async fn modbus_alerts_returns_empty_summary_when_alerts_file_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);

        let axum::Json(response) = modbus_alerts(State(state))
            .await
            .expect("modbus_alerts on missing file");

        assert_eq!(response.total_matches, 0);
        assert!(response.rules.iter().all(|r| !r.matched));
    }

    // ── list_blocks / active_block_count (blocked_ips.json fallback path) ───

    fn write_block_records(state: &AppState, records: &[crate::threat::blocker::BlockRecord]) {
        let path = PathBuf::from(&state.threat_state_dir).join("blocked_ips.json");
        std::fs::write(path, serde_json::to_vec_pretty(records).unwrap())
            .expect("write blocked_ips.json");
    }

    #[tokio::test]
    async fn list_blocks_falls_back_to_file_and_dedups_sorted() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        write_block_records(
            &state,
            &[
                crate::threat::blocker::BlockRecord {
                    ip: "203.0.113.9".into(),
                    expires_at: Utc::now().timestamp() + 3600,
                },
                crate::threat::blocker::BlockRecord {
                    ip: "203.0.113.1".into(),
                    expires_at: Utc::now().timestamp() + 3600,
                },
            ],
        );

        let axum::Json(response) = list_blocks(State(state)).await.expect("list_blocks");
        assert_eq!(
            response.blocked,
            vec!["203.0.113.1".to_string(), "203.0.113.9".to_string()]
        );
    }

    #[tokio::test]
    async fn list_blocks_is_empty_when_no_state_and_no_nft_rules() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        let axum::Json(response) = list_blocks(State(state)).await.expect("list_blocks");
        assert!(response.blocked.is_empty());
    }

    #[tokio::test]
    async fn threat_intel_excludes_expired_blocks_from_active_count() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        let now_ts = Utc::now().timestamp();
        write_block_records(
            &state,
            &[
                crate::threat::blocker::BlockRecord {
                    ip: "203.0.113.20".into(),
                    expires_at: now_ts + 3600,
                },
                crate::threat::blocker::BlockRecord {
                    ip: "203.0.113.21".into(),
                    expires_at: now_ts - 10,
                },
            ],
        );

        let axum::Json(response) = threat_intel(State(state)).await.expect("threat_intel");
        assert_eq!(response.blocked, 1);
    }

    // ── get_config / set_config ──────────────────────────────────────────────

    #[tokio::test]
    async fn get_config_returns_defaults_when_file_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        let axum::Json(cfg) = get_config(State(state)).await.expect("get_config");
        assert!(!cfg.enabled);
        assert_eq!(cfg.block_mode.as_str(), "alert_only");
    }

    #[tokio::test]
    async fn set_config_persists_patched_fields() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);

        let axum::Json(action) = set_config(
            State(state.clone()),
            Json(ThreatConfigPatch {
                enabled: Some(true),
                block_mode: Some(BlockMode::InlineBlock),
                rule_update_hours: Some(12),
                block_ttl_secs: Some(120),
                block_exempt: Some(vec!["10.0.0.0/8".into()]),
            }),
        )
        .await
        .expect("set_config");
        assert!(action.success);

        let axum::Json(cfg) = get_config(State(state)).await.expect("get_config reload");
        assert!(cfg.enabled);
        assert_eq!(cfg.block_mode.as_str(), "inline_block");
        assert_eq!(cfg.rule_update_hours, 12);
        assert_eq!(cfg.block_ttl_secs, 120);
        assert_eq!(cfg.block_exempt, vec!["10.0.0.0/8".to_string()]);
    }

    #[tokio::test]
    async fn set_config_rejects_invalid_ttl_with_bad_request() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);

        let err = set_config(
            State(state),
            Json(ThreatConfigPatch {
                enabled: None,
                block_mode: None,
                rule_update_hours: None,
                block_ttl_secs: Some(0),
                block_exempt: None,
            }),
        )
        .await
        .expect_err("zero ttl must be rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[tokio::test]
    async fn set_config_rejects_invalid_cidr_in_exempt_list() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);

        let err = set_config(
            State(state),
            Json(ThreatConfigPatch {
                enabled: None,
                block_mode: None,
                rule_update_hours: None,
                block_ttl_secs: None,
                block_exempt: Some(vec!["not-a-cidr".into()]),
            }),
        )
        .await
        .expect_err("invalid cidr must be rejected");
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    // ── block_ip / unblock / update_rules / validate_config via sgx-pa-cli ──

    struct ScopedEnvVar {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl ScopedEnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            match self.previous.take() {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Writes an executable shell script standing in for `sgx-pa-cli` and
    /// points `SGX_PA_CLI_PATH` at it so `run_cli` never touches a real binary.
    fn install_fake_cli(temp: &tempfile::TempDir, exit_code: i32) -> ScopedEnvVar {
        use std::os::unix::fs::PermissionsExt;
        let script_path = temp.path().join("fake-sgx-pa-cli.sh");
        std::fs::write(
            &script_path,
            format!(
                "#!/bin/sh\necho \"args: $@\"\necho \"boom\" 1>&2\nexit {}\n",
                exit_code
            ),
        )
        .expect("write fake cli");
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fake cli");
        ScopedEnvVar::set(
            "SGX_PA_CLI_PATH",
            script_path.to_str().expect("script path"),
        )
    }

    #[tokio::test]
    async fn block_ip_reports_success_when_cli_exits_zero() {
        let _guard = crate::test_support::async_env_lock().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let _cli = install_fake_cli(&temp, 0);
        let state = test_state(&temp);

        let axum::Json(action) = block_ip(
            State(state),
            Json(BlockReq {
                ip: "203.0.113.55".into(),
            }),
        )
        .await
        .expect("block_ip");

        assert!(action.success);
        assert!(action.stdout.contains("203.0.113.55"));
    }

    #[tokio::test]
    async fn unblock_reports_failure_when_cli_exits_nonzero() {
        let _guard = crate::test_support::async_env_lock().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let _cli = install_fake_cli(&temp, 1);
        let state = test_state(&temp);

        let axum::Json(action) = unblock(
            State(state),
            Json(UnblockReq {
                ip: "203.0.113.56".into(),
            }),
        )
        .await
        .expect("unblock (CLI reports failure but the endpoint itself succeeds)");

        assert!(!action.success);
        assert!(action.stderr.contains("boom"));
    }

    #[tokio::test]
    async fn update_rules_and_validate_config_surface_cli_output() {
        let _guard = crate::test_support::async_env_lock().await;
        let temp = tempfile::tempdir().expect("tempdir");
        let _cli = install_fake_cli(&temp, 0);
        let state = test_state(&temp);

        let axum::Json(update) = update_rules(State(state.clone()))
            .await
            .expect("update_rules");
        assert!(update.success);

        let axum::Json(validate) = validate_config(State(state))
            .await
            .expect("validate_config");
        assert!(validate.success);
    }

    #[tokio::test]
    async fn block_ip_returns_internal_error_when_cli_binary_is_missing() {
        let _guard = crate::test_support::async_env_lock().await;
        let temp = tempfile::tempdir().expect("tempdir");
        // Point SGX_PA_CLI_PATH at a nonexistent file so resolve_pa_cli_path's
        // override branch fails; on a normal dev/CI machine none of the other
        // lookup strategies (PATH, exe-sibling, fixed install paths) resolve
        // a real "sgx-pa-cli" either, so this deterministically surfaces the
        // BinaryMissing error path. (We deliberately do not mutate PATH here
        // since that would race with other tests running in parallel.)
        let _cli = ScopedEnvVar::set(
            "SGX_PA_CLI_PATH",
            temp.path().join("does-not-exist").to_str().unwrap(),
        );
        let state = test_state(&temp);

        let err = block_ip(
            State(state),
            Json(BlockReq {
                ip: "203.0.113.57".into(),
            }),
        )
        .await
        .expect_err("missing sgx-pa-cli must surface as an error");
        assert!(matches!(err, ApiError::Internal(_)));
    }

    // ── status / start (real systemctl) ──────────────────────────────────────

    #[tokio::test]
    async fn status_reports_real_systemctl_state_and_file_backed_counts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        write_alerts_jsonl(
            &state,
            &[
                alert_at(Severity::High, false, Utc::now()),
                alert_at(Severity::Low, false, Utc::now()),
            ],
        );
        write_block_records(
            &state,
            &[crate::threat::blocker::BlockRecord {
                ip: "203.0.113.99".into(),
                expires_at: Utc::now().timestamp() + 3600,
            }],
        );

        let axum::Json(response) = status(State(state)).await.expect("status");
        // Suricata genuinely isn't installed in this sandbox, so systemctl deterministically
        // reports "inactive" rather than hanging or requiring a real service.
        assert_eq!(response.suricata, "inactive");
        assert!(!response.enabled, "no config file written -> defaults");
        assert_eq!(response.alert_count, 2);
        assert_eq!(response.block_count, 1);
    }

    #[tokio::test]
    async fn start_reports_failure_when_systemctl_cannot_start_the_service() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);

        let axum::Json(action) = start(State(state)).await.expect("start");
        // There is no real suricata service (and no interactive systemd session) in this
        // sandbox, so the real `systemctl start` call fails deterministically rather than
        // ever actually starting anything.
        assert!(!action.success);
        assert!(!action.stderr.is_empty());
    }

    // ── load_alerts real I/O error (non-NotFound) ────────────────────────────

    #[tokio::test]
    async fn load_alerts_surfaces_a_real_io_error_that_is_not_file_not_found() {
        let temp = tempfile::tempdir().expect("tempdir");
        let state = test_state(&temp);
        // A directory where a file is expected produces a real "Is a directory" error, not
        // NotFound, exercising `load_alerts`'s generic-error branch deterministically.
        let path = PathBuf::from(&state.threat_state_dir).join("alerts.jsonl");
        std::fs::create_dir_all(&path).expect("create directory in place of alerts.jsonl");

        let err = load_alerts(&state)
            .await
            .expect_err("a directory can't be read as a file");
        assert!(matches!(err, ApiError::Internal(_)));

        let list_err = list_alerts(
            State(state),
            Query(AlertsQuery {
                limit: None,
                severity: None,
            }),
        )
        .await
        .expect_err("list_alerts must propagate the same error");
        assert!(matches!(list_err, ApiError::Internal(_)));
    }

    // ── summarize_threat_intel penalty matrix ────────────────────────────────

    #[test]
    fn summarize_threat_intel_covers_every_severity_and_blocked_combination() {
        let now = Utc::now();
        let cases = [
            (Severity::Critical, false, 25u32),
            (Severity::High, false, 15),
            (Severity::Medium, false, 8),
            (Severity::Low, false, 3),
            (Severity::Info, false, 1),
            (Severity::Critical, true, 5),
            (Severity::High, true, 3),
            (Severity::Medium, true, 2),
            (Severity::Low, true, 1),
            (Severity::Info, true, 0),
        ];
        for (severity, blocked, expected_penalty) in cases {
            let alerts = vec![alert_at(severity, blocked, now)];
            let summary = summarize_threat_intel(&alerts, 0, now);
            assert_eq!(
                summary.score,
                100u8.saturating_sub(expected_penalty as u8),
                "severity={severity:?} blocked={blocked}"
            );
        }
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
