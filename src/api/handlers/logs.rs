use crate::api::{error::ApiError, state::AppState};
use axum::{
    extract::{Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};

#[derive(Deserialize)]
pub struct LogsQuery {
    pub node: Option<String>,
    pub tail: Option<usize>,
    pub level: Option<String>,
    pub search: Option<String>,
}

#[derive(Serialize)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct LogsResponse {
    pub node: String,
    pub file: String,
    pub entries: Vec<LogEntry>,
    pub total: usize,
    pub timestamp: String,
}

pub async fn tail(
    State(s): State<Arc<AppState>>,
    Query(q): Query<LogsQuery>,
) -> Result<Json<LogsResponse>, ApiError> {
    let node = q.node.unwrap_or_else(|| s.node_id.clone());
    if !is_valid_node_id(&node) {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }
    let n = q.tail.unwrap_or(100).min(1000);

    let mut candidate: Option<std::path::PathBuf> = None;
    for dir in [&s.log_dir_primary, &s.log_dir_fallback] {
        let base_dir = match tokio::fs::canonicalize(dir).await {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
            let mut newest_mtime: Option<std::time::SystemTime> = None;
            while let Some(e) = rd.next_entry().await? {
                let resolved = match tokio::fs::canonicalize(e.path()).await {
                    Ok(p) => p,
                    Err(_) => continue,
                };
                if !resolved.starts_with(&base_dir) {
                    continue;
                }
                let name = e.file_name().to_string_lossy().to_string();
                if !name.starts_with(&node) {
                    continue;
                }
                let meta = match e.metadata().await {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let mt = meta.modified().ok();
                if mt > newest_mtime {
                    newest_mtime = mt;
                    candidate = Some(resolved);
                }
            }
        }
        if candidate.is_some() {
            break;
        }
    }
    let path =
        candidate.ok_or_else(|| ApiError::NotFound(format!("no log file for node {}", node)))?;
    let file = path.to_string_lossy().to_string();

    let f = tokio::fs::File::open(&path).await?;
    let mut reader = BufReader::new(f).lines();
    let mut all: Vec<String> = Vec::new();
    while let Some(line) = reader.next_line().await? {
        all.push(line);
    }

    let start = all.len().saturating_sub(n);
    let mut entries: Vec<LogEntry> = all[start..].iter().map(|raw| parse_log_line(raw)).collect();

    if let Some(lvl) = q.level.as_deref() {
        if lvl != "all" {
            entries.retain(|e| e.level.eq_ignore_ascii_case(lvl));
        }
    }
    if let Some(needle) = q.search.as_deref() {
        let n = needle.to_lowercase();
        entries.retain(|e| e.message.to_lowercase().contains(&n));
    }

    let total = entries.len();
    Ok(Json(LogsResponse {
        node,
        file,
        entries,
        total,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }))
}

fn is_valid_node_id(node: &str) -> bool {
    !node.is_empty()
        && !node.contains("..")
        && !node.contains('/')
        && !node.contains('\\')
        && node
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

fn parse_log_line(raw: &str) -> LogEntry {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) {
        return LogEntry {
            timestamp: v
                .get("timestamp")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            level: v
                .get("level")
                .and_then(|x| x.as_str())
                .unwrap_or("info")
                .to_string(),
            message: v
                .get("fields")
                .and_then(|f| f.get("message"))
                .and_then(|x| x.as_str())
                .or_else(|| v.get("message").and_then(|x| x.as_str()))
                .unwrap_or(raw)
                .to_string(),
        };
    }
    LogEntry {
        timestamp: "".into(),
        level: "info".into(),
        message: raw.to_string(),
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct AuditLogEntry {
    pub event: crate::audit::event::AuditEvent,
    pub hash: String,
    pub previous_hash: String,
}

#[derive(serde::Deserialize)]
pub struct AuditLogsQuery {
    pub category: Option<String>,
    pub search: Option<String>,
    pub node: Option<String>,
    pub severity: Option<String>,
    pub tail: Option<usize>,
}

#[derive(serde::Serialize)]
pub struct AuditLogsResponse {
    pub status: String,
    pub count: usize,
    pub items: Vec<AuditLogEntry>,
}

fn resolve_audit_log_path_for_node(node: &str, state: &AppState) -> Result<std::path::PathBuf, ApiError> {
    if let Ok(path) = std::env::var("SGX_GUARDIAN_AUDIT_LOG_PATH") {
        let explicit = std::path::PathBuf::from(path);
        if explicit.exists() {
            return Ok(explicit);
        }
    }

    for dir in [&state.log_dir_primary, &state.log_dir_fallback] {
        let directory = std::path::PathBuf::from(dir);
        if !directory.exists() {
            continue;
        }
        let file_path = directory.join(format!("audit-{}.log", node));
        if file_path.exists() {
            return Ok(file_path);
        }
    }

    // Also check for legacy audit.log
    for dir in [&state.log_dir_primary, &state.log_dir_fallback] {
        let directory = std::path::PathBuf::from(dir);
        if !directory.exists() {
            continue;
        }
        let legacy = directory.join("audit.log");
        if legacy.exists() {
            return Ok(legacy);
        }
    }

    Err(ApiError::NotFound(format!("no audit log file found for node {}", node)))
}

fn category_matches(category_enum: &crate::audit::event::AuditCategory, query: &str) -> bool {
    if let Ok(val) = serde_json::to_value(category_enum) {
        if let Some(s) = val.as_str() {
            return s.eq_ignore_ascii_case(query);
        }
    }
    false
}

fn severity_matches(severity_enum: &crate::audit::event::AuditSeverity, query: &str) -> bool {
    let query_lower = query.to_lowercase();
    match severity_enum {
        crate::audit::event::AuditSeverity::Info => query_lower == "info",
        crate::audit::event::AuditSeverity::Warning => query_lower == "warn" || query_lower == "warning",
        crate::audit::event::AuditSeverity::Critical => query_lower == "error" || query_lower == "critical",
    }
}

pub async fn audit_logs(
    State(s): State<Arc<AppState>>,
    Query(q): Query<AuditLogsQuery>,
) -> Result<Json<AuditLogsResponse>, ApiError> {
    let node = q.node.unwrap_or_else(|| s.node_id.clone());
    if !is_valid_node_id(&node) {
        return Err(ApiError::BadRequest(format!("invalid node name: {}", node)));
    }

    let path = resolve_audit_log_path_for_node(&node, &s)?;
    let f = tokio::fs::File::open(&path).await?;
    let mut reader = BufReader::new(f).lines();
    let mut all_entries: Vec<AuditLogEntry> = Vec::new();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<AuditLogEntry>(&line) {
            all_entries.push(entry);
        }
    }

    // Apply filters
    if let Some(cat) = q.category.as_deref() {
        all_entries.retain(|item| category_matches(&item.event.category, cat));
    }

    if let Some(sev) = q.severity.as_deref() {
        if !sev.eq_ignore_ascii_case("all") {
            all_entries.retain(|item| severity_matches(&item.event.severity, sev));
        }
    }

    if let Some(needle) = q.search.as_deref() {
        let n = needle.to_lowercase();
        all_entries.retain(|item| item.event.message.to_lowercase().contains(&n));
    }

    // Return newest first (reverse chronological order)
    all_entries.reverse();

    // Apply tail limits
    if let Some(limit) = q.tail {
        all_entries.truncate(limit.min(1000));
    }

    let count = all_entries.len();
    Ok(Json(AuditLogsResponse {
        status: "success".to_string(),
        count,
        items: all_entries,
    }))
}

