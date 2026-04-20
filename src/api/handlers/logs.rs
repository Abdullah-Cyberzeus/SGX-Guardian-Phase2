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
    let n = q.tail.unwrap_or(100).min(1000);

    let mut candidate: Option<std::path::PathBuf> = None;
    for dir in [&s.log_dir_primary, &s.log_dir_fallback] {
        if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
            let mut newest_mtime: Option<std::time::SystemTime> = None;
            while let Some(e) = rd.next_entry().await? {
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
                    candidate = Some(e.path());
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
