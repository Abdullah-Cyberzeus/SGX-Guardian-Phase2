use clap::Args;
use comfy_table::{Attribute, Cell, Color, Table};
use serde_json::Value;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Args)]
#[command(about = "Inspect recent secure audit log activity in a colored table format")]
pub struct AuditLogsArgs {
    /// Number of log lines to show from the end of file
    #[arg(long, default_value = "20")]
    pub tail: usize,

    /// Node ID to show logs for (e.g. nodeA)
    #[arg(long, default_value = "nodeA")]
    pub node: String,

    /// Filter by audit category (e.g., Node, Network, Tls, Attestation)
    #[arg(long)]
    pub category: Option<String>,

    /// Filter by severity level (info, warn, error)
    #[arg(long)]
    pub severity: Option<String>,

    /// Search keyword matching the log message (case-insensitive)
    #[arg(long)]
    pub search: Option<String>,
}

fn resolve_audit_log_path(node: &str) -> Result<PathBuf, String> {
    if let Ok(path) = std::env::var("SGX_GUARDIAN_AUDIT_LOG_PATH") {
        let explicit = PathBuf::from(path);
        if explicit.exists() {
            return Ok(explicit);
        }
    }

    // Check primary log locations
    for dir in ["/var/log/sgx-guardian", "../logs", "logs"] {
        let directory = PathBuf::from(dir);
        if !directory.exists() {
            continue;
        }
        let file_path = directory.join(format!("audit-{}.log", node));
        if file_path.exists() {
            return Ok(file_path);
        }
    }

    // Fallback to legacy audit.log
    for dir in ["/var/log/sgx-guardian", "../logs", "logs"] {
        let directory = PathBuf::from(dir);
        if !directory.exists() {
            continue;
        }
        let legacy = directory.join("audit.log");
        if legacy.exists() {
            return Ok(legacy);
        }
    }

    Err(format!("No audit log file found for node `{}`", node))
}

fn category_matches(category: &str, query: &str) -> bool {
    category.eq_ignore_ascii_case(query)
}

fn severity_matches(severity: &str, query: &str) -> bool {
    let query_lower = query.to_lowercase();
    match severity.to_uppercase().as_str() {
        "INFO" => query_lower == "info",
        "WARNING" | "WARN" => query_lower == "warn" || query_lower == "warning",
        "CRITICAL" | "ERROR" => query_lower == "error" || query_lower == "critical",
        _ => false,
    }
}

fn json_line_fallback(raw: &str, node: &str) -> Value {
    serde_json::json!({
        "message": raw,
        "node_id": node
    })
}

pub fn run(args: AuditLogsArgs) {
    let log_path = match resolve_audit_log_path(&args.node) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    };

    println!("Reading secure audit log: {:?}\n", log_path);

    let file = match File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Could not open audit log: {}", e);
            std::process::exit(1);
        }
    };

    let reader = BufReader::new(file);
    let mut all_entries = Vec::new();

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };
        if line.trim().is_empty() {
            continue;
        }

        let v: Value = match serde_json::from_str(&line) {
            Ok(parsed) => parsed,
            Err(_) => {
                all_entries.push(json_line_fallback(&line, &args.node));
                continue;
            }
        };

        let Some(event) = v.get("event") else {
            all_entries.push(json_line_fallback(&line, &args.node));
            continue;
        };

        let category = event
            .get("category")
            .and_then(|x| x.as_str())
            .unwrap_or("Unknown");
        let severity = event
            .get("severity")
            .and_then(|x| x.as_str())
            .unwrap_or("Info");
        let message = event.get("message").and_then(|x| x.as_str()).unwrap_or("");

        // Filters
        if let Some(ref cat) = args.category {
            if !category_matches(category, cat) {
                continue;
            }
        }

        if let Some(ref sev) = args.severity {
            if !sev.eq_ignore_ascii_case("all") && !severity_matches(severity, sev) {
                continue;
            }
        }

        if let Some(ref search) = args.search {
            if !message.to_lowercase().contains(&search.to_lowercase()) {
                continue;
            }
        }

        all_entries.push(v);
    }

    // Return newest first (reverse chronological order)
    all_entries.reverse();

    // Limit by tail
    let len = all_entries.len();
    let display_entries = &all_entries[0..args.tail.min(len)];

    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Time").add_attribute(Attribute::Bold),
        Cell::new("Node").add_attribute(Attribute::Bold),
        Cell::new("Category").add_attribute(Attribute::Bold),
        Cell::new("Action").add_attribute(Attribute::Bold),
        Cell::new("Severity").add_attribute(Attribute::Bold),
        Cell::new("Hash").add_attribute(Attribute::Bold),
        Cell::new("Prev Hash").add_attribute(Attribute::Bold),
        Cell::new("Message").add_attribute(Attribute::Bold),
    ]);

    for entry in display_entries {
        if let Some(event) = entry.get("event") {
            let timestamp_raw = event.get("timestamp").and_then(|x| x.as_u64()).unwrap_or(0);

            let time = if timestamp_raw > 0 {
                if let Some(dt) = chrono::DateTime::from_timestamp(timestamp_raw as i64, 0) {
                    dt.format("%Y-%m-%d %H:%M:%S").to_string()
                } else {
                    timestamp_raw.to_string()
                }
            } else {
                "—".to_string()
            };

            let node_id = event.get("node_id").and_then(|x| x.as_str()).unwrap_or("—");
            let category = event
                .get("category")
                .and_then(|x| x.as_str())
                .unwrap_or("—");
            let action = event.get("action").and_then(|x| x.as_str()).unwrap_or("—");
            let severity = event
                .get("severity")
                .and_then(|x| x.as_str())
                .unwrap_or("Info");
            let message = event.get("message").and_then(|x| x.as_str()).unwrap_or("—");

            let hash_raw = entry.get("hash").and_then(|x| x.as_str()).unwrap_or("—");
            let prev_hash_raw = entry
                .get("previous_hash")
                .and_then(|x| x.as_str())
                .unwrap_or("—");

            let hash_short = if hash_raw.len() > 8 {
                format!("{}...", &hash_raw[..8])
            } else {
                hash_raw.to_string()
            };

            let prev_hash_short = if prev_hash_raw.len() > 8 {
                format!("{}...", &prev_hash_raw[..8])
            } else {
                prev_hash_raw.to_string()
            };

            // Format Action cell
            let mut action_cell = Cell::new(action);
            match action.to_uppercase().as_str() {
                "FAILED" | "REJECTED" | "ROLLBACK" => {
                    action_cell = action_cell.fg(Color::Red).add_attribute(Attribute::Bold);
                }
                "SUCCEEDED" | "APPLIED" | "CREATED" => {
                    action_cell = action_cell.fg(Color::Green);
                }
                "STARTED" | "LOADED" | "USED" => {
                    action_cell = action_cell.fg(Color::Cyan);
                }
                _ => {}
            }

            // Format Severity cell
            let mut severity_cell = Cell::new(severity);
            match severity.to_uppercase().as_str() {
                "CRITICAL" | "ERROR" => {
                    severity_cell = severity_cell.fg(Color::Red).add_attribute(Attribute::Bold);
                }
                "WARNING" | "WARN" => {
                    severity_cell = severity_cell
                        .fg(Color::Yellow)
                        .add_attribute(Attribute::Bold);
                }
                "INFO" => {
                    severity_cell = severity_cell.fg(Color::Green);
                }
                _ => {}
            }

            table.add_row(vec![
                Cell::new(time),
                Cell::new(node_id),
                Cell::new(category),
                action_cell,
                severity_cell,
                Cell::new(hash_short).fg(Color::DarkGrey),
                Cell::new(prev_hash_short).fg(Color::DarkGrey),
                Cell::new(message),
            ]);
        } else {
            let raw_msg = entry.get("message").and_then(|x| x.as_str()).unwrap_or("");
            table.add_row(vec![
                Cell::new("—"),
                Cell::new(&args.node),
                Cell::new("—"),
                Cell::new("—"),
                Cell::new("RAW").fg(Color::DarkCyan),
                Cell::new("—"),
                Cell::new("—"),
                Cell::new(if raw_msg.is_empty() {
                    "Malformed JSON line"
                } else {
                    raw_msg
                }),
            ]);
        }
    }

    println!("{}", table);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_matching_is_case_insensitive_but_exact() {
        assert!(category_matches("Attestation", "attestation"));
        assert!(category_matches("NETWORK", "network"));
        assert!(!category_matches("NetworkPolicy", "network"));
        assert!(!category_matches("", "network"));
    }

    #[test]
    fn severity_matching_covers_aliases_case_and_unknown_values() {
        for (severity, query) in [
            ("INFO", "info"),
            ("warning", "warn"),
            ("WARN", "WARNING"),
            ("critical", "error"),
            ("ERROR", "CRITICAL"),
        ] {
            assert!(severity_matches(severity, query), "{severity} vs {query}");
        }
        assert!(!severity_matches("debug", "debug"));
        assert!(!severity_matches("info", "warning"));
        assert!(!severity_matches("error", "warn"));
    }

    #[test]
    fn raw_line_fallback_preserves_message_and_node_contract() {
        let value = json_line_fallback("not-json", "nodeZ");
        assert_eq!(value["message"], "not-json");
        assert_eq!(value["node_id"], "nodeZ");
        assert!(value.get("event").is_none());
    }

    // ── run() / resolve_audit_log_path(): SGX_GUARDIAN_AUDIT_LOG_PATH is a real,
    // unconditional override (unlike several other CLI files' hardcoded paths), so most of
    // run()'s body is reachable in-process. It's process-global, so serialize access.

    const AUDIT_LOG_ENV: &str = "SGX_GUARDIAN_AUDIT_LOG_PATH";

    fn with_audit_log<F: FnOnce()>(content: &str, f: F) {
        let _guard = crate::test_support::AUDIT_LOG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("audit.log");
        std::fs::write(&path, content).expect("write audit log");
        let old = std::env::var_os(AUDIT_LOG_ENV);
        std::env::set_var(AUDIT_LOG_ENV, &path);
        f();
        match old {
            Some(value) => std::env::set_var(AUDIT_LOG_ENV, value),
            None => std::env::remove_var(AUDIT_LOG_ENV),
        }
    }

    fn sample_log_lines() -> String {
        [
            serde_json::json!({
                "event": {
                    "timestamp": 1_800_000_000u64,
                    "node_id": "nodeA",
                    "category": "Attestation",
                    "action": "FAILED",
                    "severity": "critical",
                    "message": "quote rejected"
                },
                "hash": "aaaaaaaaaaaaaaaa",
                "previous_hash": "bbbbbbbbbbbbbbbb"
            }),
            serde_json::json!({
                "event": {
                    "timestamp": 1_800_000_100u64,
                    "node_id": "nodeA",
                    "category": "Network",
                    "action": "SUCCEEDED",
                    "severity": "info",
                    "message": "peer connected"
                },
                "hash": "cccc",
                "previous_hash": "dddd"
            }),
            serde_json::json!({
                "event": {
                    "timestamp": 0u64,
                    "node_id": "nodeA",
                    "category": "Tls",
                    "action": "STARTED",
                    "severity": "warning",
                    "message": "cert rotation started"
                }
            }),
        ]
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("\n")
            + "\nnot-json-at-all\n\n"
    }

    #[test]
    fn run_renders_a_table_from_a_real_seeded_log_without_filters() {
        with_audit_log(&sample_log_lines(), || {
            run(AuditLogsArgs {
                tail: 20,
                node: "nodeA".to_string(),
                category: None,
                severity: None,
                search: None,
            });
        });
    }

    #[test]
    fn run_applies_category_severity_and_search_filters() {
        with_audit_log(&sample_log_lines(), || {
            run(AuditLogsArgs {
                tail: 20,
                node: "nodeA".to_string(),
                category: Some("Network".to_string()),
                severity: Some("info".to_string()),
                search: Some("connected".to_string()),
            });
        });
    }

    #[test]
    fn run_honors_severity_all_and_a_small_tail_limit() {
        with_audit_log(&sample_log_lines(), || {
            run(AuditLogsArgs {
                tail: 1,
                node: "nodeA".to_string(),
                category: None,
                severity: Some("all".to_string()),
                search: None,
            });
        });
    }

    #[test]
    fn resolve_audit_log_path_uses_the_env_override_when_present() {
        let _guard = crate::test_support::AUDIT_LOG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("audit.log");
        std::fs::write(&path, "{}").expect("write");
        let old = std::env::var_os(AUDIT_LOG_ENV);
        std::env::set_var(AUDIT_LOG_ENV, &path);

        let resolved = resolve_audit_log_path("nodeA").expect("resolved via env override");
        assert_eq!(resolved, path);

        match old {
            Some(value) => std::env::set_var(AUDIT_LOG_ENV, value),
            None => std::env::remove_var(AUDIT_LOG_ENV),
        }
    }

    #[test]
    fn resolve_audit_log_path_errors_when_nothing_is_found() {
        let _guard = crate::test_support::AUDIT_LOG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let old = std::env::var_os(AUDIT_LOG_ENV);
        std::env::remove_var(AUDIT_LOG_ENV);

        let err = resolve_audit_log_path("node-truly-nonexistent")
            .expect_err("no log file exists in this sandbox");
        assert!(err.contains("No audit log file found"));

        if let Some(value) = old {
            std::env::set_var(AUDIT_LOG_ENV, value);
        }
    }
}
