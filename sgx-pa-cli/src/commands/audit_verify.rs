use clap::Args;
use sgx_guardian_client::audit::event::AuditEvent;
use sgx_guardian_client::audit::hasher::AuditHashChain;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

#[derive(Args)]
#[command(about = "Verify the cryptographic integrity of the secure audit logs")]
pub struct AuditVerifyArgs {
    /// Node ID to verify logs for (e.g. nodeA)
    #[arg(long, default_value = "nodeA")]
    pub node: String,
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

pub fn run(args: AuditVerifyArgs) {
    let log_path = match resolve_audit_log_path(&args.node) {
        Ok(path) => path,
        Err(e) => {
            eprintln!("❌ {}", e);
            std::process::exit(1);
        }
    };

    println!("Checking integrity of secure audit log: {:?}\n", log_path);

    let file = match File::open(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("❌ Could not open audit log: {}", e);
            std::process::exit(1);
        }
    };

    let reader = BufReader::new(file);
    let mut chain = AuditHashChain::new();

    let mut line_count = 0usize;
    let mut segment_count = 0usize;
    let mut current_segment_start: Option<usize> = None;
    let mut tampered = false;

    for (idx, line) in reader.lines().enumerate() {
        let line_no = idx + 1;
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                eprintln!("❌ Error reading line {}: {}", line_no, e);
                std::process::exit(1);
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        line_count += 1;

        let parsed: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => {
                println!(
                    "❌ Line {} is malformed: Invalid JSON representation",
                    line_no
                );
                tampered = true;
                break;
            }
        };

        let Some(event) = parsed.get("event") else {
            println!(
                "❌ Line {} is tampered: Missing 'event' payload field",
                line_no
            );
            tampered = true;
            break;
        };

        let stored_prev = parsed
            .get("previous_hash")
            .and_then(|h| h.as_str())
            .unwrap_or("GENESIS");
        let Some(stored_hash) = parsed.get("hash").and_then(|h| h.as_str()) else {
            println!("❌ Line {} is tampered: Missing 'hash' field", line_no);
            tampered = true;
            break;
        };

        let canonical_event: AuditEvent = match serde_json::from_value(event.clone()) {
            Ok(ev) => ev,
            Err(_) => {
                println!(
                    "❌ Line {} is tampered: Event payload cannot be parsed into canonical audit format",
                    line_no
                );
                tampered = true;
                break;
            }
        };

        let payload = match serde_json::to_string(&canonical_event) {
            Ok(p) => p,
            Err(_) => {
                println!(
                    "❌ Line {} is tampered: Failed to serialize canonical event",
                    line_no
                );
                tampered = true;
                break;
            }
        };

        let chain_state_matches = chain.last_hash() == stored_prev;
        let is_first_line = current_segment_start.is_none();

        if is_first_line {
            chain.set_last_hash(stored_prev.to_string());
            segment_count += 1;
            current_segment_start = Some(line_no);
        } else if !chain_state_matches {
            if stored_prev == "GENESIS" {
                chain.set_last_hash(stored_prev.to_string());
                segment_count += 1;
                current_segment_start = Some(line_no);
            } else {
                println!(
                    "❌ AUDIT LOG TAMPER DETECTED at Line {}:\n  - Reason: Hash chain link is broken (prev hash mismatch)\n  - Explanation: An entry was likely deleted or inserted before this line.\n  - Expected previous hash: {}\n  - Stored previous hash:   {}",
                    line_no, chain.last_hash(), stored_prev
                );
                tampered = true;
                break;
            }
        }

        let computed = chain.next_hash(&payload);
        if computed != stored_hash {
            let seg_start = current_segment_start.unwrap_or(line_no);
            println!(
                "❌ AUDIT LOG TAMPER DETECTED at Line {} (within segment starting at line {}):\n  - Reason: Payload signature mismatch\n  - Explanation: The log event content on this line has been directly modified.\n  - Stored hash:   {}\n  - Computed hash: {}",
                line_no, seg_start, stored_hash, computed
            );
            tampered = true;
            break;
        }
    }

    if !tampered {
        println!(
            "✅ Audit log integrity verified successfully!\n  - Verified entries: {}\n  - Verified segments: {}",
            line_count, segment_count
        );
    } else {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{resolve_audit_log_path, run, AuditVerifyArgs};
    use sgx_guardian_client::audit::event::{AuditAction, AuditCategory, AuditEvent, AuditSeverity};
    use sgx_guardian_client::audit::hasher::AuditHashChain;

    // Only the fully-valid (non-tampered) scenario avoids run()'s std::process::exit(1), so
    // that's the one case tested in-process; every tamper/error scenario is exercised via
    // `sgx-pa-cli/tests/audit_verify_cli_test.rs` instead.
    const AUDIT_LOG_ENV: &str = "SGX_GUARDIAN_AUDIT_LOG_PATH";

    fn genuine_chain_log() -> String {
        let mut chain = AuditHashChain::new();
        let mut lines = Vec::new();
        for i in 0..3u64 {
            let event = AuditEvent::new(
                "nodeA".to_string(),
                AuditCategory::Node,
                AuditSeverity::Info,
                AuditAction::Succeeded,
                format!("test event {i}"),
            );
            let payload = serde_json::to_string(&event).unwrap();
            let prev = chain.last_hash().to_string();
            let hash = chain.next_hash(&payload);
            lines.push(
                serde_json::json!({
                    "event": event,
                    "previous_hash": prev,
                    "hash": hash,
                })
                .to_string(),
            );
        }
        lines.join("\n")
    }

    #[test]
    fn run_verifies_a_genuinely_valid_hash_chain() {
        let _guard = crate::test_support::AUDIT_LOG_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("audit.log");
        std::fs::write(&path, genuine_chain_log()).expect("write audit log");
        let old = std::env::var_os(AUDIT_LOG_ENV);
        std::env::set_var(AUDIT_LOG_ENV, &path);

        run(AuditVerifyArgs {
            node: "nodeA".to_string(),
        });

        match old {
            Some(value) => std::env::set_var(AUDIT_LOG_ENV, value),
            None => std::env::remove_var(AUDIT_LOG_ENV),
        }
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
