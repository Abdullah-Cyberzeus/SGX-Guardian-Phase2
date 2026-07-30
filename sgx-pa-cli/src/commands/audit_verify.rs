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
