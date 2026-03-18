// sgx-pa-cli/src/commands/emergency_rotate.rs
// Emergency rotation of ALL critical keys.
// Use: sgx-pa-cli emergency-rotate
//
// Rotates:
//   1. DKP (Device Key Pair) — SE050 hardware or software
//   2. Software attestation key (device_nodeX.key)
//   3. TLS certificate (derived from identity key)
//
// Crypto: ECDSA-P256 + SHA-256 ONLY.

use chrono::Utc;
use std::fs;
use std::path::Path;
use std::process::Command;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
const PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";
const DKP_BASE_KEY_ID: u32 = 0x20000010;
const AGENT_DIR: &str = "/var/lib/sgx-guardian/sgx-agent";
const AUDIT_LOG_PATH: &str = "/var/log/sgx-guardian/emergency_rotation.log";

pub fn run() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║     EMERGENCY KEY ROTATION                      ║");
    println!("║     All critical keys will be rotated            ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    let timestamp = Utc::now().to_rfc3339();
    let mut audit_entries: Vec<String> = Vec::new();
    let mut success_count = 0;
    let mut fail_count = 0;

    // Detect hardware mode
    let has_ssscli = Command::new("ssscli")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_ssscli {
        println!("  Mode: Hardware (SE050 detected)");
    } else {
        println!("  Mode: Software (no SE050)");
    }
    println!();

    // ════════════════════════════════════════════════
    // KEY 1: DKP (Device Key Pair)
    // ════════════════════════════════════════════════
    println!("┌─ [1/3] DKP (Device Key Pair) ──────────────────");

    if Path::new(METADATA_PATH).exists() {
        let rotated = rotate_dkp(has_ssscli);
        if rotated {
            println!("│  ✅ DKP rotated successfully");
            audit_entries.push(format!("{} EMERGENCY DKP rotation completed", timestamp));
            success_count += 1;
        } else {
            println!("│  ❌ DKP rotation failed");
            audit_entries.push(format!("{} EMERGENCY DKP rotation FAILED", timestamp));
            fail_count += 1;
        }
    } else {
        println!("│  ⚠️  No DKP found — skipping (run daemon first)");
        audit_entries.push(format!("{} EMERGENCY DKP skipped (no metadata)", timestamp));
    }
    println!("└──────────────────────────────────────────────────\n");

    // ════════════════════════════════════════════════
    // KEY 2: Software Attestation Key (device_nodeX.key)
    // ════════════════════════════════════════════════
    println!("┌─ [2/3] Software Attestation Key ───────────────");

    let sw_rotated = rotate_software_key();
    if sw_rotated {
        println!("│  ✅ Software key rotated (will regenerate on next daemon start)");
        audit_entries.push(format!(
            "{} EMERGENCY software key rotation completed",
            timestamp
        ));
        success_count += 1;
    } else {
        println!("│  ⚠️  No software key found — skipping");
        audit_entries.push(format!(
            "{} EMERGENCY software key skipped (not found)",
            timestamp
        ));
    }
    println!("└──────────────────────────────────────────────────\n");

    // ════════════════════════════════════════════════
    // KEY 3: TLS Certificate
    // ════════════════════════════════════════════════
    println!("┌─ [3/3] TLS Certificate ────────────────────────");

    let tls_rotated = rotate_tls_cert();
    if tls_rotated {
        println!("│  ✅ TLS certificate removed (will regenerate on next daemon start)");
        audit_entries.push(format!(
            "{} EMERGENCY TLS certificate rotation completed",
            timestamp
        ));
        success_count += 1;
    } else {
        println!("│  ⚠️  No TLS certificate found — skipping");
        audit_entries.push(format!(
            "{} EMERGENCY TLS certificate skipped (not found)",
            timestamp
        ));
    }
    println!("└──────────────────────────────────────────────────\n");

    // ════════════════════════════════════════════════
    // SUMMARY
    // ════════════════════════════════════════════════
    println!("═══════════════════════════════════════════════════");
    println!("  Emergency rotation complete:");
    println!("    Rotated: {}", success_count);
    println!("    Failed:  {}", fail_count);
    println!("    Time:    {}", timestamp);
    println!("═══════════════════════════════════════════════════");

    if success_count > 0 {
        println!("\n  ⚠️  RESTART the guardian daemon to apply new keys:");
        println!("     pkill -f sgx_guardian_client");
        println!("     ./sgx_guardian_client nodeA");
    }

    // Write audit log
    write_audit_log(&audit_entries);
}

/// Rotate DKP — reuses logic from dkp_rotate
fn rotate_dkp(has_ssscli: bool) -> bool {
    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(_) => return false,
    };

    let mut keys: Vec<serde_json::Value> = {
        let trimmed = json.trim();
        if trimmed.starts_with('[') {
            match serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("❌ Failed to parse DKP metadata: {}", e);
                    eprintln!("   File may be corrupted: {}", METADATA_PATH);
                    return false;
                }
            }
        } else {
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(v) => vec![v],
                Err(e) => {
                    eprintln!("❌ Failed to parse DKP metadata: {}", e);
                    eprintln!("   File may be corrupted: {}", METADATA_PATH);
                    return false;
                }
            }
        }
    };

    let active_idx = match keys.iter().position(|k| k["status"] == "Active") {
        Some(i) => i,
        None => return false,
    };

    let current_version = keys[active_idx]["version"].as_u64().unwrap_or(1) as u32;
    let current_key_id = keys[active_idx]["key_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let new_version = current_version + 1;
    let new_key_id = DKP_BASE_KEY_ID + new_version - 1;
    let new_key_id_hex = format!("0x{:08X}", new_key_id);

    if has_ssscli {
        // Hardware: generate new SE050 key
        let gen = Command::new("ssscli")
            .args(["generate", "ecc", &new_key_id_hex, "NIST_P256"])
            .output();
        if gen.map(|o| o.status.success()).unwrap_or(false) {
            println!("│  SE050: Generated key at slot {}", new_key_id_hex);
            // Export public key
            let _ = Command::new("ssscli")
                .args(["get", "ecc", "pub", &new_key_id_hex, PUBKEY_PATH])
                .output();
        } else {
            println!("│  SE050: Key generation failed");
            return false;
        }
    }

    // Update metadata
    keys[active_idx]["status"] = serde_json::json!("Deprecated");

    keys.push(serde_json::json!({
        "key_id": new_key_id_hex,
        "label": format!("dkp-v{}", new_version),
        "algorithm": "ECDSA-P256",
        "version": new_version,
        "status": "Active",
        "created_at": Utc::now().to_rfc3339(),
        "rotated_from": current_key_id,
        "revoked_at": null,
        "revoke_reason": null,
        "public_key_path": PUBKEY_PATH
    }));

    fs::write(METADATA_PATH, serde_json::to_string_pretty(&keys).unwrap()).is_ok()
}

/// Rotate software attestation key — backup old, daemon regenerates on restart
fn rotate_software_key() -> bool {
    if !Path::new(AGENT_DIR).exists() {
        return false;
    }

    let mut found = false;
    if let Ok(entries) = fs::read_dir(AGENT_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("device_") && name.ends_with(".key") {
                let old_path = entry.path();
                let backup = format!(
                    "{}.emergency_backup_{}",
                    old_path.display(),
                    Utc::now().format("%Y%m%d_%H%M%S")
                );
                match fs::rename(&old_path, &backup) {
                    Ok(_) => {
                        println!(
                            "│  Backed up: {} → {}",
                            name,
                            Path::new(&backup).file_name().unwrap().to_string_lossy()
                        );
                        found = true;
                    }
                    Err(e) => {
                        println!("│  Failed to backup {}: {}", name, e);
                    }
                }
            }
        }
    }
    found
}

/// Rotate TLS certificate — remove old cert, daemon regenerates on restart
fn rotate_tls_cert() -> bool {
    if !Path::new(AGENT_DIR).exists() {
        return false;
    }

    let mut found = false;
    if let Ok(entries) = fs::read_dir(AGENT_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.contains("_cert.der") || name.contains("_cert.pem") {
                let path = entry.path();
                let backup = format!(
                    "{}.emergency_backup_{}",
                    path.display(),
                    Utc::now().format("%Y%m%d_%H%M%S")
                );
                match fs::rename(&path, &backup) {
                    Ok(_) => {
                        println!("│  Backed up: {}", name);
                        found = true;
                    }
                    Err(e) => {
                        println!("│  Failed to backup {}: {}", name, e);
                    }
                }
            }
        }
    }
    found
}

/// Write audit log entry for emergency rotation
fn write_audit_log(entries: &[String]) {
    let log_dir = Path::new(AUDIT_LOG_PATH)
        .parent()
        .unwrap_or(Path::new("/tmp"));
    let _ = fs::create_dir_all(log_dir);

    let mut log_content = String::new();
    // Append to existing log if present
    if let Ok(existing) = fs::read_to_string(AUDIT_LOG_PATH) {
        log_content = existing;
    }
    log_content.push_str("\n--- EMERGENCY ROTATION ---\n");
    for entry in entries {
        log_content.push_str(entry);
        log_content.push('\n');
    }
    log_content.push_str("--- END ---\n");

    match fs::write(AUDIT_LOG_PATH, &log_content) {
        Ok(_) => println!("\n  Audit log: {}", AUDIT_LOG_PATH),
        Err(e) => eprintln!("\n  Failed to write audit log: {}", e),
    }
}
