// sgx-pa-cli/src/commands/dkp_rotate.rs
// Rotate DKP: create new version, deprecate current.
// Hardware: generates real SE050 key. Software: regenerates ring keypair.
// Metadata: appends new version to array, updates old status.

use chrono::Utc;
use std::fs;
use std::path::Path;
use std::process::Command;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
const PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";
const DKP_BASE_KEY_ID: u32 = 0x20000010;
const SOFTWARE_KEY_DIR: &str = "/var/lib/sgx-guardian/sgx-agent";
const DID_DOC_ROTATION_FLAG: &str = "/var/lib/sgx-guardian/identity/.dkp_rotated.flag";

pub fn run() {
    println!("=== DKP Key Rotation ===\n");

    if !Path::new(METADATA_PATH).exists() {
        eprintln!("No DKP found. Run the guardian daemon first.");
        return;
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Read error: {}", e);
            return;
        }
    };

    // Load history (handles both old single format and new array format)
    let mut keys: Vec<serde_json::Value> = {
        let trimmed = json.trim();
        if trimmed.starts_with('[') {
            match serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("❌ Failed to parse DKP metadata: {}", e);
                    eprintln!("   File may be corrupted: {}", METADATA_PATH);
                    return;
                }
            }
        } else {
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(v) => vec![v],
                Err(e) => {
                    eprintln!("❌ Failed to parse DKP metadata: {}", e);
                    eprintln!("   File may be corrupted: {}", METADATA_PATH);
                    return;
                }
            }
        }
    };

    // Find active key
    let active_idx = keys.iter().position(|k| k["status"] == "Active");
    let active_idx = match active_idx {
        Some(i) => i,
        None => {
            eprintln!("No active key found. Cannot rotate.");
            return;
        }
    };

    let current_version = keys[active_idx]["version"].as_u64().unwrap_or(1) as u32;
    let current_key_id = keys[active_idx]["key_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    let new_version = current_version + 1;
    let new_key_id = DKP_BASE_KEY_ID + new_version - 1;
    let new_key_id_hex = format!("0x{:08X}", new_key_id);
    let new_label = format!("dkp-v{}", new_version);

    println!("Current: {} (v{}, Active)", current_key_id, current_version);
    println!("New:     {} (v{})", new_key_id_hex, new_version);

    // Check for SE050 hardware
    let has_ssscli = Command::new("ssscli")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if has_ssscli {
        // === HARDWARE MODE: generate real SE050 key ===
        println!("\n  Generating new key in SE050...");

        let gen = Command::new("ssscli")
            .args(["generate", "ecc", &new_key_id_hex, "NIST_P256"])
            .output();
        match gen {
            Ok(o) if o.status.success() => {
                println!("  SE050: Key generated at slot {}", new_key_id_hex);
            }
            Ok(o) => {
                eprintln!(
                    "  SE050 key gen failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
                return;
            }
            Err(e) => {
                eprintln!("  ssscli error: {}", e);
                return;
            }
        }

        let exp = Command::new("ssscli")
            .args(["get", "ecc", "pub", &new_key_id_hex, PUBKEY_PATH])
            .output();
        match exp {
            Ok(o) if o.status.success() => {
                println!("  SE050: Public key exported to {}", PUBKEY_PATH);
            }
            _ => {
                eprintln!("  Public key export failed");
                return;
            }
        }
    } else {
        // === SOFTWARE MODE: regenerate ring keypair ===
        println!("\n  No SE050 — software mode rotation.");
        println!("  Regenerating software keypair for new version...");
        let mut rotated = false;

        // Find and regenerate the software key file for the current node
        // Look for device_nodeA.key pattern
        if let Ok(entries) = fs::read_dir(SOFTWARE_KEY_DIR) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("device_") && name.ends_with(".key") {
                    // Delete old key file so daemon regenerates on next start
                    let old_path = entry.path();
                    let backup = format!("{}.v{}.bak", old_path.display(), current_version);
                    match fs::rename(&old_path, &backup) {
                        Ok(_) => {
                            println!("  Old software key backed up: {}", backup);
                            println!("  New key will be generated on next daemon start.");
                            rotated = true;
                        }
                        Err(e) => {
                            eprintln!("  Failed to backup old key: {}", e);
                            return;
                        }
                    }
                    break;
                }
            }
        }
        if !rotated {
            eprintln!(
                "  No software DKP key found to rotate in {}.",
                SOFTWARE_KEY_DIR
            );
            return;
        }
    }

    // === UPDATE METADATA HISTORY ===

    // Step 1: Mark old key as Deprecated (in the array)
    keys[active_idx]["status"] = serde_json::json!("Deprecated");

    // Step 2: Create new key entry
    let new_entry = serde_json::json!({
        "key_id": new_key_id_hex,
        "label": new_label,
        "algorithm": "ECDSA-P256",
        "version": new_version,
        "status": "Active",
        "created_at": Utc::now().to_rfc3339(),
        "rotated_from": current_key_id,
        "revoked_at": null,
        "revoke_reason": null,
        "public_key_path": PUBKEY_PATH
    });

    // Step 3: Append new entry to history
    keys.push(new_entry);

    // Step 4: Write entire history array
    let serialized = match serde_json::to_string_pretty(&keys) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to serialize DKP metadata: {}", e);
            return;
        }
    };
    let tmp_path = format!("{}.tmp", METADATA_PATH);
    if let Err(e) = fs::write(&tmp_path, &serialized) {
        eprintln!("❌ Failed to write temp metadata: {}", e);
        return;
    }
    if let Err(e) = fs::rename(&tmp_path, METADATA_PATH) {
        eprintln!("❌ Failed to atomically replace metadata: {}", e);
        return;
    }
    if let Err(e) = sgx_guardian_client::did::method::update_dkp_version(
        sgx_guardian_client::did::DEFAULT_DID_PATH,
        new_version,
    ) {
        eprintln!("⚠️ DID metadata update skipped: {}", e);
    }

    if let Some(parent) = Path::new(DID_DOC_ROTATION_FLAG).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(e) = fs::write(DID_DOC_ROTATION_FLAG, Utc::now().to_rfc3339()) {
        eprintln!(
            "⚠️ Could not write DID-doc rotation flag ({}): {}",
            DID_DOC_ROTATION_FLAG, e
        );
    } else {
        println!("  🔔 Signaled running daemon to refresh DID Document.");
    }

    println!("\n✅ Rotation complete:");
    println!("  {} (v{}) → Deprecated", current_key_id, current_version);
    println!("  {} (v{}) → Active", new_key_id_hex, new_version);
    println!("\n  DID Document will be re-signed on the daemon's next refresh tick");
    println!("  (within ~30 s). Restart only required if no daemon is running.");
}
