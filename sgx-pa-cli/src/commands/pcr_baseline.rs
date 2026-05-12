use base64::Engine as _;
use clap::Subcommand;
use sha2::Digest;
use std::fs;
use std::path::Path;

const PCR_DIR: &str = "/var/lib/sgx-guardian/pcr";

fn find_pcr_snapshot() -> Option<(String, String)> {
    if let Ok(entries) = std::fs::read_dir(PCR_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with("_current.json") {
                let node = name.trim_end_matches("_current.json").to_string();
                return Some((entry.path().to_string_lossy().to_string(), node));
            }
        }
    }
    let old = format!("{}/current.json", PCR_DIR);
    if Path::new(&old).exists() {
        Some((old, "unknown".into()))
    } else {
        None
    }
}

fn baseline_path_for(node_id: &str) -> String {
    format!("/etc/sgx-guardian/pcr_{}_baseline.json", node_id)
}

#[derive(Subcommand)]
pub enum PcrBaselineCmd {
    /// Create golden baseline from current PCR snapshot
    Create,
    /// Verify current snapshot against baseline
    Verify,
}

pub fn run_create() {
    println!("=== Create PCR Golden Baseline ===\n");

    let (pcr_path, node_id) = match find_pcr_snapshot() {
        Some(p) => p,
        None => {
            eprintln!("No PCR snapshot. Run daemon first.");
            return;
        }
    };
    println!("  Node: {}\n", node_id);

    let json = match fs::read_to_string(&pcr_path) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Read error: {}", e);
            return;
        }
    };
    let snap: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Parse error: {}", e);
            return;
        }
    };

    let composite = snap["composite_digest"].as_str().unwrap_or("").to_string();
    let device_uid = snap["device_uid"].as_str().unwrap_or("unknown").to_string();
    let key_version = snap["key_version"].as_u64().unwrap_or(1) as u32;
    let created_at = chrono::Utc::now().to_rfc3339();

    // Build the signing input (MUST match what PcrBaseline::verify_signature expects)
    let composite_bytes = hex::decode(&composite).unwrap_or_else(|_| vec![0u8; 32]);
    let mut sign_input = Vec::new();
    sign_input.extend_from_slice(&composite_bytes);
    sign_input.extend_from_slice(created_at.as_bytes());
    sign_input.extend_from_slice(device_uid.as_bytes());

    let sign_hash = sha2::Sha256::digest(&sign_input);

    // Try to sign with ssscli (hardware) or warn that daemon must sign
    let baseline_signature = sign_baseline_hash(&sign_hash, key_version);

    match baseline_signature {
        Some(sig_b64) => {
            let baseline = serde_json::json!({
                "pcr_values": snap["pcr_values"],
                "composite_digest": composite,
                "baseline_signature": sig_b64,
                "created_at": created_at,
                "device_uid": device_uid,
                "key_version": key_version,
                "schema_version": snap["schema_version"],
            });

            if let Some(parent) = Path::new(&baseline_path_for(&node_id)).parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::write(
                &baseline_path_for(&node_id),
                serde_json::to_string_pretty(&baseline).unwrap(),
            ) {
                Ok(_) => {
                    println!(
                        "✅ Baseline created and SIGNED at {}",
                        &baseline_path_for(&node_id)
                    );
                    println!("   Device UID: [redacted]");
                    println!("   Key version: {}", key_version);
                }
                Err(e) => eprintln!("Write error: {}", e),
            }
        }
        None => {
            // Can't sign from CLI — save unsigned baseline with warning
            let baseline = serde_json::json!({
                "pcr_values": snap["pcr_values"],
                "composite_digest": composite,
                "baseline_signature": "",
                "created_at": created_at,
                "device_uid": device_uid,
                "key_version": key_version,
                "schema_version": snap["schema_version"],
            });

            if let Some(parent) = Path::new(&baseline_path_for(&node_id)).parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::write(
                &baseline_path_for(&node_id),
                serde_json::to_string_pretty(&baseline).unwrap(),
            ) {
                Ok(_) => {
                    println!("⚠️ Baseline created but NOT SIGNED (no signing key available)");
                    println!("   Baseline at: {}", &baseline_path_for(&node_id));
                    println!("   The daemon will sign it on next startup if signature is empty.");
                }
                Err(e) => eprintln!("Write error: {}", e),
            }
        }
    }
}

/// Try to sign the baseline hash using ssscli (hardware) or software key.
fn sign_baseline_hash(hash: &[u8], key_version: u32) -> Option<String> {
    use std::process::Command;

    // Method 1: Try ssscli (hardware board)
    let key_id = format!("0x{:08X}", 0x20000010 + key_version - 1);
    let tmp_in = "/tmp/guardian_baseline_hash.bin";
    let tmp_out = "/tmp/guardian_baseline_sig.bin";

    if fs::write(tmp_in, hash).is_ok() {
        if let Ok(output) = Command::new("ssscli")
            .args(["sign", &key_id, tmp_in, tmp_out])
            .output()
        {
            if output.status.success() {
                if let Ok(sig_bytes) = fs::read(tmp_out) {
                    let _ = fs::remove_file(tmp_in);
                    let _ = fs::remove_file(tmp_out);
                    return Some(base64::engine::general_purpose::STANDARD.encode(&sig_bytes));
                }
            }
        }
        let _ = fs::remove_file(tmp_in);
        let _ = fs::remove_file(tmp_out);
    }

    // Method 2: Try ring with software key file
    let agent_dir = "/var/lib/sgx-guardian/sgx-agent";
    if let Ok(entries) = fs::read_dir(agent_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("device_") && name.ends_with(".key") {
                if let Ok(pkcs8_bytes) = fs::read(entry.path()) {
                    let rng = ring::rand::SystemRandom::new();
                    if let Ok(keypair) = ring::signature::EcdsaKeyPair::from_pkcs8(
                        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &pkcs8_bytes,
                        &rng,
                    ) {
                        if let Ok(sig) = keypair.sign(&rng, hash) {
                            return Some(
                                base64::engine::general_purpose::STANDARD.encode(sig.as_ref()),
                            );
                        }
                    }
                }
            }
        }
    }

    None
}

pub fn run_verify() {
    println!("=== Verify PCR Baseline ===\n");
    let (pcr_path, node_id) = match find_pcr_snapshot() {
        Some(p) => p,
        None => {
            eprintln!("No snapshot.");
            return;
        }
    };
    let bl_path = baseline_path_for(&node_id);
    if !Path::new(&bl_path).exists() {
        eprintln!("No baseline. Create first: sgx-pa-cli pcr-baseline create");
        return;
    }

    let baseline: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&bl_path).unwrap()).unwrap();
    let snapshot: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&pcr_path).unwrap()).unwrap();

    // Verify baseline signature first
    let sig = baseline["baseline_signature"].as_str().unwrap_or("");
    if sig.is_empty() {
        println!("  ⚠️ Baseline is NOT SIGNED — tamper protection not active");
    } else {
        println!("  Baseline signature: present");
        // Note: Full signature verification requires the DKP public key,
        // which the daemon provides at runtime. CLI can only check signature exists.
    }

    let names = [
        "BIOS/Bootloader",
        "Firmware/DTB",
        "Kernel",
        "RootFS",
        "Configuration",
    ];
    let b_pcrs = baseline["pcr_values"].as_array();
    let s_pcrs = snapshot["pcr_values"].as_array();

    if let (Some(bp), Some(sp)) = (b_pcrs, s_pcrs) {
        if bp.len() != sp.len() {
            eprintln!(
                "PCR count mismatch: baseline={}, current={}",
                bp.len(),
                sp.len()
            );
            return;
        }
        let mut all_match = true;
        for i in 0..bp.len() {
            let name = names.get(i).unwrap_or(&"?");
            if bp[i] == sp[i] {
                println!("  PCR{} [{}]: ✅ MATCH", i, name);
            } else {
                println!("  PCR{} [{}]: ❌ MISMATCH", i, name);
                println!("    Baseline: {}", bp[i].as_str().unwrap_or("?"));
                println!("    Current:  {}", sp[i].as_str().unwrap_or("?"));
                all_match = false;
            }
        }
        if all_match {
            println!("\n  Result: ✅ ALL PCRs MATCH — device integrity verified");
        } else {
            println!("\n  Result: ❌ MISMATCH DETECTED — investigate immediately");
        }
    }
}
