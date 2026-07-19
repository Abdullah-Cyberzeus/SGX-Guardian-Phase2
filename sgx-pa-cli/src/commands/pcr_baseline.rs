use base64::Engine as _;
use clap::Subcommand;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use sgx_guardian_client::secure_element::pcr::PcrBaseline;
use sha2::Digest;
use std::fs;
use std::path::Path;

const PCR_DIR: &str = "/var/lib/sgx-guardian/pcr";
const DKP_PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";
const SOFTWARE_KEY_DIR: &str = "/var/lib/sgx-guardian/sgx-agent";

struct BaselineSignature {
    signature_b64: String,
    source: &'static str,
}

fn find_pcr_snapshot() -> Option<(String, String)> {
    if let Ok(entries) = std::fs::read_dir(PCR_DIR) {
        let mut found: Vec<(String, String)> = entries
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with("_current.json") {
                    let node = name.trim_end_matches("_current.json").to_string();
                    Some((entry.path().to_string_lossy().to_string(), node))
                } else {
                    None
                }
            })
            .collect();
        found.sort();
        if let Some(first) = found.into_iter().next() {
            return Some(first);
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

fn normalize_p256_pubkey(mut key: Vec<u8>) -> Option<Vec<u8>> {
    if key.len() == 91 {
        key = key[26..].to_vec();
    }
    if key.len() == 65 {
        Some(key)
    } else {
        None
    }
}

fn local_baseline_pubkey_candidates() -> Vec<Vec<u8>> {
    let mut out = Vec::new();

    if let Ok(der) = fs::read(DKP_PUBKEY_PATH) {
        if let Some(raw) = normalize_p256_pubkey(der) {
            out.push(raw);
        }
    }

    let rng = SystemRandom::new();
    if let Ok(entries) = fs::read_dir(SOFTWARE_KEY_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("device_") || !name.ends_with(".key") {
                continue;
            }
            if let Ok(pkcs8_bytes) = fs::read(entry.path()) {
                if let Ok(keypair) =
                    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_bytes, &rng)
                {
                    out.push(keypair.public_key().as_ref().to_vec());
                }
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

fn verify_baseline_signature_locally(baseline: &PcrBaseline) -> bool {
    let pubkeys = local_baseline_pubkey_candidates();
    pubkeys
        .iter()
        .any(|pubkey| baseline.verify_signature(pubkey))
}

fn write_baseline(node_id: &str, baseline: &PcrBaseline) -> Result<(), String> {
    if let Some(parent) = Path::new(&baseline_path_for(node_id)).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Dir create error: {}", e))?;
    }
    fs::write(
        baseline_path_for(node_id),
        serde_json::to_string_pretty(baseline).map_err(|e| format!("Serialize error: {}", e))?,
    )
    .map_err(|e| format!("Write error: {}", e))
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

    let composite = match snap["composite_digest"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            eprintln!("❌ composite_digest missing from PCR snapshot");
            return;
        }
    };
    let device_uid = match snap["device_uid"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            eprintln!("❌ device_uid missing from PCR snapshot");
            return;
        }
    };
    let key_version = snap["key_version"].as_u64().unwrap_or(1) as u32;
    let schema_version = snap["schema_version"].as_u64().unwrap_or(1) as u8;
    let pcr_values: Vec<String> = match serde_json::from_value(snap["pcr_values"].clone()) {
        Ok(values) => values,
        Err(e) => {
            eprintln!("❌ pcr_values missing/invalid in snapshot: {}", e);
            return;
        }
    };
    let created_at = chrono::Utc::now().to_rfc3339();

    // Build the signing input (MUST match what PcrBaseline::verify_signature expects)
    let composite_bytes = match hex::decode(&composite) {
        Ok(b) if b.len() == 32 => b,
        Ok(b) => {
            eprintln!("❌ composite_digest must be 32 bytes, got {}", b.len());
            return;
        }
        Err(_) => {
            eprintln!("❌ Invalid composite_digest");
            return;
        }
    };
    let mut sign_input = Vec::new();
    sign_input.extend_from_slice(&composite_bytes);
    sign_input.extend_from_slice(created_at.as_bytes());
    sign_input.extend_from_slice(device_uid.as_bytes());

    let sign_hash = sha2::Sha256::digest(&sign_input);

    // Try to sign with ssscli (hardware) or warn that daemon must sign
    let baseline_signature = sign_baseline_hash(&sign_hash, key_version);

    match baseline_signature {
        Ok(Some(sig)) => {
            let baseline = PcrBaseline {
                pcr_values,
                composite_digest: composite,
                baseline_signature: sig.signature_b64,
                created_at,
                device_uid,
                key_version,
                schema_version,
            };

            if !verify_baseline_signature_locally(&baseline) {
                eprintln!(
                    "❌ Baseline was signed via {} but does NOT verify against the local DKP public key.",
                    sig.source
                );
                eprintln!(
                    "   This usually means the CLI fell back to the wrong key, or {} is stale.",
                    DKP_PUBKEY_PATH
                );
                eprintln!("   Refusing to write a misleading signed baseline.");
                return;
            }

            match write_baseline(&node_id, &baseline) {
                Ok(_) => {
                    println!(
                        "✅ Baseline created and SIGNED at {}",
                        &baseline_path_for(&node_id)
                    );
                    println!("   Signer: {}", sig.source);
                    println!("   Device UID: [redacted]");
                    println!("   Key version: {}", key_version);
                }
                Err(e) => eprintln!("{}", e),
            }
        }
        Ok(None) => {
            let baseline = PcrBaseline {
                pcr_values,
                composite_digest: composite,
                baseline_signature: String::new(),
                created_at,
                device_uid,
                key_version,
                schema_version,
            };

            match write_baseline(&node_id, &baseline) {
                Ok(_) => {
                    println!(
                        "⚠️ Baseline created but NOT SIGNED (no matching signing key available)"
                    );
                    println!("   Baseline at: {}", &baseline_path_for(&node_id));
                    println!("   The daemon will treat this baseline as untrusted until it is re-created with a valid DKP signature.");
                }
                Err(e) => eprintln!("{}", e),
            }
        }
        Err(e) => eprintln!("❌ Baseline signing failed: {}", e),
    }
}

/// Try to sign the baseline hash using ssscli (hardware) or software key.
fn sign_baseline_hash(hash: &[u8], key_version: u32) -> Result<Option<BaselineSignature>, String> {
    use std::process::Command;

    // Method 1: Try ssscli (hardware board)
    if key_version == 0 {
        return Err("key_version must be >= 1".into());
    }
    let key_id = format!("0x{:08X}", 0x20000010 + key_version - 1);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_in = format!("/tmp/guardian_baseline_hash_{}.bin", ts);
    let tmp_out = format!("/tmp/guardian_baseline_sig_{}.bin", ts);

    if fs::write(&tmp_in, hash).is_ok() {
        if let Ok(output) = Command::new("ssscli")
            .args(["sign", &key_id, &tmp_in, &tmp_out])
            .output()
        {
            if output.status.success() {
                if let Ok(sig_bytes) = fs::read(&tmp_out) {
                    let _ = fs::remove_file(&tmp_in);
                    let _ = fs::remove_file(&tmp_out);
                    return Ok(Some(BaselineSignature {
                        signature_b64: base64::engine::general_purpose::STANDARD.encode(&sig_bytes),
                        source: "SE050 hardware",
                    }));
                }
            }
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if Path::new(DKP_PUBKEY_PATH).exists() {
                let _ = fs::remove_file(&tmp_in);
                let _ = fs::remove_file(&tmp_out);
                let detail = if !stderr.is_empty() {
                    stderr
                } else if !stdout.is_empty() {
                    stdout
                } else {
                    format!("ssscli exited with status {}", output.status)
                };
                return Err(format!(
                    "SE050 signing via ssscli failed for {}: {}",
                    key_id, detail
                ));
            }
        } else if Path::new(DKP_PUBKEY_PATH).exists() {
            let _ = fs::remove_file(&tmp_in);
            let _ = fs::remove_file(&tmp_out);
            return Err(format!(
                "ssscli is unavailable, but {} exists so this board expects hardware DKP signing",
                DKP_PUBKEY_PATH
            ));
        }
        let _ = fs::remove_file(&tmp_in);
        let _ = fs::remove_file(&tmp_out);
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
                            return Ok(Some(BaselineSignature {
                                signature_b64: base64::engine::general_purpose::STANDARD
                                    .encode(sig.as_ref()),
                                source: "software fallback key",
                            }));
                        }
                    }
                }
            }
        }
    }

    Ok(None)
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

    let baseline_json = match fs::read_to_string(&bl_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Failed to load baseline from {}: {}", bl_path, e);
            return;
        }
    };
    let baseline: serde_json::Value = match serde_json::from_str(&baseline_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Failed to parse baseline from {}: {}", bl_path, e);
            return;
        }
    };
    let baseline_struct: Option<PcrBaseline> = serde_json::from_str(&baseline_json).ok();
    let snapshot: serde_json::Value = match fs::read_to_string(&pcr_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => v,
        None => {
            eprintln!("❌ Failed to load snapshot from {}", pcr_path);
            return;
        }
    };

    if let Some(v) = baseline_struct {
        if v.baseline_signature.is_empty() {
            println!("  ❌ Baseline is NOT SIGNED — tamper protection inactive");
        } else if verify_baseline_signature_locally(&v) {
            println!("  ✅ Baseline signature VERIFIED against local DKP public key");
        } else {
            println!("  ❌ Baseline signature INVALID for local DKP public key");
            println!(
                "     Check whether the baseline was signed by the wrong key or {} is stale",
                DKP_PUBKEY_PATH
            );
        }
    } else {
        println!("  ❌ Baseline format invalid — could not parse structured baseline");
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
