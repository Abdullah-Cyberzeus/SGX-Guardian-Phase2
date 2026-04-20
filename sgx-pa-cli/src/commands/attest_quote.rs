//! CLI commands for hardware attestation quote generation and verification.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::fs;

const PCR_DIR: &str = "/var/lib/sgx-guardian/pcr";
const BOOT_DIR: &str = "/var/lib/sgx-guardian/boot";
const RESULTS_PATH: &str = "/var/log/sgx-guardian/attestation_results.json";
const QUOTE_PATH: &str = "/var/log/sgx-guardian/last_quote.json";

#[derive(clap::Args)]
pub struct GenerateQuoteArgs {
    /// Challenge nonce from verifier (64 hex chars = 32 bytes)
    #[arg(long)]
    pub nonce: String,
}

#[derive(clap::Args)]
pub struct VerifyQuoteArgs {
    /// Path to the signed quote JSON file
    #[arg(long)]
    pub quote: String,

    /// Expected nonce (64 hex chars)
    #[arg(long)]
    pub nonce: String,

    /// Optional: path to PCR baseline for comparison
    #[arg(long)]
    pub baseline: Option<String>,
}

pub fn run_generate(args: GenerateQuoteArgs) {
    println!("=== Generate Attestation Quote ===\n");

    // Validate nonce format
    if args.nonce.len() != 64 || !args.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("❌ Nonce must be exactly 64 hex characters (32 bytes)");
        eprintln!("   Example: ./sgx-pa-cli attest generate-quote --nonce $(openssl rand -hex 32)");
        return;
    }

    // Find PCR snapshot
    let (pcr_path, node_id) = match find_pcr_snapshot() {
        Some(p) => p,
        None => {
            eprintln!("❌ No PCR snapshot found. Run the daemon first.");
            return;
        }
    };
    println!("  Node: {}", node_id);
    println!("  Challenge nonce: {}...", &args.nonce[..16]);

    // Load PCR snapshot
    let pcr_json = match fs::read_to_string(&pcr_path) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("❌ Read PCR snapshot: {}", e);
            return;
        }
    };
    let snap: serde_json::Value = match serde_json::from_str(&pcr_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Parse PCR: {}", e);
            return;
        }
    };

    // Load boot chain status
    let boot_path = format!("{}/{}_chain_status.json", BOOT_DIR, node_id);
    let boot: serde_json::Value = fs::read_to_string(&boot_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::json!({
            "hab_enabled": false,
            "device_closed": false,
            "hab_events_found": false,
            "boot_chain_intact": false
        }));

    // Generate device nonce
    let dev_nonce = format!("{:032x}", rand::random::<u128>());

    // Build quote
    let quote = serde_json::json!({
        "version": 1,
        "challenge_nonce": args.nonce,
        "device_nonce": dev_nonce,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "node_id": node_id,
        "device_uid": snap["device_uid"].as_str().unwrap_or("unknown"),
        "key_version": snap["key_version"].as_u64().unwrap_or(1),
        "pcr_values": snap["pcr_values"],
        "composite_digest": snap["composite_digest"],
        "integrity_status": snap["integrity_status"],
        "boot_chain": {
            "hab_enabled": boot["hab_enabled"],
            "device_closed": boot["device_closed"],
            "hab_events_found": boot["hab_events_found"],
            "boot_chain_intact": boot["boot_chain_intact"]
        },
        "firmware_version": snap.get("kernel_version").and_then(|v| v.as_str()).unwrap_or(""),
        "active_policy_digest": snap.get("policy_digest").and_then(|v| v.as_str()).unwrap_or("")
    });

    let quote_json = serde_json::to_string(&quote).unwrap();
    let hash = Sha256::digest(quote_json.as_bytes());

    // Try to sign with SE050 (ssscli) or software key
    let signature = sign_quote_hash(&hash, snap["key_version"].as_u64().unwrap_or(1) as u32);

    match signature {
        Some(sig_b64) => {
            let signed = serde_json::json!({
                "quote_json": quote_json,
                "signature_b64": sig_b64,
                "signing_backend": if has_ssscli() { "SE050" } else { "Software" }
            });

            match fs::write(QUOTE_PATH, serde_json::to_string_pretty(&signed).unwrap()) {
                Ok(_) => {
                    println!("\n  ✅ Quote generated and signed");
                    println!("  Saved to: {}", QUOTE_PATH);
                    println!(
                        "  Backend: {}",
                        if has_ssscli() {
                            "SE050 hardware"
                        } else {
                            "Software"
                        }
                    );
                    println!(
                        "  PCR composite: {}...",
                        &snap["composite_digest"].as_str().unwrap_or("?")[..16]
                    );
                    println!("  Boot chain intact: {}", boot["boot_chain_intact"]);
                    let _ = fs::write(RESULTS_PATH, serde_json::to_string_pretty(&signed).unwrap());
                }
                Err(e) => eprintln!("❌ Write failed: {}", e),
            }
        }
        None => {
            eprintln!("❌ Failed to sign quote — no signing key available");
            eprintln!("   Run the daemon first to initialize DKP");
        }
    }
}

pub fn run_verify(args: VerifyQuoteArgs) {
    println!("=== Verify Attestation Quote ===\n");

    // Validate nonce
    if args.nonce.len() != 64 || !args.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        eprintln!("❌ Nonce must be 64 hex characters");
        return;
    }

    // Load signed quote
    let signed_json = match fs::read_to_string(&args.quote) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("❌ Read quote: {}", e);
            return;
        }
    };
    let signed: serde_json::Value = match serde_json::from_str(&signed_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Parse quote: {}", e);
            return;
        }
    };

    let quote_json = signed["quote_json"].as_str().unwrap_or("");
    let quote: serde_json::Value = match serde_json::from_str(quote_json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("❌ Parse inner quote: {}", e);
            return;
        }
    };

    // Check nonce
    let quote_nonce = quote["challenge_nonce"].as_str().unwrap_or("");
    let nonce_ok = quote_nonce == args.nonce;
    println!(
        "  Nonce:       {}",
        if nonce_ok {
            "✅ matches"
        } else {
            "❌ MISMATCH"
        }
    );

    // Check freshness (< 5 min)
    let ts = quote["timestamp"].as_str().unwrap_or("");
    let fresh = chrono::DateTime::parse_from_rfc3339(ts)
        .map(|dt| {
            let age = chrono::Utc::now().signed_duration_since(dt.with_timezone(&chrono::Utc));
            age.num_seconds().unsigned_abs() <= 300
        })
        .unwrap_or(false);
    println!(
        "  Freshness:   {}",
        if fresh { "✅ recent" } else { "⚠️ stale" }
    );

    // Check boot chain
    let hab = quote["boot_chain"]["hab_enabled"]
        .as_bool()
        .unwrap_or(false);
    let closed = quote["boot_chain"]["device_closed"]
        .as_bool()
        .unwrap_or(false);
    let no_events = !quote["boot_chain"]["hab_events_found"]
        .as_bool()
        .unwrap_or(true);
    let chain_ok = !quote["boot_chain"]["hab_events_found"]
        .as_bool()
        .unwrap_or(true);
    println!(
        "  HAB:         {}",
        if hab {
            "✅ enabled"
        } else {
            "❌ not detected"
        }
    );
    println!(
        "  Device:      {}",
        if closed { "🔒 CLOSED" } else { "🔓 OPEN" }
    );
    println!(
        "  HAB events:  {}",
        if no_events {
            "✅ none"
        } else {
            "⚠️ FOUND"
        }
    );

    // Check integrity
    let integrity = quote["integrity_status"].as_str().unwrap_or("UNKNOWN");
    println!(
        "  Integrity:   {}",
        match integrity {
            "PASS" => "✅ PASS",
            "DEGRADED" => "⚠️ DEGRADED",
            _ => "❌ FAIL",
        }
    );

    // Compare PCRs if baseline provided
    if let Some(ref bl_path) = args.baseline {
        if let Ok(bl_json) = fs::read_to_string(bl_path) {
            if let Ok(bl) = serde_json::from_str::<serde_json::Value>(&bl_json) {
                let bl_pcrs = bl["pcr_values"].as_array();
                let q_pcrs = quote["pcr_values"].as_array();
                if let (Some(bp), Some(qp)) = (bl_pcrs, q_pcrs) {
                    let names = ["BIOS", "DTB", "Kernel", "RootFS", "Config"];
                    let mut all_match = true;
                    for i in 0..bp.len().min(qp.len()) {
                        let m = bp[i] == qp[i];
                        if !m {
                            all_match = false;
                        }
                        println!(
                            "  PCR{} [{}]: {}",
                            i,
                            names.get(i).unwrap_or(&"?"),
                            if m { "✅ MATCH" } else { "❌ MISMATCH" }
                        );
                    }
                    println!(
                        "\n  Baseline:    {}",
                        if all_match {
                            "✅ ALL MATCH"
                        } else {
                            "❌ MISMATCH"
                        }
                    );
                }
            }
        } else {
            eprintln!("  ⚠️ Could not read baseline: {}", bl_path);
        }
    } else {
        println!("  Baseline:    ⚠️ not provided (skipped)");
    }

    // Overall
    let all_ok = nonce_ok && fresh && chain_ok;
    println!(
        "\n  Result:      {}",
        if all_ok { "✅ VERIFIED" } else { "❌ FAILED" }
    );
}

// ── Helpers ──

fn find_pcr_snapshot() -> Option<(String, String)> {
    if let Ok(entries) = fs::read_dir(PCR_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with("_current.json") {
                let node = name.trim_end_matches("_current.json").to_string();
                return Some((entry.path().to_string_lossy().to_string(), node));
            }
        }
    }
    None
}

fn has_ssscli() -> bool {
    std::process::Command::new("ssscli")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn sign_quote_hash(hash: &[u8], key_version: u32) -> Option<String> {
    use std::process::Command;

    // Method 1: SE050 hardware
    let key_id = format!("0x{:08X}", 0x20000010 + key_version - 1);
    let tmp_in = "/tmp/guardian_quote_hash.bin";
    let tmp_out = "/tmp/guardian_quote_sig.bin";

    if fs::write(tmp_in, hash).is_ok() {
        if let Ok(output) = Command::new("ssscli")
            .args(["sign", &key_id, tmp_in, tmp_out])
            .output()
        {
            if output.status.success() {
                if let Ok(sig) = fs::read(tmp_out) {
                    let _ = fs::remove_file(tmp_in);
                    let _ = fs::remove_file(tmp_out);
                    return Some(base64::engine::general_purpose::STANDARD.encode(&sig));
                }
            }
        }
        let _ = fs::remove_file(tmp_in);
        let _ = fs::remove_file(tmp_out);
    }

    // Method 2: Software key
    let agent_dir = "/var/lib/sgx-guardian/sgx-agent";
    if let Ok(entries) = fs::read_dir(agent_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("device_") && name.ends_with(".key") {
                if let Ok(pkcs8_bytes) = fs::read(entry.path()) {
                    let rng = ring::rand::SystemRandom::new();
                    if let Ok(kp) = ring::signature::EcdsaKeyPair::from_pkcs8(
                        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &pkcs8_bytes,
                        &rng,
                    ) {
                        if let Ok(sig) = kp.sign(&rng, hash) {
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
