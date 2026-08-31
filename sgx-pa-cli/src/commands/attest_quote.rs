//! CLI commands for hardware attestation quote generation and verification.

use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::fs;

const PCR_DIR: &str = "/var/lib/sgx-guardian/pcr";
const BOOT_DIR: &str = "/var/lib/sgx-guardian/boot";
const QUOTE_PATH: &str = "/var/log/sgx-guardian/last_quote.json";
const DKP_PUB_DER_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";

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

    /// Override baseline path. If omitted, the verifier auto-loads
    /// /etc/sgx-guardian/pcr_<node_id>_baseline.json based on the
    /// quote's node_id field.
    #[arg(long)]
    pub baseline: Option<String>,
    /// Explicitly skip baseline comparison. Without this flag,
    /// missing or mismatching baseline causes FAILED result.
    #[arg(long, default_value_t = false)]
    pub no_baseline: bool,
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
                "signing_pubkey_b64": read_signing_pubkey_b64(),
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
                    let composite = snap["composite_digest"].as_str().unwrap_or("?");
                    let preview: String = composite.chars().take(16).collect();
                    println!("  PCR composite: {}...", preview);
                    println!("  Boot chain intact: {}", boot["boot_chain_intact"]);
                    // Don't write generated quote to RESULTS_PATH — that file stores
                    // verification results (different schema). Quote already saved to QUOTE_PATH.
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
    let chain_ok = quote["boot_chain"]["boot_chain_intact"]
        .as_bool()
        .unwrap_or(false)
        && !quote["boot_chain"]["hab_events_found"]
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

    // Compare PCRs against baseline.
    // Resolution order:
    //   1. --baseline <path> (operator override)
    //   2. /etc/sgx-guardian/pcr_<node_id>_baseline.json (auto, default)
    //   3. --no-baseline (explicit opt-out only)
    let quote_node_id = quote["node_id"].as_str().unwrap_or("").to_string();
    let auto_path = format!("/etc/sgx-guardian/pcr_{}_baseline.json", quote_node_id);
    let resolved_baseline_path: Option<String> = if let Some(p) = args.baseline.clone() {
        Some(p)
    } else if std::path::Path::new(&auto_path).exists() {
        Some(auto_path.clone())
    } else {
        None
    };

    let mut baseline_ok = false;
    let mut baseline_skipped = false;
    let mut baseline_load_err: Option<String> = None;

    if args.no_baseline && resolved_baseline_path.is_some() {
        baseline_skipped = true;
        println!("  Baseline:    ⚠️ skipped (--no-baseline)");
    } else if let Some(bl_path) = resolved_baseline_path.as_deref() {
        match fs::read_to_string(bl_path) {
            Ok(bl_json) => match serde_json::from_str::<serde_json::Value>(&bl_json) {
                Ok(bl) => {
                    let bl_pcrs = bl["pcr_values"].as_array();
                    let q_pcrs = quote["pcr_values"].as_array();
                    let names = ["BIOS", "DTB", "Kernel", "RootFS", "Config"];
                    if let (Some(bp), Some(qp)) = (bl_pcrs, q_pcrs) {
                        let mut all_match = bp.len() == qp.len();
                        if bp.len() != qp.len() {
                            println!(
                                "  PCR count:   ❌ MISMATCH (expected {} got {})",
                                bp.len(),
                                qp.len()
                            );
                        }
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
                            if !m {
                                println!("    expected {}", bp[i].as_str().unwrap_or("?"));
                                println!("    got      {}", qp[i].as_str().unwrap_or("?"));
                            }
                        }
                        if let (Some(bc), Some(qc)) = (
                            bl["composite_digest"].as_str(),
                            quote["composite_digest"].as_str(),
                        ) {
                            if bc != qc {
                                all_match = false;
                                println!("  Composite:   ❌ MISMATCH");
                                println!("    expected {}", bc);
                                println!("    got      {}", qc);
                            }
                        }
                        baseline_ok = all_match;
                        println!(
                            "\n  Baseline:    {} (source: {})",
                            if all_match {
                                "✅ ALL MATCH"
                            } else {
                                "❌ MISMATCH"
                            },
                            bl_path
                        );
                    } else {
                        baseline_load_err = Some("baseline missing pcr_values array".into());
                    }
                }
                Err(e) => baseline_load_err = Some(format!("baseline parse: {}", e)),
            },
            Err(e) => baseline_load_err = Some(format!("baseline read: {}", e)),
        }
    } else {
        // No on-disk peer baseline (expected on a verifier that isn't the prover).
        // Fall back to self-consistency: recompute composite from quoted PCRs and
        // compare against the quote's claimed composite_digest. The whole quote
        // is signed by the prover's DKP, so this still binds the values to HW.
        let q_pcrs = quote["pcr_values"].as_array();
        let claimed = quote["composite_digest"].as_str().unwrap_or("");
        let mut self_ok = false;
        if let (Some(pcrs), false) = (q_pcrs, claimed.is_empty()) {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            for v in pcrs {
                if let Some(s) = v.as_str() {
                    if let Ok(b) = hex::decode(s) {
                        h.update(&b);
                    }
                }
            }
            let computed = hex::encode(h.finalize());
            self_ok = computed.eq_ignore_ascii_case(claimed);
            println!(
                "  Composite:   {} (self-check: computed={} claimed={})",
                if self_ok { "✅ MATCH" } else { "❌ MISMATCH" },
                &computed[..16],
                &claimed[..16.min(claimed.len())]
            );
        }
        if args.no_baseline {
            baseline_ok = self_ok;
            println!("  ⚠️  --no-baseline: accepting self-consistency (NOT production-safe)");
        } else {
            baseline_ok = false;
            println!("  ❌ No baseline file — cannot verify PCR integrity");
            println!("     Use --baseline <path> or --no-baseline to override");
        }
    }

    if let Some(err) = &baseline_load_err {
        eprintln!("  Baseline:    ❌ {}", err);
    }

    // Verify signature
    let sig_b64 = signed["signature_b64"].as_str().unwrap_or("");
    let sig_verified = if !sig_b64.is_empty() {
        use ring::signature;
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(quote_json.as_bytes());
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap_or_default();
        let algo: &dyn signature::VerificationAlgorithm = match sig_bytes.len() {
            64 => &signature::ECDSA_P256_SHA256_FIXED,
            _ if sig_bytes.first() == Some(&0x30) => &signature::ECDSA_P256_SHA256_ASN1,
            _ => {
                println!("  Signature:   ⚠️ unknown format");
                &signature::ECDSA_P256_SHA256_FIXED
            }
        };

        // SECURITY: Always verify against the LOCAL trusted DKP key.
        // Never trust signing_pubkey_b64 from the quote envelope — attacker can embed
        // their own key and self-sign a forged quote.
        match std::fs::read(DKP_PUB_DER_PATH) {
            Ok(pubkey_der) => {
                let raw_key = normalize_p256_pubkey(&pubkey_der);
                let key = signature::UnparsedPublicKey::new(algo, raw_key);
                key.verify(&hash, &sig_bytes).is_ok()
            }
            Err(_) => {
                println!(
                    "  Signature:   ⚠️ no trusted DKP public key at {}",
                    DKP_PUB_DER_PATH
                );
                false
            }
        }
    } else {
        println!("  Signature:   ❌ missing");
        false
    };
    println!(
        "  Signature:   {}",
        if sig_verified {
            "✅ valid"
        } else {
            "❌ INVALID"
        }
    );

    // Overall result MUST factor baseline (unless --no-baseline).
    let baseline_pass = baseline_ok || baseline_skipped;
    let integrity_ok = matches!(integrity, "PASS" | "DEGRADED");
    let all_ok = nonce_ok && fresh && chain_ok && baseline_pass && sig_verified && integrity_ok;
    println!(
        "\n  Result:      {}",
        if all_ok { "✅ VERIFIED" } else { "❌ FAILED" }
    );
    if !all_ok {
        std::process::exit(1);
    }
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

fn read_signing_pubkey_b64() -> String {
    std::fs::read(DKP_PUB_DER_PATH)
        .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
        .unwrap_or_default()
}

fn normalize_p256_pubkey(pubkey_der_or_raw: &[u8]) -> &[u8] {
    // DKP pubkey file in this project is commonly 91-byte SPKI DER.
    // ring ECDSA_FIXED/ASN1 expect uncompressed raw point (65 bytes), so strip SPKI header.
    if pubkey_der_or_raw.len() == 91 {
        &pubkey_der_or_raw[26..]
    } else {
        pubkey_der_or_raw
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_p256_pubkey;

    #[test]
    fn normalize_strips_spki_header_when_91_bytes() {
        // 91 bytes -> header 26 + 65 raw point
        let mut v = vec![0u8; 91];
        // put a marker at offset 26
        v[26] = 0xAA;
        let out = normalize_p256_pubkey(&v);
        assert_eq!(out.len(), 65);
        assert_eq!(out[0], 0xAA);
    }

    #[test]
    fn normalize_leaves_other_lengths_untouched() {
        let v = vec![1u8; 65];
        let out = normalize_p256_pubkey(&v);
        assert_eq!(out.len(), 65);
        assert_eq!(out[0], 1u8);
    }

    #[test]
    fn normalize_preserves_empty_short_and_long_non_spki_inputs() {
        for size in [0, 1, 64, 65, 90, 92, 128] {
            let input = vec![size as u8; size];
            let output = normalize_p256_pubkey(&input);
            assert_eq!(output, input.as_slice());
        }
    }
}

fn sign_quote_hash(hash: &[u8], key_version: u32) -> Option<String> {
    use std::process::Command;

    // Method 1: SE050 hardware
    let key_id = format!("0x{:08X}", 0x20000010 + key_version - 1);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp_in = format!("/tmp/guardian_quote_hash_{}.bin", ts);
    let tmp_out = format!("/tmp/guardian_quote_sig_{}.bin", ts);

    if fs::write(&tmp_in, hash).is_ok() {
        if let Ok(output) = Command::new("ssscli")
            .args(["sign", &key_id, &tmp_in, &tmp_out])
            .output()
        {
            if output.status.success() {
                if let Ok(sig) = fs::read(&tmp_out) {
                    let _ = fs::remove_file(&tmp_in);
                    let _ = fs::remove_file(&tmp_out);
                    return Some(base64::engine::general_purpose::STANDARD.encode(&sig));
                }
            }
        }
        let _ = fs::remove_file(&tmp_in);
        let _ = fs::remove_file(&tmp_out);
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
