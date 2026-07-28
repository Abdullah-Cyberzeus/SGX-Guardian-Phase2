// sgx-pa-cli/src/commands/dkp_revoke.rs
// Revoke a specific DKP key version in the metadata history.
// Cannot revoke Active key — must rotate first.

use chrono::Utc;
use clap::Args;
use std::fs;
use std::path::Path;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";

#[derive(Args)]
#[command(about = "Revoke a deprecated DKP key version")]
pub struct DkpRevokeArgs {
    /// Key version to revoke
    #[arg(long)]
    pub version: u32,
    /// Reason for revocation
    #[arg(long, default_value = "admin revocation")]
    pub reason: String,
}

pub fn run(args: DkpRevokeArgs) {
    println!("=== DKP Key Revocation ===\n");

    if !Path::new(METADATA_PATH).exists() {
        eprintln!("No DKP metadata found.");
        std::process::exit(1);
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Read error: {}", e);
            std::process::exit(1);
        }
    };

    // Load history array
    let mut keys: Vec<serde_json::Value> = {
        let trimmed = json.trim();
        if trimmed.starts_with('[') {
            match serde_json::from_str::<Vec<serde_json::Value>>(trimmed) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("❌ Failed to parse DKP metadata: {}", e);
                    eprintln!("   File may be corrupted: {}", METADATA_PATH);
                    std::process::exit(1);
                }
            }
        } else {
            match serde_json::from_str::<serde_json::Value>(trimmed) {
                Ok(v) => vec![v],
                Err(e) => {
                    eprintln!("❌ Failed to parse DKP metadata: {}", e);
                    eprintln!("   File may be corrupted: {}", METADATA_PATH);
                    std::process::exit(1);
                }
            }
        }
    };

    // Find the target version
    let target_idx = keys.iter().position(|k| {
        k.get("version")
            .and_then(|v| v.as_u64())
            .and_then(|v| u32::try_from(v).ok())
            == Some(args.version)
    });

    let target_idx = match target_idx {
        Some(i) => i,
        None => {
            eprintln!("Version {} not found in key history.", args.version);
            println!("Available versions:");
            for k in &keys {
                println!(
                    "  v{} [{}]",
                    k["version"],
                    k["status"].as_str().unwrap_or("?")
                );
            }
            std::process::exit(1);
        }
    };

    let status = keys[target_idx]["status"].as_str().unwrap_or("unknown");

    // Cannot revoke active key
    if status == "Active" {
        eprintln!("Cannot revoke active key (v{}).", args.version);
        eprintln!("You must rotate first: sgx-pa-cli dkp-rotate");
        std::process::exit(1);
    }

    // Already revoked
    if status == "Revoked" {
        println!("Key v{} is already revoked.", args.version);
        return;
    }

    // Revoke the key
    keys[target_idx]["status"] = serde_json::json!("Revoked");
    keys[target_idx]["revoked_at"] = serde_json::json!(Utc::now().to_rfc3339());
    keys[target_idx]["revoke_reason"] = serde_json::json!(args.reason);

    let serialized = match serde_json::to_string_pretty(&keys) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("❌ Failed to serialize DKP metadata: {}", e);
            std::process::exit(1);
        }
    };
    let tmp_path = format!("{}.tmp", METADATA_PATH);
    if let Err(e) = fs::write(&tmp_path, &serialized) {
        eprintln!("❌ Failed to write temp metadata: {}", e);
        std::process::exit(1);
    }
    if let Err(e) = fs::rename(&tmp_path, METADATA_PATH) {
        eprintln!("❌ Failed to atomically replace metadata: {}", e);
        std::process::exit(1);
    }

    println!("✅ Key v{} revoked.", args.version);
    println!("   Reason: {}", args.reason);
    println!("   Revocation is permanent. Key cannot be un-revoked.");
    println!("   Verification of old signatures available for 30-day grace period.");
}
