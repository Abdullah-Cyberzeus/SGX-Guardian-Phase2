// sgx-pa-cli/src/commands/dkp_status.rs
// Show all DKP key versions and current status.
// Works on both hardware (board) and software (dev laptop).

use std::fs;
use std::path::Path;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
const PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";

pub fn run() {
    println!("=== DKP Key Status ===\n");

    if !Path::new(METADATA_PATH).exists() {
        println!("Status: No DKP found");
        println!("  Run the guardian daemon to auto-generate DKP.");
        return;
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to read {}: {}", METADATA_PATH, e);
            return;
        }
    };

    let keys: Vec<serde_json::Value> = {
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

    println!("Total key versions: {}\n", keys.len());

    for key in &keys {
        let status = key["status"].as_str().unwrap_or("unknown");
        let marker = match status {
            "Active" => "→",
            "Deprecated" => " ",
            "Revoked" => "✗",
            _ => "?",
        };
        println!("{} Version {}  [{}]", marker, key["version"], status);
        println!("    Key ID:    {}", key["key_id"].as_str().unwrap_or("?"));
        println!(
            "    Algorithm: {}",
            key["algorithm"].as_str().unwrap_or("?")
        );
        println!(
            "    Created:   {}",
            key["created_at"].as_str().unwrap_or("?")
        );
        if let Some(from) = key["rotated_from"].as_str() {
            println!("    Rotated from: {}", from);
        }
        if let Some(at) = key["revoked_at"].as_str() {
            println!("    Revoked at: {}", at);
            println!(
                "    Reason:     {}",
                key["revoke_reason"].as_str().unwrap_or("none")
            );
        }
        println!();
    }

    if Path::new(PUBKEY_PATH).exists() {
        let size = fs::metadata(PUBKEY_PATH).map(|m| m.len()).unwrap_or(0);
        println!("Active public key: {} ({} bytes)", PUBKEY_PATH, size);
    }

    match std::process::Command::new("ssscli")
        .arg("--version")
        .output()
    {
        Ok(o) if o.status.success() => println!("SE050: Available"),
        _ => println!("SE050: Not available (software-only mode)"),
    }
}
