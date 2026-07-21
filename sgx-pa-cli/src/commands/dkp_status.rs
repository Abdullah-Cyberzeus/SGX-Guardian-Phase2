// sgx-pa-cli/src/commands/dkp_status.rs
// Show all DKP key versions and current status.
// Works on both hardware (board) and software (dev laptop).

use std::fs;
use std::path::Path;
use std::process::Command;

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

    print_backend_status(&detect_backend(&keys));
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ActiveBackend {
    #[cfg(any(feature = "tpm", test))]
    Tpm {
        dkp_handle: u32,
        dik_handle: u32,
        algorithm: String,
    },
    Se050 {
        algorithm: String,
    },
    Software {
        algorithm: String,
    },
}

fn detect_backend(keys: &[serde_json::Value]) -> ActiveBackend {
    let active = keys.iter().find(|key| key["status"] == "Active");
    let algorithm = active
        .and_then(|key| key["algorithm"].as_str())
        .unwrap_or("ECDSA-P256")
        .to_string();

    #[cfg(feature = "tpm")]
    if let Some(dkp_handle) = active
        .and_then(|key| key["key_id"].as_str())
        .and_then(parse_hex_handle)
        .filter(|handle| is_tpm_persistent_handle(*handle))
    {
        let cfg = sgx_guardian_client::tpm::TpmConfig::default();
        return ActiveBackend::Tpm {
            dkp_handle,
            dik_handle: cfg.dik_handle,
            algorithm,
        };
    }

    if ssscli_available() {
        ActiveBackend::Se050 { algorithm }
    } else {
        ActiveBackend::Software { algorithm }
    }
}

fn print_backend_status(backend: &ActiveBackend) {
    let output = render_backend_status(backend);
    print!("{}", output);
}

fn render_backend_status(backend: &ActiveBackend) -> String {
    match backend {
        #[cfg(any(feature = "tpm", test))]
        ActiveBackend::Tpm {
            dkp_handle,
            dik_handle,
            algorithm,
        } => format!(
            "Backend: TPM 2.0\nProvider: Hardware\nDKP handle: 0x{dkp_handle:08X}\nDIK handle: 0x{dik_handle:08X}\nAlgorithm: {algorithm}\n"
        ),
        ActiveBackend::Se050 { algorithm } => format!(
            "Backend: SE050\nProvider: Hardware\nAlgorithm: {algorithm}\nSE050: Available\n"
        ),
        ActiveBackend::Software { algorithm } => format!(
            "Backend: Software\nProvider: Software\nAlgorithm: {algorithm}\nSE050: Not available (software-only mode)\n"
        ),
    }
}

fn ssscli_available() -> bool {
    Command::new("ssscli")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[cfg(feature = "tpm")]
fn is_tpm_persistent_handle(handle: u32) -> bool {
    (handle & 0xFF00_0000) == 0x8100_0000
}

#[cfg(feature = "tpm")]
fn parse_hex_handle(value: &str) -> Option<u32> {
    let value = value.trim();
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u32::from_str_radix(value, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_tpm_status_output() {
        let output = render_backend_status(&ActiveBackend::Tpm {
            dkp_handle: 0x8100_0010,
            dik_handle: 0x8100_0100,
            algorithm: "ECDSA-P256".to_string(),
        });

        assert!(output.contains("Backend: TPM 2.0"));
        assert!(output.contains("Provider: Hardware"));
        assert!(output.contains("DKP handle: 0x81000010"));
        assert!(output.contains("DIK handle: 0x81000100"));
        assert!(output.contains("Algorithm: ECDSA-P256"));
        assert!(!output.contains("SE050: Not available"));
    }

    #[test]
    fn renders_se050_status_output() {
        let output = render_backend_status(&ActiveBackend::Se050 {
            algorithm: "ECDSA-P256".to_string(),
        });

        assert!(output.contains("Backend: SE050"));
        assert!(output.contains("Provider: Hardware"));
        assert!(output.contains("Algorithm: ECDSA-P256"));
        assert!(output.contains("SE050: Available"));
    }

    #[test]
    fn renders_software_status_output() {
        let output = render_backend_status(&ActiveBackend::Software {
            algorithm: "ECDSA-P256".to_string(),
        });

        assert!(output.contains("Backend: Software"));
        assert!(output.contains("Provider: Software"));
        assert!(output.contains("Algorithm: ECDSA-P256"));
        assert!(output.contains("SE050: Not available (software-only mode)"));
    }

    #[cfg(feature = "tpm")]
    #[test]
    fn detects_tpm_active_key_from_persistent_handle_metadata() {
        let keys = vec![serde_json::json!({
            "key_id": "0x81000010",
            "algorithm": "ECDSA-P256",
            "version": 1,
            "status": "Active"
        })];

        assert_eq!(
            detect_backend(&keys),
            ActiveBackend::Tpm {
                dkp_handle: 0x8100_0010,
                dik_handle: sgx_guardian_client::tpm::TpmConfig::default().dik_handle,
                algorithm: "ECDSA-P256".to_string(),
            }
        );
    }
}
