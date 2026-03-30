use std::fs;

const BOOT_DIR: &str = "/var/lib/sgx-guardian/boot";

pub fn run() {
    println!("=== Secure Boot Chain Status ===\n");

    // Find boot chain status file
    let status_path = find_boot_status();
    match status_path {
        Some(path) => {
            let json = fs::read_to_string(&path).unwrap_or_default();
            let status: serde_json::Value = serde_json::from_str(&json).unwrap_or_default();

            println!("  Source: {}\n", path);
            println!(
                "  HAB Enabled:      {}",
                if status["hab_enabled"].as_bool().unwrap_or(false) {
                    "✅ Yes"
                } else {
                    "❌ No"
                }
            );
            println!(
                "  Device Closed:    {}",
                if status["device_closed"].as_bool().unwrap_or(false) {
                    "🔒 Yes (enforcing)"
                } else {
                    "🔓 No"
                }
            );
            println!(
                "  HAB Events:       {}",
                if status["hab_events_found"].as_bool().unwrap_or(false) {
                    "⚠️ Found"
                } else {
                    "✅ None"
                }
            );
            println!(
                "  Device Model:     {}",
                status["device_model"].as_str().unwrap_or("?")
            );
            println!(
                "  Boot Chain:       {}",
                if status["boot_chain_intact"].as_bool().unwrap_or(false) {
                    "✅ INTACT"
                } else {
                    "⚠️ INCOMPLETE"
                }
            );

            if let Some(hash) = status["guardian_binary_hash"].as_str() {
                println!("  Binary Hash:      {}...", &hash[..16]);
            }

            println!("\n  Trust Chain:");
            println!("    [Boot ROM] → [HAB verifies U-Boot] → [U-Boot verifies Kernel]");
            println!(
                "    → [Kernel loads verified RootFS] → [Guardian daemon] → [SE050 signs PCR]"
            );
        }
        None => {
            println!("  No boot chain status found. Run guardian daemon first.");
        }
    }
}

fn find_boot_status() -> Option<String> {
    if let Ok(entries) = fs::read_dir(BOOT_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with("_chain_status.json") {
                return Some(entry.path().to_string_lossy().to_string());
            }
        }
    }
    None
}
