use std::fs;

const PCR_DIR: &str = "/var/lib/sgx-guardian/pcr";

fn find_pcr_snapshot() -> Option<String> {
    if let Ok(entries) = fs::read_dir(PCR_DIR) {
        let mut found: Vec<String> = entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                if name.ends_with("_current.json") || name == "current.json" {
                    Some(e.path().to_string_lossy().to_string())
                } else {
                    None
                }
            })
            .collect();
        found.sort();
        return found.into_iter().next();
    }
    None
}

pub fn run() {
    println!("=== PCR Status ===\n");
    let pcr_path = match find_pcr_snapshot() {
        Some(p) => p,
        None => {
            println!("No PCR snapshot found. Run the guardian daemon first.");
            return;
        }
    };
    println!("  Source: {}\n", pcr_path);
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

    let names = [
        "BIOS/Bootloader",
        "Firmware/DTB",
        "Kernel",
        "RootFS",
        "Configuration",
    ];
    if let Some(pcrs) = snap["pcr_values"].as_array() {
        for (i, val) in pcrs.iter().enumerate() {
            let name = names.get(i).unwrap_or(&"Unknown");
            println!("  PCR{}: {}  ({})", i, val.as_str().unwrap_or("?"), name);
        }
    }
    println!(
        "\n  Composite:  {}",
        snap["composite_digest"].as_str().unwrap_or("?")
    );
    println!(
        "  Integrity:  {}",
        snap["integrity_status"].as_str().unwrap_or("?")
    );
    println!(
        "  Measured:   {}",
        snap["measured_at"].as_str().unwrap_or("?")
    );
    println!(
        "  Device UID: {}",
        snap["device_uid"].as_str().unwrap_or("?")
    );
    println!("  Key ver:    {}", snap["key_version"]);
    println!(
        "  Signed:     {}",
        if snap["composite_signature"].is_null() {
            "No"
        } else {
            "Yes"
        }
    );
}
