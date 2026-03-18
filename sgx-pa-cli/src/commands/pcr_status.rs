use std::fs;
use std::path::Path;

const PCR_PATH: &str = "/var/lib/sgx-guardian/pcr/current.json";

pub fn run() {
    println!("=== PCR Status ===\n");
    if !Path::new(PCR_PATH).exists() {
        println!("No PCR snapshot found. Run the guardian daemon first.");
        return;
    }
    let json = match fs::read_to_string(PCR_PATH) {
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
    println!("  Integrity:  {}", snap["integrity_status"].as_str().unwrap_or("?"));
    println!("  Measured:   {}", snap["measured_at"].as_str().unwrap_or("?"));
    println!("  Device UID: {}", snap["device_uid"].as_str().unwrap_or("?"));
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
