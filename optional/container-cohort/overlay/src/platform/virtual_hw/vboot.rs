use crate::secure_element::secure_boot::BootChainStatus;

pub fn simulated_boot_chain_status() -> BootChainStatus {
    let kernel_version = std::fs::read_to_string("/proc/version")
        .unwrap_or_default()
        .trim()
        .to_string();
    BootChainStatus {
        hab_enabled: false,
        device_closed: false,
        hab_events_found: false,
        hab_description: "SIMULATED - virtual dev platform".to_string(),
        kernel_version,
        device_model: "virtual-x86_64".to_string(),
        guardian_binary_hash: None,
        boot_chain_intact: false,
    }
}
