// src/secure_element/pcr_config.rs
// PCR measurement source configuration.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrMeasurementSource {
    pub pcr_index: usize,
    pub label: String,
    /// "file", "string", or "multi_file" (comma-separated paths)
    pub source_type: String,
    pub source: String,
    /// true = system won't boot without this, FAIL if missing
    pub critical: bool,
}

/// Hardware board measurement sources
pub fn default_measurement_sources(node_id: &str) -> Vec<PcrMeasurementSource> {
    vec![
        PcrMeasurementSource {
            pcr_index: 0,
            label: "Boot chain state".into(),
            source_type: "boot_chain".into(), // NEW type
            source: "hab_status".into(),
            critical: true,
        },
        PcrMeasurementSource {
            pcr_index: 1,
            label: "Device tree".into(),
            source_type: "file".into(),
            source: "/proc/device-tree/compatible".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 2,
            label: "Kernel".into(),
            source_type: "file".into(),
            // Prefer static binary, fallback to /proc/version
            source: if std::path::Path::new("/boot/Image").exists() {
                "/boot/Image".into()
            } else {
                "/proc/version".into()
            },
            critical: true,
        },
        PcrMeasurementSource {
            pcr_index: 3,
            label: "RootFS integrity".into(),
            source_type: "multi_file".into(),
            source: "/bin/sh,/sbin/init,/usr/bin/ssscli".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 4,
            label: "Guardian config".into(),
            source_type: "file".into(),
            source: format!("/etc/sgx-guardian/{}.yaml", node_id),
            critical: false,
        },
    ]
}

/// Software mode (dev laptop) measurement sources
pub fn software_measurement_sources() -> Vec<PcrMeasurementSource> {
    vec![
        PcrMeasurementSource {
            pcr_index: 0,
            label: "Bootloader (sim)".into(),
            source_type: "string".into(),
            source: "software-boot-v1.0".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 1,
            label: "Firmware (sim)".into(),
            source_type: "string".into(),
            source: "software-firmware-v1.0".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 2,
            label: "Kernel".into(),
            source_type: "file".into(),
            source: "/proc/version".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 3,
            label: "RootFS (sim)".into(),
            source_type: "string".into(),
            source: "software-rootfs-v1.0".into(),
            critical: false,
        },
        PcrMeasurementSource {
            pcr_index: 4,
            label: "Guardian config".into(),
            source_type: "file".into(),
            source: "/etc/sgx-guardian/schemas/uep_policy_v1.yaml".into(),
            critical: false,
        },
    ]
}
