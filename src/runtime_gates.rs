// src/runtime_gates.rs
// =============================================================
// Debug / isolation gates for diagnosing startup freezes.
// Every env var below is read ONCE at process start and cached.
// All defaults preserve existing behaviour (nothing disabled).
//
// Usage examples (shell):
//   SGX_DISABLE_NEBULA=1         ./sgx_guardian_client nodeA
//   SGX_DISABLE_RELAY_TC=1       ./sgx_guardian_client nodeA
//   SGX_DISABLE_COT_BLUETOOTH=1  ./sgx_guardian_client nodeA
//   SGX_STARTUP_COOLDOWN_MS=2000 ./sgx_guardian_client nodeA
// =============================================================

use once_cell::sync::Lazy;
#[cfg(test)]
use std::sync::atomic::{AtomicI8, Ordering};

fn env_true(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("on")
    )
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

pub struct RuntimeGates {
    // existing (already wired)
    pub disable_nebula: bool,
    pub disable_relay_tc: bool,
    pub disable_relay_stats: bool,
    pub disable_tunnel_observer: bool,
    pub disable_cot: bool,
    pub disable_cot_bluetooth: bool,
    pub disable_cot_cellular: bool,
    pub disable_cot_satellite: bool,
    pub disable_cot_refresh: bool,
    pub disable_p2p_discovery: bool,
    pub disable_attestation: bool,
    pub disable_broadcast: bool,
    pub disable_cloud_uplink: bool,
    pub disable_expiry_monitor: bool,
    pub disable_lighthouse_health: bool,

    // NEW — early-startup isolation (previously missing)
    /// Force software ring keypair, never call ssscli for identity.
    pub force_software_keys: bool,
    /// Skip DKP auto-rotation check (one ssscli call).
    pub disable_dkp_rotation: bool,
    /// Skip AttestationService::create_signed_evidence (avoid ssscli sign at startup).
    pub disable_startup_attest_evidence: bool,
    /// Skip BootChainStatus::check (devmem2 + /sys reads).
    pub disable_secure_boot_check: bool,
    /// Skip PCR measurement (lots of filesystem reads + ssscli sign).
    pub disable_pcr_measurement: bool,
    /// Skip AuditVerifier::verify on existing audit.log.
    pub disable_audit_verify: bool,
    /// Skip mTLS cert setup + gRPC server spawn.
    pub disable_grpc_server: bool,
    /// Skip plaintext cert bootstrap server on :50061 (nodeA only).
    pub disable_cert_bootstrap: bool,
    /// Skip nftables policy enforcement.
    pub disable_policy_enforcement: bool,
    /// Skip node_listener UDP 9000 receiver.
    pub disable_node_listener: bool,
    /// Maximum seconds to wait for any single ssscli subprocess.
    pub ssscli_timeout_secs: u64,

    /// Milliseconds to sleep between major subsystem startups. 0 = no cooldown.
    pub startup_cooldown_ms: u64,

    /// Skip login/auth enforcement — all API routes accessible without a Bearer token.
    pub disable_login: bool,

    // Board-freeze fix (Apr 2026)
    /// Attempt to read OCOTP fuses via /sys/bus/nvmem. Default ON.
    pub read_ocotp: bool,
    /// Compute SHA-256 of the daemon binary (17 MB, ~1 s blocking). Default OFF.
    pub measure_binary_hash: bool,
    /// Operator opt-out for OCOTP reads.
    pub disable_read_ocotp: bool,
}

impl RuntimeGates {
    fn load() -> Self {
        Self {
            disable_nebula: env_true("SGX_DISABLE_NEBULA"),
            disable_relay_tc: env_true("SGX_DISABLE_RELAY_TC"),
            disable_relay_stats: env_true("SGX_DISABLE_RELAY_STATS"),
            disable_tunnel_observer: env_true("SGX_DISABLE_TUNNEL_OBSERVER"),
            disable_cot: env_true("SGX_DISABLE_COT"),
            disable_cot_bluetooth: env_true("SGX_DISABLE_COT_BLUETOOTH"),
            disable_cot_cellular: env_true("SGX_DISABLE_COT_CELLULAR"),
            disable_cot_satellite: env_true("SGX_DISABLE_COT_SATELLITE"),
            disable_cot_refresh: env_true("SGX_DISABLE_COT_REFRESH"),
            disable_p2p_discovery: env_true("SGX_DISABLE_P2P_DISCOVERY"),
            disable_attestation: env_true("SGX_DISABLE_ATTESTATION"),
            disable_broadcast: env_true("SGX_DISABLE_BROADCAST"),
            disable_cloud_uplink: env_true("SGX_DISABLE_CLOUD_UPLINK"),
            disable_expiry_monitor: env_true("SGX_DISABLE_EXPIRY_MONITOR"),
            disable_lighthouse_health: env_true("SGX_DISABLE_LIGHTHOUSE_HEALTH"),
            force_software_keys: env_true("SGX_FORCE_SOFTWARE_KEYS")
                || env_true("SGX_DISABLE_SE050_DKP"),
            disable_dkp_rotation: env_true("SGX_DISABLE_DKP_ROTATION"),
            disable_startup_attest_evidence: env_true("SGX_DISABLE_STARTUP_ATTEST"),
            disable_secure_boot_check: env_true("SGX_DISABLE_SECURE_BOOT_CHECK"),
            disable_pcr_measurement: env_true("SGX_DISABLE_PCR"),
            disable_audit_verify: env_true("SGX_DISABLE_AUDIT_VERIFY"),
            disable_grpc_server: env_true("SGX_DISABLE_GRPC_SERVER"),
            disable_cert_bootstrap: env_true("SGX_DISABLE_CERT_BOOTSTRAP"),
            disable_policy_enforcement: env_true("SGX_DISABLE_POLICY_ENFORCEMENT"),
            disable_node_listener: env_true("SGX_DISABLE_NODE_LISTENER"),
            ssscli_timeout_secs: env_u64("SGX_SSSCLI_TIMEOUT_SECS", 10),
            startup_cooldown_ms: env_u64("SGX_STARTUP_COOLDOWN_MS", 0),
            disable_login: env_true("SGX_DISABLE_LOGIN"),
            // Default ON, with two disable options:
            // 1) SGX_DISABLE_READ_OCOTP=1
            // 2) explicit SGX_READ_OCOTP=0|false|no|off
            read_ocotp: {
                let disable = env_true("SGX_DISABLE_READ_OCOTP");
                let explicit_off = std::env::var("SGX_READ_OCOTP")
                    .ok()
                    .map(|v| matches!(v.as_str(), "0" | "false" | "FALSE" | "no" | "off"))
                    .unwrap_or(false);
                !(disable || explicit_off)
            },
            measure_binary_hash: env_true("SGX_MEASURE_BINARY_HASH"),
            disable_read_ocotp: env_true("SGX_DISABLE_READ_OCOTP"),
        }
    }

    pub fn log_summary(&self) {
        tracing::info!(
            "Runtime gates: nebula={} relay_tc={} relay_stats={} tunnel={} cot={} bt={} cell={} sat={} refresh={} p2p={} att={} bcast={} cloud={} expiry={} lhhealth={} swkeys={} dkp_rot={} startup_attest={} sbcheck={} pcr={} audit={} grpc={} cert_bootstrap={} policy={} node_listener={} ssscli_timeout_secs={} cooldown_ms={}",
            self.disable_nebula,
            self.disable_relay_tc,
            self.disable_relay_stats,
            self.disable_tunnel_observer,
            self.disable_cot,
            self.disable_cot_bluetooth,
            self.disable_cot_cellular,
            self.disable_cot_satellite,
            self.disable_cot_refresh,
            self.disable_p2p_discovery,
            self.disable_attestation,
            self.disable_broadcast,
            self.disable_cloud_uplink,
            self.disable_expiry_monitor,
            self.disable_lighthouse_health,
            self.force_software_keys,
            self.disable_dkp_rotation,
            self.disable_startup_attest_evidence,
            self.disable_secure_boot_check,
            self.disable_pcr_measurement,
            self.disable_audit_verify,
            self.disable_grpc_server,
            self.disable_cert_bootstrap,
            self.disable_policy_enforcement,
            self.disable_node_listener,
            self.ssscli_timeout_secs,
            self.startup_cooldown_ms
        );
        tracing::info!("Runtime gates: disable_login={}", self.disable_login,);
        tracing::info!(
            "Runtime gates (boot): read_ocotp={} (disable_flag={}) measure_binary_hash={}",
            self.read_ocotp,
            self.disable_read_ocotp,
            self.measure_binary_hash
        );
    }
}

pub static GATES: Lazy<RuntimeGates> = Lazy::new(RuntimeGates::load);

#[cfg(test)]
static TEST_DISABLE_LOGIN_OVERRIDE: AtomicI8 = AtomicI8::new(-1);

pub fn login_disabled() -> bool {
    #[cfg(test)]
    {
        match TEST_DISABLE_LOGIN_OVERRIDE.load(Ordering::SeqCst) {
            0 => return false,
            1 => return true,
            _ => {}
        }
    }
    GATES.disable_login
}

#[cfg(test)]
pub fn set_test_login_disabled(value: Option<bool>) {
    let encoded = match value {
        Some(false) => 0,
        Some(true) => 1,
        None => -1,
    };
    TEST_DISABLE_LOGIN_OVERRIDE.store(encoded, Ordering::SeqCst);
}
/// Sleep the configured cooldown (if > 0). Use between heavy subsystem starts.
pub async fn cooldown() {
    let ms = GATES.startup_cooldown_ms;
    if ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

/// Print STEP marker to stdout (for run_node.sh head -20 and operator visibility).
/// Intentionally not sent through tracing to avoid duplicating on the console layer.
pub fn step(n: u32, label: &str) {
    println!("STEP_{:02} {}", n, label);
}
