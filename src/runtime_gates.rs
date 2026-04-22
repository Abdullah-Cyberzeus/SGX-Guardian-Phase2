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
    /// Milliseconds to sleep between major subsystem startups. 0 = no cooldown.
    pub startup_cooldown_ms: u64,
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
            startup_cooldown_ms: env_u64("SGX_STARTUP_COOLDOWN_MS", 0),
        }
    }

    pub fn log_summary(&self) {
        tracing::info!(
            "Runtime gates: nebula={} relay_tc={} relay_stats={} tunnel={} cot={} bt={} cell={} sat={} refresh={} p2p={} att={} bcast={} cloud={} expiry={} lhhealth={} cooldown_ms={}",
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
            self.startup_cooldown_ms
        );
    }
}

pub static GATES: Lazy<RuntimeGates> = Lazy::new(RuntimeGates::load);

/// Sleep the configured cooldown (if > 0). Use between heavy subsystem starts.
pub async fn cooldown() {
    let ms = GATES.startup_cooldown_ms;
    if ms > 0 {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

/// Print STEP marker (logged + printed once to stdout for run_node.sh head -20).
pub fn step(n: u32, label: &str) {
    tracing::info!("STEP_{:02} {}", n, label);
    println!("STEP_{:02} {}", n, label);
}
