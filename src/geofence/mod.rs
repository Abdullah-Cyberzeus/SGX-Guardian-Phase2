pub mod actions;
pub mod alerts;
pub mod errors;
pub mod eval;
pub mod model;
pub mod persistence;
pub mod sources;
pub mod zones;

#[derive(Debug, Clone)]
pub struct GeofenceConfig {
    pub eval_secs: u64,
    pub hysteresis: u64,
}

impl GeofenceConfig {
    pub const DEFAULT_EVAL_SECS: u64 = 30;
    pub const DEFAULT_HYSTERESIS: u64 = 2;

    pub fn from_env() -> Self {
        Self {
            eval_secs: parse_eval_secs(std::env::var("SGX_GEOFENCE_EVAL_SECS").ok()),
            hysteresis: parse_hysteresis(std::env::var("SGX_GEOFENCE_HYSTERESIS").ok()),
        }
    }
}

pub fn spawn(node_id: String) {
    let config = GeofenceConfig::from_env();
    println!(
        "📍 Geofence engine starting interval_secs={} hysteresis={}",
        config.eval_secs, config.hysteresis
    );
    crate::audit::logger::log_audit(
        &node_id,
        crate::audit::event::AuditCategory::Geofence,
        crate::audit::event::AuditSeverity::Info,
        crate::audit::event::AuditAction::Started,
        &format!(
            "Geofence engine started interval_secs={} hysteresis={}",
            config.eval_secs, config.hysteresis
        ),
    );
    tokio::spawn(eval::evaluation_loop(node_id, config));
}

fn parse_eval_secs(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(GeofenceConfig::DEFAULT_EVAL_SECS)
        .clamp(1, 3600)
}

fn parse_hysteresis(raw: Option<String>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(GeofenceConfig::DEFAULT_HYSTERESIS)
        .clamp(1, 100)
}
