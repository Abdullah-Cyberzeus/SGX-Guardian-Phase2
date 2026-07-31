use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::geofence::actions::GeofenceAction;
use crate::geofence::model::GeofenceZone;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::fs;
use std::sync::Mutex;

static FIRED: Lazy<Mutex<HashSet<String>>> = Lazy::new(|| Mutex::new(HashSet::new()));

pub async fn dispatch(node_id: &str, zone: &GeofenceZone, transition: &str, confidence: f64) {
    let key = format!("{}:{}", zone.zone_id, transition);
    if !mark_fired(&key) {
        return;
    }
    reset_opposite(zone, transition);

    let actions = if transition == "entry" {
        &zone.automation.on_entry
    } else {
        &zone.automation.on_exit
    };

    for action in actions {
        if let Err(error) = execute(node_id, zone, transition, confidence, action.clone()).await {
            log_audit(
                node_id,
                AuditCategory::Geofence,
                AuditSeverity::Warning,
                AuditAction::Failed,
                &format!("geofence action {:?} failed: {}", action, error),
            );
        }
    }
}

pub async fn execute(
    node_id: &str,
    zone: &GeofenceZone,
    transition: &str,
    confidence: f64,
    action: GeofenceAction,
) -> Result<(), String> {
    if is_destructive(&action)
        && (!zone.automation.allow_destructive || confidence < zone.automation.min_confidence)
    {
        log_audit(
            node_id,
            AuditCategory::Geofence,
            AuditSeverity::Critical,
            AuditAction::Rejected,
            &format!(
                "geofence action {:?} downgraded for zone {} confidence={:.2}",
                action, zone.zone_id, confidence
            ),
        );
        return Ok(());
    }

    let dry_run =
        std::env::var("SGX_GEOFENCE_ACTIONS_DRYRUN").unwrap_or_else(|_| "1".into()) != "0";
    if dry_run {
        log_audit(
            node_id,
            AuditCategory::Geofence,
            AuditSeverity::Info,
            AuditAction::Used,
            &format!(
                "geofence action {:?} would-run zone={} transition={} dry_run={}",
                action, zone.zone_id, transition, dry_run
            ),
        );
        return Ok(());
    }

    run_live(node_id, action.clone()).await?;
    log_audit(
        node_id,
        AuditCategory::Geofence,
        AuditSeverity::Info,
        AuditAction::Applied,
        &format!(
            "geofence action {:?} executed zone={} transition={}",
            action, zone.zone_id, transition
        ),
    );
    Ok(())
}

async fn run_live(node_id: &str, action: GeofenceAction) -> Result<(), String> {
    match action {
        GeofenceAction::RaiseAlert { .. } | GeofenceAction::Notify { .. } => Ok(()),
        GeofenceAction::RunScan => crate::api::handlers::dkp::run_cli(&["discovery", "scan"])
            .await
            .map(|_| ())
            .map_err(|error| format!("{:?}", error)),
        GeofenceAction::EmergencyKeyRotation => {
            crate::api::handlers::dkp::run_cli(&["emergency-rotate"])
                .await
                .map(|_| ())
                .map_err(|error| format!("{:?}", error))
        }
        GeofenceAction::LockNetwork => lock_network(node_id),
    }
}

fn lock_network(node_id: &str) -> Result<(), String> {
    let iface = std::env::var("SGX_GEOFENCE_LOCK_INTERFACE")
        .map_err(|_| "SGX_GEOFENCE_LOCK_INTERFACE is required for LockNetwork".to_string())?;
    if iface.trim().is_empty()
        || !iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == ':')
    {
        return Err("SGX_GEOFENCE_LOCK_INTERFACE is invalid".to_string());
    }
    let lock_dir = std::env::var("SGX_GUARDIAN_COT_LOCK_DIR")
        .unwrap_or_else(|_| "/var/lib/sgx-guardian/cot".to_string());
    fs::create_dir_all(&lock_dir).map_err(|error| error.to_string())?;
    fs::write(
        format!("{}/transport_lock_{}.txt", lock_dir, node_id),
        format!("{}\n", iface),
    )
    .map_err(|error| error.to_string())
}

fn mark_fired(key: &str) -> bool {
    FIRED
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .insert(key.to_string())
}

fn reset_opposite(zone: &GeofenceZone, transition: &str) {
    let opposite = if transition == "entry" {
        "exit"
    } else {
        "entry"
    };
    FIRED
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .remove(&format!("{}:{}", zone.zone_id, opposite));
}

fn is_destructive(action: &GeofenceAction) -> bool {
    matches!(
        action,
        GeofenceAction::LockNetwork | GeofenceAction::EmergencyKeyRotation
    )
}
