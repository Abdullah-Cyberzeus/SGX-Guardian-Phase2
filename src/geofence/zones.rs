use crate::did::document::Proof;
use crate::geofence::actions::ZoneAutomation;
use crate::geofence::errors::{GeofenceError, GeofenceResult};
use crate::geofence::model::{
    default_rf_threshold, Fix, GeofenceRegistry, GeofenceZone, RfSignature, ZoneKind, ZoneStatus,
};
use crate::geofence::persistence;
use chrono::Utc;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Mutex;

pub static GEOFENCE_WRITE_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const EARTH_RADIUS_M: f64 = 6_371_000.0;

#[derive(Debug, Clone, Default)]
pub struct ZonePatch {
    pub name: Option<String>,
    pub kind: Option<ZoneKind>,
    pub center_lat: Option<Option<f64>>,
    pub center_lng: Option<Option<f64>>,
    pub radius_m: Option<Option<f64>>,
    pub rf_signature: Option<Option<RfSignature>>,
    pub on_entry: Option<bool>,
    pub on_exit: Option<bool>,
    pub severity: Option<String>,
    pub automation: Option<ZoneAutomation>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct NewZoneInput {
    pub name: String,
    pub kind: ZoneKind,
    pub center_lat: Option<f64>,
    pub center_lng: Option<f64>,
    pub radius_m: Option<f64>,
    pub rf_signature: Option<RfSignature>,
    pub on_entry: bool,
    pub on_exit: bool,
    pub severity: String,
    pub automation: ZoneAutomation,
    pub enabled: bool,
}

pub fn load_or_seed_registry() -> GeofenceResult<GeofenceRegistry> {
    let _guard = GEOFENCE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    load_or_seed_registry_unlocked()
}

pub fn list_zones() -> GeofenceResult<Vec<GeofenceZone>> {
    Ok(load_or_seed_registry()?.zones)
}

pub fn create_zone(mut zone: GeofenceZone) -> GeofenceResult<GeofenceZone> {
    validate_zone(&zone)?;
    let _guard = GEOFENCE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut registry = load_or_seed_registry_unlocked()?;
    if registry
        .zones
        .iter()
        .any(|existing| existing.zone_id == zone.zone_id)
    {
        zone.zone_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
    }
    let now = Utc::now().to_rfc3339();
    zone.created_at = now.clone();
    zone.updated_at = now;
    registry.zones.push(zone.clone());
    registry.sequence += 1;
    registry.generated_at = Utc::now().to_rfc3339();
    seal_registry(&mut registry)?;
    persistence::save_registry(&registry)?;
    Ok(zone)
}

pub fn update_zone(id: &str, patch: ZonePatch) -> GeofenceResult<GeofenceZone> {
    let _guard = GEOFENCE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut registry = load_or_seed_registry_unlocked()?;
    let zone = registry
        .zones
        .iter_mut()
        .find(|zone| zone.zone_id == id)
        .ok_or_else(|| GeofenceError::NotFound(id.to_string()))?;

    if let Some(name) = patch.name {
        zone.name = name;
    }
    if let Some(kind) = patch.kind {
        zone.kind = kind;
    }
    if let Some(center_lat) = patch.center_lat {
        zone.center_lat = center_lat;
    }
    if let Some(center_lng) = patch.center_lng {
        zone.center_lng = center_lng;
    }
    if let Some(radius_m) = patch.radius_m {
        zone.radius_m = radius_m;
    }
    if let Some(rf_signature) = patch.rf_signature {
        zone.rf_signature = rf_signature;
    }
    if let Some(on_entry) = patch.on_entry {
        zone.on_entry = on_entry;
    }
    if let Some(on_exit) = patch.on_exit {
        zone.on_exit = on_exit;
    }
    if let Some(severity) = patch.severity {
        zone.severity = severity;
    }
    if let Some(automation) = patch.automation {
        crate::geofence::actions::validate(&automation).map_err(GeofenceError::InvalidInput)?;
        zone.automation = automation;
    }
    if let Some(enabled) = patch.enabled {
        zone.enabled = enabled;
    }
    zone.updated_at = Utc::now().to_rfc3339();
    validate_zone(zone)?;
    let updated = zone.clone();
    registry.sequence += 1;
    registry.generated_at = Utc::now().to_rfc3339();
    seal_registry(&mut registry)?;
    persistence::save_registry(&registry)?;
    Ok(updated)
}

pub fn delete_zone(id: &str) -> GeofenceResult<GeofenceZone> {
    let _guard = GEOFENCE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut registry = load_or_seed_registry_unlocked()?;
    let index = registry
        .zones
        .iter()
        .position(|zone| zone.zone_id == id)
        .ok_or_else(|| GeofenceError::NotFound(id.to_string()))?;
    let removed = registry.zones.remove(index);
    registry.sequence += 1;
    registry.generated_at = Utc::now().to_rfc3339();
    seal_registry(&mut registry)?;
    persistence::save_registry(&registry)?;
    Ok(removed)
}

pub fn evaluate_zone(zone: &GeofenceZone, fix: &Fix) -> ZoneStatus {
    let mut status = ZoneStatus {
        zone_id: zone.zone_id.clone(),
        zone_name: zone.name.clone(),
        enabled: zone.enabled,
        inside: None,
        distance_m: None,
        rf_score: None,
    };
    if !zone.enabled {
        return status;
    }

    match (&zone.kind, fix) {
        (ZoneKind::Coordinate, Fix::Coordinate { lat, lng, .. }) => {
            if let (Some(center_lat), Some(center_lng), Some(radius_m)) =
                (zone.center_lat, zone.center_lng, zone.radius_m)
            {
                let distance = haversine_m(*lat, *lng, center_lat, center_lng);
                status.distance_m = Some(distance);
                status.inside = Some(distance <= radius_m);
            }
        }
        (ZoneKind::RfSignature, Fix::RfSignature { aps }) => {
            if let Some(signature) = &zone.rf_signature {
                let score = rf_match_score(signature, aps);
                status.rf_score = Some(score);
                status.inside = Some(score >= signature.threshold);
            }
        }
        _ => {}
    }
    status
}

pub fn haversine_m(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    let dlat = (lat2 - lat1).to_radians();
    let dlng = (lng2 - lng1).to_radians();
    let lat1 = lat1.to_radians();
    let lat2 = lat2.to_radians();
    let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlng / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().atan2((1.0 - a).sqrt())
}

pub fn validate_coordinate(lat: f64, lng: f64) -> GeofenceResult<()> {
    if !lat.is_finite() || !lng.is_finite() {
        return Err(GeofenceError::InvalidInput(
            "latitude and longitude must be finite".to_string(),
        ));
    }
    if !(-90.0..=90.0).contains(&lat) {
        return Err(GeofenceError::InvalidInput(
            "latitude must be between -90 and 90".to_string(),
        ));
    }
    if !(-180.0..=180.0).contains(&lng) {
        return Err(GeofenceError::InvalidInput(
            "longitude must be between -180 and 180".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_zone(zone: &GeofenceZone) -> GeofenceResult<()> {
    if zone.name.trim().is_empty() {
        return Err(GeofenceError::InvalidInput(
            "zone name must not be empty".to_string(),
        ));
    }
    if !matches!(
        zone.severity.as_str(),
        "info" | "low" | "medium" | "high" | "critical"
    ) {
        return Err(GeofenceError::InvalidInput(
            "severity must be info, low, medium, high, or critical".to_string(),
        ));
    }
    crate::geofence::actions::validate(&zone.automation).map_err(GeofenceError::InvalidInput)?;
    match zone.kind {
        ZoneKind::Coordinate => {
            let (lat, lng, radius) = match (zone.center_lat, zone.center_lng, zone.radius_m) {
                (Some(lat), Some(lng), Some(radius)) => (lat, lng, radius),
                _ => {
                    return Err(GeofenceError::InvalidInput(
                        "coordinate zones require center_lat, center_lng, and radius_m".to_string(),
                    ))
                }
            };
            validate_coordinate(lat, lng)?;
            if !radius.is_finite() || radius <= 0.0 {
                return Err(GeofenceError::InvalidInput(
                    "radius_m must be positive".to_string(),
                ));
            }
        }
        ZoneKind::RfSignature => {
            if let Some(signature) = &zone.rf_signature {
                validate_rf_signature(signature)?;
            }
        }
    }
    Ok(())
}

pub fn seal_registry(registry: &mut GeofenceRegistry) -> GeofenceResult<()> {
    let canonical = registry.canonical_bytes_for_proof()?;
    let digest = Sha256::digest(&canonical);
    registry.proof = Proof {
        proof_type: "DataIntegrityProof".to_string(),
        cryptosuite: "sha2-256-tamper-evident".to_string(),
        verification_method: "local-geofence-registry".to_string(),
        created: Utc::now().to_rfc3339(),
        proof_purpose: "assertionMethod".to_string(),
        proof_value: hex::encode(digest),
    };
    Ok(())
}

pub fn verify_registry(registry: &GeofenceRegistry) -> GeofenceResult<()> {
    if registry.proof.proof_value.is_empty() {
        return Err(GeofenceError::InvalidProof);
    }
    let canonical = registry.canonical_bytes_for_proof()?;
    let digest = hex::encode(Sha256::digest(&canonical));
    if digest == registry.proof.proof_value {
        Ok(())
    } else {
        Err(GeofenceError::InvalidProof)
    }
}

fn load_or_seed_registry_unlocked() -> GeofenceResult<GeofenceRegistry> {
    if let Some(registry) = persistence::load_registry()? {
        verify_registry(&registry)?;
        return Ok(registry);
    }
    let mut registry = GeofenceRegistry {
        zones: seed_zones(),
        ..GeofenceRegistry::default()
    };
    seal_registry(&mut registry)?;
    persistence::save_registry(&registry)?;
    Ok(registry)
}

fn seed_zones() -> Vec<GeofenceZone> {
    let now = Utc::now().to_rfc3339();
    vec![
        GeofenceZone {
            zone_id: "urn:sgx-guardian:geofence:facility-perimeter".to_string(),
            name: "Facility Perimeter".to_string(),
            kind: ZoneKind::Coordinate,
            center_lat: Some(24.8607),
            center_lng: Some(67.0011),
            radius_m: Some(250.0),
            rf_signature: None,
            on_entry: false,
            on_exit: true,
            severity: "high".to_string(),
            automation: ZoneAutomation::default(),
            enabled: false,
            created_at: now.clone(),
            updated_at: now.clone(),
        },
        GeofenceZone {
            zone_id: "urn:sgx-guardian:geofence:control-room".to_string(),
            name: "Control Room".to_string(),
            kind: ZoneKind::Coordinate,
            center_lat: Some(24.8607),
            center_lng: Some(67.0011),
            radius_m: Some(50.0),
            rf_signature: None,
            on_entry: true,
            on_exit: true,
            severity: "high".to_string(),
            automation: ZoneAutomation::default(),
            enabled: false,
            created_at: now.clone(),
            updated_at: now,
        },
    ]
}

fn validate_rf_signature(signature: &RfSignature) -> GeofenceResult<()> {
    if !signature.threshold.is_finite() || !(0.0..=1.0).contains(&signature.threshold) {
        return Err(GeofenceError::InvalidInput(
            "rf threshold must be between 0.0 and 1.0".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for ap in &signature.aps {
        if ap.bssid.trim().is_empty() {
            return Err(GeofenceError::InvalidInput(
                "rf BSSID must not be empty".to_string(),
            ));
        }
        seen.insert(ap.bssid.to_ascii_lowercase());
    }
    Ok(())
}

fn rf_match_score(
    signature: &RfSignature,
    current: &[crate::geofence::model::ApObservation],
) -> f64 {
    if signature.aps.is_empty() {
        return 0.0;
    }
    let current: HashSet<String> = current
        .iter()
        .map(|ap| ap.bssid.to_ascii_lowercase())
        .collect();
    let matched = signature
        .aps
        .iter()
        .filter(|ap| current.contains(&ap.bssid.to_ascii_lowercase()))
        .count();
    matched as f64 / signature.aps.len() as f64
}

pub fn new_zone(input: NewZoneInput) -> GeofenceZone {
    let now = Utc::now().to_rfc3339();
    GeofenceZone {
        zone_id: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        name: input.name,
        kind: input.kind,
        center_lat: input.center_lat,
        center_lng: input.center_lng,
        radius_m: input.radius_m,
        rf_signature: input.rf_signature.map(|mut signature| {
            if signature.threshold == 0.0 {
                signature.threshold = default_rf_threshold();
            }
            signature
        }),
        on_entry: input.on_entry,
        on_exit: input.on_exit,
        severity: input.severity,
        automation: input.automation,
        enabled: input.enabled,
        created_at: now.clone(),
        updated_at: now,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn haversine_matches_known_distance() {
        let distance = haversine_m(40.7128, -74.0060, 34.0522, -118.2437);
        assert!((3_935_000.0..3_950_000.0).contains(&distance));
    }

    #[test]
    fn validation_rejects_invalid_coordinate_zone() {
        let zone = new_zone(NewZoneInput {
            name: "bad".to_string(),
            kind: ZoneKind::Coordinate,
            center_lat: Some(100.0),
            center_lng: Some(0.0),
            radius_m: Some(50.0),
            rf_signature: None,
            on_entry: true,
            on_exit: true,
            severity: "high".to_string(),
            automation: ZoneAutomation::default(),
            enabled: true,
        });
        assert!(validate_zone(&zone).is_err());
    }

    #[test]
    fn registry_proof_detects_tamper() {
        let mut registry = GeofenceRegistry {
            zones: seed_zones(),
            ..GeofenceRegistry::default()
        };
        seal_registry(&mut registry).expect("seal");
        assert!(verify_registry(&registry).is_ok());
        registry.zones[0].name = "tampered".to_string();
        assert!(matches!(
            verify_registry(&registry),
            Err(GeofenceError::InvalidProof)
        ));
    }
}
