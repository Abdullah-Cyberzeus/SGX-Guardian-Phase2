use crate::circle::errors::CircleError;
use crate::circle::model::{public_key_from_vm, Circle, CircleKind, CircleRegistry, CircleStatus};
use crate::circle::persistence;
use crate::did::doc_persistence;
use crate::did::{DidRecord, DEFAULT_DID_PATH};
use crate::key_manager::KeyManager;
use chrono::Utc;
use once_cell::sync::Lazy;
use std::fs;
use std::sync::{Arc, Mutex as StdMutex};

pub static CIRCLE_WRITE_LOCK: Lazy<StdMutex<()>> = Lazy::new(|| StdMutex::new(()));

const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";

pub fn load_runtime_signing_context(
    node_id: &str,
) -> Result<(DidRecord, Arc<KeyManager>), CircleError> {
    let did_path = std::env::var(DID_PATH_ENV).unwrap_or_else(|_| DEFAULT_DID_PATH.to_string());
    let record = DidRecord::load(&did_path)?;
    let km = crate::vc::issue::load_runtime_key_manager(node_id)
        .map_err(|error| CircleError::Invalid(format!("key manager: {}", error)))?;
    Ok((record, km))
}

pub fn mesh_circle_id() -> Result<String, CircleError> {
    let membership = crate::vc::persistence::load_own_mesh()?.ok_or_else(|| {
        CircleError::Invalid("local membership VC not found for mesh-circle resolution".into())
    })?;
    Ok(membership.credential_subject.circle_id)
}

pub fn load_or_seed(node_id: &str) -> Result<CircleRegistry, CircleError> {
    let _guard = CIRCLE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    load_or_seed_unlocked(node_id)
}

pub fn get_circle(node_id: &str, circle_id: &str) -> Result<Circle, CircleError> {
    let registry = load_or_seed(node_id)?;
    registry
        .circles
        .into_iter()
        .find(|circle| circle.circle_id == circle_id)
        .ok_or_else(|| CircleError::NotFound(circle_id.to_string()))
}

pub fn create_circle(
    node_id: &str,
    circle_id: String,
    name: String,
    description: String,
    owner_did: String,
) -> Result<Circle, CircleError> {
    create_circle_of_kind(node_id, circle_id, name, description, owner_did, CircleKind::Comms)
}

/// [`create_circle`] with an explicit [`CircleKind`] — P2.1's `mesh::ca`
/// module is the one caller that needs `CircleKind::Mesh`; every existing
/// caller keeps going through `create_circle`, unchanged, which is this
/// function with `Comms` hardcoded exactly as it always was.
pub fn create_circle_of_kind(
    node_id: &str,
    circle_id: String,
    name: String,
    description: String,
    owner_did: String,
    kind: CircleKind,
) -> Result<Circle, CircleError> {
    let _guard = CIRCLE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    // Deliberately `load_registry_or_empty`, not `load_or_seed_unlocked`: the
    // latter's fallback seeds a first-time registry from this Guardian's own
    // local membership VC — exactly right for a *read* path (`get_circle`,
    // `mesh_circle_id`) encountering an established circle for the first
    // time, but wrong here. `mesh::ca::create_circle` issues that VC (for
    // this very circle_id) moments before calling this function, so by the
    // time this runs, `load_or_seed_unlocked` would "seed" a registry that
    // already contains the circle this call is about to insert — and the
    // conflict check just below would then collide with itself on every
    // single circle creation, not just repeats.
    let mut registry = load_registry_or_empty(node_id)?;
    if registry
        .circles
        .iter()
        .any(|circle| circle.circle_id == circle_id)
    {
        return Err(CircleError::Conflict(format!(
            "circle {} already exists",
            circle_id
        )));
    }

    let now = Utc::now().to_rfc3339();
    let circle = Circle {
        circle_id,
        name,
        description,
        owner_did,
        kind,
        status: CircleStatus::Active,
        created_at: now.clone(),
        updated_at: now,
    };
    registry.circles.push(circle.clone());
    registry.sequence += 1;
    registry
        .circles
        .sort_by(|left, right| left.circle_id.cmp(&right.circle_id));
    save_registry(node_id, &mut registry)?;
    Ok(circle)
}

pub fn edit_circle(
    node_id: &str,
    circle_id: &str,
    name: Option<String>,
    description: Option<String>,
) -> Result<Circle, CircleError> {
    let _guard = CIRCLE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut registry = load_or_seed_unlocked(node_id)?;
    let circle = registry
        .circles
        .iter_mut()
        .find(|circle| circle.circle_id == circle_id)
        .ok_or_else(|| CircleError::NotFound(circle_id.to_string()))?;
    if let Some(name) = name {
        circle.name = name;
    }
    if let Some(description) = description {
        circle.description = description;
    }
    circle.updated_at = Utc::now().to_rfc3339();
    let updated = circle.clone();
    registry.sequence += 1;
    save_registry(node_id, &mut registry)?;
    Ok(updated)
}

pub fn archive_circle(node_id: &str, circle_id: &str) -> Result<Circle, CircleError> {
    let _guard = CIRCLE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut registry = load_or_seed_unlocked(node_id)?;
    let circle = registry
        .circles
        .iter_mut()
        .find(|circle| circle.circle_id == circle_id)
        .ok_or_else(|| CircleError::NotFound(circle_id.to_string()))?;
    if circle.is_mesh() {
        return Err(CircleError::Conflict(
            "Mesh Circle cannot be archived".to_string(),
        ));
    }
    circle.status = CircleStatus::Archived;
    circle.updated_at = Utc::now().to_rfc3339();
    let archived = circle.clone();
    registry.sequence += 1;
    save_registry(node_id, &mut registry)?;
    Ok(archived)
}

pub fn unarchive_circle(node_id: &str, circle_id: &str) -> Result<Circle, CircleError> {
    let _guard = CIRCLE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut registry = load_or_seed_unlocked(node_id)?;
    let circle = registry
        .circles
        .iter_mut()
        .find(|circle| circle.circle_id == circle_id)
        .ok_or_else(|| CircleError::NotFound(circle_id.to_string()))?;
    if !circle.is_archived() {
        return Err(CircleError::Conflict(format!(
            "circle {} is not archived",
            circle_id
        )));
    }
    circle.status = CircleStatus::Active;
    circle.updated_at = Utc::now().to_rfc3339();
    let unarchived = circle.clone();
    registry.sequence += 1;
    save_registry(node_id, &mut registry)?;
    Ok(unarchived)
}

pub fn delete_circle(node_id: &str, circle_id: &str) -> Result<Circle, CircleError> {
    let _guard = CIRCLE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut registry = load_or_seed_unlocked(node_id)?;
    let position = registry
        .circles
        .iter()
        .position(|circle| circle.circle_id == circle_id)
        .ok_or_else(|| CircleError::NotFound(circle_id.to_string()))?;
    if registry.circles[position].is_mesh() {
        return Err(CircleError::Conflict(
            "Mesh Circle cannot be deleted".to_string(),
        ));
    }
    let removed = registry.circles.remove(position);
    registry.sequence += 1;
    save_registry(node_id, &mut registry)?;
    Ok(removed)
}

pub fn upsert_circle(node_id: &str, circle: Circle) -> Result<Circle, CircleError> {
    let _guard = CIRCLE_WRITE_LOCK
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    let mut registry = load_or_seed_unlocked(node_id)?;
    let mut incoming = circle.clone();
    incoming.updated_at = Utc::now().to_rfc3339();
    match registry
        .circles
        .iter_mut()
        .find(|entry| entry.circle_id == incoming.circle_id)
    {
        Some(existing) => {
            incoming.created_at = existing.created_at.clone();
            *existing = incoming.clone();
        }
        None => registry.circles.push(incoming.clone()),
    }
    registry.sequence += 1;
    registry
        .circles
        .sort_by(|left, right| left.circle_id.cmp(&right.circle_id));
    save_registry(node_id, &mut registry)?;
    Ok(incoming)
}

fn load_or_seed_unlocked(node_id: &str) -> Result<CircleRegistry, CircleError> {
    let path = persistence::registry_path();
    if path.exists() {
        return load_registry(path);
    }

    // Prefer `MeshProfile` — the actual circle name and enrollment facts —
    // over the VC-based fallback below it. This is not just a nicer
    // default: it is what actually fixes a real, reproducible bug. A
    // Guardian's very first registry read after enrolling (CA *or*
    // member — P2's `create_circle` and P4's `mesh::enroll::install` both
    // hit this) used to race the VC-based seed below, which only ever
    // knew a generic "Mesh Circle" placeholder name, never the operator's
    // real one — and once seeded, that placeholder was permanent, since
    // this function only ever runs when the file does *not* exist yet.
    // `MeshProfile` is written by both `create_circle` and `install`
    // before either ever touches the circle store, so by the time this
    // runs, if a profile exists, it already has the truth.
    if let Some(profile) = crate::mesh::profile::current() {
        let mesh = Circle {
            circle_id: profile.circle_id.clone(),
            name: profile.circle_name.clone(),
            description: String::new(),
            owner_did: profile.ca_owner_did.clone(),
            kind: CircleKind::Mesh,
            status: CircleStatus::Active,
            created_at: profile.enrolled_at.clone(),
            updated_at: profile.enrolled_at.clone(),
        };
        let mut registry = CircleRegistry {
            circles: vec![mesh],
            sequence: 1,
            proof: crate::did::document::Proof::default(),
        };
        save_registry(node_id, &mut registry)?;
        return Ok(registry);
    }

    // Legacy fallback: a Guardian with a local membership VC but no
    // `MeshProfile` (should not happen for anything enrolled through
    // Phase 0+, but keeps this function total rather than erroring out
    // for whatever pre-Phase-0 state might still reach it).
    let membership = crate::vc::persistence::load_own_mesh()?.ok_or_else(|| {
        CircleError::Invalid("local membership VC not found for circle registry seed".into())
    })?;
    let mesh = Circle {
        circle_id: membership.credential_subject.circle_id.clone(),
        name: "Mesh Circle".to_string(),
        description: "Default Guardian mesh circle".to_string(),
        owner_did: membership.issuer.clone(),
        kind: CircleKind::Mesh,
        status: CircleStatus::Active,
        created_at: membership.issuance_date.clone(),
        updated_at: membership.issuance_date.clone(),
    };
    let mut registry = CircleRegistry {
        circles: vec![mesh],
        sequence: 1,
        proof: crate::did::document::Proof::default(),
    };
    save_registry(node_id, &mut registry)?;
    Ok(registry)
}

/// Like [`load_or_seed_unlocked`], but for a caller that is about to insert
/// a circle itself and must not have that insert collide with the VC-based
/// seed (see [`create_circle_of_kind`]'s call site). Starts a brand-new,
/// empty registry when none exists on disk yet, instead of seeding one from
/// a local membership VC.
fn load_registry_or_empty(_node_id: &str) -> Result<CircleRegistry, CircleError> {
    let path = persistence::registry_path();
    if path.exists() {
        return load_registry(path);
    }
    Ok(CircleRegistry {
        circles: Vec::new(),
        sequence: 0,
        proof: crate::did::document::Proof::default(),
    })
}

fn load_registry(path: std::path::PathBuf) -> Result<CircleRegistry, CircleError> {
    let registry: CircleRegistry = serde_json::from_slice(&fs::read(path)?)?;
    verify_local_registry(&registry)?;
    Ok(registry)
}

fn save_registry(node_id: &str, registry: &mut CircleRegistry) -> Result<(), CircleError> {
    let (record, km) = load_runtime_signing_context(node_id)?;
    let vm_ref = format!("{}#dkp-v{}", record.did, record.current_dkp_version.max(1));
    registry.sign(&km, &vm_ref)?;
    persistence::write_atomic(
        &persistence::registry_path(),
        &serde_json::to_vec_pretty(registry)?,
    )?;
    Ok(())
}

fn verify_local_registry(registry: &CircleRegistry) -> Result<(), CircleError> {
    let doc = doc_persistence::load_self()?.ok_or_else(|| {
        CircleError::Invalid("local DID document missing for circle-registry verification".into())
    })?;
    let vm = doc
        .verification_method
        .iter()
        .find(|vm| vm.id == registry.proof.verification_method)
        .or_else(|| doc.verification_method.first())
        .ok_or_else(|| CircleError::InvalidProof("verification method not found".into()))?;
    let public_key = public_key_from_vm(vm)?;
    registry.verify_with_public_key(&public_key)
}
