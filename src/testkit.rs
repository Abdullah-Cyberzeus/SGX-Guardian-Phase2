//! Test/dev-only bootstrap helpers, in the same spirit as
//! `AppState::for_tests` (`#[doc(hidden)]`, shipped in the real binary but
//! not part of the supported public API): constructs a self-consistent
//! Circle-owner identity (DID record + document + owner VC) without any
//! hardware dependency, for integration tests and the `test_guardian_server`
//! binary (see `src/bin/test_guardian_server.rs`) that need `circle::create`
//! and friends to actually work end-to-end.
//!
//! Mirrors the pattern already proven in `src/circle/tests/mod.rs`'s
//! `make_material`/`save_local_owner`/`ensure_owner_vc` sequence, but as a
//! single reusable, non-`#[cfg(test)]` entry point (test modules can't be
//! called from a separate binary crate).

use crate::did::document::{DidDocument, DocBuildInput};
use crate::did::persistence::DerivationProof;
use crate::did::{doc_persistence, doc_sign, Did, DidRecord};
use crate::key_manager::KeyManager;
use crate::vc::issue;
use std::path::Path;

/// Issues the device's own mesh/owner Verifiable Credential and writes the
/// supporting DID record/document so `circle::create` (and anything that
/// transitively calls `mesh_circle_id()`/`load_runtime_signing_context()`)
/// has an owner identity to load. Pass `device_did` as the SAME DID used
/// elsewhere for this node (e.g. `AppState::device_did`) when the caller
/// needs Circle ownership and session auth to agree on "who this device
/// is" (required for member-roster/authorization lookups keyed off
/// `AppState::device_did` specifically, such as group-call creation).
///
/// Callers must first point `SGX_GUARDIAN_CIRCLE_BASE`, `SGX_GUARDIAN_VC_BASE`,
/// `SGX_GUARDIAN_DID_PATH`, `SGX_GUARDIAN_DEVICE_KEY_DIR`, and the DID-document
/// paths (`doc_persistence::{SELF_DOC_PATH_ENV, PEERS_DOC_DIR_ENV,
/// CA_AGGREGATE_PATH_ENV, VERSION_COUNTER_PATH_ENV}`) at an isolated
/// directory, and set `SGX_FORCE_SOFTWARE_KEYS=1` — production boots real
/// hardware-backed identity; this reproduces only what Circle creation
/// actually reads.
#[doc(hidden)]
pub fn bootstrap_owner_identity(
    node_name: &str,
    device_did: &str,
    key_dir: &Path,
    overlay_ip_cidr: &str,
) -> Result<(), String> {
    std::fs::create_dir_all(key_dir)
        .map_err(|error| format!("create device key dir: {}", error))?;
    let key_path = key_dir.join(format!("device_{}.key", node_name));
    let km = KeyManager::load_or_generate(key_path.to_str().ok_or("non-utf8 key path")?)
        .map_err(|error| format!("generate circle-owner key: {}", error))?;
    let pubkey = km
        .pubkey_der()
        .map_err(|error| format!("circle-owner pubkey: {}", error))?;
    let did = Did::parse(device_did).map_err(|error| format!("parse device did: {:?}", error))?;
    let now = chrono::Utc::now().to_rfc3339();

    let record = DidRecord {
        did: device_did.to_string(),
        method: "guardian".to_string(),
        method_version: "1".to_string(),
        did_id_b58: did.msi().to_string(),
        did_id_hex: hex::encode(did.id_bytes()),
        created_at: now.clone(),
        deactivated_at: None,
        derivation: DerivationProof {
            se050_uid: "01".to_string(),
            se050_uid_source: "test".to_string(),
            dkp_v1_pubkey_sha256_b16: "01".to_string(),
            dkp_v1_pubkey_path: "test".to_string(),
            dkp_v1_pubkey_der_b64: None,
            dik_pubkey_sha256_b16: "01".to_string(),
            dik_pubkey_der_b64: None,
        },
        current_dkp_version: 1,
        deriv_signature_b64: String::new(),
    };
    let did_path = std::env::var("SGX_GUARDIAN_DID_PATH")
        .map_err(|_| "SGX_GUARDIAN_DID_PATH must be set before bootstrapping".to_string())?;
    record.save(&did_path).map_err(|error| format!("save did record: {:?}", error))?;

    let mut doc = DidDocument::build(DocBuildInput {
        did: device_did,
        node_name: Some(node_name),
        current_dkp_version: 1,
        current_dkp_pubkey_der: &pubkey,
        overlay_ip_cidr: Some(overlay_ip_cidr),
        attestation_bind: None,
        cert_bootstrap_bind: Some((
            overlay_ip_cidr.split('/').next().unwrap_or("127.0.0.1"),
            50061,
        )),
        revoked: vec![],
        previous_version_id: 0,
        created_at: Some(now),
        status: Some("active".into()),
    })
    .map_err(|error| format!("build did document: {:?}", error))?;
    let vm_ref = doc
        .verification_method
        .first()
        .ok_or("did document has no verification method")?
        .id
        .clone();
    doc_sign::sign_in_place(&mut doc, &km, &vm_ref)
        .map_err(|error| format!("sign did document: {:?}", error))?;

    doc_persistence::save_self(&doc).map_err(|error| format!("save self document: {:?}", error))?;
    doc_persistence::save_peer(&doc).map_err(|error| format!("save peer document: {:?}", error))?;
    doc_persistence::save_ca_aggregate(std::slice::from_ref(&doc))
        .map_err(|error| format!("save CA aggregate: {:?}", error))?;

    issue::ensure_owner_vc(&record, &km)
        .map_err(|error| format!("issue mesh owner VC: {:?}", error))?;
    crate::virtual_id::observe_runtime_virtual_id(crate::virtual_id::RuntimeVirtualIdInputs {
        node: node_name.to_string(),
        state_path: None,
        did: device_did.to_string(),
        dkp_pubkey_der: pubkey,
        dkp_version: 1,
        pcr_values: vec!["aa".repeat(32)],
        pcr_digest: "bb".repeat(32),
        policy_digest: "cc".repeat(32),
    })
    .map_err(|error| format!("initialize runtime VirtualID: {:?}", error))?;
    Ok(())
}
