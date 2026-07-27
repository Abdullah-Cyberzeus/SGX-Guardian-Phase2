use crate::did::doc_persistence;
use crate::did::doc_sign;
use crate::did::document::DocBuildInput;
use crate::did::errors::DidError;
use crate::did::persistence::{derivation_signing_bytes, DerivationProof, DidRecord};
use crate::did::{derive, Did};
use crate::key_manager::{runtime_device_uid_details, KeyManager};
use crate::secure_element::pcr::read_dkp_key_version;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

const METHOD_VERSION: &str = "1.0";
pub const DEFAULT_DKP_PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";

pub fn create_if_absent(
    node_id: &str,
    km: &KeyManager,
    dkp_pubkey_path: &str,
    did_path: &str,
) -> Result<Did, DidError> {
    // In software/dev mode there may be no exported runtime pubkey on first boot yet.
    // Persist it up front so every node can derive and save its own local DID.
    ensure_runtime_pubkey(km, dkp_pubkey_path)?;

    let (uid_string, uid_source, uid_bytes) = read_uid(node_id)?;

    // ── Existing DID present: validate against the pinned DIK pubkey,
    //    never against a live rotatable key file ─────────────────────────
    if Path::new(did_path).exists() {
        let existing = DidRecord::load(did_path)?;
        let existing_did = Did::parse(&existing.did)?;

        // Source of truth for re-derivation is the DIK pubkey pinned in did.json.
        // Legacy records without this field are re-derived from the DIK slot.
        let pinned: Vec<u8> = match &existing.derivation.dik_pubkey_der_b64 {
            Some(b64) => general_purpose::STANDARD
                .decode(b64)
                .map_err(|e| DidError::InvalidFormat(format!("pinned DIK b64: {}", e)))?,
            None => get_dik_pubkey(dkp_pubkey_path)?,
        };

        let candidate_did = derive(&uid_bytes, &pinned);
        if existing_did != candidate_did {
            return Err(DidError::DerivationMismatch);
        }

        if let Some(when) = existing.deactivated_at {
            return Err(DidError::Deactivated(when));
        }

        return Ok(existing_did);
    }

    // ── First boot: derive from the non-rotating DIK (NOT the DKP) ───────
    let dik_pubkey = get_dik_pubkey(dkp_pubkey_path)?;
    let candidate_did = derive(&uid_bytes, &dik_pubkey);

    let derivation = DerivationProof {
        se050_uid: uid_string,
        se050_uid_source: uid_source,
        dkp_v1_pubkey_sha256_b16: String::new(),
        dkp_v1_pubkey_path: String::new(),
        dkp_v1_pubkey_der_b64: None,
        dik_pubkey_sha256_b16: hex::encode(Sha256::digest(&dik_pubkey)),
        dik_pubkey_der_b64: Some(general_purpose::STANDARD.encode(&dik_pubkey)),
    };
    let signing_bytes = derivation_signing_bytes(&derivation);
    let signature = km
        .sign(&signing_bytes)
        .map_err(|e| DidError::Signing(e.to_string()))?;

    let record = DidRecord {
        did: candidate_did.as_str().to_string(),
        method: "guardian".to_string(),
        method_version: METHOD_VERSION.to_string(),
        did_id_b58: candidate_did.msi().to_string(),
        did_id_hex: hex::encode(candidate_did.id_bytes()),
        created_at: Utc::now().to_rfc3339(),
        deactivated_at: None,
        derivation,
        current_dkp_version: read_dkp_key_version(),
        deriv_signature_b64: general_purpose::STANDARD.encode(signature),
    };
    record.save(did_path)?;
    Ok(candidate_did)
}

pub fn resolve_local(
    did_path: &str,
    dkp_pubkey_path: &str,
) -> Result<(Did, Vec<u8>, bool), DidError> {
    let record = DidRecord::load(did_path)?;
    let did = Did::parse(&record.did)?;
    let pubkey = if let Some(ref b64) = record.derivation.dik_pubkey_der_b64 {
        general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| DidError::InvalidFormat(format!("pinned DIK b64: {}", e)))?
    } else if let Some(ref b64) = record.derivation.dkp_v1_pubkey_der_b64 {
        general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| DidError::InvalidFormat(format!("pinned legacy DKP b64: {}", e)))?
    } else {
        read_dkp_pubkey(dkp_pubkey_path)?
    };
    Ok((did, pubkey, record.is_active()))
}

pub fn update_dkp_version(did_path: &str, new_version: u32) -> Result<(), DidError> {
    if !Path::new(did_path).exists() {
        return Ok(());
    }

    let mut record = DidRecord::load(did_path)?;
    if new_version <= record.current_dkp_version {
        return Ok(());
    }
    record.current_dkp_version = new_version;
    record.save(did_path)
}

pub fn deactivate(did_path: &str, _reason: &str) -> Result<(), DidError> {
    let mut record = DidRecord::load(did_path)?;
    if let Some(when) = record.deactivated_at {
        return Err(DidError::Deactivated(when));
    }
    record.deactivated_at = Some(Utc::now().to_rfc3339());
    record.save(did_path)
}

pub fn ensure_runtime_pubkey(km: &KeyManager, dkp_pubkey_path: &str) -> Result<Vec<u8>, DidError> {
    let pubkey = km
        .runtime_public_key_export()
        .map_err(|e| DidError::Io(io::Error::other(format!("pubkey export: {}", e))))?;

    if let Ok(existing) = fs::read(dkp_pubkey_path) {
        if existing == pubkey {
            return Ok(pubkey);
        }
    }

    if let Some(parent) = Path::new(dkp_pubkey_path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(dkp_pubkey_path, &pubkey)?;
    Ok(pubkey)
}

pub fn ensure_self_document(
    node_id: &str,
    km: &KeyManager,
    did_path: &str,
    dkp_pubkey_path: &str,
) -> Result<(), DidError> {
    if doc_persistence::load_self()?.is_some() {
        return Ok(());
    }

    let (did, _anchor_pk, active) = resolve_local(did_path, dkp_pubkey_path)?;
    let dkp_pub = ensure_runtime_pubkey(km, dkp_pubkey_path)?;
    if dkp_pub.is_empty() {
        return Err(DidError::InvalidFormat(
            "runtime DKP pubkey is empty".to_string(),
        ));
    }

    let input = DocBuildInput {
        did: did.as_str(),
        node_name: Some(node_id),
        current_dkp_version: read_dkp_key_version(),
        current_dkp_pubkey_der: &dkp_pub,
        overlay_ip_cidr: None,
        attestation_bind: None,
        cert_bootstrap_bind: None,
        revoked: vec![],
        previous_version_id: 0,
        created_at: None,
        status: Some(if active {
            "active".to_string()
        } else {
            "deactivated".to_string()
        }),
    };
    let mut doc = crate::did::document::DidDocument::build(input)?;
    let vm_ref = doc.verification_method[0].id.clone();
    doc_sign::sign_in_place(&mut doc, km, &vm_ref)?;
    doc_persistence::save_self(&doc)?;
    doc_persistence::write_self_floor_version(doc.sgx_version_id)?;
    Ok(())
}

fn read_dkp_pubkey(path: &str) -> Result<Vec<u8>, DidError> {
    if !Path::new(path).exists() {
        return Err(DidError::DkpPubkeyMissing(path.to_string()));
    }
    Ok(fs::read(path)?)
}

#[allow(clippy::needless_return)]
fn get_dik_pubkey(dkp_pubkey_path: &str) -> Result<Vec<u8>, DidError> {
    #[cfg(feature = "tpm")]
    {
        let cfg = crate::tpm::TpmConfig::default();
        if crate::tpm::should_attempt(&cfg) {
            return crate::tpm::dik::ensure(&cfg)
                .map_err(|e| DidError::Io(io::Error::other(format!("TPM DIK ensure: {}", e))));
        }
    }

    #[cfg(feature = "secure-element")]
    {
        let se_config = crate::secure_element::config::SeConfig::default();
        match crate::secure_element::dik::DeviceIdentityKey::ensure(&se_config) {
            Ok(pk) => return Ok(pk),
            Err(e) => {
                if !hardware_identity_expected() {
                    if let Ok(pk) = read_dkp_pubkey(dkp_pubkey_path) {
                        return Ok(pk);
                    }
                }
                return Err(DidError::Io(io::Error::other(format!("DIK ensure: {}", e))));
            }
        }
    }

    #[cfg(not(feature = "secure-element"))]
    {
        return read_dkp_pubkey(dkp_pubkey_path);
    }
}

#[cfg(feature = "secure-element")]
fn hardware_identity_expected() -> bool {
    #[cfg(feature = "tpm")]
    {
        let cfg = crate::tpm::TpmConfig::default();
        if crate::tpm::should_attempt(&cfg) {
            return true;
        }
    }

    Path::new("/proc/device-tree/model").exists()
}

fn read_uid(fallback: &str) -> Result<(String, String, Vec<u8>), DidError> {
    runtime_device_uid_details(fallback).map_err(DidError::UidUnavailable)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn uid_to_bytes_decodes_even_length_hex() {
        assert_eq!(uid_to_bytes("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(uid_to_bytes("  deadbeef  "), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn uid_to_bytes_falls_back_to_raw_bytes_for_non_hex_or_odd_length() {
        assert_eq!(uid_to_bytes("not-hex!"), b"not-hex!".to_vec());
        // Odd-length hex-looking string must not be decoded as hex.
        assert_eq!(uid_to_bytes("abc"), b"abc".to_vec());
        // Single hex char is below the minimum length gate.
        assert_eq!(uid_to_bytes("a"), b"a".to_vec());
    }
}
