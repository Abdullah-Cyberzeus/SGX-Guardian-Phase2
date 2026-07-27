use crate::did::errors::DidError;
use crate::did::persistence::{derivation_signing_bytes, DerivationProof, DidRecord};
use crate::did::{derive, Did};
use crate::key_manager::KeyManager;
use crate::secure_element::pcr::{read_device_uid, read_dkp_key_version};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::Path;

const METHOD_VERSION: &str = "1.0";

pub fn create_if_absent(
    node_id: &str,
    km: &KeyManager,
    dkp_pubkey_path: &str,
    did_path: &str,
) -> Result<Did, DidError> {
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

fn read_dkp_pubkey(path: &str) -> Result<Vec<u8>, DidError> {
    if !Path::new(path).exists() {
        return Err(DidError::DkpPubkeyMissing(path.to_string()));
    }
    Ok(fs::read(path)?)
}

fn get_dik_pubkey(dkp_pubkey_path: &str) -> Result<Vec<u8>, DidError> {
    let se_config = crate::secure_element::config::SeConfig::default();
    match crate::secure_element::dik::DeviceIdentityKey::ensure(&se_config) {
        Ok(pk) => Ok(pk),
        Err(e) => {
            // Keep software/dev flows working when no SE050 is present.
            // On hardware boards, a DIK error remains a hard DID error.
            if !Path::new("/proc/device-tree/model").exists() {
                if let Ok(pk) = read_dkp_pubkey(dkp_pubkey_path) {
                    return Ok(pk);
                }
            }
            Err(DidError::Io(io::Error::other(format!("DIK ensure: {}", e))))
        }
    }
}

fn read_uid(fallback: &str) -> Result<(String, String, Vec<u8>), DidError> {
    let uid = read_device_uid(fallback);
    if uid.trim().is_empty() {
        return Err(DidError::UidUnavailable("empty uid".to_string()));
    }

    let source = if uid.len() >= 20 && uid.chars().all(|c| c.is_ascii_hexdigit()) {
        "ssscli".to_string()
    } else {
        "fallback".to_string()
    };
    let bytes = uid_to_bytes(&uid);
    Ok((uid, source, bytes))
}

fn uid_to_bytes(uid: &str) -> Vec<u8> {
    let trimmed = uid.trim();
    if trimmed.len().is_multiple_of(2)
        && trimmed.len() >= 2
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        if let Ok(decoded) = hex::decode(trimmed) {
            return decoded;
        }
    }
    trimmed.as_bytes().to_vec()
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
