use crate::did::doc_sign;
use crate::did::{DidRecord, Resolver};
use crate::key_manager::KeyManager;
use crate::vc::credential::{sort_json_keys, VC_CONTEXT_CORE, VC_CONTEXT_STATUS_LIST_2021};
use crate::vc::errors::VcError;
use crate::vc::persistence;
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use ring::signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};

pub const STATUS_LIST_SIZE_BITS: u64 = 131072;
pub const TYPE_STATUS_LIST_CREDENTIAL: &str = "StatusList2021Credential";
pub const TYPE_STATUS_LIST_SUBJECT: &str = "StatusList2021";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusListCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: String,
    #[serde(rename = "type")]
    pub vc_type: Vec<String>,
    pub issuer: String,
    pub issuance_date: String,
    pub credential_subject: StatusListSubject,
    pub proof: crate::did::document::Proof,
    #[serde(default)]
    pub sgx_next_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StatusListSubject {
    pub id: String,
    #[serde(rename = "type")]
    pub subject_type: String,
    pub status_purpose: String,
    pub encoded_list: String,
}

#[derive(Debug, Clone)]
pub struct StatusListView {
    credential: StatusListCredential,
    bits: Vec<u8>,
}

impl StatusListView {
    pub fn id(&self) -> &str {
        &self.credential.id
    }

    pub fn issuer_did(&self) -> &str {
        &self.credential.issuer
    }

    pub fn credential(&self) -> &StatusListCredential {
        &self.credential
    }

    pub fn is_revoked(&self, index: u64) -> Result<bool, VcError> {
        let (byte_index, bit_mask) = bit_position(index, self.bits.len())?;
        Ok(self.bits[byte_index] & bit_mask != 0)
    }
}

pub struct StatusListManager {
    credential: StatusListCredential,
    bits: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StatusListIndexState {
    next_index: u64,
}

impl StatusListManager {
    pub fn load_or_create(issuer: &DidRecord, _km: &KeyManager) -> Result<Self, VcError> {
        let path = persistence::status_list_path();
        if path.exists() {
            let credential: StatusListCredential = serde_json::from_slice(&fs::read(&path)?)?;
            let bits = decode_encoded_list(&credential.credential_subject.encoded_list)?;
            let next_index = load_next_index().unwrap_or(credential.sgx_next_index);
            let mut credential = credential;
            credential.sgx_next_index = next_index;
            return Ok(Self { credential, bits });
        }

        let bits = vec![0u8; (STATUS_LIST_SIZE_BITS / 8) as usize];
        let credential = StatusListCredential {
            context: vec![VC_CONTEXT_CORE.into(), VC_CONTEXT_STATUS_LIST_2021.into()],
            id: format!("{}/status-list", issuer.did),
            vc_type: vec![
                "VerifiableCredential".into(),
                TYPE_STATUS_LIST_CREDENTIAL.into(),
            ],
            issuer: issuer.did.clone(),
            issuance_date: Utc::now().to_rfc3339(),
            credential_subject: StatusListSubject {
                id: format!("{}/status-list#list", issuer.did),
                subject_type: TYPE_STATUS_LIST_SUBJECT.into(),
                status_purpose: "revocation".into(),
                encoded_list: encode_encoded_list(&bits)?,
            },
            proof: crate::did::document::Proof::default(),
            sgx_next_index: 0,
        };

        let manager = Self { credential, bits };
        Ok(manager)
    }

    pub fn allocate_index(&mut self) -> Result<u64, VcError> {
        let index = self.credential.sgx_next_index;
        if index >= STATUS_LIST_SIZE_BITS {
            return Err(VcError::IndexOutOfRange {
                index,
                size: STATUS_LIST_SIZE_BITS,
            });
        }
        self.credential.sgx_next_index += 1;
        Ok(index)
    }

    pub fn set_revoked(&mut self, index: u64, revoked: bool) -> Result<(), VcError> {
        let (byte_index, bit_mask) = bit_position(index, self.bits.len())?;
        if revoked {
            self.bits[byte_index] |= bit_mask;
        } else {
            self.bits[byte_index] &= !bit_mask;
        }
        Ok(())
    }

    pub fn is_revoked(&self, index: u64) -> Result<bool, VcError> {
        let (byte_index, bit_mask) = bit_position(index, self.bits.len())?;
        Ok(self.bits[byte_index] & bit_mask != 0)
    }

    pub fn commit(&mut self, km: &KeyManager, vm_ref: &str) -> Result<(), VcError> {
        self.credential.issuance_date = Utc::now().to_rfc3339();
        self.credential.credential_subject.encoded_list = encode_encoded_list(&self.bits)?;
        let canonical = canonical_bytes_status_list(&self.credential)?;
        doc_sign::sign_in_place_generic(&mut self.credential.proof, &canonical, km, vm_ref)?;
        persistence::save_status_list_credential(&self.credential)?;
        save_next_index(self.credential.sgx_next_index)?;
        Ok(())
    }
}

pub async fn verify_status_list_credential(
    credential: &StatusListCredential,
    resolver: &Resolver,
    expected_issuer_did: Option<&str>,
) -> Result<StatusListView, VcError> {
    if !credential.context.iter().any(|c| c == VC_CONTEXT_CORE)
        || !credential
            .context
            .iter()
            .any(|c| c == VC_CONTEXT_STATUS_LIST_2021)
    {
        return Err(VcError::InvalidStructure(
            "missing status list contexts".to_string(),
        ));
    }
    if !credential
        .vc_type
        .iter()
        .any(|ty| ty == "VerifiableCredential")
        || !credential
            .vc_type
            .iter()
            .any(|ty| ty == TYPE_STATUS_LIST_CREDENTIAL)
    {
        return Err(VcError::InvalidStructure(
            "missing status list credential type".to_string(),
        ));
    }
    if let Some(expected) = expected_issuer_did {
        if credential.issuer != expected {
            return Err(VcError::IssuerMismatch {
                expected: expected.to_string(),
                got: credential.issuer.clone(),
            });
        }
    }

    let issuer = resolver
        .resolve(&credential.issuer)
        .await
        .map_err(|e| VcError::IssuerNotResolvable(format!("{}: {}", credential.issuer, e)))?;
    let canonical = canonical_bytes_status_list(credential)?;
    verify_proof_material(
        &issuer.public_key_der_b64,
        &credential.proof.proof_value,
        &canonical,
    )
    .map_err(|_| VcError::StatusListProofInvalid)?;
    let bits = decode_encoded_list(&credential.credential_subject.encoded_list)?;
    Ok(StatusListView {
        credential: credential.clone(),
        bits,
    })
}

pub fn encode_encoded_list(bits: &[u8]) -> Result<String, VcError> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bits)?;
    let compressed = encoder.finish()?;
    Ok(general_purpose::STANDARD.encode(compressed))
}

pub fn decode_encoded_list(encoded: &str) -> Result<Vec<u8>, VcError> {
    let compressed = general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| VcError::InvalidStructure(format!("status list b64: {}", e)))?;
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn canonical_bytes_status_list(credential: &StatusListCredential) -> Result<Vec<u8>, VcError> {
    let mut clone = credential.clone();
    clone.proof = crate::did::document::Proof::default();
    let value = serde_json::to_value(&clone)?;
    Ok(serde_json::to_vec(&sort_json_keys(&value))?)
}

fn load_next_index() -> Option<u64> {
    let path = persistence::status_list_index_path();
    let bytes = fs::read(path).ok()?;
    let state = serde_json::from_slice::<StatusListIndexState>(&bytes).ok()?;
    Some(state.next_index)
}

fn save_next_index(next_index: u64) -> Result<(), VcError> {
    let path = persistence::status_list_index_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(
        &tmp,
        serde_json::to_vec_pretty(&StatusListIndexState { next_index })?,
    )?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn bit_position(index: u64, size_bytes: usize) -> Result<(usize, u8), VcError> {
    let size_bits = (size_bytes as u64) * 8;
    if index >= size_bits {
        return Err(VcError::IndexOutOfRange {
            index,
            size: size_bits,
        });
    }
    let byte_index = (index / 8) as usize;
    let bit_in_byte = 7 - (index % 8) as u8;
    Ok((byte_index, 1u8 << bit_in_byte))
}

fn verify_proof_material(
    issuer_public_key_der_b64: &str,
    proof_value_b64: &str,
    canonical_bytes: &[u8],
) -> Result<(), VcError> {
    let public_key = general_purpose::STANDARD
        .decode(issuer_public_key_der_b64)
        .map_err(|_| VcError::InvalidProof)?;
    let public_key = normalize_p256_pubkey(&public_key).ok_or(VcError::InvalidProof)?;
    let signature = general_purpose::STANDARD
        .decode(proof_value_b64)
        .map_err(|_| VcError::InvalidProof)?;
    let digest = Sha256::digest(canonical_bytes);
    let algorithm: &dyn signature::VerificationAlgorithm = match signature.len() {
        64 => &signature::ECDSA_P256_SHA256_FIXED,
        _ if signature.first() == Some(&0x30) => &signature::ECDSA_P256_SHA256_ASN1,
        _ => return Err(VcError::InvalidProof),
    };
    let key = signature::UnparsedPublicKey::new(algorithm, public_key);
    key.verify(&digest, &signature)
        .map_err(|_| VcError::InvalidProof)
}

fn normalize_p256_pubkey(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.len() == 65 {
        return Some(bytes.to_vec());
    }
    if bytes.len() == 91 {
        return Some(bytes[26..].to_vec());
    }
    if bytes.len() > 65 && bytes[bytes.len() - 65] == 0x04 {
        return Some(bytes[bytes.len() - 65..].to_vec());
    }
    None
}
