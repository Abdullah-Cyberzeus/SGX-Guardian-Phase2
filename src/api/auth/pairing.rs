use crate::api::auth::ecdsa::normalize_p256_signature;
use crate::api::auth::store::{AdminStores, PairingChallengeRecord};
use crate::key_manager::KeyManager;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use rand::{rngs::OsRng, RngCore};
use ring::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const PAIRING_DOMAIN_SEPARATOR: &[u8] = b"sgx-guardian:pairing:v1:";
pub const DEFAULT_PAIRING_TTL_SECS: u64 = 300;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PairingChallenge {
    pub serial: String,
    pub challenge: String,
    pub nonce: String,
    pub exp: i64,
    pub issued_at: i64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PairingProofPayload {
    pub serial: String,
    pub challenge: String,
    pub nonce: String,
    pub exp: i64,
    pub node_id: String,
    pub device_did: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PairingProof {
    pub payload: PairingProofPayload,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPairing {
    pub serial: String,
    pub nonce: String,
    pub challenge: String,
    pub owner_user_id: String,
    pub device_id: String,
    pub device_did: String,
    pub node_id: String,
    pub public_key: Vec<u8>,
    pub exp: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingUsage {
    Api,
    Bootstrap,
}

pub fn validate_serial(serial: &str) -> Result<String> {
    let normalized = serial.trim();
    if normalized.is_empty() {
        return Err(anyhow!("serial is required"));
    }
    if !normalized
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(anyhow!("serial contains invalid characters"));
    }
    Ok(normalized.to_string())
}

pub fn issue_challenge(serial: &str, ttl: Duration) -> Result<PairingChallenge> {
    let serial = validate_serial(serial)?;
    let now = Utc::now().timestamp();
    Ok(PairingChallenge {
        serial,
        challenge: random_hex(32),
        nonce: random_hex(16),
        exp: now + ttl.as_secs() as i64,
        issued_at: now,
    })
}

pub fn encode_challenge(challenge: &PairingChallenge) -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(challenge).map_err(|e| anyhow!("serialize pairing challenge: {}", e))?,
    ))
}

pub fn decode_challenge(encoded: &str) -> Result<PairingChallenge> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| anyhow!("decode pairing challenge: {}", e))?;
    serde_json::from_slice(&bytes).map_err(|e| anyhow!("parse pairing challenge: {}", e))
}

pub async fn build_pairing_proof(
    challenge_code: &str,
    node_id: &str,
    device_did: &str,
    public_key: &[u8],
    signer: Arc<KeyManager>,
) -> Result<String> {
    let challenge = decode_challenge(challenge_code)?;
    let payload = PairingProofPayload {
        serial: challenge.serial.clone(),
        challenge: challenge.challenge.clone(),
        nonce: challenge.nonce.clone(),
        exp: challenge.exp,
        node_id: node_id.to_string(),
        device_did: device_did.to_string(),
        public_key: URL_SAFE_NO_PAD.encode(public_key),
    };
    let to_sign = canonical_payload_bytes(&payload)?;
    let signature = tokio::task::spawn_blocking(move || signer.sign(&to_sign))
        .await
        .map_err(|e| anyhow!("pairing signing task failed: {}", e))??;
    let signature =
        normalize_p256_signature(&signature).map_err(|e| anyhow!("pairing signature: {}", e))?;
    encode_proof(&PairingProof {
        payload,
        signature: URL_SAFE_NO_PAD.encode(signature),
    })
}

pub fn encode_proof(proof: &PairingProof) -> Result<String> {
    Ok(URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(proof).map_err(|e| anyhow!("serialize pairing proof: {}", e))?))
}

pub fn decode_proof(encoded: &str) -> Result<PairingProof> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| anyhow!("decode pairing proof: {}", e))?;
    serde_json::from_slice(&bytes).map_err(|e| anyhow!("parse pairing proof: {}", e))
}

pub fn verify_proof(encoded: &str) -> Result<AuthorizedPairing> {
    let proof = decode_proof(encoded)?;
    if proof.payload.exp <= Utc::now().timestamp() {
        return Err(anyhow!("pairing proof expired"));
    }
    let public_key = URL_SAFE_NO_PAD
        .decode(&proof.payload.public_key)
        .map_err(|e| anyhow!("decode pairing public key: {}", e))?;
    if public_key.len() != 65 || public_key.first() != Some(&0x04) {
        return Err(anyhow!(
            "pairing public key must be an uncompressed P-256 point"
        ));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(&proof.signature)
        .map_err(|e| anyhow!("decode pairing signature: {}", e))?;
    let to_verify = canonical_payload_bytes(&proof.payload)?;
    let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &public_key);
    key.verify(&to_verify, &signature)
        .map_err(|_| anyhow!("pairing signature verification failed"))?;
    let device_id = hex::encode(Sha256::digest(&public_key));
    Ok(AuthorizedPairing {
        serial: proof.payload.serial,
        nonce: proof.payload.nonce,
        challenge: proof.payload.challenge,
        owner_user_id: String::new(),
        device_id,
        device_did: proof.payload.device_did,
        node_id: proof.payload.node_id,
        public_key,
        exp: proof.payload.exp,
    })
}

pub async fn authorize_pairing_proof(
    stores: &AdminStores,
    encoded_proof: &str,
    usage: PairingUsage,
) -> Result<AuthorizedPairing> {
    let mut authorized = verify_proof(encoded_proof)?;
    let Some(mut record) = stores
        .pairings
        .get(&authorized.serial, &authorized.nonce)
        .await?
    else {
        return Err(anyhow!("pairing challenge not found"));
    };
    if record.challenge != authorized.challenge {
        return Err(anyhow!("pairing challenge mismatch"));
    }
    if record.exp != authorized.exp {
        return Err(anyhow!("pairing expiry mismatch"));
    }
    if record.exp <= Utc::now().timestamp() {
        return Err(anyhow!("pairing challenge expired"));
    }
    match usage {
        PairingUsage::Api if record.api_consumed => {
            return Err(anyhow!("pairing challenge already used for api binding"));
        }
        PairingUsage::Bootstrap if record.bootstrap_consumed => {
            return Err(anyhow!("pairing challenge already used for bootstrap"));
        }
        _ => {}
    }

    record.device_id = Some(authorized.device_id.clone());
    record.did = Some(authorized.device_did.clone());
    record.node_id = Some(authorized.node_id.clone());
    record.public_key = Some(URL_SAFE_NO_PAD.encode(&authorized.public_key));
    record.bound_at = Some(Utc::now().to_rfc3339());
    match usage {
        PairingUsage::Api => record.api_consumed = true,
        PairingUsage::Bootstrap => record.bootstrap_consumed = true,
    }
    stores.pairings.put(record.clone()).await?;
    authorized.owner_user_id = record.owner_user_id;
    Ok(authorized)
}

pub fn record_from_challenge(
    challenge: &PairingChallenge,
    owner_user_id: &str,
) -> PairingChallengeRecord {
    PairingChallengeRecord {
        serial: challenge.serial.clone(),
        challenge: challenge.challenge.clone(),
        nonce: challenge.nonce.clone(),
        exp: challenge.exp,
        owner_user_id: owner_user_id.to_string(),
        api_consumed: false,
        bootstrap_consumed: false,
        device_id: None,
        did: None,
        node_id: None,
        public_key: None,
        bound_at: None,
    }
}

fn canonical_payload_bytes(payload: &PairingProofPayload) -> Result<Vec<u8>> {
    let serialized =
        serde_json::to_vec(payload).map_err(|e| anyhow!("serialize pairing payload: {}", e))?;
    let mut out = Vec::with_capacity(PAIRING_DOMAIN_SEPARATOR.len() + serialized.len());
    out.extend_from_slice(PAIRING_DOMAIN_SEPARATOR);
    out.extend_from_slice(&serialized);
    Ok(out)
}

fn random_hex(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::auth::store::AdminStores;
    use tempfile::TempDir;

    async fn build_test_proof(
        serial: &str,
    ) -> (
        TempDir,
        Arc<KeyManager>,
        Arc<AdminStores>,
        PairingChallenge,
        String,
    ) {
        let td = TempDir::new().expect("tempdir");
        let key_path = td.path().join("device.key");
        let signer = Arc::new(
            KeyManager::load_or_generate(key_path.to_str().expect("key path"))
                .expect("load key manager"),
        );
        let stores = AdminStores::new(td.path().join("admin"));
        let challenge = issue_challenge(serial, Duration::from_secs(300)).expect("issue challenge");
        stores
            .pairings
            .put(record_from_challenge(&challenge, "user-1"))
            .await
            .expect("save challenge");
        let proof = build_pairing_proof(
            &encode_challenge(&challenge).expect("encode challenge"),
            "nodeB",
            "did:guardian:test-node-b",
            &signer.pubkey_der().expect("pubkey"),
            signer.clone(),
        )
        .await
        .expect("build pairing proof");

        (td, signer, stores, challenge, proof)
    }

    #[tokio::test]
    async fn generated_pairing_proof_verifies_successfully() {
        let (_td, signer, _stores, challenge, proof) =
            build_test_proof("GX-2024-TX-042-A9F3").await;

        let verified = verify_proof(&proof).expect("verify proof");

        assert_eq!(verified.serial, challenge.serial);
        assert_eq!(verified.challenge, challenge.challenge);
        assert_eq!(verified.nonce, challenge.nonce);
        assert_eq!(verified.device_did, "did:guardian:test-node-b");
        assert_eq!(verified.node_id, "nodeB");
        assert_eq!(verified.public_key, signer.pubkey_der().expect("pubkey"));
    }

    #[tokio::test]
    async fn tampered_pairing_proof_fails_verification() {
        let (_td, _signer, _stores, _challenge, proof) =
            build_test_proof("GX-2024-TX-042-B7C1").await;
        let mut tampered = decode_proof(&proof).expect("decode proof");
        tampered.payload.node_id = "nodeC".into();
        let tampered = encode_proof(&tampered).expect("encode tampered proof");

        let err = verify_proof(&tampered).expect_err("tampered proof must fail");
        assert!(err
            .to_string()
            .contains("pairing signature verification failed"));
    }

    #[tokio::test]
    async fn proof_round_trip_and_replay_protection_work() {
        let (_td, _signer, stores, _challenge, proof) =
            build_test_proof("GX-2024-TX-042-A9F3").await;

        let first = authorize_pairing_proof(stores.as_ref(), &proof, PairingUsage::Api)
            .await
            .expect("authorize api pairing");
        assert_eq!(first.serial, "GX-2024-TX-042-A9F3");
        assert_eq!(first.owner_user_id, "user-1");

        authorize_pairing_proof(stores.as_ref(), &proof, PairingUsage::Bootstrap)
            .await
            .expect("authorize bootstrap pairing");
        assert!(
            authorize_pairing_proof(stores.as_ref(), &proof, PairingUsage::Api)
                .await
                .is_err()
        );
    }
}
