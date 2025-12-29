// src/policy_manager.rs
use crate::enforcement::enforce_policy;
use crate::policy;
use anyhow::{Context, Result};
use base64::engine::general_purpose;
use base64::Engine as _;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;

/// Represents a successfully verified policy
#[derive(Debug, Clone)]
pub struct VerifiedPolicy {
    pub policy_yaml: String,
    pub digest_hex: String,
    pub signer_pubkey: Vec<u8>,
}

/// Signed policy envelope (same format as sgx-pa-cli)
#[derive(Debug, Deserialize)]
struct SignedPolicyEnvelope {
    version: u32,
    policy_b64: String,
    digest_hex: String,
    signature_b64: String,
    signing_pubkey_b64: String,
}

/// Verify a signed policy file cryptographically
pub fn verify_signed_policy(path: &str) -> Result<VerifiedPolicy> {
    // 1. Load signed policy file
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read signed policy file: {}", path))?;

    let envelope: SignedPolicyEnvelope =
        serde_json::from_str(&content).context("Invalid signed policy JSON")?;

    // 2. Check version
    if envelope.version != 1 {
        anyhow::bail!("Unsupported policy version: {}", envelope.version);
    }

    // 3. Decode policy YAML
    let policy_bytes = general_purpose::STANDARD
        .decode(&envelope.policy_b64)
        .context("Failed to decode policy base64")?;

    let policy_yaml = String::from_utf8(policy_bytes).context("Policy YAML is not valid UTF-8")?;

    // 4. Recompute digest
    let mut hasher = Sha256::new();
    hasher.update(policy_yaml.as_bytes());
    let digest = hasher.finalize();
    let digest_hex = hex::encode(digest);

    if digest_hex != envelope.digest_hex {
        anyhow::bail!("Policy digest mismatch");
    }

    // 5. Decode signature
    let sig_bytes = general_purpose::STANDARD
        .decode(&envelope.signature_b64)
        .context("Failed to decode signature base64")?;

    let signature = Signature::from_der(&sig_bytes).context("Invalid ECDSA signature format")?;

    // 6. Decode signer public key
    let pubkey_bytes = general_purpose::STANDARD
        .decode(&envelope.signing_pubkey_b64)
        .context("Failed to decode signer public key")?;

    let verifying_key =
        VerifyingKey::from_sec1_bytes(&pubkey_bytes).context("Invalid public key format")?;

    // 7. Verify signature
    verifying_key
        .verify(&digest, &signature)
        .context("Signature verification failed")?;

    Ok(VerifiedPolicy {
        policy_yaml,
        digest_hex,
        signer_pubkey: pubkey_bytes,
    })
}
use crate::policy_state;

/// Verify + atomically activate a signed policy
pub fn load_and_activate_policy(path: &str) -> Result<VerifiedPolicy> {
    // 1. Verify cryptographic envelope
    let verified = verify_signed_policy(path)?;

    // 2. Parse + validate policy semantics (NO side effects)
    let parsed_policy =
        policy::validate_policy(&verified.policy_yaml).context("Policy YAML parsing failed")?;

    // 3. Enforcement validation (gatekeeper)
    // If this fails → policy MUST NOT become active
    enforce_policy(&parsed_policy).context("Policy enforcement validation failed")?;

    // 4. ONLY after successful enforcement → activate policy
    if let Err(e) = policy_state::activate_policy(&verified.policy_yaml) {
        let _ = policy_state::rollback_policy();
        return Err(e.context("Policy activation failed, rollback executed"));
    }

    Ok(verified)
}
