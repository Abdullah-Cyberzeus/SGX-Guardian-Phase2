// src/policy_manager.rs
use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::enforcement::apply_policy;
use crate::policy;
use crate::policy_state::ActivationOutcome;
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
    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

    log_audit(
        &node_id,
        AuditCategory::Policy,
        AuditSeverity::Info,
        AuditAction::Started,
        &format!("Started signed policy verification: {}", path),
    );
    // 1. Load signed policy file
    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read signed policy file: {}", path))?;

    let envelope: SignedPolicyEnvelope =
        serde_json::from_str(&content).context("Invalid signed policy JSON")?;

    // 2. Check version
    if envelope.version != 1 {
        log_audit(
            &node_id,
            AuditCategory::Policy,
            AuditSeverity::Critical,
            AuditAction::Rejected,
            &format!("Unsupported policy version: {}", envelope.version),
        );

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
        log_audit(
            &node_id,
            AuditCategory::Policy,
            AuditSeverity::Critical,
            AuditAction::Rejected,
            "Policy digest mismatch detected",
        );

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
    let node_id = std::env::args().nth(1).unwrap_or("unknown-node".into());

    log_audit(
        &node_id,
        AuditCategory::Policy,
        AuditSeverity::Info,
        AuditAction::Started,
        "Policy activation workflow started",
    );
    // 1. Verify cryptographic envelope
    let verified = verify_signed_policy(path)?;

    // If this exact signed policy is already active, do not rotate backup.
    if let Some(current_digest) = policy_state::current_active_policy_digest()? {
        if current_digest.eq_ignore_ascii_case(&verified.digest_hex) {
            println!("Policy already active; skipping backup rotation");
            log_audit(
                &node_id,
                AuditCategory::Policy,
                AuditSeverity::Info,
                AuditAction::Applied,
                "Policy already active; skipping backup rotation",
            );
            return Ok(verified);
        }
    }

    // 2. Parse + validate policy semantics (NO side effects)
    let parsed_policy =
        policy::validate_policy(&verified.policy_yaml).context("Policy YAML parsing failed")?;

    // 3. Enforcement validation (gatekeeper)
    // If this fails → policy MUST NOT become active
    if let Err(e) = apply_policy(&parsed_policy) {
        log_audit(
            &node_id,
            AuditCategory::Policy,
            AuditSeverity::Critical,
            AuditAction::Rejected,
            "Policy enforcement validation failed",
        );
        return Err(e.context("Policy enforcement validation failed"));
    }

    // 4. ONLY after successful enforcement → activate policy
    match policy_state::activate_policy(&verified.policy_yaml, &verified.digest_hex) {
        Ok(ActivationOutcome::Unchanged) => {
            println!("Policy already active; skipping backup rotation");
            log_audit(
                &node_id,
                AuditCategory::Policy,
                AuditSeverity::Info,
                AuditAction::Applied,
                "Policy already active; skipping backup rotation",
            );
            return Ok(verified);
        }
        Ok(ActivationOutcome::Activated {
            backup_rotated: true,
        }) => {
            println!("New policy activated; previous active policy moved to backup");
        }
        Ok(ActivationOutcome::Activated {
            backup_rotated: false,
        }) => {
            // First activation path: there was no previous active policy to rotate.
        }
        Err(e) => {
            let _ = policy_state::rollback_policy();

            log_audit(
                &node_id,
                AuditCategory::Policy,
                AuditSeverity::Critical,
                AuditAction::Rollback,
                "Policy activation failed — rollback executed",
            );

            return Err(e.context("Policy activation failed, rollback executed"));
        }
    }
    log_audit(
        &node_id,
        AuditCategory::Policy,
        AuditSeverity::Info,
        AuditAction::Applied,
        "Policy successfully activated",
    );
    Ok(verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;
    use std::fs;

    const POLICY_YAML: &str = r#"
policy_id: "policy-test"
version: "1.0.0"
rules:
  - id: "allow-https"
    action: "ALLOW"
    src: "10.0.0.0/24"
    dst: "0.0.0.0/0"
    protocol: "TCP"
    port: 443
"#;

    fn signed_policy_envelope(policy_yaml: &str, version: u32, digest_hex: Option<String>) -> String {
        let signing_key = SigningKey::random(&mut OsRng);
        let digest = Sha256::digest(policy_yaml.as_bytes());
        let signature: Signature = signing_key.sign(&digest);
        let pubkey = signing_key.verifying_key().to_encoded_point(false);

        serde_json::json!({
            "version": version,
            "policy_b64": general_purpose::STANDARD.encode(policy_yaml.as_bytes()),
            "digest_hex": digest_hex.unwrap_or_else(|| hex::encode(digest)),
            "signature_b64": general_purpose::STANDARD.encode(signature.to_der().as_bytes()),
            "signing_pubkey_b64": general_purpose::STANDARD.encode(pubkey.as_bytes())
        })
        .to_string()
    }

    #[test]
    fn verify_signed_policy_returns_verified_policy_for_valid_envelope() {
        let td = tempdir().expect("create temp dir");
        let path = td.path().join("policy.sig");
        fs::write(&path, signed_policy_envelope(POLICY_YAML, 1, None))
            .expect("write policy file");

        let verified = verify_signed_policy(path.to_str().expect("utf8 path"))
            .expect("verify signed policy");

        assert_eq!(verified.policy_yaml, POLICY_YAML);
        assert_eq!(verified.digest_hex, hex::encode(Sha256::digest(POLICY_YAML.as_bytes())));
        assert_eq!(verified.signer_pubkey.len(), 65);
    }

    #[test]
    fn verify_signed_policy_rejects_unsupported_version() {
        let td = tempdir().expect("create temp dir");
        let path = td.path().join("policy.sig");
        fs::write(&path, signed_policy_envelope(POLICY_YAML, 2, None))
            .expect("write policy file");

        let err = verify_signed_policy(path.to_str().expect("utf8 path"))
            .expect_err("unsupported version should fail");
        assert!(err.to_string().contains("Unsupported policy version"));
    }

    #[test]
    fn verify_signed_policy_rejects_digest_mismatch() {
        let td = tempdir().expect("create temp dir");
        let path = td.path().join("policy.sig");
        fs::write(
            &path,
            signed_policy_envelope(POLICY_YAML, 1, Some("00".repeat(32))),
        )
        .expect("write policy file");

        let err = verify_signed_policy(path.to_str().expect("utf8 path"))
            .expect_err("digest mismatch should fail");
        assert!(err.to_string().contains("Policy digest mismatch"));
    }
}
