// src/commands/verify.rs
use anyhow::{Context, Result};
use base64::engine::general_purpose;
use base64::Engine as _;
use clap::Args;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;

/// Arguments for `verify` command
#[derive(Args, Debug)]
#[command(about = "Verify a signed policy.sig file")]
pub struct VerifyArgs {
    /// Signed policy JSON envelope
    #[clap(long = "signed", short = 's')]
    pub signed: String,
}

/// Structure representing the signed policy JSON envelope
#[derive(Debug, Deserialize)]
pub struct SignedPolicyEnvelope {
    pub version: u32,
    pub policy_b64: String,
    pub digest_hex: String,
    pub signature_b64: String,
    pub signing_pubkey_b64: String,
}

/// Main entry for verification command
pub fn run(args: &VerifyArgs) -> Result<()> {
    // 1) Load signed policy JSON
    let content = fs::read_to_string(&args.signed)
        .with_context(|| format!("Failed to read signed policy file {}", args.signed))?;

    let envelope: SignedPolicyEnvelope =
        serde_json::from_str(&content).context("Invalid JSON format in signed policy file")?;
    // === Validate envelope version ===
    if envelope.version != 1 {
        println!("❌ Unsupported signed policy version: {}", envelope.version);
        anyhow::bail!("Signed policy version mismatch");
    }
    println!("✔ Envelope version valid");
    println!("🔍 Verifying signed policy: {}", args.signed);

    // 2) Decode original policy YAML
    let policy_bytes = general_purpose::STANDARD
        .decode(&envelope.policy_b64)
        .context("Failed to decode base64 policy")?;

    let policy_string = String::from_utf8(policy_bytes).context("Policy was not valid UTF-8")?;

    // 3) Compute SHA-256 digest of decoded policy
    let mut hasher = Sha256::new();
    hasher.update(policy_string.as_bytes());
    let digest_computed = hasher.finalize();
    let digest_hex_new = hex::encode(digest_computed);

    // 4) Validate digest field
    if digest_hex_new != envelope.digest_hex {
        println!("❌ Digest mismatch!");
        println!("Expected: {}", envelope.digest_hex);
        println!("Found:    {}", digest_hex_new);
        anyhow::bail!("Signed policy digest failed verification");
    }
    println!("✔ Digest valid");

    // 5) Decode signature
    let sig_bytes = general_purpose::STANDARD
        .decode(&envelope.signature_b64)
        .context("Failed to decode signature base64")?;

    let signature = Signature::from_der(&sig_bytes).context("Failed to parse DER signature")?;

    // 6) Decode verifying public key
    let pubkey_bytes = general_purpose::STANDARD
        .decode(&envelope.signing_pubkey_b64)
        .context("Failed to decode signing pubkey")?;

    let verifying_key =
        VerifyingKey::from_sec1_bytes(&pubkey_bytes).context("Invalid public key format")?;

    // 7) Verify ECDSA signature
    verifying_key
        .verify(&digest_computed, &signature)
        .context("Signature verification failed")?;

    println!("✔ Signature valid");
    println!("✔ Policy integrity verified successfully");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{run, VerifyArgs};
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::{Digest, Sha256};

    fn write_envelope(temp: &std::path::Path, json: &serde_json::Value) -> String {
        let path = temp.join("signed.json");
        std::fs::write(&path, json.to_string()).unwrap();
        path.to_string_lossy().to_string()
    }

    fn genuine_envelope(policy: &str, signing_key: &SigningKey) -> serde_json::Value {
        let policy_b64 = general_purpose::STANDARD.encode(policy.as_bytes());
        let digest = Sha256::digest(policy.as_bytes());
        let digest_hex = hex::encode(digest);
        let signature: Signature = signing_key.sign(&digest);
        let signature_b64 = general_purpose::STANDARD.encode(signature.to_der().as_bytes());
        let pubkey_b64 = general_purpose::STANDARD.encode(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        serde_json::json!({
            "version": 1,
            "policy_b64": policy_b64,
            "digest_hex": digest_hex,
            "signature_b64": signature_b64,
            "signing_pubkey_b64": pubkey_b64,
        })
    }

    #[test]
    fn run_verifies_a_genuinely_valid_signed_policy() {
        let temp = tempfile::tempdir().unwrap();
        let key = SigningKey::random(&mut rand_core::OsRng);
        let envelope = genuine_envelope("policy: contents", &key);
        let path = write_envelope(temp.path(), &envelope);
        run(&VerifyArgs { signed: path }).expect("genuine signature must verify");
    }

    #[test]
    fn run_reports_missing_file() {
        let err = run(&VerifyArgs {
            signed: "/nonexistent/signed.json".to_string(),
        })
        .expect_err("missing file");
        assert!(err.to_string().contains("Failed to read"));
    }

    #[test]
    fn run_rejects_an_unsupported_version() {
        let temp = tempfile::tempdir().unwrap();
        let key = SigningKey::random(&mut rand_core::OsRng);
        let mut envelope = genuine_envelope("policy: contents", &key);
        envelope["version"] = serde_json::json!(2);
        let path = write_envelope(temp.path(), &envelope);
        let err = run(&VerifyArgs { signed: path }).expect_err("unsupported version");
        assert!(err.to_string().contains("version mismatch"));
    }

    #[test]
    fn run_rejects_a_tampered_digest() {
        let temp = tempfile::tempdir().unwrap();
        let key = SigningKey::random(&mut rand_core::OsRng);
        let mut envelope = genuine_envelope("policy: contents", &key);
        envelope["digest_hex"] = serde_json::json!("00".repeat(32));
        let path = write_envelope(temp.path(), &envelope);
        let err = run(&VerifyArgs { signed: path }).expect_err("digest mismatch");
        assert!(err.to_string().contains("digest failed verification"));
    }

    #[test]
    fn run_rejects_a_signature_from_the_wrong_key() {
        let temp = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let wrong_key = SigningKey::random(&mut rand_core::OsRng);
        let mut envelope = genuine_envelope("policy: contents", &signing_key);
        // Swap in a pubkey that doesn't match the real signature.
        envelope["signing_pubkey_b64"] = serde_json::json!(general_purpose::STANDARD
            .encode(wrong_key.verifying_key().to_encoded_point(false).as_bytes()));
        let path = write_envelope(temp.path(), &envelope);
        let err = run(&VerifyArgs { signed: path }).expect_err("signature must not verify");
        assert!(err.to_string().contains("Signature verification failed"));
    }

    #[test]
    fn run_reports_invalid_json() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bad.json");
        std::fs::write(&path, "not valid json").unwrap();
        let err = run(&VerifyArgs {
            signed: path.to_string_lossy().to_string(),
        })
        .expect_err("invalid json");
        assert!(err.to_string().contains("Invalid JSON format"));
    }
}
