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
