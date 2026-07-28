//! Policy Authority (PA) key manager — nodeA-resident.
//!
//! This module owns the cohort-wide signing keypair used for `policy.sig`.
//! The PA key is logically separate from:
//!   - the SE050-backed DKP (signs per-device PCR + attestation evidence)
//!   - the per-node identity key (used for mTLS and gRPC)
//!
//! The PA key is software ECDSA-P256 (PKCS#8) and lives under
//! /etc/sgx-guardian/policies/. Only nodeA holds the private half. Member
//! nodes receive the public half through the cert-bootstrap response.

use anyhow::{anyhow, Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const PA_DIR: &str = "/etc/sgx-guardian/policies";
const PA_PRIV_PATH: &str = "/etc/sgx-guardian/policies/pa_admin_priv.der";
const PA_PUB_PATH: &str = "/etc/sgx-guardian/policies/pa_admin_pub.der";
const SIGNED_POLICY_PATH: &str = "/etc/sgx-guardian/policies/policy.sig";

pub struct PaKey {
    keypair: EcdsaKeyPair,
    pubkey_der: Vec<u8>,
}

impl PaKey {
    /// Load existing PA key from disk; if absent, generate a fresh one,
    /// persist both private (mode 0600) and public (mode 0644), and return.
    /// Idempotent — second call on a populated directory just reloads.
    /// Calling this on a member node is harmless (member never signs), but
    /// in practice we only invoke this from the nodeA bootstrap path.
    pub fn load_or_generate() -> Result<Self> {
        let _ = fs::create_dir_all(PA_DIR);
        let rng = SystemRandom::new();

        let pkcs8 = if Path::new(PA_PRIV_PATH).exists() {
            fs::read(PA_PRIV_PATH)
                .with_context(|| format!("Read PA private key {}", PA_PRIV_PATH))?
        } else {
            tracing::info!("PA: generating new Policy Authority key (first run)");
            let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
                .map_err(|_| anyhow!("PA keygen failed"))?;
            atomic_write(PA_PRIV_PATH, doc.as_ref(), 0o600)?;
            doc.as_ref().to_vec()
        };

        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|_| anyhow!("PA private key invalid PKCS#8"))?;
        let pubkey_der = keypair.public_key().as_ref().to_vec();

        // Always (re-)write the public key file so it stays in sync.
        atomic_write(PA_PUB_PATH, &pubkey_der, 0o644)?;

        let fp = hex::encode(&Sha256::digest(&pubkey_der)[..8]);
        tracing::info!("PA: key ready (pubkey fp={})", fp);

        Ok(Self {
            keypair,
            pubkey_der,
        })
    }

    pub fn pubkey_der(&self) -> &[u8] {
        &self.pubkey_der
    }

    /// Read a YAML policy file, sign it, and atomically write the JSON
    /// envelope to /etc/sgx-guardian/policies/policy.sig.
    /// Envelope format matches the existing one used by sgx-pa-cli sign,
    /// so policy_manager::verify_signed_policy continues to work without
    /// any change.
    pub fn sign_policy_to_disk(&self, yaml_path: &str) -> Result<String> {
        use base64::engine::general_purpose;
        use base64::Engine as _;

        let yaml = fs::read_to_string(yaml_path)
            .with_context(|| format!("Read policy yaml {}", yaml_path))?;
        let digest: [u8; 32] = Sha256::digest(yaml.as_bytes()).into();
        let digest_hex = hex::encode(digest);

        let rng = SystemRandom::new();
        let sig = self
            .keypair
            .sign(&rng, &digest)
            .map_err(|_| anyhow!("PA sign failed"))?;

        // Note: ring produces fixed-size (r||s) for ECDSA_P256_SHA256_FIXED_SIGNING.
        // policy_manager::verify_signed_policy currently parses signatures via
        // p256::ecdsa::Signature::from_der. We must therefore convert fixed → DER
        // before writing the envelope, OR keep the existing on-the-wire format
        // matching sgx-pa-cli (which uses p256 crate that produces DER directly).
        // To keep policy_manager unchanged we convert fixed-size r||s into DER:
        let sig_der = encode_ecdsa_sig_fixed_to_der(sig.as_ref())?;

        let envelope = serde_json::json!({
            "version": 1,
            "policy_b64": general_purpose::STANDARD.encode(yaml.as_bytes()),
            "digest_hex": digest_hex,
            "signature_b64": general_purpose::STANDARD.encode(&sig_der),
            "signing_pubkey_b64": general_purpose::STANDARD.encode(&self.pubkey_der),
        });

        let pretty = serde_json::to_string_pretty(&envelope)?;
        atomic_write(SIGNED_POLICY_PATH, pretty.as_bytes(), 0o644)?;

        let pubkey_digest: [u8; 32] = Sha256::digest(&self.pubkey_der).into();
        let fp = hex::encode(&pubkey_digest[..8]);
        tracing::info!(
            "PA: policy signed (digest={}, pa_fp={}, written to {})",
            digest_hex,
            fp,
            SIGNED_POLICY_PATH
        );

        Ok(digest_hex)
    }
}

fn atomic_write(path: &str, bytes: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;

    #[cfg(not(unix))]
    let _ = mode;

    let tmp = format!("{}.tmp", path);
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("Create tmp file {}", tmp))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("Rename {} → {}", tmp, path))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    Ok(())
}

/// Convert ring's fixed-size r||s ECDSA-P256 signature (64 bytes) into a
/// DER-encoded ECDSA signature, which is what policy_manager + sgx-pa-cli
/// verify expect.
fn encode_ecdsa_sig_fixed_to_der(fixed: &[u8]) -> Result<Vec<u8>> {
    if fixed.len() != 64 {
        return Err(anyhow!(
            "Unexpected fixed signature length {} (want 64)",
            fixed.len()
        ));
    }
    // Use p256 crate to render DER from raw r||s.
    use p256::ecdsa::Signature as P256Sig;
    let sig =
        P256Sig::try_from(fixed).map_err(|e| anyhow!("Build P256 signature from r||s: {:?}", e))?;
    Ok(sig.to_der().as_bytes().to_vec())
}
