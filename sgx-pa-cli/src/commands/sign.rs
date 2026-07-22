use base64::engine::general_purpose;
use base64::Engine as _;
use clap::Args;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::SecretKey;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const POLICY_SIG_OUTPUT_PATH: &str = "/etc/sgx-guardian/policies/policy.sig";
const PA_ADMIN_PUB_DER_OUTPUT_PATH: &str = "/etc/sgx-guardian/policies/pa_admin_pub.der";

/// Command-line arguments for the `sign` operation, which signs a policy file
/// using the guardian's locally stored ECDSA-P256 private key.
#[derive(Args)]
#[command(about = "Sign a policy file using the local guardian private key")]
pub struct SignArgs {
    /// Path to the policy YAML or JSON file to be signed
    pub file: String,
}
/// Loads the guardian private key, computes a SHA-256 digest of the policy file,
/// signs it using ECDSA-P256, and writes the Base64-encoded signature to
/// `policy.sig`. Handles missing files, invalid keys, and bad formats safely.
pub fn execute(args: SignArgs) -> bool {
    let policy_path = &args.file;
    println!("Signing policy file: {}", policy_path);

    // 1 Read policy content (safe version)
    let data = match fs::read_to_string(policy_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("❌ Failed to read policy file: {}", e);
            return false;
        }
    };

    // 2 Create SHA256 digest of the policy file
    let digest = Sha256::digest(data.as_bytes());

    // 3 Load private key (Base64 encoded) — safe version
    let key_content = match fs::read_to_string("/etc/sgx-guardian/guardian_private.key") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Missing guardian_private.key: {}", e);
            return false;
        }
    };

    let priv_bytes: Vec<u8> = match general_purpose::STANDARD.decode(key_content) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ Failed to decode private key: {}", e);
            return false;
        }
    };

    // 4 Convert Vec<u8> → [u8; 32]
    let priv_array: [u8; 32] = match priv_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("❌ Invalid private key length (must be 32 bytes)");
            return false;
        }
    };

    // 5 Convert to SecretKey (same logic as before)
    let secret_key = match SecretKey::from_bytes((&priv_array).into()) {
        Ok(sk) => sk,
        Err(_) => {
            eprintln!("❌ Invalid private key format");
            return false;
        }
    };
    let signing_key = SigningKey::from(secret_key);

    // 6 Sign the digest
    let signature: Signature = signing_key.sign(&digest);
    // === New JSON envelope support (Day-2 Sprint-3) ===

    // 6b. Compute hex digest (existing digest already computed)
    let digest_hex = hex::encode(digest);

    // 6c. Base64-encode raw YAML for envelope
    let policy_b64 = general_purpose::STANDARD.encode(data.as_bytes());

    // 6d. Extract public key (DER encoded)
    let pubkey_der = signing_key.verifying_key().to_encoded_point(false);
    let pubkey_bytes = pubkey_der.as_bytes();
    let pubkey_b64 = general_purpose::STANDARD.encode(pubkey_bytes);

    // 6e. Final JSON envelope
    let envelope = json!({
        "version": 1,
        "policy_b64": policy_b64,
        "digest_hex": digest_hex,
        "signature_b64": general_purpose::STANDARD.encode(signature.to_der().as_bytes()),
        "signing_pubkey_b64": pubkey_b64
    });

    if let Some(parent) = Path::new(POLICY_SIG_OUTPUT_PATH).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("❌ Unable to create policy output directory: {}", e);
            return false;
        }
    }

    // 7 Save Base64-encoded signature (old logic kept as-is)
    // === Replace old write with JSON envelope output ===
    if let Err(e) = fs::write(
        POLICY_SIG_OUTPUT_PATH,
        serde_json::to_string_pretty(&envelope).unwrap(),
    ) {
        eprintln!("❌ Unable to write signed policy file: {}", e);
        return false;
    }
    println!("✅ Policy signed successfully → {}", POLICY_SIG_OUTPUT_PATH);

    // Also export the bare DER public key so nodeA can distribute it.
    if let Err(e) = fs::write(PA_ADMIN_PUB_DER_OUTPUT_PATH, pubkey_bytes) {
        eprintln!(
            "⚠️  Failed to write {}: {}",
            PA_ADMIN_PUB_DER_OUTPUT_PATH, e
        );
        return false;
    } else {
        let fp = hex::encode(&Sha256::digest(pubkey_bytes)[..8]);
        println!(
            "🔑 PA public key exported to {} (fp={})\n   → scp this to nodeA:{}",
            PA_ADMIN_PUB_DER_OUTPUT_PATH, fp, PA_ADMIN_PUB_DER_OUTPUT_PATH
        );
    }

    true
}
