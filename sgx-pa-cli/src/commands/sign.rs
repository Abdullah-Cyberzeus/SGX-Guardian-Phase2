use base64::engine::general_purpose;
use base64::Engine as _;
use clap::Args;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::SecretKey;
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Args)]
#[command(about = "Sign a policy file using the local guardian private key")]
pub struct SignArgs {
    /// Path to the policy YAML or JSON file to be signed
    pub file: String,
}
pub fn execute(args: SignArgs) {
    let policy_path = &args.file;
    println!("Signing policy file: {}", policy_path);

    // 1 Read policy content (safe version)
    let data = match fs::read_to_string(policy_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("❌ Failed to read policy file: {}", e);
            return;
        }
    };

    // 2 Create SHA256 digest of the policy file
    let digest = Sha256::digest(data.as_bytes());

    // 3 Load private key (Base64 encoded) — safe version
    let key_content = match fs::read_to_string("guardian_private.key") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("❌ Missing guardian_private.key: {}", e);
            return;
        }
    };

    let priv_bytes: Vec<u8> = match general_purpose::STANDARD.decode(key_content) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("❌ Failed to decode private key: {}", e);
            return;
        }
    };

    // 4 Convert Vec<u8> → [u8; 32]
    let priv_array: [u8; 32] = match priv_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("❌ Invalid private key length (must be 32 bytes)");
            return;
        }
    };

    // 5 Convert to SecretKey (same logic as before)
    let secret_key = SecretKey::from_bytes((&priv_array).into()).expect("Invalid key format");
    let signing_key = SigningKey::from(secret_key);

    // 6 Sign the digest
    let signature: Signature = signing_key.sign(&digest);

    // 7 Save Base64-encoded signature (old logic kept as-is)
    if let Err(e) = fs::write(
        "policy.sig",
        general_purpose::STANDARD.encode(signature.to_der().as_bytes()),
    ) {
        eprintln!("❌ Unable to write signature file: {}", e);
        return;
    }

    println!("✅ Policy signed successfully → policy.sig");
}
