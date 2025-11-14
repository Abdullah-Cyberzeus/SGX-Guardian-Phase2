use base64::engine::general_purpose;
use base64::Engine as _;
use clap::Args;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::SecretKey;
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Args)]
pub struct SignArgs {
    /// Path to the policy YAML or JSON file to be signed
    pub file: String,
}
pub fn execute(args: SignArgs) {
    let policy_path = &args.file;
    println!("Signing policy file: {}", policy_path);

    // 1 Read policy content
    let data = fs::read_to_string(policy_path).expect("Unable to read policy file");

    // 2 Create SHA256 digest of the policy file
    let digest = Sha256::digest(data.as_bytes());

    // 3 Load private key (Base64 encoded)
    let priv_bytes: Vec<u8> = general_purpose::STANDARD
        .decode(fs::read_to_string("guardian_private.key").expect("Missing guardian_private.key"))
        .expect("Failed to decode private key");

    // 4 Convert Vec<u8> → [u8; 32]
    let priv_array: [u8; 32] = priv_bytes
        .try_into()
        .expect("Invalid private key length (must be 32 bytes)");

    // 5 Convert to SecretKey (p256 expects GenericArray<u8, U32>)
    let secret_key = SecretKey::from_bytes((&priv_array).into()).expect("Invalid key format");
    let signing_key = SigningKey::from(secret_key);

    // 6 Sign the digest
    let signature: Signature = signing_key.sign(&digest);

    // 7 Save Base64-encoded signature file
    fs::write(
        "policy.sig",
        general_purpose::STANDARD.encode(signature.to_der().as_bytes()),
    )
    .expect("Unable to write signature file");
    println!("✅ Policy signed successfully → policy.sig");
}
