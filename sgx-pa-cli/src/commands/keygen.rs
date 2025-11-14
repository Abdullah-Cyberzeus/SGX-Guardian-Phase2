use base64::engine::general_purpose;
use base64::Engine as _;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::fs;

pub fn execute() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = VerifyingKey::from(&signing_key);
    let priv_bytes = signing_key.to_bytes();
    let pub_bytes = verify_key.to_encoded_point(false);
    fs::write(
        "guardian_private.key",
        general_purpose::STANDARD.encode(priv_bytes),
    )
    .unwrap();
    fs::write(
        "guardian_public.key",
        general_purpose::STANDARD.encode(pub_bytes.as_bytes()),
    )
    .unwrap();
    println!("✅ ECDSA-P256 keypair generated and saved locally.");
}
