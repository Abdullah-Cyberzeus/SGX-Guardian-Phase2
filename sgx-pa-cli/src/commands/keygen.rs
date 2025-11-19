use base64::engine::general_purpose;
use base64::Engine as _;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Generate a new ECDSA-P256 keypair and store it locally
pub fn execute() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = VerifyingKey::from(&signing_key);
    let priv_bytes = signing_key.to_bytes();
    let pub_bytes = verify_key.to_encoded_point(false);
    // Write private key (unsafe default perms)
    fs::write(
        "guardian_private.key",
        general_purpose::STANDARD.encode(priv_bytes),
    )
    .expect("Failed to write private key file");

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions("guardian_private.key", perms)
            .expect("Failed to set private key permissions");
    }

    fs::write(
        "guardian_public.key",
        general_purpose::STANDARD.encode(pub_bytes.as_bytes()),
    )
    .unwrap();
    println!("✅ ECDSA-P256 keypair generated and saved locally.");
}
