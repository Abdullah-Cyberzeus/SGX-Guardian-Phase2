use base64::engine::general_purpose;
use base64::Engine as _;
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Generates a new ECDSA-P256 keypair for the SGX Policy Authority.
/// Writes the private key to `guardian_private.key` and the public key to
/// `guardian_public.key`, with overwrite protection and secure file
/// permissions on Unix-based systems.
pub fn execute() {
    let signing_key = SigningKey::random(&mut OsRng);
    let verify_key = VerifyingKey::from(&signing_key);
    let priv_bytes = signing_key.to_bytes();
    let pub_bytes = verify_key.to_encoded_point(false);
    // Prevent accidental overwrite of an existing private key
    if Path::new("guardian_private.key").exists() {
        eprintln!("❌ guardian_private.key already exists; refusing to overwrite. Move or backup the existing key before regenerating.");
        return;
    }
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
    // Prevent accidental overwrite of an existing public key
    if Path::new("guardian_public.key").exists() {
        eprintln!("⚠️ guardian_public.key already exists; not overwriting existing public key to avoid accidental mismatch.");
        // proceed to still write if you want to force — currently we skip overwriting to be safe
        return;
    }
    fs::write(
        "guardian_public.key",
        general_purpose::STANDARD.encode(pub_bytes.as_bytes()),
    )
    .expect("Failed to write public key file");
    println!("✅ ECDSA-P256 keypair generated and saved locally.");
}
