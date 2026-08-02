use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::{aead, agreement, rand, rand::SecureRandom};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub ciphertext: String,       // base64
    pub nonce: String,            // base64
    pub ephemeral_pubkey: String, // base64 (sender's ephemeral public key in uncompressed format)
}

pub fn encrypt_payload(
    plaintext: &[u8],
    peer_jwk_x: &str,
    peer_jwk_y: &str,
) -> Result<EncryptedMessage, String> {
    let rng = rand::SystemRandom::new();

    // 1. Generate Ephemeral Keypair
    let my_private_key = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
        .map_err(|_| "Failed to generate ephemeral key")?;
    let my_public_key = my_private_key
        .compute_public_key()
        .map_err(|_| "Failed to compute public key")?;

    // 2. Parse peer's public key from JWK x and y
    let x_bytes = URL_SAFE_NO_PAD
        .decode(peer_jwk_x)
        .map_err(|_| "Invalid JWK x")?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(peer_jwk_y)
        .map_err(|_| "Invalid JWK y")?;

    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err("JWK coordinates must be 32 bytes".to_string());
    }

    let mut uncompressed_key = vec![0x04];
    uncompressed_key.extend_from_slice(&x_bytes);
    uncompressed_key.extend_from_slice(&y_bytes);

    let peer_public_key_parsed =
        agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, &uncompressed_key);

    // 3. Perform ECDH to get shared secret
    let mut key_material = [0u8; 32];
    agreement::agree_ephemeral(my_private_key, &peer_public_key_parsed, |key_m| {
        let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, b"sgx-guardian-chat-v1");
        let prk = salt.extract(key_m);
        let okm = prk.expand(&[b"aes-key"], ring::hkdf::HKDF_SHA256).unwrap();
        okm.fill(&mut key_material).unwrap();
    })
    .map_err(|_| "ECDH failed")?;

    // 4. Encrypt with AES-256-GCM
    let unbound_key = aead::UnboundKey::new(&aead::AES_256_GCM, &key_material)
        .map_err(|_| "Invalid AES key length")?;
    let less_safe_key = aead::LessSafeKey::new(unbound_key);

    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "Nonce generation failed")?;
    let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

    let mut in_out = plaintext.to_vec();
    less_safe_key
        .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out)
        .map_err(|_| "Encryption failed")?;

    Ok(EncryptedMessage {
        ciphertext: base64::engine::general_purpose::STANDARD.encode(&in_out),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        ephemeral_pubkey: base64::engine::general_purpose::STANDARD.encode(my_public_key.as_ref()),
    })
}
