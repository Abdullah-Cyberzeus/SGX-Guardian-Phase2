use ring::aead::{BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use ring::hkdf::HKDF_SHA256;
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::path::PathBuf;

const SALT: &[u8] = b"sgx-guardian-integration-oauth-salt-v1";
const NONCE_LEN: usize = 12;

struct SingleNonceSequence(Option<[u8; NONCE_LEN]>);

impl NonceSequence for SingleNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        let nonce_bytes = self.0.take().ok_or(ring::error::Unspecified)?;
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

/// Derives a 256-bit encryption key from system machine-id or fallback seed
fn derive_encryption_key() -> Result<UnboundKey, String> {
    let machine_id = get_machine_id();
    let salt = ring::hkdf::Salt::new(HKDF_SHA256, SALT);
    let prk = salt.extract(machine_id.as_bytes());

    let mut okm = [0u8; 32];
    let info: &[&[u8]] = &[b"sgx-guardian-vendor-tokens"];
    let okm_output = prk
        .expand(info, HKDF_SHA256)
        .map_err(|_| "HKDF expansion failed".to_string())?;

    okm_output
        .fill(&mut okm)
        .map_err(|_| "HKDF fill failed".to_string())?;

    UnboundKey::new(&AES_256_GCM, &okm).map_err(|_| "Invalid key length".to_string())
}

/// Reads `/etc/machine-id` or returns fallback unique host identifier
fn get_machine_id() -> String {
    let paths = ["/etc/machine-id", "/var/lib/dbus/machine-id"];
    for p in &paths {
        if let Ok(id) = fs::read_to_string(p) {
            let trimmed = id.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }

    // Fallback: persistent machine seed file in SGX data directory or hostname
    let data_dir =
        std::env::var("SGX_DATA_DIR").unwrap_or_else(|_| "/var/lib/sgx-guardian".to_string());
    let seed_path = PathBuf::from(&data_dir).join(".machine_seed");
    if let Ok(seed) = fs::read_to_string(&seed_path) {
        return seed.trim().to_string();
    }

    let rng = SystemRandom::new();
    let mut seed_bytes = [0u8; 16];
    let _ = rng.fill(&mut seed_bytes);
    let hex_seed = hex::encode(seed_bytes);
    let _ = fs::create_dir_all(&data_dir);
    let _ = fs::write(&seed_path, &hex_seed);

    hex_seed
}

/// Encrypts plaintext bytes using AES-256-GCM
pub fn encrypt_tokens(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let unbound_key = derive_encryption_key()?;
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| "RNG failure".to_string())?;

    let nonce_seq = SingleNonceSequence(Some(nonce_bytes));
    let mut sealing_key = SealingKey::new(unbound_key, nonce_seq);

    let mut in_out = plaintext.to_vec();
    sealing_key
        .seal_in_place_append_tag(ring::aead::Aad::empty(), &mut in_out)
        .map_err(|_| "Encryption failed".to_string())?;

    let mut result = Vec::with_capacity(NONCE_LEN + in_out.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&in_out);

    Ok(result)
}

/// Decrypts ciphertext bytes using AES-256-GCM
pub fn decrypt_tokens(ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() <= NONCE_LEN {
        return Err("Ciphertext payload too short".to_string());
    }

    let (nonce_bytes, payload) = ciphertext.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce_bytes);

    let unbound_key = derive_encryption_key()?;
    let nonce_seq = SingleNonceSequence(Some(nonce_arr));
    let mut opening_key = OpeningKey::new(unbound_key, nonce_seq);

    let mut in_out = payload.to_vec();
    let out = opening_key
        .open_in_place(ring::aead::Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed or invalid authentication tag".to_string())?;

    Ok(out.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let plaintext = b"secret_oauth_access_token_123456789";
        let encrypted = encrypt_tokens(plaintext).expect("Encryption failed");
        assert_ne!(plaintext, &encrypted[..]);

        let decrypted = decrypt_tokens(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_tamper_detection() {
        let plaintext = b"sensitive_token";
        let mut encrypted = encrypt_tokens(plaintext).expect("Encryption failed");

        // Tamper with payload byte
        let last_idx = encrypted.len() - 1;
        encrypted[last_idx] ^= 0xFF;

        assert!(decrypt_tokens(&encrypted).is_err());
    }
}
