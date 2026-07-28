use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ring::aead::{
    Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM,
};
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::os::unix::fs::PermissionsExt;

fn get_key_file() -> String {
    std::env::var("GUARDIAN_KEY_FILE").unwrap_or_else(|_| "/etc/guardian/wifi_key.bin".to_string())
}

const ROCKYOU_LIST: &str = include_str!("rockyou_top1000.txt");

fn get_or_create_key() -> Result<[u8; 32], String> {
    if let Ok(key) = fs::read(get_key_file()) {
        if key.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&key);
            return Ok(arr);
        }
    }

    let mut key = [0u8; 32];
    SystemRandom::new()
        .fill(&mut key)
        .map_err(|_| "Failed to generate random key")?;
    if let Some(parent) = std::path::Path::new(&get_key_file()).parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Failed to create key directory: {}", e))?;
    }
    fs::write(get_key_file(), key).map_err(|e| format!("Failed to write key file: {}", e))?;
    fs::set_permissions(get_key_file(), fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set key file permissions: {}", e))?;
    Ok(key)
}

struct RandomNonceSequence([u8; 12]);
impl NonceSequence for RandomNonceSequence {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Nonce::try_assume_unique_for_key(&self.0)
    }
}

pub fn encrypt_password(password: &str) -> Result<String, String> {
    if password.is_empty() {
        return Err("Cannot encrypt empty password".to_string());
    }
    let key = get_or_create_key()?;
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| "Failed to generate nonce")?;

    let unbound_key =
        UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "Failed to create unbound key")?;
    let mut sealing_key = SealingKey::new(unbound_key, RandomNonceSequence(nonce_bytes));

    let mut data = password.as_bytes().to_vec();
    sealing_key
        .seal_in_place_append_tag(Aad::empty(), &mut data)
        .map_err(|_| "Failed to seal data")?;

    let mut final_data = nonce_bytes.to_vec();
    final_data.extend(data);
    Ok(BASE64.encode(&final_data))
}

pub fn decrypt_password(encrypted: &str) -> Result<String, String> {
    if encrypted.is_empty() {
        return Err("Cannot decrypt empty input".to_string());
    }

    let key = get_or_create_key()?;
    let decoded = BASE64
        .decode(encrypted)
        .map_err(|_| "Base64 error".to_string())?;
    if decoded.len() < 12 {
        return Err("Too short".to_string());
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(&decoded[0..12]);
    let mut data = decoded[12..].to_vec();

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key).map_err(|_| "Key error".to_string())?;
    let mut opening_key = OpeningKey::new(unbound_key, RandomNonceSequence(nonce_bytes));

    let dec_bytes = opening_key
        .open_in_place(Aad::empty(), &mut data)
        .map_err(|_| "Decryption error".to_string())?;
    String::from_utf8(dec_bytes.to_vec()).map_err(|_| "UTF-8 error".to_string())
}

pub fn validate_hotspot_password(pw: &str) -> Result<(), &'static str> {
    if pw.len() < 8 {
        return Err("Password must be at least 8 characters long");
    }
    if !pw.chars().any(|c| !c.is_alphanumeric()) {
        return Err("Password must contain at least one non-alphanumeric character");
    }

    let is_common = ROCKYOU_LIST.lines().any(|line| line.trim() == pw);
    if is_common {
        return Err("Password is too common (found in rockyou list)");
    }

    Ok(())
}
