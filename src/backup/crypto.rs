use crate::backup::errors::BackupError;
use argon2::Argon2;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hmac;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::io::{Read, Write};

const MAGIC: &[u8; 8] = b"SGXBAK1\0";
const SALT_BYTES: usize = 16;
const NONCE_PREFIX_BYTES: usize = 7;
const NONCE_BYTES: usize = 12;
const CHUNK_BYTES: usize = 64 * 1024;
const TAG_BYTES: usize = 16;
const HMAC_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoHeader {
    pub version: u32,
    pub kdf: String,
    pub cipher: String,
    pub chunk_bytes: u32,
    pub salt_b64: String,
    pub nonce_prefix_b64: String,
}

#[derive(Debug, Clone)]
pub struct EncryptResult {
    pub header: CryptoHeader,
    pub bundle_hmac_sha256: String,
}

pub fn encrypt_to_writer(
    plaintext: &[u8],
    passphrase: &str,
    mut writer: impl Write,
) -> Result<EncryptResult, BackupError> {
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);

    let mut key_material = derive_key_material(passphrase, &salt)?;
    let enc_key = make_aead_key(&key_material[..32])?;
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &key_material[32..64]);
    key_material.fill(0);

    let header = CryptoHeader {
        version: 1,
        kdf: "Argon2id/default".to_string(),
        cipher: "AES-256-GCM/STREAM-BE32+HMAC-SHA256".to_string(),
        chunk_bytes: CHUNK_BYTES as u32,
        salt_b64: general_purpose::STANDARD.encode(salt),
        nonce_prefix_b64: general_purpose::STANDARD.encode(nonce_prefix),
    };
    let header_bytes = serde_json::to_vec(&header)?;
    let header_len = u32::try_from(header_bytes.len())
        .map_err(|_| BackupError::Crypto("backup crypto header is too large".to_string()))?;

    let mut mac_ctx = hmac::Context::with_key(&mac_key);
    writer.write_all(MAGIC)?;
    mac_ctx.update(MAGIC);
    writer.write_all(&header_len.to_be_bytes())?;
    mac_ctx.update(&header_len.to_be_bytes());
    writer.write_all(&header_bytes)?;
    mac_ctx.update(&header_bytes);

    let mut offset = 0;
    let mut index = 0_u32;
    while offset < plaintext.len() {
        let end = plaintext.len().min(offset + CHUNK_BYTES);
        let mut chunk = plaintext[offset..end].to_vec();
        let last = end == plaintext.len();
        enc_key
            .seal_in_place_append_tag(
                make_nonce(&nonce_prefix, index, last),
                Aad::empty(),
                &mut chunk,
            )
            .map_err(|_| BackupError::Crypto("backup chunk encryption failed".to_string()))?;
        let len = u32::try_from(chunk.len())
            .map_err(|_| BackupError::Crypto("encrypted backup chunk is too large".to_string()))?;
        writer.write_all(&len.to_be_bytes())?;
        mac_ctx.update(&len.to_be_bytes());
        writer.write_all(&chunk)?;
        mac_ctx.update(&chunk);
        offset = end;
        index = index
            .checked_add(1)
            .ok_or_else(|| BackupError::Crypto("too many backup chunks".to_string()))?;
    }

    if plaintext.is_empty() {
        let len = 0_u32.to_be_bytes();
        writer.write_all(&len)?;
        mac_ctx.update(&len);
    }

    let tag = mac_ctx.sign();
    writer.write_all(tag.as_ref())?;
    writer.flush()?;

    Ok(EncryptResult {
        header,
        bundle_hmac_sha256: hex::encode(tag.as_ref()),
    })
}

pub fn decrypt_from_reader(
    reader: impl Read,
    passphrase: &str,
    max_bytes: u64,
) -> Result<Vec<u8>, BackupError> {
    let mut bundle = Vec::new();
    reader
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bundle)?;
    if bundle.len() as u64 > max_bytes {
        return Err(BackupError::BundleTooLarge {
            size: bundle.len() as u64,
            max: max_bytes,
        });
    }
    decrypt_bundle_bytes(&bundle, passphrase)
}

pub fn decrypt_bundle_bytes(bundle: &[u8], passphrase: &str) -> Result<Vec<u8>, BackupError> {
    if bundle.len() < MAGIC.len() + 4 + HMAC_BYTES {
        return Err(BackupError::Integrity("bundle is truncated".to_string()));
    }
    if &bundle[..MAGIC.len()] != MAGIC {
        return Err(BackupError::Integrity("bad backup magic".to_string()));
    }
    let header_len_offset = MAGIC.len();
    let header_len = u32::from_be_bytes(
        bundle[header_len_offset..header_len_offset + 4]
            .try_into()
            .expect("slice length checked"),
    ) as usize;
    let header_start = header_len_offset + 4;
    let header_end = header_start
        .checked_add(header_len)
        .ok_or_else(|| BackupError::Integrity("invalid header length".to_string()))?;
    if header_end + HMAC_BYTES > bundle.len() {
        return Err(BackupError::Integrity("truncated header".to_string()));
    }
    let header: CryptoHeader = serde_json::from_slice(&bundle[header_start..header_end])?;
    if header.version != 1 {
        return Err(BackupError::UnsupportedSchema(format!(
            "crypto header version {}",
            header.version
        )));
    }
    if header.chunk_bytes != CHUNK_BYTES as u32 {
        return Err(BackupError::UnsupportedSchema(format!(
            "unsupported chunk size {}",
            header.chunk_bytes
        )));
    }

    let salt = general_purpose::STANDARD.decode(&header.salt_b64)?;
    let nonce_prefix = general_purpose::STANDARD.decode(&header.nonce_prefix_b64)?;
    if nonce_prefix.len() != NONCE_PREFIX_BYTES {
        return Err(BackupError::Integrity("invalid nonce prefix".to_string()));
    }

    let mut key_material = derive_key_material(passphrase, &salt)?;
    let enc_key = make_aead_key(&key_material[..32])?;
    let mac_key = hmac::Key::new(hmac::HMAC_SHA256, &key_material[32..64]);
    key_material.fill(0);

    let hmac_start = bundle.len() - HMAC_BYTES;
    hmac::verify(&mac_key, &bundle[..hmac_start], &bundle[hmac_start..])
        .map_err(|_| BackupError::Integrity("bundle HMAC mismatch".to_string()))?;

    let mut out = Vec::new();
    let mut cursor = header_end;
    let mut index = 0_u32;
    while cursor < hmac_start {
        if cursor + 4 > hmac_start {
            return Err(BackupError::Integrity("truncated chunk header".to_string()));
        }
        let cipher_len = u32::from_be_bytes(
            bundle[cursor..cursor + 4]
                .try_into()
                .expect("slice length checked"),
        ) as usize;
        cursor += 4;
        if cipher_len == 0 {
            if cursor != hmac_start {
                return Err(BackupError::Integrity(
                    "empty chunk is only valid at end of stream".to_string(),
                ));
            }
            break;
        }
        if cipher_len < TAG_BYTES || cursor + cipher_len > hmac_start {
            return Err(BackupError::Integrity("invalid chunk length".to_string()));
        }
        let last = cursor + cipher_len == hmac_start;
        let mut sealed = bundle[cursor..cursor + cipher_len].to_vec();
        let plain = enc_key
            .open_in_place(
                make_nonce_slice(&nonce_prefix, index, last)?,
                Aad::empty(),
                &mut sealed,
            )
            .map_err(|_| BackupError::Integrity("backup decrypt failed".to_string()))?;
        out.extend_from_slice(plain);
        cursor += cipher_len;
        index = index
            .checked_add(1)
            .ok_or_else(|| BackupError::Integrity("too many chunks".to_string()))?;
    }
    Ok(out)
}

fn derive_key_material(passphrase: &str, salt: &[u8]) -> Result<[u8; 64], BackupError> {
    if passphrase.is_empty() {
        return Err(BackupError::InvalidRequest(
            "backup passphrase must not be empty".to_string(),
        ));
    }
    let mut argon_out = [0_u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut argon_out)
        .map_err(|error| BackupError::Crypto(format!("argon2id failed: {}", error)))?;
    let digest = Sha512::digest(argon_out);
    argon_out.fill(0);
    let mut out = [0_u8; 64];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn make_aead_key(bytes: &[u8]) -> Result<LessSafeKey, BackupError> {
    let unbound = UnboundKey::new(&AES_256_GCM, bytes)
        .map_err(|_| BackupError::Crypto("invalid AES-256-GCM key".to_string()))?;
    Ok(LessSafeKey::new(unbound))
}

fn make_nonce(prefix: &[u8; NONCE_PREFIX_BYTES], index: u32, last: bool) -> Nonce {
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_BYTES..NONCE_PREFIX_BYTES + 4].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_BYTES - 1] = u8::from(last);
    Nonce::assume_unique_for_key(nonce)
}

fn make_nonce_slice(prefix: &[u8], index: u32, last: bool) -> Result<Nonce, BackupError> {
    let prefix: &[u8; NONCE_PREFIX_BYTES] = prefix
        .try_into()
        .map_err(|_| BackupError::Integrity("invalid nonce prefix".to_string()))?;
    Ok(make_nonce(prefix, index, last))
}
