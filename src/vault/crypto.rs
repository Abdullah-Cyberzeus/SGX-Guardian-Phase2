use crate::vault::errors::VaultError;
use crate::vault::ingest::IngestMeta;
use crate::vault::model::{EncMeta, VaultRecord};
use crate::vault::wrapper::KeyWrapper;
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use sha2::{Digest, Sha256};
use std::io::{BufReader, BufWriter, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const NONCE_PREFIX_BYTES: usize = 7;
const NONCE_BYTES: usize = 12;
const LENGTH_PREFIX_BYTES: usize = 4;
const GCM_TAG_BYTES: usize = 16;

#[derive(Debug, Clone)]
pub struct EncryptOutcome {
    pub size_cipher: u64,
    pub enc: EncMeta,
}

fn expected_chunk_count(size_plain: u64, chunk_bytes: u32) -> u32 {
    if size_plain == 0 {
        0
    } else {
        size_plain.div_ceil(chunk_bytes as u64) as u32
    }
}

fn expected_plain_len(size_plain: u64, chunk_bytes: u32, index: u32, chunk_count: u32) -> usize {
    if chunk_count == 0 {
        return 0;
    }
    let standard = chunk_bytes as u64;
    let remainder = size_plain % standard;
    let is_last = index + 1 == chunk_count;
    let len = if is_last && remainder != 0 {
        remainder
    } else {
        standard
    };
    len as usize
}

fn make_nonce(prefix: &[u8; NONCE_PREFIX_BYTES], index: u32, last: bool) -> Nonce {
    let mut nonce = [0_u8; NONCE_BYTES];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_BYTES..NONCE_PREFIX_BYTES + 4].copy_from_slice(&index.to_be_bytes());
    nonce[NONCE_BYTES - 1] = u8::from(last);
    Nonce::assume_unique_for_key(nonce)
}

fn make_key(bytes: &[u8; 32]) -> Result<LessSafeKey, VaultError> {
    let key = UnboundKey::new(&AES_256_GCM, bytes)
        .map_err(|_| VaultError::Crypto("invalid AES-256-GCM key".to_string()))?;
    Ok(LessSafeKey::new(key))
}

fn create_plaintext_output(path: &Path) -> Result<std::fs::File, VaultError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path)?;
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

pub fn encrypt_file(
    input_path: &Path,
    output_path: &Path,
    meta: &IngestMeta,
    wrapper: &impl KeyWrapper,
) -> Result<EncryptOutcome, VaultError> {
    let input = std::fs::File::open(input_path)?;
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Err(VaultError::InvalidStructure(format!(
            "path is not a regular file: {}",
            input_path.display()
        )));
    }

    let chunk_count = expected_chunk_count(meta.size_plain, meta.chunk_bytes);
    if metadata.len() != meta.size_plain {
        return Err(VaultError::Conflict(format!(
            "expected plaintext size {} but found {}",
            meta.size_plain,
            metadata.len()
        )));
    }

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let output = std::fs::File::create(output_path)?;

    let mut dek = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut dek);
    let key = make_key(&dek)?;
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce_prefix);

    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut hasher = Sha256::new();
    let mut total_plain = 0_u64;
    let mut total_cipher = 0_u64;

    for index in 0..chunk_count {
        let expected_len =
            expected_plain_len(meta.size_plain, meta.chunk_bytes, index, chunk_count);
        let mut chunk = vec![0_u8; expected_len];
        if expected_len > 0 {
            reader.read_exact(&mut chunk)?;
        }
        total_plain += expected_len as u64;
        hasher.update(&chunk);

        let nonce = make_nonce(&nonce_prefix, index, index + 1 == chunk_count);
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut chunk)
            .map_err(|_| VaultError::Crypto("chunk encryption failed".to_string()))?;

        let len = u32::try_from(chunk.len()).map_err(|_| {
            VaultError::InvalidStructure(format!(
                "encrypted chunk {} too large: {}",
                index,
                chunk.len()
            ))
        })?;
        writer.write_all(&len.to_be_bytes())?;
        writer.write_all(&chunk)?;
        total_cipher += LENGTH_PREFIX_BYTES as u64 + chunk.len() as u64;
    }

    let mut probe = [0_u8; 1];
    if reader.read(&mut probe)? != 0 {
        return Err(VaultError::Conflict(
            "plaintext file contains trailing bytes after expected size".to_string(),
        ));
    }

    if total_plain != meta.size_plain {
        return Err(VaultError::Conflict(format!(
            "encrypted plaintext bytes {} did not match expected {}",
            total_plain, meta.size_plain
        )));
    }

    let actual_sha = hex::encode(hasher.finalize());
    if actual_sha != meta.sha256_plain {
        return Err(VaultError::Integrity {
            expected: meta.sha256_plain.clone(),
            got: actual_sha,
        });
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;

    let wrapped_dek = wrapper.wrap(&dek)?;
    Ok(EncryptOutcome {
        size_cipher: total_cipher,
        enc: EncMeta {
            algo: "AES-256-GCM/STREAM-BE32".to_string(),
            chunk_bytes: meta.chunk_bytes,
            base_nonce_b64: general_purpose::STANDARD.encode(nonce_prefix),
            wrapped_dek_b64: general_purpose::STANDARD.encode(wrapped_dek),
            wrap_scheme: wrapper.scheme().to_string(),
            wrap_key_id: wrapper.key_id(),
        },
    })
}

pub fn decrypt_file(
    input_path: &Path,
    output_path: &Path,
    record: &VaultRecord,
    wrapper: &impl KeyWrapper,
) -> Result<(), VaultError> {
    if record.enc.algo != "AES-256-GCM/STREAM-BE32" {
        return Err(VaultError::InvalidStructure(format!(
            "unsupported encryption algorithm '{}'",
            record.enc.algo
        )));
    }

    if record.enc.wrap_scheme != wrapper.scheme() {
        return Err(VaultError::InvalidStructure(format!(
            "wrap scheme mismatch: record={}, wrapper={}",
            record.enc.wrap_scheme,
            wrapper.scheme()
        )));
    }
    let wrapper_key_id = wrapper.key_id();
    if record.enc.wrap_key_id != wrapper_key_id {
        return Err(VaultError::InvalidStructure(format!(
            "wrap key id mismatch: record={}, wrapper={}",
            record.enc.wrap_key_id, wrapper_key_id
        )));
    }

    let wrapped_dek = general_purpose::STANDARD.decode(&record.enc.wrapped_dek_b64)?;
    let dek = wrapper.unwrap(&wrapped_dek)?;
    let key = make_key(&dek)?;

    let prefix = general_purpose::STANDARD.decode(&record.enc.base_nonce_b64)?;
    if prefix.len() != NONCE_PREFIX_BYTES {
        return Err(VaultError::InvalidStructure(format!(
            "base nonce must be {} bytes, got {}",
            NONCE_PREFIX_BYTES,
            prefix.len()
        )));
    }
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_BYTES];
    nonce_prefix.copy_from_slice(&prefix);

    let chunk_count = expected_chunk_count(record.size_plain, record.enc.chunk_bytes);

    let input = std::fs::File::open(input_path)?;
    let output = create_plaintext_output(output_path)?;

    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut hasher = Sha256::new();
    let mut total_plain = 0_u64;

    for index in 0..chunk_count {
        let mut len_bytes = [0_u8; LENGTH_PREFIX_BYTES];
        reader.read_exact(&mut len_bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                VaultError::InvalidStructure(format!("truncated chunk header at index {}", index))
            } else {
                error.into()
            }
        })?;
        let cipher_len = u32::from_be_bytes(len_bytes) as usize;
        if cipher_len < GCM_TAG_BYTES {
            return Err(VaultError::InvalidStructure(format!(
                "ciphertext chunk {} too short: {}",
                index, cipher_len
            )));
        }

        let mut sealed = vec![0_u8; cipher_len];
        reader.read_exact(&mut sealed).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                VaultError::InvalidStructure(format!("truncated ciphertext at index {}", index))
            } else {
                error.into()
            }
        })?;

        let nonce = make_nonce(&nonce_prefix, index, index + 1 == chunk_count);
        let plain = key
            .open_in_place(nonce, Aad::empty(), &mut sealed)
            .map_err(|_| VaultError::Crypto(format!("chunk {} authentication failed", index)))?;

        let expected_len = expected_plain_len(
            record.size_plain,
            record.enc.chunk_bytes,
            index,
            chunk_count,
        );
        if plain.len() != expected_len {
            return Err(VaultError::InvalidStructure(format!(
                "chunk {} plaintext length mismatch: expected {}, got {}",
                index,
                expected_len,
                plain.len()
            )));
        }

        if !plain.is_empty() {
            writer.write_all(plain)?;
        }
        hasher.update(&*plain);
        total_plain += plain.len() as u64;
    }

    let mut probe = [0_u8; 1];
    if reader.read(&mut probe)? != 0 {
        return Err(VaultError::InvalidStructure(
            "ciphertext contains trailing bytes".to_string(),
        ));
    }

    if total_plain != record.size_plain {
        return Err(VaultError::Conflict(format!(
            "decrypted {} bytes but record expected {}",
            total_plain, record.size_plain
        )));
    }

    let actual_sha = hex::encode(hasher.finalize());
    if actual_sha != record.sha256_plain {
        return Err(VaultError::Integrity {
            expected: record.sha256_plain.clone(),
            got: actual_sha,
        });
    }

    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    struct MockKeyWrapper;

    impl KeyWrapper for MockKeyWrapper {
        fn scheme(&self) -> &'static str {
            "mock-wrapper"
        }
        fn key_id(&self) -> String {
            "mock-key-1".to_string()
        }
        fn wrap(&self, dek: &[u8; 32]) -> Result<Vec<u8>, VaultError> {
            Ok(dek.to_vec())
        }
        fn unwrap(&self, wrapped: &[u8]) -> Result<[u8; 32], VaultError> {
            if wrapped.len() != 32 {
                return Err(VaultError::Crypto("invalid wrapped key length".into()));
            }
            let mut key = [0_u8; 32];
            key.copy_from_slice(wrapped);
            Ok(key)
        }
    }

    #[test]
    fn test_expected_chunk_count_and_len() {
        assert_eq!(expected_chunk_count(0, 1024), 0);
        assert_eq!(expected_chunk_count(500, 1024), 1);
        assert_eq!(expected_chunk_count(1024, 1024), 1);
        assert_eq!(expected_chunk_count(1025, 1024), 2);
        assert_eq!(expected_chunk_count(2048, 1024), 2);

        // 2500 bytes with 1000-byte chunks -> 3 chunks
        assert_eq!(expected_plain_len(2500, 1000, 0, 3), 1000);
        assert_eq!(expected_plain_len(2500, 1000, 1, 3), 1000);
        assert_eq!(expected_plain_len(2500, 1000, 2, 3), 500);
    }

    #[test]
    fn test_make_key_validates_aes256() {
        let key_bytes = [0x42_u8; 32];
        let key = make_key(&key_bytes);
        assert!(key.is_ok());
    }

    #[test]
    fn test_encrypt_and_decrypt_file_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let input_file = dir.path().join("plain.txt");
        let cipher_file = dir.path().join("cipher.bin");
        let output_file = dir.path().join("decrypted.txt");

        let original_data = b"Guardian Secure Vault Payload: Hello World 2026!";
        std::fs::write(&input_file, original_data).unwrap();

        let sha256_plain = hex::encode(Sha256::digest(original_data));
        let ingest_meta = IngestMeta {
            filename: "plain.txt".into(),
            mime: "text/plain".into(),
            sha256_plain: sha256_plain.clone(),
            size_plain: original_data.len() as u64,
            chunk_bytes: 16, // small chunk to force multi-chunk encryption
        };

        let wrapper = MockKeyWrapper;
        let outcome = encrypt_file(&input_file, &cipher_file, &ingest_meta, &wrapper)
            .expect("encrypt file");

        assert!(cipher_file.exists());
        assert_eq!(outcome.enc.chunk_bytes, 16);
        assert_eq!(outcome.enc.wrap_scheme, "mock-wrapper");

        let record = VaultRecord {
            vault_id: "v-test-1".into(),
            namespace: "personal".into(),
            circle_id: "".into(),
            filename: "plain.txt".into(),
            mime: "text/plain".into(),
            size_plain: original_data.len() as u64,
            size_cipher: outcome.size_cipher,
            sha256_plain,
            sender_did: "did:guardian:uploader".into(),
            received_at: "2026-08-27T00:00:00Z".into(),
            source: crate::vault::model::VaultSource::Upload,
            folder_id: "f1".into(),
            starred: false,
            description: "Test upload".into(),
            owner_did: "did:guardian:owner".into(),
            revoked: false,
            revoked_at: None,
            expires_at: None,
            conversation_recipient_did: None,
            message_id: None,
            enc: outcome.enc,
        };

        decrypt_file(&cipher_file, &output_file, &record, &wrapper).expect("decrypt file");

        let decrypted_data = std::fs::read(&output_file).unwrap();
        assert_eq!(decrypted_data, original_data);
    }
}

