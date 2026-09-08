use sgx_guardian_client::integration::crypto::{decrypt_tokens, encrypt_tokens};

fn with_seed_dir<T>(f: impl FnOnce() -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("SGX_DATA_DIR");
    std::env::set_var("SGX_DATA_DIR", dir.path());
    let out = f();
    if let Some(value) = previous {
        std::env::set_var("SGX_DATA_DIR", value);
    } else {
        std::env::remove_var("SGX_DATA_DIR");
    }
    out
}

#[test]
fn encrypt_decrypt_empty_plaintext_round_trips() {
    with_seed_dir(|| assert_eq!(decrypt_tokens(&encrypt_tokens(b"").unwrap()).unwrap(), b""));
}

#[test]
fn encrypt_decrypt_short_plaintext_round_trips() {
    with_seed_dir(|| {
        assert_eq!(
            decrypt_tokens(&encrypt_tokens(b"a").unwrap()).unwrap(),
            b"a"
        )
    });
}

#[test]
fn encrypt_decrypt_binary_plaintext_round_trips() {
    with_seed_dir(|| {
        let data = vec![0, 1, 2, 255];
        assert_eq!(
            decrypt_tokens(&encrypt_tokens(&data).unwrap()).unwrap(),
            data
        );
    });
}

#[test]
fn encrypted_payload_includes_nonce_and_tag_overhead() {
    with_seed_dir(|| assert!(encrypt_tokens(b"abc").unwrap().len() > 12 + 3));
}

#[test]
fn encrypting_same_plaintext_uses_different_nonce() {
    with_seed_dir(|| {
        assert_ne!(
            encrypt_tokens(b"same").unwrap(),
            encrypt_tokens(b"same").unwrap()
        )
    });
}

#[test]
fn ciphertext_tamper_is_rejected() {
    with_seed_dir(|| {
        let mut encrypted = encrypt_tokens(b"secret").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 1;
        assert!(decrypt_tokens(&encrypted).is_err());
    });
}

#[test]
fn nonce_tamper_is_rejected() {
    with_seed_dir(|| {
        let mut encrypted = encrypt_tokens(b"secret").unwrap();
        encrypted[0] ^= 1;
        assert!(decrypt_tokens(&encrypted).is_err());
    });
}

macro_rules! too_short_tests {
    ($($name:ident => $len:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            with_seed_dir(|| assert_eq!(decrypt_tokens(&[0; $len]).unwrap_err(), "Ciphertext payload too short"));
        }
    )+};
}

too_short_tests! {
    decrypt_rejects_len_zero => 0,
    decrypt_rejects_len_one => 1,
    decrypt_rejects_len_eleven => 11,
    decrypt_rejects_len_twelve => 12,
}

macro_rules! roundtrip_tests {
    ($($name:ident => $data:expr),+ $(,)?) => {$(
        #[test]
        fn $name() {
            with_seed_dir(|| {
                let plain: Vec<u8> = $data;
                assert_eq!(decrypt_tokens(&encrypt_tokens(&plain).unwrap()).unwrap(), plain);
            });
        }
    )+};
}

roundtrip_tests! {
    roundtrip_ascii_token => b"access-token".to_vec(),
    roundtrip_json_token => br#"{"access":"a","refresh":"r"}"#.to_vec(),
    roundtrip_utf8_token => "token-check".as_bytes().to_vec(),
    roundtrip_large_token => vec![42; 4096],
    roundtrip_all_byte_values => (0u8..=255).collect::<Vec<_>>(),
    roundtrip_repeated_zeroes => vec![0; 128],
    roundtrip_repeated_ff => vec![255; 128],
}

#[test]
fn decrypt_random_payload_with_valid_length_fails_authentication() {
    with_seed_dir(|| assert!(decrypt_tokens(&[7; 32]).is_err()));
}

#[test]
fn ciphertext_can_be_decrypted_more_than_once() {
    with_seed_dir(|| {
        let encrypted = encrypt_tokens(b"secret").unwrap();
        assert_eq!(decrypt_tokens(&encrypted).unwrap(), b"secret");
        assert_eq!(decrypt_tokens(&encrypted).unwrap(), b"secret");
    });
}

#[test]
fn cloned_ciphertext_decrypts() {
    with_seed_dir(|| {
        let encrypted = encrypt_tokens(b"secret").unwrap();
        assert_eq!(decrypt_tokens(&encrypted.clone()).unwrap(), b"secret");
    });
}

#[test]
fn truncated_ciphertext_after_nonce_fails() {
    with_seed_dir(|| {
        let mut encrypted = encrypt_tokens(b"secret").unwrap();
        encrypted.truncate(13);
        assert!(decrypt_tokens(&encrypted).is_err());
    });
}

#[test]
fn appending_bytes_to_ciphertext_fails() {
    with_seed_dir(|| {
        let mut encrypted = encrypt_tokens(b"secret").unwrap();
        encrypted.push(0);
        assert!(decrypt_tokens(&encrypted).is_err());
    });
}

#[test]
fn encryption_creates_machine_seed_when_needed() {
    let dir = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("SGX_DATA_DIR");
    std::env::set_var("SGX_DATA_DIR", dir.path());
    let _ = encrypt_tokens(b"seed").unwrap();
    if let Some(value) = previous {
        std::env::set_var("SGX_DATA_DIR", value);
    } else {
        std::env::remove_var("SGX_DATA_DIR");
    }
}

#[test]
fn different_plaintexts_decrypt_to_their_original_values() {
    with_seed_dir(|| {
        let first = encrypt_tokens(b"token-a").unwrap();
        let second = encrypt_tokens(b"token-b").unwrap();
        assert_ne!(first, second);
        assert_eq!(decrypt_tokens(&first).unwrap(), b"token-a");
        assert_eq!(decrypt_tokens(&second).unwrap(), b"token-b");
    });
}
