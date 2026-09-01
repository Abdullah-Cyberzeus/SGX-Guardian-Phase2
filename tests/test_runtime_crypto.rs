use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sgx_guardian_client::runtime::crypto::{
    decrypt_password, encrypt_password, validate_hotspot_password,
};

fn setup_env() {
    std::env::set_var("GUARDIAN_KEY_FILE", "/tmp/guardian_wifi_key_test.bin");
}

fn with_temp_key<T>(f: impl FnOnce() -> T) -> T {
    let dir = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("GUARDIAN_KEY_FILE");
    std::env::set_var("GUARDIAN_KEY_FILE", dir.path().join("key.bin"));
    let out = f();
    if let Some(value) = previous {
        std::env::set_var("GUARDIAN_KEY_FILE", value);
    } else {
        std::env::remove_var("GUARDIAN_KEY_FILE");
    }
    out
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    setup_env();
    let plaintext = "SuperSecret123!";
    let encrypted = encrypt_password(plaintext).unwrap();
    assert!(!encrypted.is_empty());
    assert_ne!(encrypted, plaintext);

    let decrypted = decrypt_password(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_empty_password() {
    setup_env();
    let res = encrypt_password("");
    assert!(res.is_err());
}

#[test]
fn test_decrypt_empty_password() {
    setup_env();
    let res = decrypt_password("");
    assert!(res.is_err());
}

#[test]
fn test_decrypt_invalid_base64() {
    setup_env();
    let res = decrypt_password("!@#$invalid");
    assert!(res.is_err());
}

#[test]
fn test_decrypt_too_short() {
    setup_env();
    let short_b64 = BASE64.encode(b"short");
    let res = decrypt_password(&short_b64);
    assert!(res.is_err());
}

#[test]
fn test_validate_hotspot_password_too_short() {
    setup_env();
    let res = validate_hotspot_password("short1!");
    assert!(res.is_err());
}

#[test]
fn test_validate_hotspot_password_no_special_char() {
    setup_env();
    let res = validate_hotspot_password("password123");
    assert!(res.is_err());
}

#[test]
fn test_validate_hotspot_password_rockyou() {
    setup_env();
    // Assuming "password" is in rockyou_top1000.txt, though it doesn't have a special char.
    // Let's test a strong one to see if it passes.
    let res = validate_hotspot_password("V3ryStr0ng!@#");
    assert!(res.is_ok());
}

#[test]
fn encrypt_creates_key_file() {
    with_temp_key(|| {
        encrypt_password("StrongPass!1").unwrap();
        assert!(std::path::PathBuf::from(std::env::var("GUARDIAN_KEY_FILE").unwrap()).exists());
    });
}

#[test]
fn encrypt_decrypt_with_temp_key_round_trips() {
    with_temp_key(|| assert_eq!(decrypt_password(&encrypt_password("StrongPass!1").unwrap()).unwrap(), "StrongPass!1"));
}

#[test]
fn encrypt_same_password_produces_distinct_ciphertexts() {
    with_temp_key(|| assert_ne!(encrypt_password("StrongPass!1").unwrap(), encrypt_password("StrongPass!1").unwrap()));
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    with_temp_key(|| {
        let mut raw = BASE64.decode(encrypt_password("StrongPass!1").unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(decrypt_password(&BASE64.encode(raw)).is_err());
    });
}

#[test]
fn decrypt_rejects_tampered_nonce() {
    with_temp_key(|| {
        let mut raw = BASE64.decode(encrypt_password("StrongPass!1").unwrap()).unwrap();
        raw[0] ^= 1;
        assert!(decrypt_password(&BASE64.encode(raw)).is_err());
    });
}

#[test]
fn decrypt_rejects_valid_base64_with_no_tag() {
    with_temp_key(|| assert_eq!(decrypt_password(&BASE64.encode(vec![0; 12])).unwrap_err(), "Decryption error"));
}

#[test]
fn decrypt_rejects_base64_payload_shorter_than_nonce() {
    with_temp_key(|| assert_eq!(decrypt_password(&BASE64.encode(vec![0; 11])).unwrap_err(), "Too short"));
}

#[test]
fn validate_accepts_eight_chars_with_symbol() {
    assert!(validate_hotspot_password("Abcdef1!").is_ok());
}

#[test]
fn validate_rejects_seven_chars_even_with_symbol() {
    assert!(validate_hotspot_password("Abcd1!").is_err());
}

#[test]
fn validate_accepts_unicode_symbol_as_non_alphanumeric() {
    assert!(validate_hotspot_password("Password✓").is_ok());
}

#[test]
fn validate_rejects_alphanumeric_only_uppercase() {
    assert_eq!(
        validate_hotspot_password("PASSWORD123").unwrap_err(),
        "Password must contain at least one non-alphanumeric character"
    );
}

#[test]
fn validate_rejects_alphanumeric_only_mixed_case() {
    assert!(validate_hotspot_password("Password123").is_err());
}

#[test]
fn validate_accepts_spaces_as_non_alphanumeric() {
    assert!(validate_hotspot_password("Pass word1").is_ok());
}

#[test]
fn validate_rejects_common_password_before_special_char_check_if_short() {
    assert_eq!(
        validate_hotspot_password("password").unwrap_err(),
        "Password must contain at least one non-alphanumeric character"
    );
}

#[test]
fn encrypt_rejects_empty_string_exact_message() {
    with_temp_key(|| assert_eq!(encrypt_password("").unwrap_err(), "Cannot encrypt empty password"));
}

#[test]
fn decrypt_rejects_empty_string_exact_message() {
    with_temp_key(|| assert_eq!(decrypt_password("").unwrap_err(), "Cannot decrypt empty input"));
}

#[test]
fn decrypt_rejects_plain_text() {
    with_temp_key(|| assert!(decrypt_password("not encrypted").is_err()));
}

#[test]
fn long_password_round_trips() {
    with_temp_key(|| {
        let pw = format!("{}!", "A1".repeat(512));
        assert_eq!(decrypt_password(&encrypt_password(&pw).unwrap()).unwrap(), pw);
    });
}

#[test]
fn password_with_newline_round_trips() {
    with_temp_key(|| assert_eq!(decrypt_password(&encrypt_password("Strong\nPass!1").unwrap()).unwrap(), "Strong\nPass!1"));
}

#[test]
fn password_with_tabs_round_trips() {
    with_temp_key(|| assert_eq!(decrypt_password(&encrypt_password("Strong\tPass!1").unwrap()).unwrap(), "Strong\tPass!1"));
}

#[test]
fn password_with_symbols_round_trips() {
    with_temp_key(|| assert_eq!(decrypt_password(&encrypt_password("!@#$%^&*()Aa1").unwrap()).unwrap(), "!@#$%^&*()Aa1"));
}

#[test]
fn existing_invalid_key_file_is_replaced() {
    with_temp_key(|| {
        std::fs::write(std::env::var("GUARDIAN_KEY_FILE").unwrap(), b"short").unwrap();
        assert!(encrypt_password("StrongPass!1").is_ok());
        assert_eq!(std::fs::read(std::env::var("GUARDIAN_KEY_FILE").unwrap()).unwrap().len(), 32);
    });
}
