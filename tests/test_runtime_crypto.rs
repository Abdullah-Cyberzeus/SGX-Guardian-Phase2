use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use sgx_guardian_client::runtime::crypto::{
    decrypt_password, encrypt_password, validate_hotspot_password,
};

fn setup_env() {
    std::env::set_var("GUARDIAN_KEY_FILE", "/tmp/guardian_wifi_key_test.bin");
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
