use sgx_guardian_client::policy_authority::PaKey;

// ─── PaKey ───────────────────────────────────────────────────

#[test]
fn test_pa_key_load_or_generate() {
    // This writes to /etc/sgx-guardian/policies — guard with writable check
    let writable = {
        let test_file = "/etc/sgx-guardian/policies/dummy_pa_test.txt";
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/policies");
        if std::fs::write(test_file, "").is_ok() {
            let _ = std::fs::remove_file(test_file);
            true
        } else {
            false
        }
    };

    if writable {
        let result = PaKey::load_or_generate();
        assert!(result.is_ok(), "PA key gen failed: {:?}", result.err());

        let pa = result.unwrap();
        let pubkey = pa.pubkey_der();
        // P256 uncompressed point = 65 bytes
        assert_eq!(pubkey.len(), 65, "P256 pubkey should be 65 bytes, got {}", pubkey.len());
        // First byte of uncompressed P256 point is 0x04
        assert_eq!(pubkey[0], 0x04, "P256 uncompressed point should start with 0x04");
    }
}

#[test]
fn test_pa_key_idempotent_reload() {
    let writable = {
        let test_file = "/etc/sgx-guardian/policies/dummy_pa_test2.txt";
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/policies");
        if std::fs::write(test_file, "").is_ok() {
            let _ = std::fs::remove_file(test_file);
            true
        } else {
            false
        }
    };

    if writable {
        let pa1 = PaKey::load_or_generate().unwrap();
        let pa2 = PaKey::load_or_generate().unwrap();

        // Both loads should return the same public key
        assert_eq!(
            pa1.pubkey_der(),
            pa2.pubkey_der(),
            "Idempotent reload should return same pubkey"
        );
    }
}

#[test]
fn test_pa_sign_policy_to_disk() {
    let writable = {
        let test_file = "/etc/sgx-guardian/policies/dummy_pa_test3.txt";
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/policies");
        if std::fs::write(test_file, "").is_ok() {
            let _ = std::fs::remove_file(test_file);
            true
        } else {
            false
        }
    };

    if writable {
        let pa = PaKey::load_or_generate().unwrap();

        // Create a temp YAML policy
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "version: 1\nrules:\n  - allow: all\n").unwrap();

        let result = pa.sign_policy_to_disk(tmp.path().to_str().unwrap());
        assert!(result.is_ok(), "sign_policy_to_disk failed: {:?}", result.err());

        let digest_hex = result.unwrap();
        assert_eq!(digest_hex.len(), 64, "SHA-256 hex digest should be 64 chars");

        // Verify policy.sig was written
        let sig_path = "/etc/sgx-guardian/policies/policy.sig";
        assert!(std::path::Path::new(sig_path).exists(), "policy.sig not written");

        let envelope = std::fs::read_to_string(sig_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&envelope).unwrap();
        assert_eq!(parsed["version"], 1);
        assert!(parsed["policy_b64"].as_str().unwrap().len() > 0);
        assert!(parsed["signature_b64"].as_str().unwrap().len() > 0);
        assert!(parsed["signing_pubkey_b64"].as_str().unwrap().len() > 0);
        assert_eq!(parsed["digest_hex"].as_str().unwrap(), digest_hex);
    }
}

#[test]
fn test_pa_sign_policy_missing_yaml() {
    let writable = {
        let test_file = "/etc/sgx-guardian/policies/dummy_pa_test4.txt";
        let _ = std::fs::create_dir_all("/etc/sgx-guardian/policies");
        if std::fs::write(test_file, "").is_ok() {
            let _ = std::fs::remove_file(test_file);
            true
        } else {
            false
        }
    };

    if writable {
        let pa = PaKey::load_or_generate().unwrap();
        let result = pa.sign_policy_to_disk("/tmp/nonexistent_policy_12345.yaml");
        assert!(result.is_err(), "sign of non-existent YAML should fail");
    }
}
