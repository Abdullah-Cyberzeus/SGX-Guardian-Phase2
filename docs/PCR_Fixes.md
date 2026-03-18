# PCR Improvements — Codex/GPT Review Fixes
**Only the fixes. The rest of the PCR plan is already implemented.**




## Cross-Check Results

| # | Issue | Codex | GPT | My Verdict | Priority |
|---|-------|-------|-----|-----------|----------|
| 1 | Missing `sha2::Digest` import in main.rs | ✅ Valid | ✅ Valid | ✅ **VALID** — compile error | HIGH |
| 2 | `cargo build --bin sgx-pa-cli` workspace issue | ✅ Valid | ✅ Valid | ⚠️ **MINOR** — use `-p sgx-pa-cli` | LOW |
| 3 | AttestationEvidence new fields break tests | ✅ Valid | ✅ Valid | ✅ **VALID** — struct literal break | HIGH |
| 4 | Baseline signature reuses snapshot signature (WRONG) | ✅ Valid | ✅ Valid | ✅ **VALID — CRITICAL BUG** | CRITICAL |
| 5 | Board testing not executable locally | ✅ Valid | ✅ Valid | Expected — not a code issue | IGNORE |
| 6 | File ownership issue | ✅ Valid | ✅ Valid | Environment — not a code issue | IGNORE |

**3 real fixes needed. The rest are environment issues.**




---




## FIX 1: Missing `sha2::Digest` Import in main.rs

In the PCR measurement block in `src/main.rs`, `sha2::Sha256::digest()` is called but `Digest` trait isn't in scope.

**Find** in main.rs (near the PCR block):
```rust
        let sign_hash = sha2::Sha256::digest(&sign_input);
```

**The `Digest` trait must be imported.** Add at the top of the PCR block:

```rust
    // === PCR Measurement (ATT-003) ===
    println!("\n  Measuring platform integrity (PCR)...");
    {
        use sgx_guardian_client::secure_element::pcr::*;
        use sgx_guardian_client::secure_element::pcr_config;
        use sha2::Digest;  // ← ADD THIS LINE
```

Alternatively, use the fully qualified call without the import:

```rust
        let sign_hash = <sha2::Sha256 as sha2::Digest>::digest(&sign_input);
```

**Simpler approach:** Just add `use sha2::Digest;` inside the block. This is the cleanest fix.




---




## FIX 2: cargo build for sgx-pa-cli

Our `Cargo.toml` has:
```toml
[workspace]
members = ["sgx-pa-cli"]
```

The correct command from the workspace root is:

```bash
# Either of these work:
cargo build -p sgx-pa-cli
# OR
cargo build --bin sgx-pa-cli
```

If `--bin` doesn't work in your environment, use `-p`. This is not a code fix, just a command fix. Update your workflow to use:

```bash
cargo build -p sgx-pa-cli
```




---




## FIX 3: AttestationEvidence New Fields Break Existing Tests

The current `AttestationEvidence` struct had 4 fields. We added `pcr_values` and `key_version`. ALL test code that creates `AttestationEvidence` with struct literals now fails to compile.

**Affected files:**
- `src/attestation_service.rs` (internal test `make_test_evidence`)
- `tests/test_attestation.rs` (integration test `make_evidence`)

### Fix in `src/attestation_service.rs` — internal test helper

Find `make_test_evidence` function (in `#[cfg(test)]` block). It returns:

```rust
        AttestationEvidence {
            nonce: nonce.to_string(),
            policy_digest,
            signature: general_purpose::STANDARD.encode(sig_der.as_bytes()),
            pubkey_der_b64: general_purpose::STANDARD.encode(spki),
        }
```

**REPLACE with:**

```rust
        AttestationEvidence {
            nonce: nonce.to_string(),
            policy_digest,
            signature: general_purpose::STANDARD.encode(sig_der.as_bytes()),
            pubkey_der_b64: general_purpose::STANDARD.encode(spki),
            pcr_values: None,
            key_version: None,
        }
```


### Fix in `tests/test_attestation.rs` — integration test helper

Find `make_evidence` function. It returns:

```rust
    AttestationEvidence {
        nonce: nonce.to_string(),
        policy_digest: digest,
        signature: general_purpose::STANDARD.encode(sig_der.as_bytes()),
        pubkey_der_b64: general_purpose::STANDARD.encode(pubkey_bytes),
    }
```

**REPLACE with:**

```rust
    AttestationEvidence {
        nonce: nonce.to_string(),
        policy_digest: digest,
        signature: general_purpose::STANDARD.encode(sig_der.as_bytes()),
        pubkey_der_b64: general_purpose::STANDARD.encode(pubkey_bytes),
        pcr_values: None,
        key_version: None,
    }
```

### Also update `create_signed_evidence()` in attestation_service.rs

The actual production code also needs the new fields. Find the return in `create_signed_evidence()`:

```rust
        Ok(AttestationEvidence {
            nonce,
            policy_digest,
            signature: signature_b64,
            pubkey_der_b64: pubkey_b64,
        })
```

**REPLACE with:**

```rust
        // Load PCR snapshot if available
        let pcr_values = crate::secure_element::pcr::PcrSnapshot::load(
            "/var/lib/sgx-guardian/pcr/current.json"
        ).ok();

        // Read DKP key version
        let key_version = Some(crate::secure_element::pcr::read_dkp_key_version());

        Ok(AttestationEvidence {
            nonce,
            policy_digest,
            signature: signature_b64,
            pubkey_der_b64: pubkey_b64,
            pcr_values,
            key_version,
        })
```

### Also check the serialization roundtrip test

In `tests/test_attestation.rs`, find `test_attestation_evidence_serialization_roundtrip`:

```rust
    assert_eq!(original.nonce, deserialized.nonce);
    assert_eq!(original.policy_digest, deserialized.policy_digest);
    assert_eq!(original.signature, deserialized.signature);
    assert_eq!(original.pubkey_der_b64, deserialized.pubkey_der_b64);
```

This test is fine because we used `#[serde(skip_serializing_if = "Option::is_none")]` — the `None` fields just won't appear in JSON, and deserialization will set them to `None` via `Option` default. No change needed here IF the struct derives `Default` for the new fields. Since they're `Option`, serde handles them automatically.

**But verify:** the `AttestationEvidence` struct definition must have the new fields as `Option`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub nonce: String,
    pub policy_digest: String,
    pub signature: String,
    pub pubkey_der_b64: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pcr_values: Option<crate::secure_element::pcr::PcrSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_version: Option<u32>,
}
```

The `default` attribute ensures old JSON without these fields deserializes correctly (sets to `None`).




---




## FIX 4: Baseline Signature Logic — CRITICAL BUG

This is the most important fix. The `pcr_baseline.rs` CLI command copies the snapshot's `composite_signature` directly as the baseline signature. But:

- **Snapshot signature signs:** `SHA256(composite_bytes || nonce_bytes || timestamp_bytes)`
- **Baseline verification expects:** `SHA256(composite_bytes || created_at_bytes || device_uid_bytes)`

These are DIFFERENT inputs. The baseline signature would ALWAYS fail verification.

### The Problem (in `sgx-pa-cli/src/commands/pcr_baseline.rs` `run_create()`)

```rust
    let baseline = serde_json::json!({
        "baseline_signature": snap["composite_signature"],  // ← WRONG: this is snapshot sig
        ...
    });
```

### The Fix

The CLI must **create a NEW signature** specifically for the baseline, signing the correct inputs. Since the CLI doesn't have access to `KeyManager`, it needs to call `ssscli` or read the software key.

**Replace the entire `run_create()` function:**

```rust
pub fn run_create() {
    println!("=== Create PCR Golden Baseline ===\n");

    if !Path::new(PCR_PATH).exists() {
        eprintln!("No PCR snapshot. Run guardian daemon first.");
        return;
    }

    let json = match fs::read_to_string(PCR_PATH) {
        Ok(j) => j,
        Err(e) => { eprintln!("Read error: {}", e); return; }
    };
    let snap: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => { eprintln!("Parse error: {}", e); return; }
    };

    let composite = snap["composite_digest"].as_str().unwrap_or("").to_string();
    let device_uid = snap["device_uid"].as_str().unwrap_or("unknown").to_string();
    let key_version = snap["key_version"].as_u64().unwrap_or(1) as u32;
    let created_at = chrono::Utc::now().to_rfc3339();

    // Build the signing input (MUST match what PcrBaseline::verify_signature expects)
    let composite_bytes = hex::decode(&composite).unwrap_or_else(|_| vec![0u8; 32]);
    let mut sign_input = Vec::new();
    sign_input.extend_from_slice(&composite_bytes);
    sign_input.extend_from_slice(created_at.as_bytes());
    sign_input.extend_from_slice(device_uid.as_bytes());

    let sign_hash = sha2::Sha256::digest(&sign_input);

    // Try to sign with ssscli (hardware) or warn that daemon must sign
    let baseline_signature = sign_baseline_hash(&sign_hash, key_version);

    match baseline_signature {
        Some(sig_b64) => {
            let baseline = serde_json::json!({
                "pcr_values": snap["pcr_values"],
                "composite_digest": composite,
                "baseline_signature": sig_b64,
                "created_at": created_at,
                "device_uid": device_uid,
                "key_version": key_version,
                "schema_version": snap["schema_version"],
            });

            if let Some(parent) = Path::new(BASELINE_PATH).parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::write(BASELINE_PATH, serde_json::to_string_pretty(&baseline).unwrap()) {
                Ok(_) => {
                    println!("✅ Baseline created and SIGNED at {}", BASELINE_PATH);
                    println!("   Device UID: {}", device_uid);
                    println!("   Key version: {}", key_version);
                }
                Err(e) => eprintln!("Write error: {}", e),
            }
        }
        None => {
            // Can't sign from CLI — save unsigned baseline with warning
            let baseline = serde_json::json!({
                "pcr_values": snap["pcr_values"],
                "composite_digest": composite,
                "baseline_signature": "",
                "created_at": created_at,
                "device_uid": device_uid,
                "key_version": key_version,
                "schema_version": snap["schema_version"],
            });

            if let Some(parent) = Path::new(BASELINE_PATH).parent() {
                let _ = fs::create_dir_all(parent);
            }
            match fs::write(BASELINE_PATH, serde_json::to_string_pretty(&baseline).unwrap()) {
                Ok(_) => {
                    println!("⚠️ Baseline created but NOT SIGNED (no signing key available)");
                    println!("   Baseline at: {}", BASELINE_PATH);
                    println!("   The daemon will sign it on next startup if signature is empty.");
                }
                Err(e) => eprintln!("Write error: {}", e),
            }
        }
    }
}

/// Try to sign the baseline hash using ssscli (hardware) or software key.
fn sign_baseline_hash(hash: &[u8], key_version: u32) -> Option<String> {
    use std::process::Command;

    // Method 1: Try ssscli (hardware board)
    let key_id = format!("0x{:08X}", 0x20000010 + key_version - 1);
    let tmp_in = "/tmp/guardian_baseline_hash.bin";
    let tmp_out = "/tmp/guardian_baseline_sig.bin";

    if fs::write(tmp_in, hash).is_ok() {
        if let Ok(output) = Command::new("ssscli")
            .args(["sign", &key_id, tmp_in, tmp_out])
            .output()
        {
            if output.status.success() {
                if let Ok(sig_bytes) = fs::read(tmp_out) {
                    let _ = fs::remove_file(tmp_in);
                    let _ = fs::remove_file(tmp_out);
                    return Some(base64::engine::general_purpose::STANDARD.encode(&sig_bytes));
                }
            }
        }
        let _ = fs::remove_file(tmp_in);
        let _ = fs::remove_file(tmp_out);
    }

    // Method 2: Try ring with software key file
    let agent_dir = "/var/lib/sgx-guardian/sgx-agent";
    if let Ok(entries) = fs::read_dir(agent_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("device_") && name.ends_with(".key") {
                if let Ok(pkcs8_bytes) = fs::read(entry.path()) {
                    let rng = ring::rand::SystemRandom::new();
                    if let Ok(keypair) = ring::signature::EcdsaKeyPair::from_pkcs8(
                        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                        &pkcs8_bytes,
                        &rng,
                    ) {
                        if let Ok(sig) = keypair.sign(&rng, hash) {
                            return Some(base64::engine::general_purpose::STANDARD
                                .encode(sig.as_ref()));
                        }
                    }
                }
            }
        }
    }

    None
}
```

### Also fix `run_verify()` to check signature

Find the current `run_verify()` which only compares values. Add signature verification:

After the line that loads baseline and snapshot, add:

```rust
    // Verify baseline signature first
    let sig = baseline["baseline_signature"].as_str().unwrap_or("");
    if sig.is_empty() {
        println!("  ⚠️ Baseline is NOT SIGNED — tamper protection not active");
    } else {
        println!("  Baseline signature: present");
        // Note: Full signature verification requires the DKP public key,
        // which the daemon provides at runtime. CLI can only check signature exists.
    }
```

### Also add import in pcr_baseline.rs

At the top of the file:

```rust
use base64::Engine as _;
use sha2::Digest;
```

### Also add `ring` dependency check

The `sgx-pa-cli/Cargo.toml` already has `ring = "0.17"` — confirmed from the project knowledge. No dependency change needed.




---




## FIX 2 (Build Command)

Update your build workflow:

```bash
# Build both binaries from workspace root:
cargo build                           # builds sgx_guardian_client
cargo build -p sgx-pa-cli             # builds sgx-pa-cli

# Or build everything at once:
cargo build --workspace

# For cross-compile:
cross build --release --target aarch64-unknown-linux-gnu --features secure-element
cross build --release --target aarch64-unknown-linux-gnu -p sgx-pa-cli
```




---




## Summary: Apply in This Order

```
Step 1: Fix attestation_service.rs — add `default` to serde attributes
        on pcr_values and key_version fields

Step 2: Fix attestation_service.rs — update create_signed_evidence()
        return to include pcr_values and key_version

Step 3: Fix attestation_service.rs internal test — add pcr_values: None,
        key_version: None to make_test_evidence()

Step 4: Fix tests/test_attestation.rs — add pcr_values: None,
        key_version: None to make_evidence()

Step 5: Fix main.rs PCR block — add `use sha2::Digest;` inside the block

Step 6: Fix sgx-pa-cli pcr_baseline.rs — replace run_create() with
        proper signing logic (not copying snapshot signature)

Step 7: cargo build → verify compiles
        cargo test → verify all tests pass
        cargo build -p sgx-pa-cli → verify CLI compiles
```
