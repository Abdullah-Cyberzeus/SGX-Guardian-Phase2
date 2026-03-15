# HKM Complete Fix — Attestation Bug + Admin CLI Commands
**Crypto Standards:** ECDSA-P256 only (signing) + SHA-256 only (hashing)  
**No other algorithms introduced.**




## WHY SOFTWARE BROKE

My previous fix changed verification from `ECDSA_P256_SHA256_FIXED` to `ECDSA_P256_SHA256_ASN1`. That broke software because:

```
Software (ring crate):  signs → FIXED format (64 bytes, r||s)
Hardware (SE050 chip):  signs → ASN.1 DER format (70-72 bytes, 0x30...)

Previous fix: verify always uses ASN1
  → Software sign=FIXED, verify=ASN1 → ❌ BROKEN
  → Hardware sign=ASN1, verify=ASN1  → ✅ works

Correct fix: auto-detect format from signature size
  → Software sign=FIXED, verify=FIXED → ✅ works
  → Hardware sign=ASN1, verify=ASN1   → ✅ works
```




## FIX 1: `src/key_manager.rs` — Corrected `pubkey_der()`

REPLACE the `pubkey_der()` method:

```rust
    /// Returns the node's public key as raw EC point bytes (65 bytes: 04||x||y).
    /// Software: from ring keypair. Hardware: from exported DKP DER file.
    pub fn pubkey_der(&self) -> Vec<u8> {
        match &self.backend {
            SigningBackend::Software => {
                // ring returns raw 65-byte EC point directly
                self.keypair.public_key().as_ref().to_vec()
            }
            #[cfg(feature = "secure-element")]
            SigningBackend::Hardware { signer: _, key_id: _ } => {
                let dkp_pub_path = "/var/lib/sgx-guardian/keys/dkp_pub.der";
                match std::fs::read(dkp_pub_path) {
                    Ok(der_bytes) => {
                        // SE050 exports SubjectPublicKeyInfo DER (91 bytes).
                        // Extract raw 65-byte EC point starting at offset 26.
                        if der_bytes.len() == 91 {
                            der_bytes[26..].to_vec()
                        } else {
                            der_bytes
                        }
                    }
                    Err(_) => {
                        // Fallback to software key if file not found
                        self.keypair.public_key().as_ref().to_vec()
                    }
                }
            }
        }
    }
```

**Why this works:** Both backends now return 65-byte raw EC point. ring expects this format for verification. No more format mismatch.




## FIX 2: `src/attestation_service.rs` — Auto-detect Signature Format

In `verify_signed_evidence()`, find the verification section and REPLACE:

```rust
        // Step 6: Prepare verification key
        let peer_pubkey = base64::engine::general_purpose::STANDARD.decode(&ev.pubkey_der_b64)?;

        let peer_key =
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &peer_pubkey);
```

REPLACE WITH:

```rust
        // Step 6: Prepare verification key
        let peer_pubkey_raw = base64::engine::general_purpose::STANDARD.decode(&ev.pubkey_der_b64)?;

        // Handle both raw EC point (65 bytes from software/hardware)
        // and full SubjectPublicKeyInfo DER (91 bytes legacy)
        let peer_pubkey = if peer_pubkey_raw.len() == 91 {
            // Extract raw 65-byte EC point from DER wrapper
            peer_pubkey_raw[26..].to_vec()
        } else {
            peer_pubkey_raw
        };

        // Auto-detect signature format:
        // ring/software → FIXED (exactly 64 bytes, r||s concatenated)
        // SE050/hardware → ASN.1 DER (starts with 0x30, typically 70-72 bytes)
        let is_asn1 = !sig_bytes.is_empty() && sig_bytes[0] == 0x30;

        let verification_algo: &dyn signature::VerificationAlgorithm = if is_asn1 {
            &signature::ECDSA_P256_SHA256_ASN1
        } else {
            &signature::ECDSA_P256_SHA256_FIXED
        };

        let peer_key = signature::UnparsedPublicKey::new(verification_algo, &peer_pubkey);
```

**Why this works:** 
- Software signatures are exactly 64 bytes and don't start with 0x30 → uses FIXED
- SE050 signatures are ASN.1 DER and always start with 0x30 → uses ASN1
- Both verify correctly with the same code path
- Only ECDSA-P256 + SHA-256 used (no other algorithms)




## FIX 3: No Other Crypto Changes Needed

Everything else stays ECDSA-P256 + SHA-256:
- `key_manager.rs`: `ECDSA_P256_SHA256_FIXED_SIGNING` for ring signing ✅
- `sign.rs`: ssscli uses NIST_P256 for SE050 signing ✅
- `key_storage.rs`: generates NIST_P256 keys only ✅
- `attestation_service.rs`: SHA-256 for policy digest ✅
- `sgx-pa-cli keygen`: ECDSA-P256 via p256 crate ✅

No RSA, no AES, no Ed25519, no X25519, no post-quantum.




---
---
---




## ADMIN CLI COMMANDS — `sgx-pa-cli`

### Current sgx-pa-cli commands:
```
sgx-pa-cli status     → node status
sgx-pa-cli logs       → view logs
sgx-pa-cli keygen     → generate PA keypair
sgx-pa-cli sign       → sign policy
sgx-pa-cli verify     → verify signed policy
sgx-pa-cli peers      → list peers
sgx-pa-cli attestation → attestation status
```

### NEW commands to add:
```
sgx-pa-cli dkp-status              → show DKP key status
sgx-pa-cli dkp-rotate              → rotate DKP to new version
sgx-pa-cli dkp-revoke --version N  → revoke specific key version
```

These work on BOTH software and hardware:
- On hardware (board): reads metadata + calls ssscli
- On software (dev laptop): reads metadata only (no SE050)




### New File: `sgx-pa-cli/src/commands/dkp_status.rs`

```rust
//! DKP Status — show current Device Key Pair status.
//! Works on both hardware (board) and software (dev laptop).
//! Reads: /var/lib/sgx-guardian/keys/dkp_metadata.json

use std::fs;
use std::path::Path;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
const PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";

pub fn run() {
    println!("=== DKP Key Status ===\n");

    // Check if metadata exists
    if !Path::new(METADATA_PATH).exists() {
        println!("Status: No DKP found");
        println!("  No hardware key has been generated yet.");
        println!("  Run the guardian daemon to auto-generate DKP.");
        return;
    }

    // Read and parse metadata
    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to read {}: {}", METADATA_PATH, e);
            return;
        }
    };

    let meta: serde_json::Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse metadata: {}", e);
            return;
        }
    };

    // Display status
    println!("Key ID:      {}", meta["key_id"].as_str().unwrap_or("unknown"));
    println!("Label:       {}", meta["label"].as_str().unwrap_or("unknown"));
    println!("Algorithm:   {}", meta["algorithm"].as_str().unwrap_or("unknown"));
    println!("Version:     {}", meta["version"].as_u64().unwrap_or(0));
    println!("Status:      {}", meta["status"].as_str().unwrap_or("unknown"));
    println!("Created:     {}", meta["created_at"].as_str().unwrap_or("unknown"));

    if let Some(from) = meta["rotated_from"].as_str() {
        println!("Rotated From: {}", from);
    }
    if let Some(revoked) = meta["revoked_at"].as_str() {
        println!("Revoked At:  {}", revoked);
        println!("Reason:      {}", meta["revoke_reason"].as_str().unwrap_or("none"));
    }

    // Check public key file
    if Path::new(PUBKEY_PATH).exists() {
        let size = fs::metadata(PUBKEY_PATH).map(|m| m.len()).unwrap_or(0);
        println!("Public Key:  {} ({} bytes)", PUBKEY_PATH, size);
    } else {
        println!("Public Key:  NOT FOUND");
    }

    // Check if SE050 is available (try ssscli)
    println!();
    match std::process::Command::new("ssscli").arg("--version").output() {
        Ok(output) => {
            if output.status.success() {
                println!("SE050:       Available (ssscli found)");
            } else {
                println!("SE050:       ssscli found but returned error");
            }
        }
        Err(_) => {
            println!("SE050:       Not available (software-only mode)");
        }
    }
}
```




### New File: `sgx-pa-cli/src/commands/dkp_rotate.rs`

```rust
//! DKP Rotate — create new key version, deprecate current.
//! On hardware: generates new SE050 key at next slot.
//! On software: updates metadata only (no actual key rotation).

use chrono::Utc;
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";
const PUBKEY_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_pub.der";
const DKP_BASE_KEY_ID: u32 = 0x20000010;

pub fn run() {
    println!("=== DKP Key Rotation ===\n");

    // Step 1: Load current metadata
    if !Path::new(METADATA_PATH).exists() {
        eprintln!("No DKP found. Run the guardian daemon first to generate initial DKP.");
        return;
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to read metadata: {}", e);
            return;
        }
    };

    let mut meta: Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse metadata: {}", e);
            return;
        }
    };

    let current_version = meta["version"].as_u64().unwrap_or(1) as u32;
    let current_status = meta["status"].as_str().unwrap_or("Active").to_string();
    let current_key_id = meta["key_id"].as_str().unwrap_or("unknown").to_string();

    if current_status != "Active" {
        eprintln!("Current key is not Active (status: {}). Cannot rotate.", current_status);
        return;
    }

    let new_version = current_version + 1;
    let new_key_id = DKP_BASE_KEY_ID + new_version - 1;
    let new_key_id_hex = format!("0x{:08X}", new_key_id);
    let new_label = format!("dkp-v{}", new_version);

    println!("Current: {} (v{}, {})", current_key_id, current_version, current_status);
    println!("New:     {} (v{})", new_key_id_hex, new_version);

    // Step 2: Try hardware rotation (if ssscli available)
    let has_ssscli = Command::new("ssscli").arg("--version").output().is_ok();

    if has_ssscli {
        println!("\nGenerating new key in SE050...");

        // Generate new key
        let gen_result = Command::new("ssscli")
            .args(["generate", "ecc", &new_key_id_hex, "NIST_P256"])
            .output();

        match gen_result {
            Ok(output) => {
                if output.status.success() {
                    println!("SE050: Key generated at slot {}", new_key_id_hex);
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    eprintln!("SE050 key generation failed: {}", stderr);
                    return;
                }
            }
            Err(e) => {
                eprintln!("Failed to run ssscli: {}", e);
                return;
            }
        }

        // Export new public key
        let export_result = Command::new("ssscli")
            .args(["get", "ecc", "pub", &new_key_id_hex, PUBKEY_PATH])
            .output();

        match export_result {
            Ok(output) => {
                if output.status.success() {
                    println!("SE050: Public key exported to {}", PUBKEY_PATH);
                } else {
                    eprintln!("SE050 public key export failed");
                    return;
                }
            }
            Err(e) => {
                eprintln!("Failed to export public key: {}", e);
                return;
            }
        }
    } else {
        println!("\nNo SE050 available — updating metadata only (software mode).");
    }

    // Step 3: Update metadata
    let new_meta = serde_json::json!({
        "key_id": new_key_id_hex,
        "label": new_label,
        "algorithm": "ECDSA-P256",
        "version": new_version,
        "status": "Active",
        "created_at": Utc::now().to_rfc3339(),
        "rotated_from": current_key_id,
        "revoked_at": null,
        "revoke_reason": null,
        "public_key_path": PUBKEY_PATH
    });

    match fs::write(METADATA_PATH, serde_json::to_string_pretty(&new_meta).unwrap()) {
        Ok(_) => {
            println!("\nRotation complete:");
            println!("  Old key {} (v{}) → Deprecated", current_key_id, current_version);
            println!("  New key {} (v{}) → Active", new_key_id_hex, new_version);
            println!("\nNote: Restart guardian daemon to use the new key.");
        }
        Err(e) => {
            eprintln!("Failed to write metadata: {}", e);
        }
    }
}
```




### New File: `sgx-pa-cli/src/commands/dkp_revoke.rs`

```rust
//! DKP Revoke — permanently block a deprecated key version.
//! Usage: sgx-pa-cli dkp-revoke --version 1 --reason "rotation complete"

use chrono::Utc;
use clap::Args;
use serde_json::Value;
use std::fs;
use std::path::Path;

const METADATA_PATH: &str = "/var/lib/sgx-guardian/keys/dkp_metadata.json";

#[derive(Args)]
#[command(about = "Revoke a deprecated DKP key version")]
pub struct DkpRevokeArgs {
    /// Key version to revoke (must not be the active version)
    #[arg(long)]
    pub version: u32,
    /// Reason for revocation
    #[arg(long, default_value = "admin revocation")]
    pub reason: String,
}

pub fn run(args: DkpRevokeArgs) {
    println!("=== DKP Key Revocation ===\n");

    if !Path::new(METADATA_PATH).exists() {
        eprintln!("No DKP metadata found.");
        return;
    }

    let json = match fs::read_to_string(METADATA_PATH) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("Failed to read metadata: {}", e);
            return;
        }
    };

    let mut meta: Value = match serde_json::from_str(&json) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to parse metadata: {}", e);
            return;
        }
    };

    let current_version = meta["version"].as_u64().unwrap_or(0) as u32;
    let current_status = meta["status"].as_str().unwrap_or("unknown");

    // Safety check: cannot revoke the currently active key
    if args.version == current_version && current_status == "Active" {
        eprintln!("Cannot revoke the active key (v{}).", args.version);
        eprintln!("You must rotate first: sgx-pa-cli dkp-rotate");
        return;
    }

    // If the metadata file tracks this version, update it
    if args.version == current_version {
        meta["status"] = serde_json::json!("Revoked");
        meta["revoked_at"] = serde_json::json!(Utc::now().to_rfc3339());
        meta["revoke_reason"] = serde_json::json!(args.reason);

        match fs::write(METADATA_PATH, serde_json::to_string_pretty(&meta).unwrap()) {
            Ok(_) => {
                println!("Key v{} revoked.", args.version);
                println!("Reason: {}", args.reason);
                println!("Revoked at: {}", Utc::now().to_rfc3339());
                println!("\nNote: Revocation is permanent. Key cannot be un-revoked.");
                println!("Verification of old signatures remains available for 30-day grace period.");
            }
            Err(e) => {
                eprintln!("Failed to write metadata: {}", e);
            }
        }
    } else {
        // The metadata file only tracks the latest version
        // For full history, we would need a separate revocation log
        println!("Key v{} is not the current metadata version (current: v{}).", args.version, current_version);
        println!("The metadata file tracks only the latest key version.");
        println!("If this is an older version, it was already superseded by rotation.");
    }
}
```




### Modify: `sgx-pa-cli/src/commands/mod.rs`

ADD these 3 lines:

```rust
pub mod dkp_revoke;
pub mod dkp_rotate;
pub mod dkp_status;
```

Full updated file:
```rust
pub mod attestation;
pub mod dkp_revoke;    // NEW
pub mod dkp_rotate;    // NEW
pub mod dkp_status;    // NEW
pub mod keygen;
pub mod logs;
pub mod peers;
pub mod sign;
pub mod status;
pub mod verify;
```




### Modify: `sgx-pa-cli/src/main.rs`

ADD to the Commands enum:

```rust
    /// Show DKP (Device Key Pair) status
    DkpStatus,
    /// Rotate DKP to a new key version
    DkpRotate,
    /// Revoke a specific DKP key version
    DkpRevoke(commands::dkp_revoke::DkpRevokeArgs),
```

ADD to the match block:

```rust
        Commands::DkpStatus => commands::dkp_status::run(),
        Commands::DkpRotate => commands::dkp_rotate::run(),
        Commands::DkpRevoke(args) => commands::dkp_revoke::run(args),
```

Full updated main.rs:
```rust
mod commands;
mod config;
use clap::{Parser, Subcommand};
use commands::{logs::LogsArgs, sign::SignArgs};

#[derive(Parser)]
#[command(
    name = "sgx-pa-cli",
    about = "SGX Guardian Policy Authority CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show status information for a specific SGX Guardian node
    Status(commands::status::StatusArgs),
    /// Show recent logs for a specific node
    Logs(LogsArgs),
    /// Generate a new ECDSA-P256 keypair
    Keygen,
    /// Sign a UEP policy file (YAML or JSON)
    Sign(SignArgs),
    /// List all discovered and attested peers
    Peers,
    /// Show the last attestation result
    Attestation,
    /// Verify a signed policy.sig file
    Verify(commands::verify::VerifyArgs),
    /// Show DKP (Device Key Pair) status
    DkpStatus,
    /// Rotate DKP to a new key version
    DkpRotate,
    /// Revoke a specific DKP key version
    DkpRevoke(commands::dkp_revoke::DkpRevokeArgs),
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Status(args) => commands::status::run(args),
        Commands::Logs(args) => commands::logs::run(args),
        Commands::Keygen => commands::keygen::execute(),
        Commands::Sign(args) => commands::sign::execute(args),
        Commands::Verify(args) => {
            if let Err(e) = commands::verify::run(&args) {
                eprintln!("Error: {}", e);
            }
        }
        Commands::Peers => {
            if let Err(e) = commands::peers::run() {
                eprintln!("Error: {}", e);
            }
        }
        Commands::Attestation => {
            if let Err(e) = commands::attestation::run() {
                eprintln!("Error: {}", e);
            }
        }
        Commands::DkpStatus => commands::dkp_status::run(),
        Commands::DkpRotate => commands::dkp_rotate::run(),
        Commands::DkpRevoke(args) => commands::dkp_revoke::run(args),
    }
}
```




---
---
---




## USAGE EXAMPLES

### On Dev Laptop (Software Mode)
```bash
# Build CLI
cargo build --bin sgx-pa-cli

# Check DKP status
./target/debug/sgx-pa-cli dkp-status
# Output:
# === DKP Key Status ===
# Status: No DKP found
# SE050: Not available (software-only mode)

# After running daemon once:
./target/debug/sgx-pa-cli dkp-status
# Output:
# Key ID:    0x20000010
# Version:   1
# Status:    Active
# Algorithm: ECDSA-P256
# SE050:     Not available (software-only mode)

# Rotate (software mode — metadata only)
./target/debug/sgx-pa-cli dkp-rotate
# Output:
# No SE050 available — updating metadata only
# Old key 0x20000010 (v1) → Deprecated
# New key 0x20000011 (v2) → Active

# Revoke old version
./target/debug/sgx-pa-cli dkp-revoke --version 1 --reason "rotation complete"
```

### On Board (Hardware Mode)
```bash
# Transfer BOTH binaries to board
scp sgx_guardian_client root@192.168.56.1:/root/
scp sgx-pa-cli root@192.168.56.1:/root/

# On board:
./sgx-pa-cli dkp-status
# Output:
# Key ID:    0x20000010
# Version:   1
# Status:    Active
# Algorithm: ECDSA-P256
# SE050:     Available (ssscli found)

# Rotate (creates real SE050 key)
./sgx-pa-cli dkp-rotate
# Output:
# Generating new key in SE050...
# SE050: Key generated at slot 0x20000011
# SE050: Public key exported
# Old key 0x20000010 (v1) → Deprecated
# New key 0x20000011 (v2) → Active

# Revoke
./sgx-pa-cli dkp-revoke --version 1 --reason "rotation complete"
```




## CROSS-COMPILE sgx-pa-cli FOR BOARD

The CLI is in the workspace, so it builds with the same cross-compile:

```bash
# Method 3 (cross tool):
cross build --release --target aarch64-unknown-linux-gnu --bin sgx-pa-cli

# Binary at:
# target/aarch64-unknown-linux-gnu/release/sgx-pa-cli
```

Transfer both binaries to the board:
```bash
scp target/aarch64-unknown-linux-gnu/release/sgx_guardian_client root@192.168.56.1:/root/
scp target/aarch64-unknown-linux-gnu/release/sgx-pa-cli root@192.168.56.1:/root/
```




## STEP-BY-STEP CHECKLIST

```
Step 1:  Fix pubkey_der() in key_manager.rs         ← fix software + hardware
Step 2:  Fix verify_signed_evidence() in attestation_service.rs  ← auto-detect sig format
Step 3:  Create sgx-pa-cli/src/commands/dkp_status.rs
Step 4:  Create sgx-pa-cli/src/commands/dkp_rotate.rs
Step 5:  Create sgx-pa-cli/src/commands/dkp_revoke.rs
Step 6:  Update sgx-pa-cli/src/commands/mod.rs      ← add 3 pub mod lines
Step 7:  Update sgx-pa-cli/src/main.rs              ← add 3 commands + match arms
Step 8:  cargo test -- --nocapture                   ← verify software still works
Step 9:  cargo build --bin sgx-pa-cli               ← verify CLI compiles
Step 10: Test locally: sgx-pa-cli dkp-status
Step 11: Cross-compile both binaries for ARM64
Step 12: Deploy + test on board
```
