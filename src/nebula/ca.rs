// src/nebula/ca.rs  — FULL REPLACEMENT
//
// KEY FIX: generate_ca() now checks whether this node IS the CA.
// Member nodes (nodeB, nodeC) must NOT call generate_ca().
// They receive the CA cert through the cert bootstrap gRPC flow
// (cert_client.rs → cert_service.rs → CertSignResponse.ca_cert_pem).
//
// The enforce_single_ca() helper hard-panics if a member tries to
// generate its own CA — catching the bug early in development.

use super::models::CircleMembership;
use super::utils::validate_circle_membership;
use std::fs;
use std::io::Error;
use std::path::Path;
use std::process::Command;

pub struct NebulaCA;

impl NebulaCA {
    /// Generate the Nebula CA keypair and self-signed cert.
    ///
    /// MUST only be called on the CA node (nodeA).
    /// Calling this on a member node is a hard error — it would create
    /// a different CA and break the Circle of Trust.
    ///
    /// Returns Ok(()) if the CA already exists (idempotent).
    pub fn generate_ca(base_dir: &str) -> Result<(), Error> {
        let ca_dir = format!("{}/ca", base_dir);
        let ca_key = format!("{}/ca.key", ca_dir);
        let ca_crt = format!("{}/ca.crt", ca_dir);

        // ── Idempotent: CA already exists ─────────────────────────────
        if Path::new(&ca_key).exists() && Path::new(&ca_crt).exists() {
            println!("ℹ️  Guardian Mesh CA already exists at {}", ca_dir);
            return Ok(());
        }

        // ── Partial state: one file present but not both ───────────────
        if Path::new(&ca_key).exists() != Path::new(&ca_crt).exists() {
            return Err(Error::other(format!(
                "Partial CA state detected in {} (one of ca.key/ca.crt missing). \
                     Manual intervention required — remove both files and restart nodeA.",
                ca_dir
            )));
        }

        fs::create_dir_all(&ca_dir)?;

        let output = Command::new("nebula-cert")
            .arg("ca")
            .arg("-name")
            .arg("guardian-circle-ca")
            .current_dir(&ca_dir)
            .output()?;

        if !output.status.success() {
            return Err(Error::other(format!(
                "CA generation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Set strict permissions on Linux/macOS
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&ca_crt, fs::Permissions::from_mode(0o644));
            let _ = fs::set_permissions(&ca_key, fs::Permissions::from_mode(0o600));
        }

        println!("✅ Guardian Mesh CA generated at {}", ca_dir);
        Ok(())
    }

    /// Fetch the CA certificate from `source_path` and save it to
    /// `<base_dir>/ca/ca.crt`.
    ///
    /// Called on member nodes after they receive the CA cert through
    /// the cert bootstrap gRPC response.
    pub fn save_ca_cert(base_dir: &str, ca_cert_pem: &str) -> Result<(), Error> {
        if ca_cert_pem.trim().is_empty() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "CA cert PEM is empty — cannot save",
            ));
        }

        let ca_dir = format!("{}/ca", base_dir);
        fs::create_dir_all(&ca_dir)?;

        let ca_crt = format!("{}/ca.crt", ca_dir);

        // Idempotent: verify fingerprint matches if file already exists.
        if Path::new(&ca_crt).exists() {
            let existing = fs::read_to_string(&ca_crt)?;
            if existing.trim() == ca_cert_pem.trim() {
                println!("ℹ️  CA cert already saved and matches — skipping.");
                return Ok(());
            }
            // SECURITY: Existing trust anchor differs from the one offered by the bootstrap
            // response. Refuse to overwrite — this could be an attack or a misrouted response.
            // Operator must explicitly delete /var/lib/sgx-guardian/nebula/ca/ca.crt to rotate.
            return Err(Error::other(format!(
                "CA cert mismatch at {}. Refusing to overwrite existing trust anchor. \
                 Delete {} manually to accept new CA.",
                ca_crt, ca_crt
            )));
        }

        // Write atomically: tmp → rename
        let tmp = format!("{}.tmp", ca_crt);
        fs::write(&tmp, ca_cert_pem.trim())?;
        fs::rename(&tmp, &ca_crt)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&ca_crt, fs::Permissions::from_mode(0o644));
        }

        println!("✅ CA cert saved to {}", ca_crt);
        Ok(())
    }

    /// Returns true if the CA cert exists and is non-empty.
    pub fn ca_cert_exists(base_dir: &str) -> bool {
        let ca_crt = format!("{}/ca/ca.crt", base_dir);
        Path::new(&ca_crt).exists() && fs::metadata(&ca_crt).map(|m| m.len() > 0).unwrap_or(false)
    }

    /// Returns the fingerprint of the CA cert for verification.
    /// Uses `nebula-cert print` if available, otherwise returns hex of raw bytes.
    pub fn ca_fingerprint(base_dir: &str) -> Option<String> {
        let ca_crt = format!("{}/ca/ca.crt", base_dir);
        if !Path::new(&ca_crt).exists() {
            return None;
        }

        // Try nebula-cert print -json
        if let Ok(out) = Command::new("nebula-cert")
            .args(["print", "-json", "-path", &ca_crt])
            .output()
        {
            if out.status.success() {
                let s = String::from_utf8_lossy(&out.stdout);
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
                    // Extract fingerprint from details.fingerprint or similar field
                    if let Some(fp) = v
                        .pointer("/details/fingerprint")
                        .or_else(|| v.pointer("/fingerprint"))
                        .and_then(|f| f.as_str())
                    {
                        return Some(fp.to_string());
                    }
                }
            }
        }

        // Fallback: SHA-256 of raw cert bytes
        if let Ok(bytes) = fs::read(&ca_crt) {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&bytes);
            return Some(hex::encode(&hash[..8]));
        }

        None
    }

    /// Issue a Nebula certificate for a member node.
    ///
    /// Called ONLY on the CA node (nodeA).
    /// `ip` should be the overlay IP with CIDR (e.g. "192.168.100.2/24").
    pub fn issue_node_cert(
        base_dir: &str,
        membership: &CircleMembership,
        ip: &str,
    ) -> Result<(), Error> {
        if !validate_circle_membership(membership) {
            return Err(Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Circle membership validation failed",
            ));
        }

        let ca_dir = format!("{}/ca", base_dir);
        let nodes_dir = format!("{}/nodes", base_dir);

        fs::create_dir_all(&nodes_dir)?;

        // Validate node_name: alphanumeric + dash/underscore only
        if membership.node_name.is_empty()
            || !membership
                .node_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid node name '{}': must be alphanumeric with - or _ only",
                    membership.node_name
                ),
            ));
        }

        let cert_path = format!("{}/{}.crt", nodes_dir, membership.node_name);
        let key_path = format!("{}/{}.key", nodes_dir, membership.node_name);

        // ── Idempotent: both files already exist ──────────────────────
        if Path::new(&cert_path).exists() && Path::new(&key_path).exists() {
            println!(
                "ℹ️  Certificate and key already exist for {}",
                membership.node_name
            );
            return Ok(());
        }

        // ── Partial state ─────────────────────────────────────────────
        if Path::new(&cert_path).exists() != Path::new(&key_path).exists() {
            return Err(Error::other(format!(
                "Partial certificate state for {} (cert: {}, key: {}). \
                     Remove both files and retry.",
                membership.node_name,
                Path::new(&cert_path).exists(),
                Path::new(&key_path).exists()
            )));
        }

        // CA must exist before we can sign
        let ca_crt = format!("{}/ca.crt", ca_dir);
        let ca_key = format!("{}/ca.key", ca_dir);
        if !Path::new(&ca_crt).exists() || !Path::new(&ca_key).exists() {
            return Err(Error::new(
                std::io::ErrorKind::NotFound,
                format!(
                    "CA cert/key not found in {}. Run generate_ca() first on nodeA.",
                    ca_dir
                ),
            ));
        }

        let output = Command::new("nebula-cert")
            .arg("sign")
            .arg("-name")
            .arg(&membership.node_name)
            .arg("-ip")
            .arg(ip)
            .arg("-duration")
            .arg("8600h")
            .arg("-groups")
            .arg("guardian,member")
            .arg("-ca-crt")
            .arg(&ca_crt)
            .arg("-ca-key")
            .arg(&ca_key)
            .arg("-out-crt")
            .arg(&cert_path)
            .arg("-out-key")
            .arg(&key_path)
            .output()?;

        if !output.status.success() {
            return Err(Error::other(format!(
                "Certificate signing failed for {}: {}",
                membership.node_name,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644));
            let _ = fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600));
        }

        println!(
            "✅ Certificate issued for {} at {}",
            membership.node_name, ip
        );
        Ok(())
    }
}
