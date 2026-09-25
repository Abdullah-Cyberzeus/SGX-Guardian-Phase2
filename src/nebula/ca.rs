// src/nebula/ca.rs  — FULL REPLACEMENT
//
// KEY FIX: generate_ca() now checks whether this node IS the CA.
// Member nodes (nodeB, nodeC) must NOT call generate_ca().
// They receive the CA cert through the cert bootstrap gRPC flow
// (cert_client.rs → cert_service.rs → CertSignResponse.ca_cert_pem).
//
// The enforce_single_ca() helper hard-panics if a member tries to
// generate its own CA — catching the bug early in development.

use super::bin::nebula_cert_command;
use super::models::CircleMembership;
use super::utils::validate_circle_membership;
use std::fs;
use std::io::Error;
use std::path::Path;

/// Subject name of the CA certificate, and the validity and groups stamped on
/// the member certificates it signs.
///
/// Before Phase 0 these were three literals inside `generate_ca`/`issue_node_cert`,
/// so every circle's CA shared the subject name `guardian-circle-ca`. That makes
/// two circles indistinguishable in `nebula-cert print` output and in the §4.5
/// fingerprint pin the operator is asked to compare. Phase 2 supplies per-circle
/// values; Phase 0 only threads the parameter through, with
/// [`CaIdentity::legacy_default`] preserving today's behaviour exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaIdentity {
    /// `-name` on the CA certificate.
    pub ca_name: String,
    /// `-duration` on issued member certificates.
    pub node_cert_duration: String,
    /// `-groups` on issued member certificates.
    pub node_groups: String,
}

impl CaIdentity {
    /// The values every pre-Phase-0 install used. Keeping these byte-identical
    /// means a migrated circle keeps signing certificates indistinguishable
    /// from the ones it signed before the upgrade.
    pub fn legacy_default() -> Self {
        Self {
            ca_name: "guardian-circle-ca".to_string(),
            node_cert_duration: "8600h".to_string(),
            node_groups: "guardian,member".to_string(),
        }
    }

    /// A named circle's identity, for Phase 2's Create Mesh Circle flow.
    ///
    /// `"<circle_name> CA"` (space-separated, matching the plan's own
    /// wording) rather than a slug — `nebula-cert -name` accepts any string,
    /// and this is what shows up in `nebula-cert print` for an operator
    /// comparing fingerprints, so it reads better as a name than a slug does.
    pub fn for_circle(circle_name: &str) -> Self {
        Self {
            ca_name: format!("{circle_name} CA"),
            ..Self::legacy_default()
        }
    }
}

impl Default for CaIdentity {
    fn default() -> Self {
        Self::legacy_default()
    }
}

pub struct NebulaCA;

impl NebulaCA {
    /// Generate the Nebula CA keypair and self-signed cert.
    ///
    /// MUST only be called on the CA node (nodeA).
    /// Calling this on a member node is a hard error — it would create
    /// a different CA and break the Circle of Trust.
    ///
    /// Returns Ok(()) if the CA already exists (idempotent).
    ///
    /// Uses [`CaIdentity::legacy_default`]; call [`NebulaCA::generate_ca_with`]
    /// to name the CA after its circle.
    pub fn generate_ca(base_dir: &str) -> Result<(), Error> {
        Self::generate_ca_with(base_dir, &CaIdentity::legacy_default())
    }

    /// [`NebulaCA::generate_ca`] with an explicit CA identity.
    pub fn generate_ca_with(base_dir: &str, identity: &CaIdentity) -> Result<(), Error> {
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

        // NOTE: no `-curve` flag, so the CA is Nebula's default (25519). Member
        // keygen must match — see `issue_node_cert_from_pub`.
        let output = nebula_cert_command()?
            .arg("ca")
            .arg("-name")
            .arg(&identity.ca_name)
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
        if let Some(out) = nebula_cert_command()
            .ok()
            .and_then(|mut c| c.args(["print", "-json", "-path", &ca_crt]).output().ok())
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
    /// `ip` should be the overlay IP with CIDR (e.g. "10.20.0.2/24") — whatever
    /// the circle's own overlay subnet is.
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

        let identity = CaIdentity::legacy_default();
        let output = nebula_cert_command()?
            .arg("sign")
            .arg("-name")
            .arg(&membership.node_name)
            .arg("-ip")
            .arg(ip)
            .arg("-duration")
            .arg(&identity.node_cert_duration)
            .arg("-groups")
            .arg(&identity.node_groups)
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

    /// Sign a member certificate from a **public key the member generated
    /// itself**, so no private key is ever created on — or transmitted by —
    /// the CA. This is the P0.1 hotfix for blocker B1.
    ///
    /// `nebula_public_key_pem` is the contents of the member's
    /// `nebula-cert keygen -out-pub` file. The member keeps the matching
    /// `-out-key` private key and never sends it anywhere.
    ///
    /// Differences from [`NebulaCA::issue_node_cert`], all deliberate:
    ///
    /// * `-in-pub` replaces `-out-key`, so `nebula-cert` writes only a `.crt`.
    /// * **No partial-state guard.** `issue_node_cert` errors when a `.crt`
    ///   exists without a matching `.key`, which was a sound corruption check
    ///   while the CA held both. Here that state is the *normal* one, so the
    ///   same guard would reject every certificate this function ever issues.
    /// * The caller's idempotency check must key off the `.crt` and the stored
    ///   public-key fingerprint, never the absent `.key` (see `cert_service`).
    ///
    /// The curve is not specified, matching `generate_ca`, which also takes
    /// Nebula's default (25519). A member that ran `keygen -curve P256` while
    /// the CA is 25519 produces a key `nebula-cert sign` refuses; that shows up
    /// here as a signing error naming the curve mismatch.
    pub fn issue_node_cert_from_pub(
        base_dir: &str,
        membership: &CircleMembership,
        ip: &str,
        nebula_public_key_pem: &str,
    ) -> Result<(), Error> {
        Self::issue_node_cert_from_pub_with(
            base_dir,
            membership,
            ip,
            nebula_public_key_pem,
            &CaIdentity::legacy_default(),
        )
    }

    /// [`NebulaCA::issue_node_cert_from_pub`] with an explicit CA identity.
    pub fn issue_node_cert_from_pub_with(
        base_dir: &str,
        membership: &CircleMembership,
        ip: &str,
        nebula_public_key_pem: &str,
        identity: &CaIdentity,
    ) -> Result<(), Error> {
        if !validate_circle_membership(membership) {
            return Err(Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Circle membership validation failed",
            ));
        }
        validate_node_name(&membership.node_name)?;

        if nebula_public_key_pem.trim().is_empty() {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "Nebula public key PEM is empty — cannot sign without a member public key",
            ));
        }
        // A private key here would mean the member sent us material it must
        // never send, or that a caller passed the wrong file. Refuse rather
        // than write it to disk: `nebula-cert sign -in-pub` would reject it
        // anyway, but only after it had been persisted to the temp path.
        if nebula_public_key_pem.contains("PRIVATE KEY") {
            return Err(Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to sign: the supplied PEM contains a PRIVATE KEY, not a public key",
            ));
        }

        let ca_dir = format!("{}/ca", base_dir);
        let nodes_dir = format!("{}/nodes", base_dir);
        fs::create_dir_all(&nodes_dir)?;

        let cert_path = format!("{}/{}.crt", nodes_dir, membership.node_name);

        let ca_crt = format!("{}/ca.crt", ca_dir);
        let ca_key = format!("{}/ca.key", ca_dir);
        if !Path::new(&ca_crt).exists() || !Path::new(&ca_key).exists() {
            return Err(Error::new(
                std::io::ErrorKind::NotFound,
                format!("CA cert/key not found in {}. Create the circle first.", ca_dir),
            ));
        }

        // `nebula-cert` reads the public key from a path, so it is staged in
        // the CA's own nodes/ directory (same filesystem, predictable
        // permissions) and removed on every exit path below.
        let pub_path = format!("{}/{}.pub.tmp", nodes_dir, membership.node_name);
        fs::write(&pub_path, nebula_public_key_pem.as_bytes())?;

        // Captured *before* signing, not just checked after (see the check
        // below): a Guardian self-signing its own cert — `mesh::ca::create_circle`
        // signing the CA's own membership, P2.1 — legitimately already holds
        // `nodes/<node_name>.key` (its own local keygen output, from *before*
        // this call), since signer and signee are the same entity. Checking
        // only post-sign existence made that legitimate, pre-existing key look
        // exactly like nebula-cert having secretly created one — confirmed by
        // direct reproduction against the real binary: `sign -in-pub` with no
        // `-out-key` never touches `<name>.key`, present or not, before or
        // after. So the only real signal is *did a key appear that was not
        // there before*.
        let key_path = format!("{}/{}.key", nodes_dir, membership.node_name);
        let key_pre_existed = Path::new(&key_path).exists();

        let signed = nebula_cert_command()?
            .arg("sign")
            .arg("-name")
            .arg(&membership.node_name)
            .arg("-ip")
            .arg(ip)
            .arg("-duration")
            .arg(&identity.node_cert_duration)
            .arg("-groups")
            .arg(&identity.node_groups)
            .arg("-ca-crt")
            .arg(&ca_crt)
            .arg("-ca-key")
            .arg(&ca_key)
            .arg("-in-pub")
            .arg(&pub_path)
            .arg("-out-crt")
            .arg(&cert_path)
            .output();

        let _ = fs::remove_file(&pub_path);
        let output = signed?;

        if !output.status.success() {
            return Err(Error::other(format!(
                "Certificate signing failed for {} (from public key): {}",
                membership.node_name,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // The whole point of this function: assert no private key was
        // *produced by this call*. A future `nebula-cert` that changed
        // `-in-pub` semantics would trip this rather than silently
        // reintroducing B1 — `key_pre_existed` is what keeps a legitimate
        // self-signing caller's own key from tripping it too.
        if !key_pre_existed && Path::new(&key_path).exists() {
            let _ = fs::remove_file(&key_path);
            return Err(Error::other(format!(
                "nebula-cert wrote a private key for {} despite -in-pub; \
                 the key was deleted and the certificate is not trusted",
                membership.node_name
            )));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644));
        }

        println!(
            "✅ Certificate issued for {} at {} from its own public key (no key on the CA)",
            membership.node_name, ip
        );
        Ok(())
    }
}

/// Node names reach file paths and Nebula certificate subjects, so they are
/// restricted to the same conservative set the mesh profile uses.
fn validate_node_name(node_name: &str) -> Result<(), Error> {
    if node_name.is_empty()
        || !node_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("Invalid node name '{node_name}': must be alphanumeric with - or _ only"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership(name: &str) -> CircleMembership {
        CircleMembership {
            node_name: name.to_string(),
            circle_id: "circle-7f3c1a".to_string(),
            vc_hash: "abc123".to_string(),
            is_valid: true,
        }
    }

    #[test]
    fn signing_from_a_public_key_refuses_an_empty_pem() {
        let dir = tempfile::tempdir().unwrap();
        let err = NebulaCA::issue_node_cert_from_pub(
            &dir.path().display().to_string(),
            &membership("nodeB"),
            "192.168.100.2/24",
            "   ",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn signing_from_a_public_key_refuses_a_private_key_pem() {
        // Guards against a caller wiring up the wrong keygen output file and
        // silently reintroducing B1 from the other direction.
        let dir = tempfile::tempdir().unwrap();
        let err = NebulaCA::issue_node_cert_from_pub(
            &dir.path().display().to_string(),
            &membership("nodeB"),
            "192.168.100.2/24",
            "-----BEGIN NEBULA X25519 PRIVATE KEY-----\nAAAA\n-----END NEBULA X25519 PRIVATE KEY-----\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("PRIVATE KEY"));
    }

    #[test]
    fn signing_from_a_public_key_requires_the_ca_material() {
        let dir = tempfile::tempdir().unwrap();
        let err = NebulaCA::issue_node_cert_from_pub(
            &dir.path().display().to_string(),
            &membership("nodeB"),
            "192.168.100.2/24",
            "-----BEGIN NEBULA X25519 PUBLIC KEY-----\nAAAA\n-----END NEBULA X25519 PUBLIC KEY-----\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn signing_from_a_public_key_rejects_a_traversing_node_name() {
        let dir = tempfile::tempdir().unwrap();
        let err = NebulaCA::issue_node_cert_from_pub(
            &dir.path().display().to_string(),
            &membership("../../etc/shadow"),
            "192.168.100.2/24",
            "-----BEGIN NEBULA X25519 PUBLIC KEY-----\nAAAA\n-----END NEBULA X25519 PUBLIC KEY-----\n",
        )
        .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn signing_from_a_public_key_leaves_no_staged_pub_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().display().to_string();
        // No CA material, so signing fails early — the staged file must still
        // be cleaned up, since the member's public key should not linger.
        let _ = NebulaCA::issue_node_cert_from_pub(
            &base,
            &membership("nodeB"),
            "192.168.100.2/24",
            "-----BEGIN NEBULA X25519 PUBLIC KEY-----\nAAAA\n-----END NEBULA X25519 PUBLIC KEY-----\n",
        );
        let staged = dir.path().join("nodes/nodeB.pub.tmp");
        assert!(!staged.exists(), "staged public key was left at {staged:?}");
    }

    #[test]
    fn the_legacy_ca_identity_matches_what_pre_phase_0_installs_used() {
        // A migrated circle must keep signing byte-identical certificates.
        let identity = CaIdentity::legacy_default();
        assert_eq!(identity.ca_name, "guardian-circle-ca");
        assert_eq!(identity.node_cert_duration, "8600h");
        assert_eq!(identity.node_groups, "guardian,member");
        assert_eq!(CaIdentity::default(), identity);
    }

    #[test]
    fn a_named_circle_gets_a_distinguishable_ca_name() {
        let identity = CaIdentity::for_circle("SGX-Alpha");
        assert_eq!(identity.ca_name, "SGX-Alpha CA");
        // Validity and groups are unchanged from the legacy defaults.
        assert_eq!(
            identity.node_cert_duration,
            CaIdentity::legacy_default().node_cert_duration
        );
    }
}
