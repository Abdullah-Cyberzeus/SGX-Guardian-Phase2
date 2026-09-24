//! Local Nebula key generation — the member half of the P0.1 hotfix (B1).
//!
//! Before Phase 0 the CA ran `nebula-cert sign -out-key`, producing the
//! member's **private key on the CA** and shipping it back over plaintext gRPC
//! on the LAN (`:50061`) and through the VPS broker on the WAN. That violated
//! Principle 7 of the spec and meant a compromised CA, or anyone on the LAN who
//! could guess a `node_id`, held every member's identity.
//!
//! Now the member runs `nebula-cert keygen` itself and sends only the public
//! half. The private key is written once, mode 0600, and never read by anything
//! but the local `nebula` daemon.
//!
//! ## Curve
//!
//! `nebula-cert keygen` defaults to **25519**, and so does `nebula-cert ca`
//! (`NebulaCA::generate_ca` passes no `-curve`). Every existing Guardian CA is
//! therefore 25519, and the member must not pass `-curve P256` to match its
//! *device* DID key — those are unrelated keys, and a mismatch makes
//! `nebula-cert sign` reject the public key. This module deliberately never
//! passes `-curve`.

use std::path::{Path, PathBuf};

use crate::nebula::bin::nebula_cert_command;

/// Where a Guardian's own Nebula keypair lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalKeypair {
    /// `<base>/nodes/<guardian_id>.key` — never transmitted.
    pub private_key_path: PathBuf,
    /// `<base>/nodes/<guardian_id>.pub` — sent to the CA.
    pub public_key_path: PathBuf,
    /// Contents of `public_key_path`, ready for `CertSignRequest`.
    pub public_key_pem: String,
}

#[derive(Debug, thiserror::Error)]
pub enum KeygenError {
    #[error("nebula-cert is unavailable: {0}")]
    BinaryMissing(#[from] crate::nebula::bin::NebulaBinaryMissing),
    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },
    #[error("nebula-cert keygen failed for {guardian_id}: {stderr}")]
    Keygen { guardian_id: String, stderr: String },
    #[error("generated public key for {guardian_id} is empty")]
    EmptyPublicKey { guardian_id: String },
}

fn io(context: impl Into<String>) -> impl FnOnce(std::io::Error) -> KeygenError {
    let context = context.into();
    move |source| KeygenError::Io { context, source }
}

fn paths_for(nebula_base_dir: &str, guardian_id: &str) -> (PathBuf, PathBuf) {
    let nodes = Path::new(nebula_base_dir).join("nodes");
    (
        nodes.join(format!("{guardian_id}.key")),
        nodes.join(format!("{guardian_id}.pub")),
    )
}

/// Reads an existing local keypair, if both halves are present and non-empty.
pub fn existing(nebula_base_dir: &str, guardian_id: &str) -> Option<LocalKeypair> {
    let (private_key_path, public_key_path) = paths_for(nebula_base_dir, guardian_id);
    if !private_key_path.exists() || !public_key_path.exists() {
        return None;
    }
    let public_key_pem = std::fs::read_to_string(&public_key_path).ok()?;
    if public_key_pem.trim().is_empty() {
        return None;
    }
    Some(LocalKeypair {
        private_key_path,
        public_key_path,
        public_key_pem,
    })
}

/// Generates a Nebula keypair for this Guardian, or returns the existing one.
///
/// Idempotent: enrollment retries must not rotate the key, or the certificate
/// the CA is part-way through issuing would no longer match.
pub fn ensure_local_keypair(
    nebula_base_dir: &str,
    guardian_id: &str,
) -> Result<LocalKeypair, KeygenError> {
    if let Some(existing) = existing(nebula_base_dir, guardian_id) {
        return Ok(existing);
    }
    generate(nebula_base_dir, guardian_id)
}

/// Unconditionally generates a fresh keypair, replacing any half-written one.
///
/// Used by the stale-identity path in `cert_client`, which discards a cached
/// cert/key pair that belongs to a previous local identity (P0.1b). Before
/// Phase 0 that path only deleted files, because the CA would mint a new key;
/// now the member must mint its own replacement or it can never re-enroll.
pub fn generate(nebula_base_dir: &str, guardian_id: &str) -> Result<LocalKeypair, KeygenError> {
    let (private_key_path, public_key_path) = paths_for(nebula_base_dir, guardian_id);
    let nodes_dir = private_key_path
        .parent()
        .expect("key path always has a parent");
    std::fs::create_dir_all(nodes_dir).map_err(io(format!("create {}", nodes_dir.display())))?;

    // A partial keypair from an interrupted run would make `keygen` fail on
    // "file exists", so clear both halves first.
    let _ = std::fs::remove_file(&private_key_path);
    let _ = std::fs::remove_file(&public_key_path);

    // No `-curve`: see the module docs. The CA is 25519 and these must match.
    let output = nebula_cert_command()?
        .arg("keygen")
        .arg("-out-key")
        .arg(&private_key_path)
        .arg("-out-pub")
        .arg(&public_key_path)
        .output()
        .map_err(io("run nebula-cert keygen"))?;

    if !output.status.success() {
        return Err(KeygenError::Keygen {
            guardian_id: guardian_id.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(io("restrict permissions on the Nebula private key"))?;
        let _ = std::fs::set_permissions(&public_key_path, std::fs::Permissions::from_mode(0o644));
    }

    let public_key_pem = std::fs::read_to_string(&public_key_path)
        .map_err(io(format!("read {}", public_key_path.display())))?;
    if public_key_pem.trim().is_empty() {
        return Err(KeygenError::EmptyPublicKey {
            guardian_id: guardian_id.to_string(),
        });
    }

    println!(
        "🔑 Generated local Nebula keypair for {} — the private key stays on this Guardian",
        guardian_id
    );
    Ok(LocalKeypair {
        private_key_path,
        public_key_path,
        public_key_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_keypair_reads_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(existing(&dir.path().display().to_string(), "nodeB").is_none());
    }

    #[test]
    fn a_half_written_keypair_is_not_reused() {
        // Only the public half survived an interrupted keygen. Reusing it would
        // send the CA a key the member cannot prove it holds.
        let dir = tempfile::tempdir().unwrap();
        let nodes = dir.path().join("nodes");
        std::fs::create_dir_all(&nodes).unwrap();
        std::fs::write(nodes.join("nodeB.pub"), "PUB").unwrap();

        assert!(existing(&dir.path().display().to_string(), "nodeB").is_none());
    }

    #[test]
    fn an_empty_public_key_is_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let nodes = dir.path().join("nodes");
        std::fs::create_dir_all(&nodes).unwrap();
        std::fs::write(nodes.join("nodeB.key"), "KEY").unwrap();
        std::fs::write(nodes.join("nodeB.pub"), "   \n").unwrap();

        assert!(existing(&dir.path().display().to_string(), "nodeB").is_none());
    }

    #[test]
    fn a_complete_keypair_is_reused_rather_than_rotated() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().display().to_string();
        let nodes = dir.path().join("nodes");
        std::fs::create_dir_all(&nodes).unwrap();
        std::fs::write(nodes.join("nodeB.key"), "KEY").unwrap();
        std::fs::write(nodes.join("nodeB.pub"), "PUBLIC-KEY-PEM").unwrap();

        let found = existing(&base, "nodeB").expect("a complete pair must be found");
        assert_eq!(found.public_key_pem, "PUBLIC-KEY-PEM");

        // The idempotent entry point must return the same pair without running
        // keygen — an enrollment retry may not rotate the key mid-issuance.
        let reused = ensure_local_keypair(&base, "nodeB").unwrap();
        assert_eq!(reused, found);
        assert_eq!(
            std::fs::read_to_string(nodes.join("nodeB.key")).unwrap(),
            "KEY",
            "the existing private key must not be replaced"
        );
    }

    #[test]
    fn key_paths_sit_beside_the_certificate_nebula_expects() {
        let (key, pubkey) = paths_for("/var/lib/sgx-guardian/nebula", "edge-7");
        assert_eq!(
            key,
            Path::new("/var/lib/sgx-guardian/nebula/nodes/edge-7.key")
        );
        assert_eq!(
            pubkey,
            Path::new("/var/lib/sgx-guardian/nebula/nodes/edge-7.pub")
        );
    }
}
