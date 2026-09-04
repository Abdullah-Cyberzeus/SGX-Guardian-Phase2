//! Selection of the tamper-evident audit log the node writes and pre-verifies.
//!
//! The pre-init verifier and the writer must agree on one path. They did not
//! historically (the verifier checked a shared file while the writer produced
//! a per-node one), so the selection lives in one tested place.

use super::GuardianPaths;
use std::path::PathBuf;

/// Fallback log directory used on developer machines without `/var/log` write
/// access.
pub const DEV_LOG_DIR: &str = "logs";

/// The production and development audit log paths for a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogPaths {
    pub prod: PathBuf,
    pub dev: PathBuf,
}

impl AuditLogPaths {
    pub fn for_node(paths: &GuardianPaths, node_id: &str) -> Self {
        let file = format!("audit-{node_id}.log");
        Self {
            prod: paths.log_root.join(&file),
            dev: PathBuf::from(DEV_LOG_DIR).join(&file),
        }
    }

    /// The path the startup verifier should check: the production log when it
    /// exists, otherwise the development one. Verifying the wrong file would
    /// pass on a stale or empty artefact.
    pub fn verification_target(&self) -> PathBuf {
        if self.prod.exists() {
            self.prod.clone()
        } else {
            self.dev.clone()
        }
    }

    /// The path the writer is initialised with — always the production one, so
    /// a running daemon never splits its chain across two files.
    pub fn writer_target(&self) -> PathBuf {
        self.prod.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_per_node_under_the_configured_log_root() {
        let paths = GuardianPaths::rooted_at("/base");
        let audit = AuditLogPaths::for_node(&paths, "nodeB");

        assert_eq!(
            audit.prod,
            PathBuf::from("/base/var/log/sgx-guardian/audit-nodeB.log")
        );
        assert_eq!(audit.dev, PathBuf::from("logs/audit-nodeB.log"));
        assert_eq!(audit.writer_target(), audit.prod);
    }

    #[test]
    fn verification_target_prefers_an_existing_production_log() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let paths = GuardianPaths::rooted_at(temp.path());
        std::fs::create_dir_all(&paths.log_root).expect("create log root");
        let audit = AuditLogPaths::for_node(&paths, "nodeA");

        assert_eq!(
            audit.verification_target(),
            audit.dev,
            "with no production log the dev path is checked"
        );

        std::fs::write(&audit.prod, b"{}\n").expect("write production log");
        assert_eq!(audit.verification_target(), audit.prod);
    }

    #[test]
    fn writer_and_verifier_agree_once_the_production_log_exists() {
        let temp = tempfile::tempdir().expect("create sandbox");
        let paths = GuardianPaths::rooted_at(temp.path());
        std::fs::create_dir_all(&paths.log_root).expect("create log root");
        let audit = AuditLogPaths::for_node(&paths, "nodeC");
        std::fs::write(audit.writer_target(), b"{}\n").expect("write log");

        assert_eq!(audit.verification_target(), audit.writer_target());
    }
}
