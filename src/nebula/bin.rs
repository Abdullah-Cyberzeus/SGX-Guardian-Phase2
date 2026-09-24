//! Single resolution point for the `nebula-cert` / `nebula` binaries.
//!
//! Before Phase 0 every call site spelled `Command::new("nebula-cert")`, which
//! resolves through `PATH` and fails with a bare `NotFound` io error. That was
//! tolerable while `nebula-cert` only ever ran on the CA, where the installer
//! guarantees it. P0.1 moves key generation onto the *member*, so the binary is
//! now on the critical path of every Guardian, including boards whose image may
//! not carry it. A missing binary there must produce a readable reason the
//! lifecycle can surface (P1.3) rather than an opaque failure.
//!
//! Resolution order, first hit wins:
//!   1. `$SGX_NEBULA_CERT_BIN` (or `$SGX_NEBULA_BIN`) — explicit operator override
//!   2. `PATH`
//!   3. the vendored copies shipped next to the container image
//!
//! Callers use [`nebula_cert_command`] instead of `Command::new`, so the search
//! and its error message live in exactly one place.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Vendored fallbacks, relative to the working directory and to the installed
/// tree. Kept in one list so a new deployment layout is a one-line change.
const VENDORED_CANDIDATES: &[&str] = &[
    "docker/vendor",
    "/usr/local/lib/sgx-guardian/vendor",
    "/opt/sgx-guardian/vendor",
];

/// Why a Nebula binary could not be located.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NebulaBinaryMissing {
    pub binary: String,
    pub searched: Vec<String>,
}

impl std::fmt::Display for NebulaBinaryMissing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "`{}` not found — searched {}. Install Nebula (scripts/install_nebula.sh) \
             or point SGX_NEBULA_CERT_BIN at the binary.",
            self.binary,
            self.searched.join(", ")
        )
    }
}

impl std::error::Error for NebulaBinaryMissing {}

impl From<NebulaBinaryMissing> for std::io::Error {
    fn from(err: NebulaBinaryMissing) -> Self {
        std::io::Error::new(std::io::ErrorKind::NotFound, err.to_string())
    }
}

fn env_override(keys: &[&str]) -> Option<PathBuf> {
    for key in keys {
        if let Ok(raw) = std::env::var(key) {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let path = PathBuf::from(trimmed);
            if path.is_file() {
                return Some(path);
            }
            tracing::warn!(
                "{} is set to {} but that is not a file — ignoring the override",
                key,
                trimmed
            );
        }
    }
    None
}

fn resolve(binary: &str, env_keys: &[&str]) -> Result<PathBuf, NebulaBinaryMissing> {
    let mut searched = Vec::new();

    if let Some(path) = env_override(env_keys) {
        return Ok(path);
    }
    searched.extend(env_keys.iter().map(|k| format!("${k}")));

    if let Ok(path) = which::which(binary) {
        return Ok(path);
    }
    searched.push("PATH".to_string());

    for dir in VENDORED_CANDIDATES {
        let candidate = Path::new(dir).join(binary);
        if candidate.is_file() {
            return Ok(candidate);
        }
        searched.push(candidate.display().to_string());
    }

    Err(NebulaBinaryMissing {
        binary: binary.to_string(),
        searched,
    })
}

/// Absolute path to `nebula-cert`, or a readable reason it is unavailable.
pub fn nebula_cert_path() -> Result<PathBuf, NebulaBinaryMissing> {
    resolve("nebula-cert", &["SGX_NEBULA_CERT_BIN"])
}

/// Absolute path to the `nebula` daemon, or a readable reason it is unavailable.
pub fn nebula_path() -> Result<PathBuf, NebulaBinaryMissing> {
    resolve("nebula", &["SGX_NEBULA_BIN"])
}

/// A `Command` for `nebula-cert`, resolved through [`nebula_cert_path`].
///
/// This is the only constructor Guardian code should use — it keeps the search
/// order and the "not installed" message identical everywhere.
pub fn nebula_cert_command() -> Result<Command, NebulaBinaryMissing> {
    Ok(Command::new(nebula_cert_path()?))
}

/// Whether `nebula-cert` can be located at all. Used by the health and install
/// checks that want a boolean rather than a command.
pub fn nebula_cert_available() -> bool {
    nebula_cert_path().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_binary_reports_every_location_it_looked_in() {
        let err = NebulaBinaryMissing {
            binary: "nebula-cert".into(),
            searched: vec!["$SGX_NEBULA_CERT_BIN".into(), "PATH".into()],
        };
        let rendered = err.to_string();
        assert!(rendered.contains("nebula-cert"));
        assert!(rendered.contains("$SGX_NEBULA_CERT_BIN"));
        assert!(rendered.contains("PATH"));
        // The message must name the remedy, since it surfaces in the UI via
        // the lifecycle error state rather than in a developer's terminal.
        assert!(rendered.contains("install_nebula.sh"));
    }

    #[test]
    fn a_missing_binary_converts_to_a_not_found_io_error() {
        let err = NebulaBinaryMissing {
            binary: "nebula-cert".into(),
            searched: vec!["PATH".into()],
        };
        let io_err: std::io::Error = err.into();
        assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
        assert!(io_err.to_string().contains("nebula-cert"));
    }

    #[test]
    fn an_env_override_pointing_at_a_real_file_wins() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("nebula-cert");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();

        // Deliberately not using the public helper: the env var is process-wide
        // and would race other tests in the same binary.
        let resolved = {
            std::env::set_var("SGX_TEST_NEBULA_BIN", fake.display().to_string());
            let r = env_override(&["SGX_TEST_NEBULA_BIN"]);
            std::env::remove_var("SGX_TEST_NEBULA_BIN");
            r
        };
        assert_eq!(resolved, Some(fake));
    }

    #[test]
    fn an_env_override_pointing_at_a_missing_file_is_ignored() {
        let resolved = {
            std::env::set_var("SGX_TEST_NEBULA_MISSING", "/nonexistent/nebula-cert");
            let r = env_override(&["SGX_TEST_NEBULA_MISSING"]);
            std::env::remove_var("SGX_TEST_NEBULA_MISSING");
            r
        };
        assert_eq!(resolved, None, "a bogus override must fall through to PATH");
    }
}
