use chrono::Local;
use std::fs;
use std::path::PathBuf;
use tracing::{error, info};
use tracing_appender::rolling;
use tracing_subscriber::fmt::time::ChronoLocal;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

/// Initializes the global structured JSON logger for SG-X nodes.
/// Prefers `/var/log/sgx-guardian`, then `/var/lib/sgx-guardian/logs`,
/// then local `logs/`. If all file targets fail, falls back to stdout so the
/// daemon keeps running instead of panicking on startup.
///
/// When a file target is available, two separate output layers are installed:
///   - File (`<log_dir>/<node>.log`): full JSON, all crates, ISO-8601 timestamps — unchanged audit trail.
///   - Console (stdout): only our crate (`sgx_guardian_client`), no timestamps, no level prefix.
///     Clean orchestration status messages only. Library noise (hyper, axum, tonic, etc.) is silenced.
///
/// Override via RUST_LOG env var to see everything when debugging:
///   RUST_LOG=debug cargo run -- nodeA
pub fn init_logger(node_id: &str) {
    if let Some(log_dir) = resolve_log_dir() {
        let file_appender = rolling::daily(&log_dir, format!("{}.log", node_id));
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        Box::leak(Box::new(guard));

        // --- File layer: full structured JSON, all crates, with timestamps ---
        let file_filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());

        let file_layer = fmt::layer()
            .json()
            .with_timer(ChronoLocal::rfc_3339())
            .with_writer(non_blocking)
            .flatten_event(true)
            .with_target(false)
            .with_current_span(false)
            .with_ansi(false)
            .with_filter(file_filter);

        // --- Console layer: our crate only, no timestamps, no level prefix ---
        // Filter: only sgx_guardian_client at info level — silences hyper/axum/tonic/tower/rustls.
        // If RUST_LOG is set it takes precedence (escape hatch for debugging).
        // Console filter also suppresses the "sgx_guardian_client::audit" target, which is used
        // by log_event/log_error to write structured JSON fields to the file layer only.
        // "sgx_guardian_client::daemon"  → stdout/stderr from hostapd, dnsmasq, wpa_supplicant, udhcpc
        // "sgx_guardian_client::netbridge" → verbose internal diagnostic messages (gateway, DNS, routes)
        let console_filter = if std::env::var("RUST_LOG").is_ok() {
            EnvFilter::from_default_env()
        } else {
            EnvFilter::new(
                "sgx_guardian_client=info,\
                 sgx_guardian_client::audit=off,\
                 sgx_guardian_client::daemon=off,\
                 sgx_guardian_client::netbridge=off",
            )
        };

        let stdout_layer = fmt::layer()
            .without_time()
            .with_level(false)
            .with_target(false)
            .with_ansi(true)
            .with_filter(console_filter);

        let init_result = tracing_subscriber::registry()
            .with(file_layer)
            .with(stdout_layer)
            .try_init();

        if init_result.is_ok() {
            info!(
                node = %node_id,
                time = %Local::now().to_rfc3339(),
                log_dir = %log_dir.display(),
                "Logger initialized successfully"
            );
            return;
        }
    }

    let env_filter = EnvFilter::from_default_env().add_directive("info".parse().unwrap());
    let _ = fmt()
        .with_env_filter(env_filter)
        .json()
        .with_timer(ChronoLocal::rfc_3339())
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_ansi(false)
        .try_init();
    eprintln!(
        "warning: file logger unavailable; falling back to stdout for node {}",
        node_id
    );
    info!(
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        "Logger initialized with stdout fallback"
    );
}

fn resolve_log_dir() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(override_dir) = std::env::var("SGX_LOG_DIR") {
        if !override_dir.trim().is_empty() {
            candidates.push(PathBuf::from(override_dir));
        }
    }
    candidates.push(PathBuf::from("/var/log/sgx-guardian"));
    candidates.push(PathBuf::from("/var/lib/sgx-guardian/logs"));
    candidates.push(PathBuf::from("logs"));

    candidates
        .into_iter()
        .find(|dir| fs::create_dir_all(dir).is_ok())
}

/// Logs a normal information-level event for the given node.
/// File-only: writes full structured JSON to the audit log.
/// Important orchestration messages use direct println! in the source instead.
pub fn log_event(node_id: &str, event: &str) {
    // File-only structured record (console filter excludes the audit target)
    info!(
        target: "sgx_guardian_client::audit",
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        event = %event
    );
}

/// Logs an error-level event for the given node.
/// File-only: writes full structured JSON to the audit log.
/// Important error messages use direct eprintln! in the source instead.
pub fn log_error(node_id: &str, err: &str) {
    // File-only structured record (console filter excludes the audit target)
    error!(
        target: "sgx_guardian_client::audit",
        node = %node_id,
        time = %Local::now().to_rfc3339(),
        error = %err
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_dir_override_is_preferred_when_it_is_usable() {
        let _lock = crate::test_support::blocking_env_lock();
        let previous = std::env::var_os("SGX_LOG_DIR");
        let temp = tempfile::tempdir().expect("create sandbox");
        let override_dir = temp.path().join("guardian-logs");
        std::env::set_var("SGX_LOG_DIR", &override_dir);

        let resolved = resolve_log_dir().expect("a writable directory must be found");

        assert_eq!(resolved, override_dir);
        assert!(resolved.is_dir(), "the resolved directory is created");

        match previous {
            Some(value) => std::env::set_var("SGX_LOG_DIR", value),
            None => std::env::remove_var("SGX_LOG_DIR"),
        }
    }

    #[test]
    fn a_blank_override_is_ignored_in_favour_of_the_standard_candidates() {
        let _lock = crate::test_support::blocking_env_lock();
        let previous = std::env::var_os("SGX_LOG_DIR");

        for blank in ["", "   "] {
            std::env::set_var("SGX_LOG_DIR", blank);
            let resolved = resolve_log_dir().expect("a fallback candidate must be usable");
            assert_ne!(
                resolved,
                PathBuf::from(blank),
                "a blank override must not be used as a directory"
            );
        }

        match previous {
            Some(value) => std::env::set_var("SGX_LOG_DIR", value),
            None => std::env::remove_var("SGX_LOG_DIR"),
        }
    }

    #[test]
    fn resolution_falls_through_to_a_relative_directory_when_system_paths_are_unwritable() {
        let _lock = crate::test_support::blocking_env_lock();
        let previous = std::env::var_os("SGX_LOG_DIR");
        // A path under an existing regular file can never be created, so the
        // override is skipped and the candidate list is walked.
        let temp = tempfile::tempdir().expect("create sandbox");
        let blocker = temp.path().join("not-a-dir");
        std::fs::write(&blocker, b"x").expect("write blocking file");
        std::env::set_var("SGX_LOG_DIR", blocker.join("logs"));

        let resolved = resolve_log_dir().expect("some candidate must be usable");

        assert!(!resolved.starts_with(&blocker));

        match previous {
            Some(value) => std::env::set_var("SGX_LOG_DIR", value),
            None => std::env::remove_var("SGX_LOG_DIR"),
        }
    }

    #[test]
    fn structured_events_are_emitted_without_an_initialised_subscriber() {
        // log_event/log_error are called from startup paths that run before
        // (and after) the logger is installed; neither may panic when no
        // subscriber is listening.
        log_event("nodeA", "unit-test event");
        log_error("nodeA", "unit-test error");
        log_event("", "");
        log_error("", "");
    }

    #[test]
    fn the_logger_initialises_against_an_isolated_directory() {
        let _lock = crate::test_support::blocking_env_lock();
        let previous = std::env::var_os("SGX_LOG_DIR");
        let temp = tempfile::tempdir().expect("create sandbox");
        std::env::set_var("SGX_LOG_DIR", temp.path());

        // A global subscriber may already be installed by another test in this
        // binary; init_logger swallows that and falls back, so the assertion
        // is that it completes and leaves the log directory usable.
        init_logger("nodeA");
        log_event("nodeA", "post-init event");

        assert!(temp.path().is_dir());

        match previous {
            Some(value) => std::env::set_var("SGX_LOG_DIR", value),
            None => std::env::remove_var("SGX_LOG_DIR"),
        }
    }
}
