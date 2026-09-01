use crate::audit::event::{AuditAction, AuditCategory, AuditSeverity};
use crate::audit::logger::log_audit;
use crate::threat::error::{ThreatError, ThreatResult};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

/// Bundled Suricata install prefix.  All sub-commands use paths relative to
/// this so the host Python installation is never touched.
const OPT_SURICATA: &str = "/opt/suricata";
const CONFIG_TEST_TIMEOUT_SECS: u64 = 180;

pub struct RuleManager;

impl RuleManager {
    pub async fn update_rules(node_id: &str) -> ThreatResult<String> {
        let binary = format!("{}/bin/suricata-update", OPT_SURICATA);
        if !std::path::Path::new(&binary).exists() {
            return Err(ThreatError::BinaryMissing);
        }

        // Env vars scoped to this Command only — never set globally via profile.d.
        // The bundle layout has varied across board images (`dist-packages`,
        // `site-packages`, versioned python dirs). Discover it dynamically so
        // rule updates do not depend on one exact packaging layout.
        //
        // Intentionally DO NOT set LD_LIBRARY_PATH here: on the boards it can
        // make `/usr/bin/python3` load incompatible bundled libraries and die
        // with `Illegal instruction` / signal exits before any stderr appears.
        let pythonpath = suricata_pythonpath();

        let fut = Command::new(&binary)
            .env("PYTHONPATH", &pythonpath)
            .kill_on_drop(true)
            .output();

        let output = timeout(Duration::from_secs(300), fut)
            .await
            .map_err(|_| ThreatError::ServiceStart("Guardian update timed out (300s)".into()))?
            .map_err(map_spawn_error)?;

        if !output.status.success() {
            return Err(ThreatError::ServiceStart(command_failure_detail(
                output.status.code(),
                &output.stdout,
                &output.stderr,
                "Guardian update exited without any diagnostic output",
            )));
        }

        Self::validate_config("/etc/suricata/suricata.yaml").await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let summary = stdout
            .lines()
            .find(|line| line.contains("Loaded "))
            .or_else(|| stdout.lines().rev().find(|line| !line.trim().is_empty()))
            .unwrap_or("rules updated")
            .to_string();

        reload_or_restart_suricata().await?;

        log_audit(
            node_id,
            AuditCategory::Network,
            AuditSeverity::Info,
            AuditAction::Updated,
            &format!("Guardian update: {}", summary),
        );

        Ok(summary)
    }

    pub async fn validate_config(yaml_path: &str) -> ThreatResult<()> {
        let binary = format!("{}/bin/suricata", OPT_SURICATA);

        let fut = Command::new(&binary)
            .args(["-T", "-c", yaml_path])
            .kill_on_drop(true)
            .output();

        let output = timeout(Duration::from_secs(CONFIG_TEST_TIMEOUT_SECS), fut)
            .await
            .map_err(|_| {
                ThreatError::BadConfig(format!(
                    "Guardian config test timed out ({}s)",
                    CONFIG_TEST_TIMEOUT_SECS
                ))
            })?
            .map_err(map_spawn_error)?;

        if output.status.success() {
            return Ok(());
        }

        Err(ThreatError::BadConfig(command_failure_detail(
            output.status.code(),
            &output.stdout,
            &output.stderr,
            "Guardian config validation failed without diagnostic output",
        )))
    }
}

fn suricata_pythonpath() -> String {
    discover_python_paths(Path::new(OPT_SURICATA)).join(":")
}

fn discover_python_paths(root: &Path) -> Vec<String> {
    let lib_dir = root.join("lib");
    let mut paths = Vec::new();

    push_python_path(&mut paths, lib_dir.join("python3").join("dist-packages"));
    push_python_path(&mut paths, lib_dir.join("python3").join("site-packages"));
    push_python_path(&mut paths, lib_dir.join("python3"));

    if let Ok(entries) = std::fs::read_dir(&lib_dir) {
        let mut dirs = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_dir()
                    && path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .map(|name| name.starts_with("python3"))
                        .unwrap_or(false)
            })
            .collect::<Vec<PathBuf>>();
        dirs.sort();

        for dir in dirs {
            push_python_path(&mut paths, dir.join("dist-packages"));
            push_python_path(&mut paths, dir.join("site-packages"));
            push_python_path(&mut paths, dir);
        }
    }

    if paths.is_empty() {
        paths.push(lib_dir.join("python3").join("dist-packages"));
    }

    paths
        .into_iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect()
}

fn push_python_path(paths: &mut Vec<PathBuf>, candidate: PathBuf) {
    if candidate.is_dir() && !paths.iter().any(|seen| seen == &candidate) {
        paths.push(candidate);
    }
}

async fn reload_or_restart_suricata() -> ThreatResult<()> {
    let mut last_error = None;

    for args in [["reload", "suricata"], ["restart", "suricata"]] {
        let output = Command::new("systemctl")
            .args(args)
            .kill_on_drop(true)
            .output()
            .await
            .map_err(map_spawn_error)?;

        if output.status.success() {
            return Ok(());
        }

        last_error = Some(command_failure_detail(
            output.status.code(),
            &output.stdout,
            &output.stderr,
            "Guardian service reload/restart failed without diagnostic output",
        ));
    }

    Err(ThreatError::ServiceStart(last_error.unwrap_or_else(|| {
        "Guardian service reload/restart failed".to_string()
    })))
}

fn command_failure_detail(
    status_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    fallback: &str,
) -> String {
    let mut details = vec![match status_code {
        Some(code) => format!("exit {}", code),
        None => "terminated by signal".to_string(),
    }];

    let stderr = summarized_output(stderr);
    if !stderr.is_empty() {
        details.push(format!("stderr: {}", stderr));
    }

    let stdout = summarized_output(stdout);
    if !stdout.is_empty() {
        details.push(format!("stdout: {}", stdout));
    }

    if details.len() == 1 {
        details.push(fallback.to_string());
    }

    details.join(" | ")
}

fn summarized_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join(" | ")
}

fn map_spawn_error(err: std::io::Error) -> ThreatError {
    if err.kind() == ErrorKind::NotFound {
        ThreatError::BinaryMissing
    } else {
        ThreatError::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        command_failure_detail, discover_python_paths, map_spawn_error,
        reload_or_restart_suricata, summarized_output, RuleManager,
    };
    use crate::threat::error::ThreatError;
    use tempfile::tempdir;

    #[test]
    fn command_failure_detail_includes_exit_and_streams() {
        let detail = command_failure_detail(
            Some(2),
            b"line one\nline two\n",
            b"bad config\n",
            "fallback",
        );
        assert!(detail.contains("exit 2"));
        assert!(detail.contains("stderr: bad config"));
        assert!(detail.contains("stdout: line one | line two"));
    }

    #[test]
    fn command_failure_detail_uses_fallback_for_blank_output() {
        let detail = command_failure_detail(Some(1), b"", b"\n", "fallback detail");
        assert_eq!(detail, "exit 1 | fallback detail");
    }

    #[test]
    fn discover_python_paths_supports_dist_and_versioned_layouts() {
        let dir = tempdir().expect("tempdir");
        let lib = dir.path().join("lib");
        std::fs::create_dir_all(lib.join("python3").join("dist-packages")).expect("python3 dist");
        std::fs::create_dir_all(lib.join("python3.11").join("site-packages"))
            .expect("python3.11 site");

        let paths = discover_python_paths(dir.path());

        assert_eq!(
            paths,
            vec![
                lib.join("python3")
                    .join("dist-packages")
                    .to_string_lossy()
                    .to_string(),
                lib.join("python3").to_string_lossy().to_string(),
                lib.join("python3.11")
                    .join("site-packages")
                    .to_string_lossy()
                    .to_string(),
                lib.join("python3.11").to_string_lossy().to_string(),
            ]
        );
    }

    #[test]
    fn discover_python_paths_falls_back_to_the_default_dist_packages_path_when_nothing_exists() {
        let dir = tempdir().expect("tempdir");
        // No `lib/` directory created at all -- every candidate misses, so
        // the function falls back to a single synthesized default path.
        let paths = discover_python_paths(dir.path());
        assert_eq!(
            paths,
            vec![dir
                .path()
                .join("lib")
                .join("python3")
                .join("dist-packages")
                .to_string_lossy()
                .to_string()]
        );
    }

    #[test]
    fn summarized_output_trims_blank_lines_and_caps_at_three() {
        let text = "\n  first  \nsecond\n\nthird\nfourth\n";
        assert_eq!(summarized_output(text.as_bytes()), "first | second | third");
        assert_eq!(summarized_output(b""), "");
        assert_eq!(summarized_output(b"\n\n  \n"), "");
    }

    #[test]
    fn map_spawn_error_distinguishes_missing_binary_from_other_io_errors() {
        let not_found = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        assert!(matches!(
            map_spawn_error(not_found),
            ThreatError::BinaryMissing
        ));

        let denied = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        assert!(matches!(map_spawn_error(denied), ThreatError::Io(_)));
    }

    #[tokio::test]
    async fn update_rules_returns_binary_missing_when_suricata_update_is_not_installed() {
        // `/opt/suricata` genuinely does not exist in this sandbox, so this
        // exercises the real, deterministic "not installed" branch rather
        // than a mocked one.
        let err = RuleManager::update_rules("nodeA")
            .await
            .expect_err("suricata-update is not installed here");
        assert!(matches!(err, ThreatError::BinaryMissing));
    }

    #[tokio::test]
    async fn validate_config_returns_binary_missing_when_suricata_is_not_installed() {
        let err = RuleManager::validate_config("/etc/suricata/suricata.yaml")
            .await
            .expect_err("suricata binary is not installed here");
        assert!(matches!(err, ThreatError::BinaryMissing));
    }

    #[tokio::test]
    async fn reload_or_restart_suricata_surfaces_a_real_systemctl_failure() {
        // `systemctl` itself is present in this sandbox, but there is no
        // running systemd/D-Bus session to authenticate against, so both the
        // "reload" and "restart" attempts fail deterministically and fast --
        // a real command-execution failure, not a mock.
        let err = reload_or_restart_suricata()
            .await
            .expect_err("no systemd session is available in this sandbox");
        assert!(matches!(err, ThreatError::ServiceStart(_)));
    }
}
