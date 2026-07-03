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
            .map_err(|_| ThreatError::ServiceStart("suricata-update timed out (300s)".into()))?
            .map_err(map_spawn_error)?;

        if !output.status.success() {
            return Err(ThreatError::ServiceStart(command_failure_detail(
                output.status.code(),
                &output.stdout,
                &output.stderr,
                "suricata-update exited without any diagnostic output",
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
            &format!("suricata-update: {}", summary),
        );

        Ok(summary)
    }

    pub async fn validate_config(yaml_path: &str) -> ThreatResult<()> {
        let binary = format!("{}/bin/suricata", OPT_SURICATA);

        let fut = Command::new(&binary)
            .args(["-T", "-c", yaml_path])
            .kill_on_drop(true)
            .output();

        let output = timeout(Duration::from_secs(60), fut)
            .await
            .map_err(|_| ThreatError::BadConfig("suricata config-test timed out (60s)".into()))?
            .map_err(map_spawn_error)?;

        if output.status.success() {
            return Ok(());
        }

        Err(ThreatError::BadConfig(command_failure_detail(
            output.status.code(),
            &output.stdout,
            &output.stderr,
            "suricata config validation failed without diagnostic output",
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
            "systemctl reload/restart suricata failed without diagnostic output",
        ));
    }

    Err(ThreatError::ServiceStart(last_error.unwrap_or_else(|| {
        "systemctl reload/restart suricata failed".to_string()
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
    use super::{command_failure_detail, discover_python_paths};
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
}
