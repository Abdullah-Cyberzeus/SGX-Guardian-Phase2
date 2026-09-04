use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{watch, Mutex};
use tokio::time::{self, Duration};

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessStatus {
    Starting,
    Running,
    Stopped,
    Crashed,
}
use std::sync::atomic::{AtomicBool, Ordering};

fn status_after_exit(is_stopping: bool) -> ProcessStatus {
    if is_stopping {
        ProcessStatus::Stopped
    } else {
        ProcessStatus::Crashed
    }
}

pub struct ProcessRunner {
    command: String,
    args: Vec<String>,
    child: Arc<Mutex<Option<Child>>>,
    status_sender: watch::Sender<ProcessStatus>,
    status_receiver: watch::Receiver<ProcessStatus>,
    stopping: Arc<AtomicBool>,
}

impl ProcessRunner {
    /// Creates a new asynchronous process runner
    pub fn new(command: String, args: Vec<String>) -> Self {
        let (tx, rx) = watch::channel(ProcessStatus::Stopped);
        ProcessRunner {
            command,
            args,
            child: Arc::new(Mutex::new(None)),
            status_sender: tx,
            status_receiver: rx,
            stopping: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Allows external modules (like ap.rs) to subscribe to status changes
    pub fn subscribe(&self) -> watch::Receiver<ProcessStatus> {
        self.status_receiver.clone()
    }

    /// Gets the current status of the process
    pub fn get_status(&self) -> ProcessStatus {
        self.status_receiver.borrow().clone()
    }

    /// Spawns the process asynchronously and sets up log/status monitoring
    pub async fn start(&self) -> Result<(), std::io::Error> {
        let mut child_guard = self.child.lock().await;

        if child_guard.is_some() {
            return Ok(()); // Already running
        }

        self.stopping.store(false, Ordering::SeqCst);
        let _ = self.status_sender.send(ProcessStatus::Starting);

        let child_result = Command::new(&self.command)
            .args(&self.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true) // Ensure child is killed if ProcessRunner is dropped
            .spawn();

        let mut child = match child_result {
            Ok(child) => child,
            Err(error) => {
                let _ = self.status_sender.send(ProcessStatus::Crashed);
                return Err(error);
            }
        };

        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");

        let cmd_name_out = self.command.clone();
        // Spawn async task to capture and forward stdout — file-only via daemon target
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                tracing::info!(target: "sgx_guardian_client::daemon", "{} STDOUT: {}", cmd_name_out, line);
            }
        });

        let cmd_name_err = self.command.clone();
        // Spawn async task to capture and forward stderr — file-only via daemon target
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                tracing::warn!(target: "sgx_guardian_client::daemon", "{} STDERR: {}", cmd_name_err, line);
            }
        });

        *child_guard = Some(child);
        let _ = self.status_sender.send(ProcessStatus::Running);

        // Spawn async task to monitor process exits/crashes
        // The monitor must not keep a daemon alive after its owning orchestrator is
        // dropped (for example when a transition task is aborted). The Child uses
        // kill_on_drop, so a weak reference preserves that ownership boundary.
        let child_ref = Arc::downgrade(&self.child);
        let status_tx = self.status_sender.clone();
        let cmd_name_exit = self.command.clone();
        let stopping_flag = Arc::clone(&self.stopping);

        tokio::spawn(async move {
            loop {
                let Some(child_arc) = child_ref.upgrade() else {
                    break;
                };
                let mut status_opt = None;
                let mut is_running = true;

                {
                    let mut monitor_child = child_arc.lock().await;
                    if let Some(c) = monitor_child.as_mut() {
                        match c.try_wait() {
                            Ok(Some(status)) => status_opt = Some(Ok(status)),
                            Ok(None) => {} // Still running
                            Err(e) => status_opt = Some(Err(e)),
                        }
                    } else {
                        // Child was taken by stop() or already cleared
                        is_running = false;
                    }
                }

                if let Some(result) = status_opt {
                    // Clear the child process from state since it has exited
                    let mut monitor_child = child_arc.lock().await;
                    *monitor_child = None;
                    drop(monitor_child);

                    let is_stopping = stopping_flag.load(Ordering::SeqCst);
                    let next_status = status_after_exit(is_stopping);
                    match result {
                        Ok(status) if is_stopping => {
                            tracing::debug!("{} stopped with status {}", cmd_name_exit, status);
                        }
                        Ok(status) => {
                            tracing::warn!(
                                target: "sgx_guardian_client::daemon",
                                "{} exited unexpectedly with status {}",
                                cmd_name_exit,
                                status
                            );
                        }
                        Err(error) if is_stopping => {
                            tracing::debug!(
                                "Failed waiting for {} during shutdown: {}",
                                cmd_name_exit,
                                error
                            );
                        }
                        Err(error) => {
                            tracing::warn!(
                                target: "sgx_guardian_client::daemon",
                                "Failed waiting for {}: {}",
                                cmd_name_exit,
                                error
                            );
                        }
                    }
                    let _ = status_tx.send(next_status);
                    break;
                }

                if !is_running {
                    break;
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        Ok(())
    }

    /// Gracefully stops the process
    pub async fn stop(&self) -> Result<(), std::io::Error> {
        self.stopping.store(true, Ordering::SeqCst);
        let mut child_guard = self.child.lock().await;

        if let Some(mut child) = child_guard.take() {
            if let Some(pid) = child.id() {
                // Send graceful SIGTERM first so hostapd broadcasts de-auth frames to connected clients
                let _ = std::process::Command::new("kill")
                    .arg("-TERM")
                    .arg(pid.to_string())
                    .status();

                // Allow a brief window for de-auth frames to physically transmit
                let _ = tokio::time::timeout(std::time::Duration::from_millis(1500), child.wait())
                    .await;
            }

            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        let _ = self.status_sender.send(ProcessStatus::Stopped);
        Ok(())
    }

    /// Sends a SIGHUP signal to the running process to trigger a configuration reload.
    pub async fn send_sighup(&self) -> Result<(), std::io::Error> {
        let child_guard = self.child.lock().await;
        if let Some(child) = child_guard.as_ref() {
            if let Some(pid) = child.id() {
                let status = std::process::Command::new("kill")
                    .arg("-HUP")
                    .arg(pid.to_string())
                    .status()?;
                if !status.success() {
                    return Err(std::io::Error::other(format!(
                        "Failed to send SIGHUP to {} (pid {})",
                        self.command, pid
                    )));
                }
                tracing::info!("Sent SIGHUP to {} (pid {})", self.command, pid);
            }
        }
        Ok(())
    }

    pub async fn send_signal(&self, signal: &str) -> Result<(), std::io::Error> {
        let child_guard = self.child.lock().await;
        let pid = child_guard
            .as_ref()
            .and_then(Child::id)
            .ok_or_else(|| std::io::Error::other(format!("{} is not running", self.command)))?;
        let status = std::process::Command::new("kill")
            .arg(format!("-{}", signal))
            .arg(pid.to_string())
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "failed to send {} to {} (pid {})",
                signal, self.command, pid
            )))
        }
    }

    /// Supports restart handling by stopping and then starting again
    pub async fn restart(&self) -> Result<(), std::io::Error> {
        self.stop().await?;
        // Small delay to ensure resources (like the wifi interface) are fully released
        time::sleep(Duration::from_millis(500)).await;
        self.start().await
    }

    /// Spawns a background task that monitors the process status and automatically restarts it if it crashes.
    pub fn enable_auto_restart(self: Arc<Self>) {
        let mut rx = self.subscribe();
        let runner = Arc::downgrade(&self);

        tokio::spawn(async move {
            'status_loop: while rx.changed().await.is_ok() {
                let Some(active_runner) = runner.upgrade() else {
                    break;
                };

                if *rx.borrow() == ProcessStatus::Stopped
                    && active_runner.stopping.load(Ordering::SeqCst)
                {
                    break;
                }

                if *rx.borrow() == ProcessStatus::Crashed {
                    tracing::warn!(target: "sgx_guardian_client::daemon",
                        "🔥 {} process exited unexpectedly; starting recovery...",
                        active_runner.command
                    );
                    drop(active_runner);

                    let mut retry_delay = Duration::from_secs(2);
                    loop {
                        tokio::time::sleep(retry_delay).await;
                        let Some(active_runner) = runner.upgrade() else {
                            break 'status_loop;
                        };
                        if active_runner.stopping.load(Ordering::SeqCst) {
                            break 'status_loop;
                        }

                        match active_runner.start().await {
                            Ok(()) => {
                                tracing::info!(
                                    target: "sgx_guardian_client::daemon",
                                    "✅ {} process successfully auto-restarted.",
                                    active_runner.command
                                );
                                break;
                            }
                            Err(error) => {
                                tracing::warn!(
                                    target: "sgx_guardian_client::daemon",
                                    "Failed to auto-restart {}: {}; retrying in {}s",
                                    active_runner.command,
                                    error,
                                    retry_delay.as_secs()
                                );
                                retry_delay =
                                    std::cmp::min(retry_delay * 2, Duration::from_secs(30));
                            }
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tempfile::TempDir;

    #[test]
    fn unexpected_clean_exit_is_a_crash_for_managed_daemons() {
        assert_eq!(status_after_exit(false), ProcessStatus::Crashed);
    }

    #[test]
    fn intentional_stop_remains_stopped() {
        assert_eq!(status_after_exit(true), ProcessStatus::Stopped);
    }

    /// Waits (bounded by a real 5s timeout, driven by the watch channel rather
    /// than a polling sleep) until the runner's status matches `expected`.
    async fn wait_for_status(rx: &mut watch::Receiver<ProcessStatus>, expected: ProcessStatus) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if *rx.borrow() == expected {
                    return;
                }
                rx.changed().await.expect("status watch channel closed unexpectedly");
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for status {:?}", expected));
    }

    #[tokio::test]
    async fn start_success_reports_running_then_stop_reports_stopped() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);

        runner.start().await.expect("spawning sleep must succeed");
        assert_eq!(runner.get_status(), ProcessStatus::Running);

        runner.stop().await.expect("stop must succeed");
        assert_eq!(runner.get_status(), ProcessStatus::Stopped);
    }

    #[tokio::test]
    async fn start_missing_binary_returns_error_and_marks_crashed() {
        let runner = ProcessRunner::new(
            "definitely-not-a-real-sgx-guardian-binary".to_string(),
            vec![],
        );

        let err = runner
            .start()
            .await
            .expect_err("spawning a missing binary must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(runner.get_status(), ProcessStatus::Crashed);
    }

    #[tokio::test]
    async fn duplicate_start_is_idempotent_and_does_not_respawn() {
        let dir = TempDir::new().expect("tempdir");
        let marker = dir.path().join("marker.txt");
        let script = format!("echo run >> {} ; sleep 5", marker.display());
        let runner = ProcessRunner::new("sh".to_string(), vec!["-c".to_string(), script]);

        // `start()` returns as soon as the child is spawned, not once the shell
        // has actually run `echo`. Waiting for the marker makes "the first
        // process really ran" an explicit precondition — without it, a loaded
        // machine could have `stop()` kill the child before it was ever
        // scheduled, leaving an empty marker and failing the count below for a
        // reason that has nothing to do with duplicate starts.
        async fn marker_lines(path: &std::path::Path) -> usize {
            tokio::fs::read_to_string(path)
                .await
                .unwrap_or_default()
                .lines()
                .count()
        }

        async fn await_marker_lines(path: &std::path::Path, expected: usize) {
            for _ in 0..100 {
                if marker_lines(path).await >= expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            panic!(
                "marker never reached {expected} line(s); saw {}",
                marker_lines(path).await
            );
        }

        runner.start().await.expect("first start succeeds");
        assert_eq!(runner.get_status(), ProcessStatus::Running);
        await_marker_lines(&marker, 1).await;

        // A second call while already running must be a pure no-op: Ok(()), no new spawn.
        runner.start().await.expect("duplicate start remains Ok");
        assert_eq!(runner.get_status(), ProcessStatus::Running);

        // Give a second process time to appear if the no-op were broken, so a
        // regression here fails rather than racing past unnoticed.
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            marker_lines(&marker).await,
            1,
            "duplicate start must not spawn a second process"
        );

        runner.stop().await.expect("stop succeeds");
        assert_eq!(
            marker_lines(&marker).await,
            1,
            "stopping must not have spawned anything either"
        );
    }

    #[tokio::test]
    async fn duplicate_stop_and_stop_without_start_are_safe_noops() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);

        // Stopping before ever starting must not panic or error.
        runner.stop().await.expect("stop without start is a noop");
        assert_eq!(runner.get_status(), ProcessStatus::Stopped);

        runner.start().await.expect("start succeeds");
        assert_eq!(runner.get_status(), ProcessStatus::Running);

        runner.stop().await.expect("first stop succeeds");
        assert_eq!(runner.get_status(), ProcessStatus::Stopped);

        // A second stop call on an already-stopped runner must also be a safe noop.
        runner.stop().await.expect("duplicate stop remains Ok");
        assert_eq!(runner.get_status(), ProcessStatus::Stopped);
    }

    #[tokio::test]
    async fn unexpected_nonzero_exit_without_stop_is_reported_crashed() {
        let runner = ProcessRunner::new("sh".to_string(), vec!["-c".to_string(), "exit 7".to_string()]);
        let mut rx = runner.subscribe();

        runner.start().await.expect("start succeeds");
        wait_for_status(&mut rx, ProcessStatus::Crashed).await;
        assert_eq!(runner.get_status(), ProcessStatus::Crashed);
    }

    #[tokio::test]
    async fn unexpected_clean_exit_without_stop_is_still_reported_crashed() {
        // Exit code 0 does not matter: an exit that Guardian did not request
        // (stopping == false) is always treated as a crash for managed daemons.
        let runner = ProcessRunner::new("sh".to_string(), vec!["-c".to_string(), "exit 0".to_string()]);
        let mut rx = runner.subscribe();

        runner.start().await.expect("start succeeds");
        wait_for_status(&mut rx, ProcessStatus::Crashed).await;
        assert_eq!(runner.get_status(), ProcessStatus::Crashed);
    }

    #[tokio::test]
    async fn send_sighup_to_unhandled_process_terminates_it_and_marks_crashed() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);
        let mut rx = runner.subscribe();

        runner.start().await.expect("start succeeds");
        assert_eq!(runner.get_status(), ProcessStatus::Running);

        // `sleep` installs no SIGHUP handler, so the default disposition (terminate)
        // applies; the exit is unexpected from Guardian's point of view since stop()
        // was never called, so it must surface as Crashed, not Stopped.
        runner
            .send_sighup()
            .await
            .expect("SIGHUP delivery to a live process must succeed");

        wait_for_status(&mut rx, ProcessStatus::Crashed).await;
    }

    #[tokio::test]
    async fn send_sighup_when_not_running_is_a_noop_ok() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);
        runner
            .send_sighup()
            .await
            .expect("SIGHUP against a never-started runner is a harmless noop");
    }

    #[tokio::test]
    async fn send_signal_errors_when_process_is_not_running() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);
        let err = runner
            .send_signal("TERM")
            .await
            .expect_err("signaling a never-started runner must fail");
        assert!(err.to_string().contains("is not running"));
    }

    #[tokio::test]
    async fn send_signal_reports_failure_for_an_invalid_signal_name() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);
        runner.start().await.expect("start succeeds");

        let err = runner
            .send_signal("NOT_A_REAL_SIGNAL")
            .await
            .expect_err("kill must reject an unknown signal name");
        assert!(err.to_string().contains("failed to send"));

        // The process itself must still be alive/unaffected by the rejected signal.
        assert_eq!(runner.get_status(), ProcessStatus::Running);
        runner.stop().await.expect("cleanup stop succeeds");
    }

    #[tokio::test]
    async fn send_signal_success_leads_to_unexpected_crash() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);
        let mut rx = runner.subscribe();
        runner.start().await.expect("start succeeds");

        runner
            .send_signal("TERM")
            .await
            .expect("sending TERM to a live process must succeed");

        wait_for_status(&mut rx, ProcessStatus::Crashed).await;
    }

    #[tokio::test]
    async fn restart_stops_then_starts_the_process_again() {
        let runner = ProcessRunner::new("sleep".to_string(), vec!["30".to_string()]);
        runner.start().await.expect("initial start succeeds");
        assert_eq!(runner.get_status(), ProcessStatus::Running);

        runner.restart().await.expect("restart succeeds");
        assert_eq!(runner.get_status(), ProcessStatus::Running);

        runner.stop().await.expect("cleanup stop succeeds");
    }

    #[tokio::test]
    async fn auto_restart_recovers_after_a_single_crash() {
        let dir = TempDir::new().expect("tempdir");
        let flag = dir.path().join("started_once");
        // First invocation: touch the flag and exit nonzero (a crash).
        // Second invocation (the auto-restart retry): the flag now exists, so
        // it execs into a long-lived process instead of exiting.
        let script = format!(
            "if [ -f {flag} ]; then exec sleep 30; else touch {flag}; exit 1; fi",
            flag = flag.display()
        );
        let runner = Arc::new(ProcessRunner::new(
            "sh".to_string(),
            vec!["-c".to_string(), script],
        ));
        let mut rx = runner.subscribe();
        runner.clone().enable_auto_restart();

        runner.start().await.expect("first start succeeds");
        wait_for_status(&mut rx, ProcessStatus::Crashed).await;

        // The supervisor task waits out its backoff (2s) and retries; the retry
        // succeeds this time, bringing the runner back to Running.
        wait_for_status(&mut rx, ProcessStatus::Running).await;

        runner.stop().await.expect("cleanup stop succeeds");
    }
}
