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
    use super::{status_after_exit, ProcessStatus};

    #[test]
    fn unexpected_clean_exit_is_a_crash_for_managed_daemons() {
        assert_eq!(status_after_exit(false), ProcessStatus::Crashed);
    }

    #[test]
    fn intentional_stop_remains_stopped() {
        assert_eq!(status_after_exit(true), ProcessStatus::Stopped);
    }
}
