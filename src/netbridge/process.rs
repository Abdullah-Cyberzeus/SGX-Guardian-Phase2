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

pub struct ProcessRunner {
    command: String,
    args: Vec<String>,
    child: Arc<Mutex<Option<Child>>>,
    status_sender: watch::Sender<ProcessStatus>,
    status_receiver: watch::Receiver<ProcessStatus>,
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

        let _ = self.status_sender.send(ProcessStatus::Starting);

        let mut child = Command::new(&self.command)
            .args(&self.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true) // Ensure child is killed if ProcessRunner is dropped
            .spawn()?;

        let stdout = child.stdout.take().expect("Failed to capture stdout");
        let stderr = child.stderr.take().expect("Failed to capture stderr");

        let cmd_name_out = self.command.clone();
        // Spawn async task to capture and forward stdout
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                tracing::debug!("{} STDOUT: {}", cmd_name_out, line);
            }
        });

        let cmd_name_err = self.command.clone();
        // Spawn async task to capture and forward stderr
        tokio::spawn(async move {
            let mut reader = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                tracing::debug!("{} STDERR: {}", cmd_name_err, line);
            }
        });

        *child_guard = Some(child);
        let _ = self.status_sender.send(ProcessStatus::Running);

        // Spawn async task to monitor process exits/crashes
        let child_arc = Arc::clone(&self.child);
        let status_tx = self.status_sender.clone();
        let cmd_name_exit = self.command.clone();

        tokio::spawn(async move {
            loop {
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
                    match result {
                        Ok(status) => {
                            if status.success() {
                                tracing::debug!("{} exited cleanly", cmd_name_exit);
                                let _ = status_tx.send(ProcessStatus::Stopped);
                            } else {
                                tracing::debug!(
                                    "{} crashed or exited with error: {}",
                                    cmd_name_exit,
                                    status
                                );
                                let _ = status_tx.send(ProcessStatus::Crashed);
                            }
                        }
                        Err(e) => {
                            tracing::debug!("Failed to wait on {} process: {}", cmd_name_exit, e);
                            let _ = status_tx.send(ProcessStatus::Crashed);
                        }
                    }

                    // Clear the child process from state since it has exited
                    let mut monitor_child = child_arc.lock().await;
                    *monitor_child = None;
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
        let runner = Arc::clone(&self);

        tokio::spawn(async move {
            while rx.changed().await.is_ok() {
                if *rx.borrow() == ProcessStatus::Crashed {
                    tracing::warn!(
                        "🔥 {} process crashed! Auto-restarting in 10 seconds...",
                        runner.command
                    );
                    tokio::time::sleep(Duration::from_secs(10)).await;

                    if let Err(e) = runner.restart().await {
                        tracing::debug!("Failed to auto-restart {}: {}", runner.command, e);
                    } else {
                        tracing::debug!(
                            "✅ {} process successfully auto-restarted.",
                            runner.command
                        );
                    }
                }
            }
        });
    }
}
