use clap::{Args, Subcommand};
use sgx_guardian_client::api::auth::pairing::build_pairing_proof;
use sgx_guardian_client::did::{DidRecord, DEFAULT_DID_PATH};
use sgx_guardian_client::vc::issue::{load_runtime_key_manager, resolve_runtime_node_id};
use std::io::Write;
use std::sync::Arc;

const DID_PATH_ENV: &str = "SGX_GUARDIAN_DID_PATH";

#[derive(Args)]
#[command(about = "Device pairing helpers")]
pub struct PairingArgs {
    #[command(subcommand)]
    pub command: PairingCommand,
}

#[derive(Subcommand)]
pub enum PairingCommand {
    /// Build a signed pairing proof from a server-issued pairing code
    Proof(ProofArgs),
}

#[derive(Args)]
pub struct ProofArgs {
    /// Pairing code returned by GET /api/v1/devices/pairing-code
    #[arg(long)]
    pub pairing_code: String,
    /// Local node identifier (defaults to runtime discovery)
    #[arg(long)]
    pub node_id: Option<String>,
}

pub fn run(args: PairingArgs) {
    match args.command {
        PairingCommand::Proof(a) => cmd_proof(a),
    }
}

fn cmd_proof(args: ProofArgs) {
    match emit_pairing_proof_to_stdout(|| build_runtime_pairing_proof(args)) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

fn emit_pairing_proof_to_stdout<F>(build_proof: F) -> Result<(), String>
where
    F: FnOnce() -> Result<String, String>,
{
    let proof = with_stdout_redirected_to_stderr(build_proof)
        .map_err(|e| format!("failed to redirect stdout for pairing proof: {}", e))??;

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{proof}").map_err(|e| format!("failed to write pairing proof: {}", e))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush pairing proof: {}", e))?;
    Ok(())
}

fn build_runtime_pairing_proof(args: ProofArgs) -> Result<String, String> {
    let node_id = args
        .node_id
        .or_else(resolve_runtime_node_id)
        .ok_or_else(|| "node-id is required (pass --node-id or set SGX_NODE_ID)".to_string())?;

    let did_path = runtime_did_path();
    let device_did = DidRecord::load(&did_path)
        .map(|record| record.did)
        .map_err(|e| format!("failed to load device DID from {}: {}", did_path, e))?;

    let km = load_runtime_key_manager(&node_id)
        .map_err(|e| format!("failed to load device key for {}: {}", node_id, e))?;
    let public_key = km
        .pubkey_der()
        .map_err(|e| format!("failed to load device public key: {}", e))?;

    let signer = Arc::new(km);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start async runtime: {}", e))?;

    rt.block_on(build_pairing_proof(
        &args.pairing_code,
        &node_id,
        &device_did,
        &public_key,
        signer,
    ))
    .map_err(|e| format!("failed to build pairing proof: {e}"))
}

fn runtime_did_path() -> String {
    std::env::var(DID_PATH_ENV).unwrap_or_else(|_| DEFAULT_DID_PATH.to_string())
}

#[cfg(unix)]
fn with_stdout_redirected_to_stderr<F, T>(f: F) -> std::io::Result<T>
where
    F: FnOnce() -> T,
{
    use std::io;

    struct StdoutRedirectGuard {
        saved_stdout: libc::c_int,
    }

    impl Drop for StdoutRedirectGuard {
        fn drop(&mut self) {
            let _ = std::io::stdout().flush();
            unsafe {
                libc::dup2(self.saved_stdout, libc::STDOUT_FILENO);
                libc::close(self.saved_stdout);
            }
        }
    }

    unsafe {
        std::io::stdout().flush()?;
        let saved_stdout = libc::dup(libc::STDOUT_FILENO);
        if saved_stdout < 0 {
            return Err(io::Error::last_os_error());
        }
        if libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) < 0 {
            let err = io::Error::last_os_error();
            libc::close(saved_stdout);
            return Err(err);
        }

        let guard = StdoutRedirectGuard { saved_stdout };
        let value = f();
        drop(guard);
        Ok(value)
    }
}

#[cfg(not(unix))]
fn with_stdout_redirected_to_stderr<F, T>(f: F) -> std::io::Result<T>
where
    F: FnOnce() -> T,
{
    Ok(f())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    #[cfg(unix)]
    use std::os::fd::FromRawFd;
    use std::sync::{Mutex, OnceLock};

    #[cfg(unix)]
    fn capture_stdio<F>(f: F) -> (String, String)
    where
        F: FnOnce(),
    {
        let _guard = capture_lock().lock().expect("capture lock");

        unsafe fn make_pipe() -> [libc::c_int; 2] {
            let mut fds = [0; 2];
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0, "create pipe");
            fds
        }

        unsafe {
            let stdout_pipe = make_pipe();
            let stderr_pipe = make_pipe();
            let saved_stdout = libc::dup(libc::STDOUT_FILENO);
            let saved_stderr = libc::dup(libc::STDERR_FILENO);
            assert!(saved_stdout >= 0, "dup stdout");
            assert!(saved_stderr >= 0, "dup stderr");

            assert_eq!(
                libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO),
                libc::STDOUT_FILENO
            );
            assert_eq!(
                libc::dup2(stderr_pipe[1], libc::STDERR_FILENO),
                libc::STDERR_FILENO
            );
            libc::close(stdout_pipe[1]);
            libc::close(stderr_pipe[1]);

            f();

            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();

            assert_eq!(
                libc::dup2(saved_stdout, libc::STDOUT_FILENO),
                libc::STDOUT_FILENO
            );
            assert_eq!(
                libc::dup2(saved_stderr, libc::STDERR_FILENO),
                libc::STDERR_FILENO
            );
            libc::close(saved_stdout);
            libc::close(saved_stderr);

            let mut stdout = String::new();
            let mut stderr = String::new();
            std::fs::File::from_raw_fd(stdout_pipe[0])
                .read_to_string(&mut stdout)
                .expect("read stdout");
            std::fs::File::from_raw_fd(stderr_pipe[0])
                .read_to_string(&mut stderr)
                .expect("read stderr");

            (stdout, stderr)
        }
    }

    #[cfg(unix)]
    fn capture_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[cfg(unix)]
    #[test]
    fn pairing_proof_stdout_is_single_base64url_line() {
        let (stdout, stderr) = capture_stdio(|| {
            emit_pairing_proof_to_stdout(|| {
                let mut noisy_stdout = std::io::stdout().lock();
                writeln!(noisy_stdout, "Existing DKP found...").expect("write status line");
                writeln!(noisy_stdout, "Using existing device identity key...")
                    .expect("write status line");
                noisy_stdout.flush().expect("flush status lines");
                Ok("abcDEF0123_-".to_string())
            })
            .expect("emit proof");
        });

        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines, vec!["abcDEF0123_-"]);
        assert!(lines[0]
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')));
        assert!(stderr.contains("Existing DKP found..."));
        assert!(stderr.contains("Using existing device identity key..."));
    }
}
