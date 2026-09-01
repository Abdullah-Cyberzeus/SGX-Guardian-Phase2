use clap::{Args, Subcommand};
use sgx_guardian_client::api::auth::pairing::build_pairing_proof;
use sgx_guardian_client::did::{DidRecord, DEFAULT_DID_PATH};
use sgx_guardian_client::vc::issue::{load_runtime_key_manager, resolve_runtime_node_id};
use std::io::Write;

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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to start async runtime: {}", e))?;

    rt.block_on(build_pairing_proof(
        &args.pairing_code,
        &node_id,
        &device_did,
        &public_key,
        km,
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
    use super::{build_runtime_pairing_proof, emit_pairing_proof_to_stdout, ProofArgs};

    // `build_runtime_pairing_proof` never reaches its real network call (`build_pairing_proof`)
    // unless node-id resolution, DID loading, and key-manager loading all succeed first — all
    // of which fail deterministically here (no node-id source configured, no DID file), so
    // these tests never touch the network.

    #[test]
    fn build_runtime_pairing_proof_requires_a_node_id() {
        // SGX_GUARDIAN_DID_DOC_PATH is also mutated by diddoc.rs's tests; share its lock so
        // the two files' tests can't race on the same process-global env var.
        let _guard = crate::test_support::DID_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::remove_var("SGX_NODE_ID");
        std::env::remove_var("SGX_GUARDIAN_DID_DOC_PATH");
        let err = build_runtime_pairing_proof(ProofArgs {
            pairing_code: "code123".to_string(),
            node_id: None,
        })
        .expect_err("no node-id source is configured in this sandbox");
        assert!(err.contains("node-id is required"));
    }

    #[test]
    fn build_runtime_pairing_proof_reports_missing_did_file() {
        let _guard = crate::test_support::DID_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let did_path = temp.path().join("does-not-exist.json");
        let old = std::env::var_os("SGX_GUARDIAN_DID_PATH");
        std::env::set_var("SGX_GUARDIAN_DID_PATH", &did_path);

        let err = build_runtime_pairing_proof(ProofArgs {
            pairing_code: "code123".to_string(),
            node_id: Some("nodeTest".to_string()),
        })
        .expect_err("missing DID file");
        assert!(err.contains("failed to load device DID"));

        match old {
            Some(value) => std::env::set_var("SGX_GUARDIAN_DID_PATH", value),
            None => std::env::remove_var("SGX_GUARDIAN_DID_PATH"),
        }
    }

    #[test]
    fn emit_pairing_proof_to_stdout_propagates_the_closures_error() {
        let err = emit_pairing_proof_to_stdout(|| Err::<String, _>("boom".to_string()))
            .expect_err("closure error must propagate");
        assert_eq!(err, "boom");
    }

    #[test]
    fn emit_pairing_proof_to_stdout_writes_a_successful_proof() {
        emit_pairing_proof_to_stdout(|| Ok("fake-proof-json".to_string()))
            .expect("writing a successful proof must succeed");
    }
}
