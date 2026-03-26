//! SGX Guardian Policy Authority CLI tool.
//! Provides commands for viewing logs, signing policies, generating keys,
//! checking node status, and inspecting attested peers.
mod commands;
mod config;
use clap::{Parser, Subcommand};
use commands::{logs::LogsArgs, sign::SignArgs};
/// Top-level CLI definition for the SGX Policy Authority tool.
/// Parses subcommands for key generation, policy signing, logs,
/// peer inspection, and attestation status.
#[derive(Parser)]
#[command(
    name = "sgx-pa-cli",
    about = "SGX Guardian Policy Authority CLI",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
/// Defines all supported sgx-pa-cli subcommands, including policy signing,
/// key generation, node status inspection, log viewing, and peer discovery output.
#[derive(Subcommand)]
enum Commands {
    /// Show status information for a specific SGX Guardian node
    Status(commands::status::StatusArgs),
    /// Show secure boot chain status
    BootStatus,
    /// Show recent logs for a specific node
    Logs(LogsArgs),
    /// Generate a new ECDSA-P256 keypair
    Keygen,
    /// Sign a UEP policy file (YAML or JSON)
    Sign(SignArgs),
    /// List all discovered and attested peers
    Peers,
    /// Show the last attestation result
    Attestation,
    /// Verify a signed policy.sig file
    Verify(commands::verify::VerifyArgs),
    /// Show DKP key history/status
    DkpStatus,
    /// Rotate DKP to next version
    DkpRotate,
    /// Revoke a specific DKP version
    DkpRevoke(commands::dkp_revoke::DkpRevokeArgs),
    /// Emergency rotation of ALL critical keys
    EmergencyRotate,
    /// Show current PCR measurement values
    PcrStatus,
    /// Create golden PCR baseline from current snapshot
    PcrBaselineCreate,
    /// Verify current PCR values against golden baseline
    PcrBaselineVerify,
}
/// Entry point for the SGX Policy Authority CLI.
/// Dispatches the selected subcommand and routes execution
/// to the corresponding handler in the `commands` module.
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Status(args) => commands::status::run(args),
        Commands::BootStatus => commands::boot_status::run(),
        Commands::Logs(args) => commands::logs::run(args),
        Commands::Keygen => commands::keygen::execute(),
        Commands::Sign(args) => commands::sign::execute(args),
        Commands::Verify(args) => {
            if let Err(e) = commands::verify::run(&args) {
                eprintln!("Error: {}", e);
            }
        }
        Commands::Peers => {
            if let Err(e) = commands::peers::run() {
                eprintln!("Error: {}", e);
            }
        }
        Commands::Attestation => {
            if let Err(e) = commands::attestation::run() {
                eprintln!("Error: {}", e);
            }
        }
        Commands::DkpStatus => commands::dkp_status::run(),
        Commands::DkpRotate => commands::dkp_rotate::run(),
        Commands::DkpRevoke(args) => commands::dkp_revoke::run(args),
        Commands::EmergencyRotate => commands::emergency_rotate::run(),
        Commands::PcrStatus => commands::pcr_status::run(),
        Commands::PcrBaselineCreate => commands::pcr_baseline::run_create(),
        Commands::PcrBaselineVerify => commands::pcr_baseline::run_verify(),
    }
}
