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
    /// Sign a UEP policy file (YAML or JSON) — laptop/legacy flow
    Sign(SignArgs),
    /// Sign a UEP policy with the nodeA-resident PA key and deploy it locally
    /// so it auto-distributes to members through cert bootstrap.
    PolicySignAndDeploy(commands::sign_and_deploy::SignAndDeployArgs),
    /// List all discovered and attested peers
    Peers,
    /// Show the last attestation result
    Attestation,
    /// Generate a signed attestation quote
    AttestGenerate(commands::attest_quote::GenerateQuoteArgs),
    /// Verify a signed attestation quote
    AttestVerify(commands::attest_quote::VerifyQuoteArgs),
    /// Verify a signed policy.sig file
    Verify(commands::verify::VerifyArgs),
    /// Show DKP key history/status
    DkpStatus,
    /// Rotate DKP to next version
    DkpRotate,
    /// Revoke a specific DKP version
    DkpRevoke(commands::dkp_revoke::DkpRevokeArgs),
    /// DID lifecycle and registry operations
    Did(commands::did::DidArgs),
    /// Emergency rotation of ALL critical keys
    EmergencyRotate,
    /// Show current PCR measurement values
    PcrStatus,
    /// Create golden PCR baseline from current snapshot
    PcrBaselineCreate,
    /// Verify current PCR values against golden baseline
    PcrBaselineVerify,
    /// Relay management commands
    Relay(commands::relay::RelayArgs),
    /// List relay nodes
    RelayList,
    /// Show relay stats for a node
    RelayStats(commands::relay::RelayStatsArgs),
    /// Set relay limits for a node
    RelaySetLimit(commands::relay::RelaySetLimitArgs),
    /// Enable/disable relay for a node
    RelayToggle(commands::relay::RelayToggleArgs),
    /// CoT transport management commands
    Transport(commands::transport::TransportArgs),
    /// Alias for `transport list`
    #[command(name = "transport-list")]
    TransportList(commands::transport::TransportListArgs),
    /// Alias for `transport stats`
    #[command(name = "transport-stats")]
    TransportStats(commands::transport::TransportListArgs),
    /// Alias for `transport lock`
    #[command(name = "transport-lock")]
    TransportLock(commands::transport::TransportLockArgs),
    /// Alias for `transport unlock`
    #[command(name = "transport-unlock")]
    TransportUnlock(commands::transport::TransportUnlockArgs),
    /// Alias for `transport show`
    #[command(name = "transport-show")]
    TransportShow(commands::transport::TransportListArgs),
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
        Commands::Sign(args) => {
            if !commands::sign::execute(args) {
                std::process::exit(1);
            }
        }
        Commands::PolicySignAndDeploy(args) => commands::sign_and_deploy::execute(args),
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
        Commands::AttestGenerate(args) => commands::attest_quote::run_generate(args),
        Commands::AttestVerify(args) => commands::attest_quote::run_verify(args),
        Commands::DkpStatus => commands::dkp_status::run(),
        Commands::DkpRotate => commands::dkp_rotate::run(),
        Commands::DkpRevoke(args) => commands::dkp_revoke::run(args),
        Commands::Did(args) => commands::did::run(args),
        Commands::EmergencyRotate => commands::emergency_rotate::run(),
        Commands::PcrStatus => commands::pcr_status::run(),
        Commands::PcrBaselineCreate => commands::pcr_baseline::run_create(),
        Commands::PcrBaselineVerify => commands::pcr_baseline::run_verify(),
        Commands::Relay(args) => {
            if let Err(e) = commands::relay::run(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelayList => {
            if let Err(e) = commands::relay::run_list() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelayStats(args) => {
            if let Err(e) = commands::relay::run_stats(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelaySetLimit(args) => {
            if let Err(e) = commands::relay::run_set_limit(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::RelayToggle(args) => {
            if let Err(e) = commands::relay::run_toggle(args) {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Transport(args) => commands::transport::run(args),
        Commands::TransportList(args) => {
            commands::transport::run(commands::transport::TransportArgs {
                command: commands::transport::TransportCommand::List(args),
            })
        }
        Commands::TransportStats(args) => {
            commands::transport::run(commands::transport::TransportArgs {
                command: commands::transport::TransportCommand::Stats(args),
            })
        }
        Commands::TransportLock(args) => {
            commands::transport::run(commands::transport::TransportArgs {
                command: commands::transport::TransportCommand::Lock(args),
            })
        }
        Commands::TransportUnlock(args) => {
            commands::transport::run(commands::transport::TransportArgs {
                command: commands::transport::TransportCommand::Unlock(args),
            })
        }
        Commands::TransportShow(args) => {
            commands::transport::run(commands::transport::TransportArgs {
                command: commands::transport::TransportCommand::Show(args),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_relay_commands_parse() {
        let c0 = Cli::try_parse_from(["sgx-pa-cli", "relay-list"]);
        assert!(c0.is_ok());

        let c1 = Cli::try_parse_from(["sgx-pa-cli", "relay", "list"]);
        assert!(c1.is_ok());

        let c2 = Cli::try_parse_from([
            "sgx-pa-cli",
            "relay",
            "set-limit",
            "nodeB",
            "--max-peers",
            "10",
            "--max-bandwidth-mbps",
            "20",
        ]);
        assert!(c2.is_ok());

        let c3 = Cli::try_parse_from(["sgx-pa-cli", "relay", "toggle", "nodeC", "--enable"]);
        assert!(c3.is_ok());
    }

    #[test]
    fn test_transport_commands_parse() {
        assert!(Cli::try_parse_from(["sgx-pa-cli", "transport", "list"]).is_ok());
        assert!(Cli::try_parse_from(["sgx-pa-cli", "transport", "stats"]).is_ok());
        assert!(Cli::try_parse_from(["sgx-pa-cli", "transport-list"]).is_ok());
        assert!(Cli::try_parse_from(["sgx-pa-cli", "transport-show"]).is_ok());
        assert!(Cli::try_parse_from(["sgx-pa-cli", "transport-lock", "ens33"]).is_ok());
        assert!(Cli::try_parse_from(["sgx-pa-cli", "transport-unlock"]).is_ok());
    }
}
