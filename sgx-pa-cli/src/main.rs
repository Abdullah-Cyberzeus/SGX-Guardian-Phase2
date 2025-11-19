mod commands;
mod config;
use clap::{Parser, Subcommand};
use commands::{logs::LogsArgs, sign::SignArgs};

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

#[derive(Subcommand)]
enum Commands {
    /// Show status information for a specific SGX Guardian node
    Status(commands::status::StatusArgs),
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
}
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Status(args) => commands::status::run(args),
        Commands::Logs(args) => commands::logs::run(args),
        Commands::Keygen => commands::keygen::execute(),
        Commands::Sign(args) => commands::sign::execute(args),
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
    }
}
