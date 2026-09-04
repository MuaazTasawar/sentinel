mod verify;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "sentinel-cli", about = "Sentinel vault admin tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Unseal a node using a quorum of hardware keys (Phase 4).
    Unseal,
    /// Verify the tamper-evident audit log chain.
    Verify {
        /// Path to the JSON-encoded audit log to check.
        #[arg(default_value = "audit-log.json")]
        path: PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Unseal => {
            println!("unseal: not yet implemented (Phase 4)");
            Ok(())
        }
        Commands::Verify { path } => verify::run(path),
    }
}