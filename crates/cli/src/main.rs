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
    /// Verify the tamper-evident audit log chain (Phase 3).
    Verify,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Unseal => println!("unseal: not yet implemented (Phase 4)"),
        Commands::Verify => println!("verify: not yet implemented (Phase 3)"),
    }
    Ok(())
}