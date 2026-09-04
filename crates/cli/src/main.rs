mod unseal;
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
    /// Unseal a node using a quorum of hardware keys.
    Unseal {
        /// Number of key holders required (e.g. 2 for "2 of 3").
        #[arg(long)]
        threshold: u8,
        /// Path to a JSON file mapping holder id -> path to their
        /// encrypted Shamir share (produced at provisioning time).
        #[arg(long, default_value = "unseal-manifest.json")]
        manifest: PathBuf,
    },
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
        Commands::Unseal { threshold, manifest } => {
            let raw = std::fs::read_to_string(&manifest)
                .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", manifest.display()))?;
            let manifest_entries: Vec<(String, String)> = serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("failed to parse {}: {e}", manifest.display()))?;
            let encrypted_shares: Vec<(String, Vec<u8>)> = manifest_entries
                .into_iter()
                .map(|(holder, path)| -> anyhow::Result<(String, Vec<u8>)> {
                    let bytes = std::fs::read(&path)
                        .map_err(|e| anyhow::anyhow!("failed to read share for {holder} at {path}: {e}"))?;
                    Ok((holder, bytes))
                })
                .collect::<anyhow::Result<Vec<_>>>()?;

            let kek = unseal::run(threshold, &encrypted_shares)?;
            println!("Reconstructed KEK: {} bytes (not persisted).", kek.len());
            Ok(())
        }
        Commands::Verify { path } => verify::run(path),
    }
}