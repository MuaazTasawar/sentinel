mod unseal;
mod verify;

use std::io::Read;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

use unseal::{NodeArgs, NodeClient, SubmitOutcome};

#[derive(Parser)]
#[command(name = "sentinel-cli", about = "Sentinel vault admin tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Unseal a running node: each key holder touches their YubiKey and the
    /// node verifies the quorum.
    Unseal {
        #[command(flatten)]
        node: NodeArgs,
        /// Path to a JSON file listing `[holder id, path to their encrypted
        /// Shamir share]` pairs (produced at provisioning time).
        #[arg(long, default_value = "unseal-manifest.json")]
        manifest: PathBuf,
    },
    /// Submit one already-decrypted share (hex, read from stdin) without a
    /// YubiKey. For scripted setups and testing: it puts a plaintext share
    /// in your shell, so do not use it where hardware keys are required.
    SubmitShare {
        #[command(flatten)]
        node: NodeArgs,
        /// Label for the key holder submitting this share.
        #[arg(long)]
        holder: String,
    },
    /// Seal a running node immediately (drops its in-memory key).
    Seal {
        #[command(flatten)]
        node: NodeArgs,
    },
    /// Discard a half-finished unseal session on the node.
    ResetUnseal {
        #[command(flatten)]
        node: NodeArgs,
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
        Commands::Unseal { node, manifest } => {
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

            let client = NodeClient::connect(&node)?;
            unseal::run(&client, &encrypted_shares)
        }
        Commands::SubmitShare { node, holder } => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let client = NodeClient::connect(&node)?;
            match client.submit_share(&holder, input.trim())? {
                SubmitOutcome::Unsealed => println!("unsealed"),
                SubmitOutcome::Pending { contributed, threshold } => println!("pending {contributed}/{threshold}"),
            }
            Ok(())
        }
        Commands::Seal { node } => {
            NodeClient::connect(&node)?.seal()?;
            println!("sealed");
            Ok(())
        }
        Commands::ResetUnseal { node } => {
            NodeClient::connect(&node)?.reset_session()?;
            println!("unseal session reset");
            Ok(())
        }
        Commands::Verify { path } => verify::run(path),
    }
}