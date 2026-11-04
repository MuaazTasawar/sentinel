mod init;
mod pki;
mod unseal;
mod verify;

use std::collections::HashMap;
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
    /// Verify the tamper-evident audit log chain (the node's audit file).
    Verify {
        /// The audit log: the node's JSON-lines file, or a JSON-array export.
        #[arg(default_value = "audit-log.json")]
        path: PathBuf,
        /// The tip hash recorded elsewhere (e.g. from the dashboard). Catches
        /// entries removed from the END of the log, which the chain alone cannot.
        #[arg(long)]
        expect_tip: Option<String>,
        /// Fail if the log has fewer entries than this.
        #[arg(long)]
        expect_entries: Option<usize>,
        /// Accept a final record cut short by a crash.
        #[arg(long)]
        allow_torn_tail: bool,
    },
    /// Provision a new vault: generate the root key, split it into shares, and
    /// write the canary and one protected share file per holder.
    Init {
        /// A key holder's name. Repeat for each holder.
        #[arg(long = "holder", required = true)]
        holders: Vec<String>,
        /// How many holders must submit a share to unseal.
        #[arg(long)]
        threshold: u8,
        /// Output directory (must not already contain anything).
        #[arg(long)]
        out: PathBuf,
        /// `passphrase` (default) protects each share with its holder's
        /// passphrase; `plain` writes unprotected hex (development only).
        #[arg(long, default_value = "passphrase")]
        format: String,
        /// Read each holder's passphrase from the environment variable
        /// <PREFIX>_<HOLDER> instead of prompting (automation only: passphrases
        /// in the environment are weaker than typed ones).
        #[arg(long)]
        passphrase_env_prefix: Option<String>,
    },
    /// Unseal one share: a holder decrypts their passphrase-protected share
    /// file locally and submits just that share to the node.
    UnsealFile {
        #[command(flatten)]
        node: NodeArgs,
        /// The share-<name>.enc file produced by `init`.
        #[arg(long)]
        file: PathBuf,
        /// Read the passphrase from this environment variable instead of prompting.
        #[arg(long)]
        passphrase_env: Option<String>,
    },
    /// Create or use a certificate authority for the cluster's mTLS.
    #[command(subcommand)]
    Pki(PkiCommand),
}

#[derive(Subcommand)]
enum PkiCommand {
    /// Create a new certificate authority (ca.crt, ca.key).
    Ca {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "Sentinel CA")]
        cn: String,
        #[arg(long, default_value_t = 825)]
        days: u32,
    },
    /// Issue a node or client certificate. The Common Name is the identity the
    /// node's authorization policy (peer_cns, admin_cns, ...) matches on.
    Issue {
        /// Directory holding ca.crt and ca.key.
        #[arg(long)]
        ca: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        cn: String,
        /// `node` (server and client auth) or `client` (client auth only).
        #[arg(long, default_value = "client")]
        kind: String,
        /// DNS name or IP address the certificate is valid for. Repeatable.
        /// Required for `node` certificates.
        #[arg(long = "san")]
        sans: Vec<String>,
        #[arg(long, default_value_t = 90)]
        days: u32,
    },
}

fn passphrase_for(holder: &str, prefix: &Option<String>) -> anyhow::Result<String> {
    if let Some(prefix) = prefix {
        let var = format!("{prefix}_{}", holder.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_"));
        return std::env::var(&var).map_err(|_| anyhow::anyhow!("environment variable {var} is not set"));
    }
    let first = rpassword::prompt_password(format!("Passphrase for {holder} (min {} characters): ", init::MIN_PASSPHRASE_LEN))?;
    let second = rpassword::prompt_password(format!("Repeat passphrase for {holder}: "))?;
    if first != second {
        anyhow::bail!("the two passphrases for {holder} did not match");
    }
    Ok(first)
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
        Commands::Verify { path, expect_tip, expect_entries, allow_torn_tail } => {
            verify::run(path, &verify::VerifyOptions { expect_tip, expect_entries, allow_torn_tail })
        }
        Commands::Init { holders, threshold, out, format, passphrase_env_prefix } => {
            let format = match format.as_str() {
                "passphrase" => init::ShareFormat::Passphrase,
                "plain" => init::ShareFormat::Plain,
                other => anyhow::bail!("unknown --format {other:?}: use `passphrase` or `plain`"),
            };
            let mut passphrases = HashMap::new();
            if format == init::ShareFormat::Passphrase {
                for h in &holders {
                    passphrases.insert(h.clone(), passphrase_for(h, &passphrase_env_prefix)?);
                }
            }
            let report = init::provision(&init::InitParams { holders, threshold, out, format }, &passphrases)?;
            println!("Vault provisioned.");
            println!("  canary:        {}", report.canary_file.display());
            for (holder, path) in &report.share_files {
                println!("  share ({holder}): {}", path.display());
            }
            println!("  instructions:  {}", report.instructions.display());
            println!("The root key was never written to disk. Read the instructions file next.");
            Ok(())
        }
        Commands::UnsealFile { node, file, passphrase_env } => {
            let text = std::fs::read_to_string(&file).map_err(|e| anyhow::anyhow!("failed to read {}: {e}", file.display()))?;
            let passphrase = match passphrase_env {
                Some(var) => std::env::var(&var).map_err(|_| anyhow::anyhow!("environment variable {var} is not set"))?,
                None => rpassword::prompt_password("Passphrase: ")?,
            };
            let (holder, share_bytes) = init::open_share(&text, &passphrase)?;
            let client = NodeClient::connect(&node)?;
            match client.submit_share(&holder, &init::to_hex(&share_bytes))? {
                SubmitOutcome::Unsealed => println!("{holder}: share accepted. Quorum reached: the node is unsealed."),
                SubmitOutcome::Pending { contributed, threshold } => println!("{holder}: share accepted ({contributed}/{threshold} so far)"),
            }
            Ok(())
        }
        Commands::Pki(PkiCommand::Ca { out, cn, days }) => {
            let (crt, key) = pki::create_ca(&out, &cn, days)?;
            println!("CA created:\n  certificate: {}\n  private key: {} (keep this offline and safe)", crt.display(), key.display());
            Ok(())
        }
        Commands::Pki(PkiCommand::Issue { ca, out, cn, kind, sans, days }) => {
            let kind = match kind.as_str() {
                "node" => pki::CertKind::Node,
                "client" => pki::CertKind::Client,
                other => anyhow::bail!("unknown --kind {other:?}: use `node` or `client`"),
            };
            let (crt, key) = pki::issue(&ca, &out, &cn, kind, &sans, days)?;
            println!("issued {cn}:\n  certificate: {}\n  private key: {}", crt.display(), key.display());
            Ok(())
        }
    }
}