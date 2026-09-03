mod config;
mod errors;

use config::NodeConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    let cfg = NodeConfig::load()?;
    tracing::info!(node_id = cfg.node_id, "sentinel node starting (scaffold)");

    // TODO(Phase 1-6): crypto core, storage, audit chain, hardware unseal,
    // and the Raft actor all get constructed and wired in here.
    // TODO(Phase 7): mTLS Axum router + axum::serve with graceful shutdown.

    Ok(())
}