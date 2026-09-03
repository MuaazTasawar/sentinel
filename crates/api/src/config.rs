use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    /// This node's unique id within the Raft cluster.
    pub node_id: u64,
    /// Address the client-facing mTLS API binds to.
    pub api_bind_addr: String,
    /// Address the Raft peer RPC listener binds to.
    pub raft_bind_addr: String,
    /// Static list of peer addresses for cluster bootstrap.
    pub peers: Vec<String>,
    /// Path to the sled storage directory.
    pub storage_path: String,
    /// Path to this node's TLS certificate.
    pub tls_cert_path: String,
    /// Path to this node's TLS private key.
    pub tls_key_path: String,
    /// Path to the CA cert used to verify client/peer certs (mTLS).
    pub ca_cert_path: String,
}

impl NodeConfig {
    pub fn load() -> anyhow::Result<Self> {
        let cfg = config::Config::builder()
            .add_source(config::Environment::with_prefix("SENTINEL").separator("__"))
            .add_source(config::File::with_name(".env").required(false))
            .build()?;
        Ok(cfg.try_deserialize()?)
    }
}