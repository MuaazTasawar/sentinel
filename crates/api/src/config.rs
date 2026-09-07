use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub node_id: u64,
    pub api_bind_addr: String,
    pub raft_bind_addr: String,
    pub peers: Vec<String>,
    pub storage_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
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

    /// Parses `peers` (each entry formatted `"<node_id>=<base_url>"`,
    /// e.g. `"2=https://10.0.0.2:8443"`) into a lookup table for
    /// `HttpTransport`. Fails loudly at startup on a malformed entry
    /// rather than silently dropping a peer, since a dropped peer is the
    /// kind of misconfiguration that's easy to miss until an election
    /// mysteriously can't reach quorum.
    pub fn parse_peer_addrs(&self) -> anyhow::Result<std::collections::HashMap<u64, String>> {
        self.peers
            .iter()
            .map(|entry| {
                let (id_str, addr) = entry
                    .split_once('=')
                    .ok_or_else(|| anyhow::anyhow!("malformed peer entry {entry:?}, expected \"<node_id>=<url>\""))?;
                let id: u64 = id_str.parse().map_err(|_| anyhow::anyhow!("invalid node id in peer entry {entry:?}"))?;
                Ok((id, addr.to_string()))
            })
            .collect()
    }
}