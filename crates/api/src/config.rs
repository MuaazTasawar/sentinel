use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// Name of the optional config file, looked up in the working directory.
/// It is always parsed as TOML. (Earlier versions asked the `config` crate
/// to resolve the bare name `.env`, which silently meant "`.env.toml`" and
/// confused everyone; the name is now spelled out.)
pub const CONFIG_FILE: &str = ".env.toml";

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    pub node_id: u64,
    pub api_bind_addr: String,
    /// Peer entries formatted `"<node_id>=<base_url>"`. From the config
    /// file this is a TOML array; from the environment it is a
    /// comma-separated list, e.g.
    /// `SENTINEL__PEERS="2=https://10.0.0.2:8443,3=https://10.0.0.3:8443"`.
    #[serde(default)]
    pub peers: Vec<String>,
    pub storage_path: String,
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub ca_cert_path: String,
    /// How many distinct key holders must submit a share before this node
    /// unseals ("2" means a 2-of-N quorum). It must match the threshold the
    /// shares were created with. Shamir needs at least 2.
    #[serde(default = "default_unseal_threshold")]
    pub unseal_threshold: u8,
    /// Directory for Raft's durable state (term, vote, log). Defaults to
    /// `<storage_path>.raft`. Keep it on durable storage, and never delete it
    /// without also deleting `storage_path` (or the reverse).
    #[serde(default)]
    pub raft_dir: Option<String>,
    /// How long a write waits for a majority of the cluster to commit it.
    #[serde(default = "default_commit_timeout_ms")]
    pub commit_timeout_ms: u64,

    // ---- authorization (see middleware/authz.rs) ----
    /// Certificate Common Names of the other cluster nodes (may call /raft/*).
    #[serde(default)]
    pub peer_cns: Vec<String>,
    /// Common Names allowed to unseal/seal (/sys/*).
    #[serde(default)]
    pub admin_cns: Vec<String>,
    /// Common Names allowed to write/delete (and read) secrets.
    #[serde(default)]
    pub writer_cns: Vec<String>,
    /// Common Names allowed to read/list secrets and view status.
    #[serde(default)]
    pub reader_cns: Vec<String>,
    /// Certificate serial numbers (hex) to refuse after the TLS handshake.
    #[serde(default)]
    pub revoked_serials: Vec<String>,
    /// DEVELOPMENT ONLY: any client with a valid certificate may do anything.
    #[serde(default)]
    pub insecure_allow_any_client: bool,

    // ---- provisioning and audit ----
    /// Where the tamper-evident audit log is written (JSON lines, fsync'd per
    /// entry). Defaults to `<storage_path>.audit.jsonl`.
    #[serde(default)]
    pub audit_path: Option<String>,
    /// The `canary.bin` produced by `sentinel-cli init`. Installed into this
    /// node's storage at startup if it has none; a different canary already in
    /// storage is a startup error (wrong vault / wrong directory).
    #[serde(default)]
    pub canary_file: Option<String>,
    /// DEVELOPMENT ONLY: let the first successful unseal of an empty vault
    /// define the canary (trust on first use). Off by default: a vault must be
    /// provisioned with `sentinel-cli init`.
    #[serde(default)]
    pub allow_canary_bootstrap: bool,
}

fn default_unseal_threshold() -> u8 {
    2
}

fn default_commit_timeout_ms() -> u64 {
    5_000
}

impl NodeConfig {
    pub fn policy_config(&self) -> crate::middleware::authz::PolicyConfig {
        crate::middleware::authz::PolicyConfig {
            peer_cns: self.peer_cns.clone(),
            admin_cns: self.admin_cns.clone(),
            writer_cns: self.writer_cns.clone(),
            reader_cns: self.reader_cns.clone(),
            revoked_serials: self.revoked_serials.clone(),
            insecure_allow_any_client: self.insecure_allow_any_client,
        }
    }

    pub fn audit_path(&self) -> std::path::PathBuf {
        match &self.audit_path {
            Some(path) => std::path::PathBuf::from(path),
            None => std::path::PathBuf::from(format!("{}.audit.jsonl", self.storage_path)),
        }
    }

    pub fn raft_dir(&self) -> std::path::PathBuf {
        match &self.raft_dir {
            Some(dir) => std::path::PathBuf::from(dir),
            None => std::path::PathBuf::from(format!("{}.raft", self.storage_path)),
        }
    }

    /// Loads `.env.toml` (if present) and then the process environment.
    /// Precedence: **environment overrides the file**, which is what every
    /// twelve-factor-style deployment expects. (The previous version had
    /// this backwards: the file silently beat the environment.)
    pub fn load() -> anyhow::Result<Self> {
        Self::build(Some(Path::new(CONFIG_FILE)), None)
    }

    /// Testable core of `load`. `env_override` replaces the real process
    /// environment when `Some`, so tests never have to mutate global state.
    pub(crate) fn build(file: Option<&Path>, env_override: Option<HashMap<String, String>>) -> anyhow::Result<Self> {
        let mut builder = config::Config::builder();
        if let Some(path) = file {
            builder = builder.add_source(config::File::new(&path.to_string_lossy(), config::FileFormat::Toml).required(false));
        }
        let env = config::Environment::with_prefix("SENTINEL")
            .prefix_separator("__")
            .separator("__")
            .list_separator(",")
            .with_list_parse_key("peers")
            .with_list_parse_key("peer_cns")
            .with_list_parse_key("admin_cns")
            .with_list_parse_key("writer_cns")
            .with_list_parse_key("reader_cns")
            .with_list_parse_key("revoked_serials")
            .try_parsing(true)
            .source(env_override);
        builder = builder.add_source(env);
        Ok(builder.build()?.try_deserialize()?)
    }

    /// Parses `peers` (each entry formatted `"<node_id>=<base_url>"`,
    /// e.g. `"2=https://10.0.0.2:8443"`) into a lookup table for
    /// `HttpTransport`. Fails loudly at startup on a malformed entry
    /// rather than silently dropping a peer, since a dropped peer is the
    /// kind of misconfiguration that's easy to miss until an election
    /// mysteriously can't reach quorum.
    pub fn parse_peer_addrs(&self) -> anyhow::Result<HashMap<u64, String>> {
        let mut out = HashMap::new();
        for entry in &self.peers {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            let (id_str, addr) = entry
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("malformed peer entry {entry:?}, expected \"<node_id>=<url>\""))?;
            let id: u64 = id_str
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid node id in peer entry {entry:?}"))?;
            if id == self.node_id {
                anyhow::bail!("peer entry {entry:?} lists this node's own id ({id}); a node must not be its own peer");
            }
            if out.insert(id, addr.trim().to_string()).is_some() {
                anyhow::bail!("duplicate peer id {id} in config");
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn base_env() -> HashMap<String, String> {
        [
            ("SENTINEL__NODE_ID", "1"),
            ("SENTINEL__API_BIND_ADDR", "127.0.0.1:8443"),
            ("SENTINEL__STORAGE_PATH", "data"),
            ("SENTINEL__TLS_CERT_PATH", "pki/node.crt"),
            ("SENTINEL__TLS_KEY_PATH", "pki/node.key"),
            ("SENTINEL__CA_CERT_PATH", "pki/ca.crt"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn peers_can_come_from_a_comma_separated_env_var() {
        let mut env = base_env();
        env.insert("SENTINEL__PEERS".into(), "2=https://10.0.0.2:8443,3=https://10.0.0.3:8443".into());
        let cfg = NodeConfig::build(None, Some(env)).unwrap();
        let peers = cfg.parse_peer_addrs().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[&2], "https://10.0.0.2:8443");
        assert_eq!(peers[&3], "https://10.0.0.3:8443");
    }

    #[test]
    fn a_single_peer_in_env_still_parses_as_a_list() {
        let mut env = base_env();
        env.insert("SENTINEL__PEERS".into(), "2=https://10.0.0.2:8443".into());
        let cfg = NodeConfig::build(None, Some(env)).unwrap();
        assert_eq!(cfg.parse_peer_addrs().unwrap().len(), 1);
    }

    #[test]
    fn missing_peers_means_a_single_node_cluster() {
        let cfg = NodeConfig::build(None, Some(base_env())).unwrap();
        assert!(cfg.parse_peer_addrs().unwrap().is_empty());
    }

    #[test]
    fn environment_overrides_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".env.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            "node_id = 9\napi_bind_addr = \"0.0.0.0:1\"\npeers = [\"2=https://file:1\"]\nstorage_path = \"file-data\"\ntls_cert_path = \"c\"\ntls_key_path = \"k\"\nca_cert_path = \"ca\""
        )
        .unwrap();

        let mut env = HashMap::new();
        env.insert("SENTINEL__NODE_ID".to_string(), "4".to_string());
        let cfg = NodeConfig::build(Some(&path), Some(env)).unwrap();
        assert_eq!(cfg.node_id, 4, "env must beat the file");
        assert_eq!(cfg.storage_path, "file-data", "file values not overridden by env still apply");
        assert_eq!(cfg.parse_peer_addrs().unwrap()[&2], "https://file:1");
    }

    #[test]
    fn unseal_threshold_defaults_to_two_and_can_be_overridden() {
        let cfg = NodeConfig::build(None, Some(base_env())).unwrap();
        assert_eq!(cfg.unseal_threshold, 2);

        let mut env = base_env();
        env.insert("SENTINEL__UNSEAL_THRESHOLD".into(), "3".into());
        assert_eq!(NodeConfig::build(None, Some(env)).unwrap().unseal_threshold, 3);
    }

    #[test]
    fn raft_dir_defaults_next_to_the_storage_dir_and_commit_timeout_has_a_default() {
        let cfg = NodeConfig::build(None, Some(base_env())).unwrap();
        assert_eq!(cfg.raft_dir(), std::path::PathBuf::from("data.raft"));
        assert_eq!(cfg.commit_timeout_ms, 5_000);

        let mut env = base_env();
        env.insert("SENTINEL__RAFT_DIR".into(), "/var/lib/sentinel/raft".into());
        env.insert("SENTINEL__COMMIT_TIMEOUT_MS".into(), "250".into());
        let cfg = NodeConfig::build(None, Some(env)).unwrap();
        assert_eq!(cfg.raft_dir(), std::path::PathBuf::from("/var/lib/sentinel/raft"));
        assert_eq!(cfg.commit_timeout_ms, 250);
    }

    #[test]
    fn authorization_lists_come_from_comma_separated_env_vars_and_default_to_empty_and_secure() {
        let cfg = NodeConfig::build(None, Some(base_env())).unwrap();
        assert!(cfg.admin_cns.is_empty() && cfg.peer_cns.is_empty() && cfg.revoked_serials.is_empty());
        assert!(!cfg.insecure_allow_any_client, "the insecure switch must default to off");

        let mut env = base_env();
        env.insert("SENTINEL__ADMIN_CNS".into(), "root,deputy".into());
        env.insert("SENTINEL__WRITER_CNS".into(), "app-w".into());
        env.insert("SENTINEL__PEER_CNS".into(), "node1,node2,node3".into());
        env.insert("SENTINEL__REVOKED_SERIALS".into(), "00:ab,0xcd".into());
        let cfg = NodeConfig::build(None, Some(env)).unwrap();
        assert_eq!(cfg.admin_cns, vec!["root", "deputy"]);
        assert_eq!(cfg.writer_cns, vec!["app-w"]);
        assert_eq!(cfg.peer_cns.len(), 3);
        let policy = crate::middleware::authz::Policy::new(&cfg.policy_config(), true).unwrap();
        assert!(policy.is_revoked("ab") && policy.is_revoked("CD"));
    }

    #[test]
    fn audit_and_provisioning_settings_default_to_safe_values() {
        let cfg = NodeConfig::build(None, Some(base_env())).unwrap();
        assert_eq!(cfg.audit_path(), std::path::PathBuf::from("data.audit.jsonl"));
        assert!(cfg.canary_file.is_none());
        assert!(!cfg.allow_canary_bootstrap, "trust-on-first-use must be opt-in");

        let mut env = base_env();
        env.insert("SENTINEL__AUDIT_PATH".into(), "/var/log/sentinel/audit.jsonl".into());
        env.insert("SENTINEL__CANARY_FILE".into(), "/etc/sentinel/canary.bin".into());
        env.insert("SENTINEL__ALLOW_CANARY_BOOTSTRAP".into(), "true".into());
        let cfg = NodeConfig::build(None, Some(env)).unwrap();
        assert_eq!(cfg.audit_path(), std::path::PathBuf::from("/var/log/sentinel/audit.jsonl"));
        assert_eq!(cfg.canary_file.as_deref(), Some("/etc/sentinel/canary.bin"));
        assert!(cfg.allow_canary_bootstrap);
    }

    #[test]
    fn malformed_peer_entry_fails_loudly() {
        let mut env = base_env();
        env.insert("SENTINEL__PEERS".into(), "not-a-valid-entry".into());
        let cfg = NodeConfig::build(None, Some(env)).unwrap();
        assert!(cfg.parse_peer_addrs().is_err());
    }

    #[test]
    fn a_node_cannot_list_itself_or_a_peer_twice() {
        let mut env = base_env();
        env.insert("SENTINEL__PEERS".into(), "1=https://self:1".into());
        assert!(NodeConfig::build(None, Some(env)).unwrap().parse_peer_addrs().is_err());

        let mut env = base_env();
        env.insert("SENTINEL__PEERS".into(), "2=https://a:1,2=https://b:1".into());
        assert!(NodeConfig::build(None, Some(env)).unwrap().parse_peer_addrs().is_err());
    }
}