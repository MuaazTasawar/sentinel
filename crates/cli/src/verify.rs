use std::path::PathBuf;

use sentinel_audit::AuditChain;

/// Loads a JSON-encoded audit chain from disk and verifies its integrity.
/// Prints a clear pass/fail result and the specific break point on
/// failure, and returns a non-zero-exit-worthy error so this is safe to
/// use in scripts/CI (`sentinel-cli verify audit-log.json && deploy.sh`).
pub fn run(path: PathBuf) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("failed to read {}: {e}", path.display()))?;
    let entries = serde_json::from_str(&raw)
        .map_err(|e| anyhow::anyhow!("failed to parse {} as an audit chain: {e}", path.display()))?;
    let chain = AuditChain::from_entries(entries);

    match chain.verify() {
        Ok(()) => {
            println!(
                "chain OK — {} entries, tip hash {}",
                chain.entries().len(),
                hex_encode(&chain.tip_hash())
            );
            Ok(())
        }
        Err(e) => {
            println!("chain INTEGRITY VIOLATION: {e}");
            Err(anyhow::anyhow!("audit chain verification failed: {e}"))
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_audit::AuditChain as Chain;

    fn write_chain(path: &std::path::Path, chain: &Chain) {
        let json = serde_json::to_string_pretty(chain.entries()).unwrap();
        std::fs::write(path, json).unwrap();
    }

    #[test]
    fn verifies_a_clean_chain_file() {
        let mut chain = Chain::new();
        chain.append("node started");
        chain.append("secret written: db-password");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        write_chain(&path, &chain);

        assert!(run(path).is_ok());
    }

    #[test]
    fn rejects_a_tampered_chain_file() {
        let mut chain = Chain::new();
        chain.append("node started");
        chain.append("secret written: db-password");

        // Simulate a tampered file: parse back, mutate, re-write.
        let json = serde_json::to_string(chain.entries()).unwrap();
        let mut entries: Vec<sentinel_audit::AuditEntry> = serde_json::from_str(&json).unwrap();
        entries[1].event = "secret written: something-else".to_string();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        std::fs::write(&path, serde_json::to_string_pretty(&entries).unwrap()).unwrap();

        assert!(run(path).is_err());
    }
}