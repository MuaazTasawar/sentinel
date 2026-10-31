use std::path::PathBuf;

use anyhow::{bail, Context};
use sentinel_audit::{parse_log, AuditChain};

/// What to check beyond the chain being internally consistent.
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions {
    /// The tip hash recorded somewhere the log's custodian cannot edit (for
    /// example copied from the dashboard). The hash chain alone cannot reveal
    /// that the *newest* entries were cut off the end; this can.
    pub expect_tip: Option<String>,
    /// The number of entries you expect the log to contain (at least).
    pub expect_entries: Option<usize>,
    /// Accept a final record that was cut short (what a crash mid-write
    /// leaves), instead of treating it as a failure.
    pub allow_torn_tail: bool,
}

/// Loads an audit log (the node's JSON-lines file, or a JSON-array export) and
/// verifies it. Prints a clear pass/fail line with the exact break point on
/// failure, and returns an error so it is safe in scripts and CI
/// (`sentinel-cli verify audit.jsonl && deploy.sh`).
pub fn run(path: PathBuf, opts: &VerifyOptions) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    let parsed = parse_log(&raw).map_err(|e| anyhow::anyhow!("failed to parse {} as an audit log: {e}", path.display()))?;

    if parsed.torn_tail {
        if opts.allow_torn_tail {
            println!("note: the final record is incomplete and was ignored (expected only after a crash)");
        } else {
            println!("audit log has an INCOMPLETE FINAL RECORD");
            bail!("the final record in {} is incomplete; rerun with --allow-torn-tail if this log was copied while the node was writing or after a crash", path.display());
        }
    }

    let chain = AuditChain::from_entries(parsed.entries);
    if let Err(e) = chain.verify() {
        println!("chain INTEGRITY VIOLATION: {e}");
        bail!("audit chain verification failed: {e}");
    }
    let tip = hex_encode(&chain.tip_hash());
    println!("chain OK - {} entries, tip hash {tip}", chain.entries().len());

    if let Some(expected) = &opts.expect_tip {
        let expected = expected.trim().to_ascii_lowercase();
        if expected != tip {
            println!("TIP MISMATCH: expected {expected}");
            bail!("the log's tip hash does not match the expected one: entries may have been removed from the end, or the log was replaced");
        }
        println!("tip hash matches the expected value");
    }
    if let Some(min) = opts.expect_entries
        && chain.entries().len() < min {
            println!("TOO FEW ENTRIES: expected at least {min}");
            bail!("the log has {} entries but at least {min} were expected: entries may have been removed", chain.entries().len());
        }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_audit::{open_persistent, AuditChain as Chain};

    fn write_chain(path: &std::path::Path, chain: &Chain) {
        let json = serde_json::to_string_pretty(chain.entries()).unwrap();
        std::fs::write(path, json).unwrap();
    }

    fn opts() -> VerifyOptions {
        VerifyOptions::default()
    }

    #[test]
    fn verifies_a_clean_chain_file() {
        let mut chain = Chain::new();
        chain.append("node started");
        chain.append("secret written: db-password");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        write_chain(&path, &chain);

        assert!(run(path, &opts()).is_ok());
    }

    #[test]
    fn rejects_a_tampered_chain_file() {
        let mut chain = Chain::new();
        chain.append("node started");
        chain.append("secret written: db-password");

        let json = serde_json::to_string(chain.entries()).unwrap();
        let mut entries: Vec<sentinel_audit::AuditEntry> = serde_json::from_str(&json).unwrap();
        entries[1].event = "secret written: something-else".to_string();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.json");
        std::fs::write(&path, serde_json::to_string_pretty(&entries).unwrap()).unwrap();

        assert!(run(path, &opts()).is_err());
    }

    /// The real producer: the exact file a node writes.
    fn node_written_log(dir: &std::path::Path, events: usize) -> (PathBuf, String) {
        let path = dir.join("audit.jsonl");
        let (mut chain, _) = open_persistent(&path).unwrap();
        for i in 0..events {
            chain.append(format!("event {i}"));
        }
        (path, hex_encode(&chain.tip_hash()))
    }

    #[test]
    fn verifies_the_file_a_node_actually_writes() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = node_written_log(dir.path(), 5);
        assert!(run(path, &opts()).is_ok());
    }

    #[test]
    fn a_tampered_node_log_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = node_written_log(dir.path(), 4);
        let text = std::fs::read_to_string(&path).unwrap().replace("event 2", "event X");
        std::fs::write(&path, text).unwrap();
        assert!(run(path, &opts()).is_err());
    }

    #[test]
    fn a_truncated_tail_is_caught_by_the_expected_tip_and_only_by_it() {
        let dir = tempfile::tempdir().unwrap();
        let (path, recorded_tip) = node_written_log(dir.path(), 6);

        // Untouched: passes with the recorded tip.
        let with_tip = VerifyOptions { expect_tip: Some(recorded_tip.to_uppercase()), ..opts() };
        assert!(run(path.clone(), &with_tip).is_ok(), "tip comparison is case-insensitive");

        // An attacker deletes the newest two entries. The chain still verifies...
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: String = text.lines().take(4).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, kept).unwrap();
        assert!(run(path.clone(), &opts()).is_ok(), "the truncated chain is internally consistent");
        // ...but the externally recorded tip, or entry count, exposes it.
        assert!(run(path.clone(), &with_tip).is_err());
        assert!(run(path, &VerifyOptions { expect_entries: Some(6), ..opts() }).is_err());
    }

    #[test]
    fn a_log_with_a_crash_torn_tail_needs_an_explicit_flag() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = node_written_log(dir.path(), 3);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"index\":3,\"timestamp\":\"2026-01-01");
        std::fs::write(&path, text).unwrap();

        assert!(run(path.clone(), &opts()).is_err(), "must not silently accept an incomplete record");
        assert!(run(path, &VerifyOptions { allow_torn_tail: true, ..opts() }).is_ok());
    }

    #[test]
    fn missing_and_garbage_files_are_errors() {
        let dir = tempfile::tempdir().unwrap();
        assert!(run(dir.path().join("nope"), &opts()).is_err());
        let bad = dir.path().join("bad");
        std::fs::write(&bad, "line one\nline two\n").unwrap();
        assert!(run(bad, &opts()).is_err());
    }
}