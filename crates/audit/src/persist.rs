//! Durable storage for the audit chain: an append-only JSON-lines file, one
//! [`AuditEntry`] per line, fsync'd as each entry is appended.
//!
//! Crash behaviour: a process killed mid-write can leave a final line that is
//! incomplete. [`open_persistent`] recognises exactly that case (an
//! unterminated, unparseable *last* line), cuts it off, and reports that it
//! did so. A bad line anywhere else is corruption or tampering and is refused.
//!
//! What this does and does not prove: the hash chain makes any alteration,
//! insertion or deletion *inside* the log detectable. It cannot, by itself,
//! reveal that the newest entries were chopped off the end; for that, compare
//! the tip hash against a value recorded elsewhere (the dashboard shows it,
//! and `sentinel-cli verify --expect-tip` checks it).

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::{AuditChain, AuditEntry, AuditError, AuditSink};

/// A log parsed from text, plus where the trustworthy part ends.
#[derive(Debug)]
pub struct ParsedLog {
    pub entries: Vec<AuditEntry>,
    /// The final line was incomplete (typically a crash mid-write) and was ignored.
    pub torn_tail: bool,
    /// Number of bytes of the input that are complete, valid records.
    pub good_len: usize,
}

/// Parses either format the project has used: a pretty-printed JSON array
/// (the original export format) or JSON lines (what the node writes).
pub fn parse_log(text: &str) -> Result<ParsedLog, AuditError> {
    if text.trim_start().starts_with('[') {
        let entries: Vec<AuditEntry> =
            serde_json::from_str(text).map_err(|e| AuditError::Malformed { line: 1, reason: e.to_string() })?;
        return Ok(ParsedLog { entries, torn_tail: false, good_len: text.len() });
    }

    let mut entries = Vec::new();
    let mut good_len = 0usize;
    let mut offset = 0usize;
    let segments: Vec<&str> = text.split_inclusive('\n').collect();
    let last = segments.len().saturating_sub(1);
    for (i, segment) in segments.iter().enumerate() {
        let terminated = segment.ends_with('\n');
        let trimmed = segment.trim();
        offset += segment.len();
        if trimmed.is_empty() {
            if terminated {
                good_len = offset;
            }
            continue;
        }
        match serde_json::from_str::<AuditEntry>(trimmed) {
            Ok(entry) => {
                entries.push(entry);
                good_len = offset;
            }
            Err(_) if i == last && !terminated => {
                return Ok(ParsedLog { entries, torn_tail: true, good_len });
            }
            Err(e) => return Err(AuditError::Malformed { line: i + 1, reason: e.to_string() }),
        }
    }
    Ok(ParsedLog { entries, torn_tail: false, good_len })
}

/// Appends entries to a file, one JSON object per line, syncing each one to disk.
#[derive(Debug)]
pub struct FileSink {
    file: File,
}

impl AuditSink for FileSink {
    fn persist(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        let mut line = serde_json::to_string(entry).map_err(|e| AuditError::Io(e.to_string()))?;
        line.push('\n');
        self.file.write_all(line.as_bytes()).map_err(|e| AuditError::Io(e.to_string()))?;
        self.file.sync_data().map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(())
    }
}

/// Opens (creating if needed) the audit file at `path` and returns a verified
/// chain that writes every new entry back to it, plus whether a torn final
/// record had to be discarded.
///
/// Fails, without modifying the file, if the existing log does not verify.
///
/// The file is deliberately NOT opened in append-only mode: on Windows an
/// append-only handle may not be truncated, which would make crash recovery
/// (cutting off a torn final record) fail with "Access is denied". Instead it is
/// opened read+write and positioned at the end before every use.
pub fn open_persistent(path: &Path) -> Result<(AuditChain, bool), AuditError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
        }
    let io = |e: std::io::Error| AuditError::Io(format!("{}: {e}", path.display()));
    let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path).map_err(io)?;

    let mut text = String::new();
    file.read_to_string(&mut text).map_err(io)?;
    let parsed = parse_log(&text)?;

    // Verify before touching the file at all.
    AuditChain::from_entries(parsed.entries.clone()).verify()?;

    if parsed.torn_tail {
        file.set_len(parsed.good_len as u64).map_err(io)?;
        file.sync_all().map_err(io)?;
    } else if !text.is_empty() && !text.ends_with('\n') {
        // A complete final record that merely lacks its newline: add it so the
        // next entry starts on its own line.
        file.seek(SeekFrom::End(0)).map_err(io)?;
        file.write_all(b"\n").map_err(io)?;
        file.sync_data().map_err(io)?;
    }
    file.seek(SeekFrom::End(0)).map_err(io)?;

    let chain = AuditChain::with_sink(parsed.entries, Box::new(FileSink { file }))?;
    Ok((chain, parsed.torn_tail))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        (dir, path)
    }

    #[test]
    fn entries_survive_a_restart_with_the_same_tip() {
        let (_dir, path) = temp_log();
        let tip;
        {
            let (mut chain, torn) = open_persistent(&path).unwrap();
            assert!(!torn && chain.entries().is_empty() && chain.is_persistent());
            chain.append("node started");
            chain.append("secret written: db (by app)");
            chain.append("secret read: db (by app)");
            assert!(chain.is_healthy());
            tip = chain.tip_hash();
        }
        let (chain, torn) = open_persistent(&path).unwrap();
        assert!(!torn);
        assert_eq!(chain.entries().len(), 3);
        assert_eq!(chain.tip_hash(), tip, "the reloaded chain must end at exactly the same hash");
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn the_chain_keeps_growing_correctly_across_restarts() {
        let (_dir, path) = temp_log();
        for round in 0..4 {
            let (mut chain, _) = open_persistent(&path).unwrap();
            assert_eq!(chain.entries().len(), round * 2);
            chain.append(format!("start {round}"));
            chain.append(format!("work {round}"));
            assert!(chain.verify().is_ok());
        }
        let (chain, _) = open_persistent(&path).unwrap();
        assert_eq!(chain.entries().len(), 8);
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn a_torn_final_record_from_a_crash_is_discarded_and_the_rest_survives() {
        let (_dir, path) = temp_log();
        {
            let (mut chain, _) = open_persistent(&path).unwrap();
            chain.append("one");
            chain.append("two");
        }
        // Simulate the process dying halfway through writing record three.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"index\":2,\"timestamp\":\"2026-01-01T00:0").unwrap();
        drop(f);

        let (mut chain, torn) = open_persistent(&path).unwrap();
        assert!(torn, "the recovery must be reported, never silent");
        assert_eq!(chain.entries().len(), 2);
        chain.append("three");
        assert!(chain.verify().is_ok());

        let (again, torn_again) = open_persistent(&path).unwrap();
        assert!(!torn_again);
        assert_eq!(again.entries().len(), 3, "the new entry landed on its own clean line");
    }

    #[test]
    fn a_complete_final_record_missing_only_its_newline_is_kept() {
        let (_dir, path) = temp_log();
        {
            let (mut chain, _) = open_persistent(&path).unwrap();
            chain.append("one");
            chain.append("two");
        }
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.trim_end_matches('\n')).unwrap();

        let (mut chain, torn) = open_persistent(&path).unwrap();
        assert!(!torn);
        assert_eq!(chain.entries().len(), 2);
        chain.append("three");
        let (again, _) = open_persistent(&path).unwrap();
        assert_eq!(again.entries().len(), 3);
    }

    #[test]
    fn a_tampered_entry_makes_the_node_refuse_to_open_the_log() {
        let (_dir, path) = temp_log();
        {
            let (mut chain, _) = open_persistent(&path).unwrap();
            chain.append("secret read: db (by alice)");
            chain.append("secret read: db (by bob)");
        }
        let text = std::fs::read_to_string(&path).unwrap().replace("by alice", "by nobody");
        std::fs::write(&path, &text).unwrap();
        let err = open_persistent(&path).expect_err("a tampered log must be refused");
        assert!(matches!(err, AuditError::HashMismatch { index: 0 }), "got {err:?}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text, "refusing must not modify the evidence");
    }

    #[test]
    fn deleting_or_reordering_entries_inside_the_log_is_detected() {
        let (_dir, path) = temp_log();
        {
            let (mut chain, _) = open_persistent(&path).unwrap();
            for i in 0..4 {
                chain.append(format!("event {i}"));
            }
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        let without_second = [lines[0], lines[2], lines[3]].join("\n") + "\n";
        std::fs::write(&path, without_second).unwrap();
        assert!(open_persistent(&path).is_err(), "a deleted middle entry must break the chain");

        let swapped = [lines[0], lines[2], lines[1], lines[3]].join("\n") + "\n";
        std::fs::write(&path, swapped).unwrap();
        assert!(open_persistent(&path).is_err(), "reordered entries must break the chain");
    }

    #[test]
    fn dropping_the_newest_entries_is_not_detectable_from_the_file_alone() {
        // Honest limitation, pinned by a test: only an externally recorded tip
        // hash can reveal a truncated tail.
        let (_dir, path) = temp_log();
        let full_tip;
        {
            let (mut chain, _) = open_persistent(&path).unwrap();
            for i in 0..4 {
                chain.append(format!("event {i}"));
            }
            full_tip = chain.tip_hash();
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let first_two: String = text.lines().take(2).map(|l| format!("{l}\n")).collect();
        std::fs::write(&path, first_two).unwrap();

        let (chain, torn) = open_persistent(&path).unwrap();
        assert!(!torn && chain.entries().len() == 2, "the truncated log still verifies");
        assert_ne!(chain.tip_hash(), full_tip, "but its tip no longer matches the one recorded elsewhere");
    }

    #[test]
    fn garbage_in_the_middle_of_the_file_is_corruption_not_a_torn_tail() {
        let (_dir, path) = temp_log();
        {
            let (mut chain, _) = open_persistent(&path).unwrap();
            chain.append("one");
            chain.append("two");
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = text.lines().map(String::from).collect();
        lines.insert(1, "this is not json".to_string());
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();
        assert!(matches!(open_persistent(&path), Err(AuditError::Malformed { line: 2, .. })));
    }

    #[test]
    fn both_the_json_array_export_and_json_lines_parse() {
        let mut chain = AuditChain::new();
        chain.append("a");
        chain.append("b");
        let array = serde_json::to_string_pretty(chain.entries()).unwrap();
        let lines: String = chain.entries().iter().map(|e| serde_json::to_string(e).unwrap() + "\n").collect();

        for text in [array, lines] {
            let parsed = parse_log(&text).unwrap();
            assert_eq!(parsed.entries.len(), 2);
            assert!(!parsed.torn_tail);
            assert!(AuditChain::from_entries(parsed.entries).verify().is_ok());
        }
        assert!(parse_log("").unwrap().entries.is_empty());
        assert!(parse_log("\n\n").unwrap().entries.is_empty());
    }

    #[derive(Debug)]
    struct DeadDisk;
    impl AuditSink for DeadDisk {
        fn persist(&mut self, _: &AuditEntry) -> Result<(), AuditError> {
            Err(AuditError::Io("disk full".into()))
        }
    }

    #[test]
    fn a_failing_disk_marks_the_chain_degraded_and_it_stays_degraded() {
        let mut chain = AuditChain::with_sink(vec![], Box::new(DeadDisk)).unwrap();
        assert!(chain.is_healthy());
        chain.append("this one cannot be saved");
        assert!(!chain.is_healthy());
        assert!(chain.degradation().unwrap().contains("disk full"));
        chain.append("later entries keep working in memory");
        assert!(!chain.is_healthy(), "degradation is sticky");
        assert_eq!(chain.entries().len(), 2);
        assert!(chain.verify().is_ok(), "the in-memory chain itself is still consistent");
    }

    #[test]
    fn a_chain_without_a_sink_is_always_healthy() {
        let mut chain = AuditChain::new();
        chain.append("x");
        assert!(chain.is_healthy() && !chain.is_persistent());
    }
}