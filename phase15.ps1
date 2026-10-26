# Sentinel - Phase 15: Raft persistence, commit-gated writes, replicated seal
#
# Run from the project root (the folder containing Cargo.toml):
#     powershell -ExecutionPolicy Bypass -File .\phase15.ps1
#
# Writes 14 files (UTF-8, no BOM, LF line endings) and then verifies every one
# against the SHA-256 of the exact version that was compiled and tested.
# Nothing outside those 14 paths is touched.

param([string]$Root = (Get-Location).Path)
$ErrorActionPreference = 'Stop'

if (-not ((Test-Path (Join-Path $Root 'Cargo.toml')) -and (Test-Path (Join-Path $Root 'crates')))) {
  Write-Host "This does not look like the Sentinel project root: $Root" -ForegroundColor Red
  Write-Host "cd into the folder that contains Cargo.toml and crates\, then run again." -ForegroundColor Red
  exit 1
}

function Write-SentinelFile([string]$Path, [string]$Content) {
  $full = Join-Path $Root $Path
  $dir  = Split-Path $full -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
  $lf = $Content -replace "`r`n", "`n"
  [System.IO.File]::WriteAllText($full, $lf, (New-Object System.Text.UTF8Encoding($false)))
  Write-Host "wrote $Path"
}

Write-SentinelFile 'crates\consensus\Cargo.toml' @'
[package]
name = "sentinel-consensus"
version.workspace = true
edition.workspace = true
license.workspace = true
authors.workspace = true

[dependencies]
async-trait = "0.1.92"
bincode = "1.3"
rand = "0.8"
serde = { version = "1.0.229", features = ["derive"] }
serde_json = "1.0.151"
thiserror = "2.0.20"
tokio = { version = "1.53.1", features = ["full"] }
tracing = "0.1.44"

[dev-dependencies]
serde_json = "1.0.151"
tempfile = "3"
'@

Write-SentinelFile 'crates\consensus\src\lib.rs' @'
pub mod actor;
pub mod log;
pub mod persist;
pub mod rpc;
pub mod state;

pub use actor::{
    spawn_raft_actor, spawn_raft_actor_persistent, spawn_raft_actor_with_apply, ElectionTimeoutRange, RaftHandle,
    Transport, TransportError,
};
pub use log::{LogEntry, LogError, LogOp, ReplicatedLog};
pub use persist::{FileStore, MemoryStore, PersistError, PersistedState, RaftStore};
pub use rpc::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};
pub use state::{RaftState, ReplicationOutcome, Role, MAX_ENTRIES_PER_APPEND};

#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("not the leader")]
    NotLeader,
    #[error("term mismatch: local {local}, remote {remote}")]
    TermMismatch { local: u64, remote: u64 },
    /// The proposal was appended but not confirmed committed in time. It
    /// may still commit later; callers must treat the outcome as unknown.
    #[error("timed out waiting for the entry to be committed by a majority")]
    CommitTimeout,
    /// The entry this node proposed was overwritten by a different leader's
    /// entry at the same index, so it will never commit.
    #[error("leadership was lost before the entry committed; it was discarded")]
    LeadershipLost,
    #[error("empty commands are reserved for leader no-ops")]
    EmptyCommand,
    #[error("the raft actor has stopped")]
    Stopped,
}
'@

Write-SentinelFile 'crates\consensus\src\log.rs' @'
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: u64,
    pub index: u64,
    pub command: Vec<u8>,
}

/// One mutation of the log, recorded in order so the actor can make exactly
/// those changes durable before it acknowledges anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogOp {
    Append(LogEntry),
    /// Delete the entry at this index and everything after it.
    TruncateFrom(u64),
}

impl LogEntry {
    /// A new leader appends an empty "no-op" entry at the start of its term
    /// so that entries from earlier terms can be committed (Raft only
    /// commits by counting replicas for entries of the *current* term).
    /// No-ops occupy a log slot but carry no command for the state machine.
    pub fn is_noop(&self) -> bool {
        self.command.is_empty()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum LogError {
    #[error("log is missing the entry at index {0} needed to check prev_log_term")]
    MissingPrevEntry(u64),
    #[error("prev_log_term mismatch at index {index}: local {local}, leader {leader}")]
    PrevTermMismatch { index: u64, local: u64, leader: u64 },
    #[error("persisted log is not contiguous: expected index {expected}, found {found}")]
    NonContiguous { expected: u64, found: u64 },
}

/// The replicated log. Indices are 1-based, matching the Raft paper's
/// convention - index 0 is the sentinel "before the log began" position,
/// so `prev_log_index == 0` always trivially satisfies the consistency
/// check (there's nothing to compare against for the very first entry).
#[derive(Debug, Default, Clone)]
pub struct ReplicatedLog {
    entries: Vec<LogEntry>,
    /// Mutations since the last `drain_journal`, oldest first.
    journal: Vec<LogOp>,
}

impl ReplicatedLog {
    pub fn new() -> Self {
        Self { entries: Vec::new(), journal: Vec::new() }
    }

    /// Rebuilds a log from entries loaded off disk. They must be contiguous
    /// from index 1; anything else means the stored log is damaged. Loading
    /// does not count as a mutation (nothing needs persisting).
    pub fn from_entries(entries: Vec<LogEntry>) -> Result<Self, LogError> {
        for (i, e) in entries.iter().enumerate() {
            let expected = i as u64 + 1;
            if e.index != expected {
                return Err(LogError::NonContiguous { expected, found: e.index });
            }
        }
        Ok(Self { entries, journal: Vec::new() })
    }

    /// Takes the recorded mutations (oldest first), leaving the journal empty.
    pub fn drain_journal(&mut self) -> Vec<LogOp> {
        std::mem::take(&mut self.journal)
    }

    pub fn last_index(&self) -> u64 {
        self.entries.last().map(|e| e.index).unwrap_or(0)
    }

    pub fn last_term(&self) -> u64 {
        self.entries.last().map(|e| e.term).unwrap_or(0)
    }

    pub fn get(&self, index: u64) -> Option<&LogEntry> {
        if index == 0 {
            return None;
        }
        self.entries.get((index - 1) as usize)
    }

    pub fn term_at(&self, index: u64) -> u64 {
        if index == 0 {
            return 0;
        }
        self.get(index).map(|e| e.term).unwrap_or(0)
    }

    /// Leader-side: appends a brand-new entry authored in `term`. Returns
    /// the index it was assigned.
    pub fn append_new(&mut self, term: u64, command: Vec<u8>) -> u64 {
        let index = self.last_index() + 1;
        let entry = LogEntry { term, index, command };
        self.journal.push(LogOp::Append(entry.clone()));
        self.entries.push(entry);
        index
    }

    /// Every entry at or after `index`, for sending to a follower that's
    /// behind. `index == 0` returns the whole log.
    pub fn entries_from(&self, index: u64) -> Vec<LogEntry> {
        if index == 0 {
            return self.entries.clone();
        }
        self.entries.iter().filter(|e| e.index >= index).cloned().collect()
    }

    /// At most `max` entries starting at `index`, in order. Used to bound
    /// the size of a single AppendEntries message.
    pub fn entries_range(&self, index: u64, max: usize) -> Vec<LogEntry> {
        let start = index.max(1) as usize - 1;
        self.entries.iter().skip(start).take(max).cloned().collect()
    }

    /// Follower-side: the Raft AppendEntries consistency check (section 5.3) -
    /// reject if the entry immediately before `new_entries` doesn't
    /// match what the leader thinks is there - followed by the
    /// "delete-conflicting-entries-then-append" rule for entries that do
    /// pass the check. `new_entries` must be contiguous, starting at
    /// `prev_log_index + 1`.
    pub fn append_entries(
        &mut self,
        prev_log_index: u64,
        prev_log_term: u64,
        new_entries: &[LogEntry],
    ) -> Result<(), LogError> {
        if prev_log_index > 0 {
            if prev_log_index > self.last_index() {
                return Err(LogError::MissingPrevEntry(prev_log_index));
            }
            let local_term = self.term_at(prev_log_index);
            if local_term != prev_log_term {
                return Err(LogError::PrevTermMismatch {
                    index: prev_log_index,
                    local: local_term,
                    leader: prev_log_term,
                });
            }
        }

        for entry in new_entries {
            match self.get(entry.index) {
                Some(existing) if existing.term == entry.term => {
                    continue;
                }
                Some(_) => {
                    self.entries.truncate((entry.index - 1) as usize);
                    self.journal.push(LogOp::TruncateFrom(entry.index));
                    self.journal.push(LogOp::Append(entry.clone()));
                    self.entries.push(entry.clone());
                }
                None => {
                    self.journal.push(LogOp::Append(entry.clone()));
                    self.entries.push(entry.clone());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(term: u64, index: u64) -> LogEntry {
        LogEntry { term, index, command: vec![index as u8] }
    }

    #[test]
    fn empty_log_has_zero_last_index_and_term() {
        let log = ReplicatedLog::new();
        assert_eq!(log.last_index(), 0);
        assert_eq!(log.last_term(), 0);
    }

    #[test]
    fn append_new_assigns_sequential_indices() {
        let mut log = ReplicatedLog::new();
        assert_eq!(log.append_new(1, vec![1]), 1);
        assert_eq!(log.append_new(1, vec![2]), 2);
        assert_eq!(log.append_new(2, vec![3]), 3);
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.last_term(), 2);
    }

    #[test]
    fn append_entries_accepts_first_entry_when_prev_index_is_zero() {
        let mut log = ReplicatedLog::new();
        let result = log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)]);
        assert!(result.is_ok());
        assert_eq!(log.last_index(), 2);
    }

    #[test]
    fn append_entries_rejects_missing_prev_entry() {
        let mut log = ReplicatedLog::new();
        let err = log.append_entries(5, 1, &[entry(1, 6)]).unwrap_err();
        assert!(matches!(err, LogError::MissingPrevEntry(5)));
    }

    #[test]
    fn append_entries_rejects_prev_term_mismatch() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1)]).unwrap();
        let err = log.append_entries(1, 2, &[entry(2, 2)]).unwrap_err();
        assert!(matches!(err, LogError::PrevTermMismatch { index: 1, local: 1, leader: 2 }));
    }

    #[test]
    fn append_entries_is_idempotent_for_identical_resend() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)]).unwrap();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)]).unwrap();
        assert_eq!(log.last_index(), 2);
        assert_eq!(log.get(1).unwrap().command, vec![1]);
    }

    #[test]
    fn append_entries_truncates_conflicting_suffix() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2), entry(1, 3)]).unwrap();
        log.append_entries(1, 1, &[entry(2, 2)]).unwrap();
        assert_eq!(log.last_index(), 2);
        assert_eq!(log.term_at(2), 2);
        assert!(log.get(3).is_none());
    }

    #[test]
    fn entries_from_returns_correct_suffix() {
        let mut log = ReplicatedLog::new();
        log.append_new(1, vec![1]);
        log.append_new(1, vec![2]);
        log.append_new(2, vec![3]);
        let suffix = log.entries_from(2);
        assert_eq!(suffix.len(), 2);
        assert_eq!(suffix[0].index, 2);
        assert_eq!(suffix[1].index, 3);
    }

    #[test]
    fn entries_range_is_bounded_and_ordered() {
        let mut log = ReplicatedLog::new();
        for i in 0..5u8 {
            log.append_new(1, vec![i + 1]);
        }
        let r = log.entries_range(2, 2);
        assert_eq!(r.iter().map(|e| e.index).collect::<Vec<_>>(), vec![2, 3]);
        assert_eq!(log.entries_range(4, 10).len(), 2);
        assert!(log.entries_range(6, 10).is_empty());
        assert_eq!(log.entries_range(0, 1)[0].index, 1, "index 0 is treated as 'from the start'");
    }

    #[test]
    fn a_log_entry_with_no_command_is_a_noop() {
        assert!(LogEntry { term: 1, index: 1, command: vec![] }.is_noop());
        assert!(!LogEntry { term: 1, index: 1, command: vec![0] }.is_noop());
    }

    #[test]
    fn every_mutation_is_journaled_in_order_and_draining_empties_it() {
        let mut log = ReplicatedLog::new();
        log.append_new(1, vec![1]);
        log.append_entries(1, 1, &[entry(1, 2), entry(1, 3)]).unwrap();
        // A conflicting entry at index 2 truncates 2.. and appends the replacement.
        log.append_entries(1, 1, &[entry(2, 2)]).unwrap();

        let ops = log.drain_journal();
        assert_eq!(
            ops,
            vec![
                LogOp::Append(LogEntry { term: 1, index: 1, command: vec![1] }),
                LogOp::Append(entry(1, 2)),
                LogOp::Append(entry(1, 3)),
                LogOp::TruncateFrom(2),
                LogOp::Append(entry(2, 2)),
            ]
        );
        assert!(log.drain_journal().is_empty());
    }

    #[test]
    fn an_identical_resend_journals_nothing() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)]).unwrap();
        log.drain_journal();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)]).unwrap();
        assert!(log.drain_journal().is_empty(), "nothing changed, so nothing to persist");
    }

    #[test]
    fn replaying_the_journal_reproduces_the_log() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2), entry(1, 3)]).unwrap();
        log.append_entries(1, 1, &[entry(2, 2), entry(2, 3), entry(2, 4)]).unwrap();

        let mut rebuilt: Vec<LogEntry> = Vec::new();
        for op in log.drain_journal() {
            match op {
                LogOp::Append(e) => rebuilt.push(e),
                LogOp::TruncateFrom(i) => rebuilt.truncate(i as usize - 1),
            }
        }
        assert_eq!(rebuilt, log.entries_from(0));
    }

    #[test]
    fn from_entries_accepts_a_contiguous_log_and_rejects_gaps() {
        let ok = ReplicatedLog::from_entries(vec![entry(1, 1), entry(1, 2)]).unwrap();
        assert_eq!(ok.last_index(), 2);
        assert!(ok.clone().drain_journal().is_empty(), "loading is not a mutation");

        let gap = ReplicatedLog::from_entries(vec![entry(1, 1), entry(1, 3)]).unwrap_err();
        assert!(matches!(gap, LogError::NonContiguous { expected: 2, found: 3 }));
        assert!(ReplicatedLog::from_entries(vec![entry(1, 2)]).is_err(), "must start at 1");
    }

    #[test]
    fn entries_from_zero_returns_everything() {
        let mut log = ReplicatedLog::new();
        log.append_new(1, vec![1]);
        log.append_new(1, vec![2]);
        assert_eq!(log.entries_from(0).len(), 2);
    }
}
'@

Write-SentinelFile 'crates\consensus\src\persist.rs' @'
//! Durable storage for the parts of Raft that must survive a crash.
//!
//! Raft's safety argument assumes three things are on stable storage
//! *before* a node answers any RPC: its `current_term`, its `voted_for`, and
//! its log. Forget a vote and a node can vote twice in one term (two
//! leaders); forget log entries it already acknowledged and a committed
//! entry can vanish. The actor therefore calls into a [`RaftStore`] and only
//! replies once the call has returned.
//!
//! Two implementations are provided:
//! * [`FileStore`]: the real one. A write-ahead log of log mutations (each
//!   record length-prefixed and CRC-checked, fsync'd per batch) plus a tiny
//!   hard-state file replaced atomically.
//! * [`MemoryStore`]: for tests, with failure injection.
//!
//! Known limitation: there are no snapshots or log compaction, so the WAL
//! grows with the log.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bincode::Options;

use crate::log::{LogEntry, LogOp};

#[derive(thiserror::Error, Debug)]
pub enum PersistError {
    #[error("raft storage I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("raft storage is corrupt: {0}")]
    Corrupt(String),
    #[error("injected storage failure")]
    Injected,
}

/// Everything recovered from disk at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistedState {
    pub term: u64,
    pub voted_for: Option<u64>,
    pub entries: Vec<LogEntry>,
}

/// Synchronous, blocking storage. Each call must not return until the data
/// is durable. (Blocking the async actor for an fsync is deliberate: a Raft
/// node should not make progress faster than its disk.)
pub trait RaftStore: Send {
    /// Reads back everything persisted so far. Must be called once, before
    /// any write.
    fn load(&mut self) -> Result<PersistedState, PersistError>;
    fn save_hard_state(&mut self, term: u64, voted_for: Option<u64>) -> Result<(), PersistError>;
    /// Makes a batch of log mutations durable, in order, as one unit.
    fn apply_log_ops(&mut self, ops: &[LogOp]) -> Result<(), PersistError>;
}

fn apply_op_to_vec(entries: &mut Vec<LogEntry>, op: &LogOp) -> Result<(), PersistError> {
    match op {
        LogOp::Append(e) => {
            let expected = entries.len() as u64 + 1;
            if e.index != expected {
                return Err(PersistError::Corrupt(format!("append of index {} but log ends at {}", e.index, expected - 1)));
            }
            entries.push(e.clone());
        }
        LogOp::TruncateFrom(i) => {
            if *i == 0 {
                return Err(PersistError::Corrupt("truncate from index 0".into()));
            }
            entries.truncate(*i as usize - 1);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// In-memory store (tests)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemInner {
    state: PersistedState,
    fail_writes: bool,
}

/// A `RaftStore` that keeps everything in memory. Clones share the same
/// data, so a test can "restart" a node by handing a clone to a new actor.
#[derive(Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<MemInner>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// While set, every write fails (simulating a dead disk).
    pub fn set_fail_writes(&self, fail: bool) {
        self.inner.lock().unwrap().fail_writes = fail;
    }

    pub fn snapshot(&self) -> PersistedState {
        self.inner.lock().unwrap().state.clone()
    }
}

impl RaftStore for MemoryStore {
    fn load(&mut self) -> Result<PersistedState, PersistError> {
        Ok(self.inner.lock().unwrap().state.clone())
    }

    fn save_hard_state(&mut self, term: u64, voted_for: Option<u64>) -> Result<(), PersistError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_writes {
            return Err(PersistError::Injected);
        }
        inner.state.term = term;
        inner.state.voted_for = voted_for;
        Ok(())
    }

    fn apply_log_ops(&mut self, ops: &[LogOp]) -> Result<(), PersistError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_writes {
            return Err(PersistError::Injected);
        }
        for op in ops {
            apply_op_to_vec(&mut inner.state.entries, op)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// File store
// ---------------------------------------------------------------------------

const WAL_FILE: &str = "log.wal";
const HARD_STATE_FILE: &str = "hard_state";
const HARD_STATE_TMP: &str = "hard_state.tmp";
/// Sanity bound on one WAL record, so a corrupt length prefix can never make
/// us allocate gigabytes.
const MAX_RECORD_BYTES: u32 = 64 * 1024 * 1024;
const RECORD_HEADER: usize = 8; // u32 length + u32 crc

/// CRC-32 (IEEE 802.3), bitwise. Small and dependency-free; the WAL is not
/// throughput-bound.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (!(crc & 1)).wrapping_add(1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn codec() -> impl bincode::Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().with_limit(MAX_RECORD_BYTES as u64)
}

pub struct FileStore {
    dir: PathBuf,
    wal: Option<File>,
}

impl FileStore {
    /// Opens (creating if needed) a store rooted at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, PersistError> {
        fs::create_dir_all(dir.as_ref())?;
        Ok(Self { dir: dir.as_ref().to_path_buf(), wal: None })
    }

    fn read_hard_state(&self) -> Result<(u64, Option<u64>), PersistError> {
        let path = self.dir.join(HARD_STATE_FILE);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, None)),
            Err(e) => return Err(e.into()),
        };
        if bytes.len() < 4 {
            return Err(PersistError::Corrupt("hard_state file is truncated".into()));
        }
        let (crc_bytes, payload) = bytes.split_at(4);
        if u32::from_le_bytes(crc_bytes.try_into().unwrap()) != crc32(payload) {
            return Err(PersistError::Corrupt("hard_state checksum mismatch".into()));
        }
        codec().deserialize(payload).map_err(|e| PersistError::Corrupt(format!("hard_state: {e}")))
    }

    fn wal(&mut self) -> Result<&mut File, PersistError> {
        self.wal.as_mut().ok_or_else(|| PersistError::Corrupt("FileStore::load must be called before writing".into()))
    }
}

impl RaftStore for FileStore {
    fn load(&mut self) -> Result<PersistedState, PersistError> {
        let (term, voted_for) = self.read_hard_state()?;

        let mut file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(self.dir.join(WAL_FILE))?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;

        let mut entries: Vec<LogEntry> = Vec::new();
        let mut pos = 0usize;
        // Replay records until the first one that is incomplete or fails its
        // checksum. That can only be the tail of a write that was in flight
        // when the process died, so everything from there is discarded.
        while pos + RECORD_HEADER <= raw.len() {
            let len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap());
            let crc = u32::from_le_bytes(raw[pos + 4..pos + 8].try_into().unwrap());
            if len > MAX_RECORD_BYTES {
                break;
            }
            let end = pos + RECORD_HEADER + len as usize;
            if end > raw.len() {
                break;
            }
            let payload = &raw[pos + RECORD_HEADER..end];
            if crc32(payload) != crc {
                break;
            }
            let op: LogOp = match codec().deserialize(payload) {
                Ok(op) => op,
                Err(_) => break,
            };
            apply_op_to_vec(&mut entries, &op)?;
            pos = end;
        }

        if pos < raw.len() {
            tracing::warn!(discarded_bytes = raw.len() - pos, "raft WAL had a torn or corrupt tail; truncating it");
            file.set_len(pos as u64)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        self.wal = Some(file);

        Ok(PersistedState { term, voted_for, entries })
    }

    fn save_hard_state(&mut self, term: u64, voted_for: Option<u64>) -> Result<(), PersistError> {
        let payload = codec().serialize(&(term, voted_for)).map_err(|e| PersistError::Corrupt(e.to_string()))?;
        let mut bytes = crc32(&payload).to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);

        let tmp = self.dir.join(HARD_STATE_TMP);
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.dir.join(HARD_STATE_FILE))?;
        #[cfg(unix)]
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    fn apply_log_ops(&mut self, ops: &[LogOp]) -> Result<(), PersistError> {
        if ops.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        for op in ops {
            let payload = codec().serialize(op).map_err(|e| PersistError::Corrupt(e.to_string()))?;
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&crc32(&payload).to_le_bytes());
            buf.extend_from_slice(&payload);
        }
        let wal = self.wal()?;
        wal.write_all(&buf)?;
        wal.sync_data()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(term: u64, index: u64) -> LogEntry {
        LogEntry { term, index, command: vec![index as u8; 3] }
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn an_empty_directory_loads_as_a_blank_node() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path()).unwrap();
        assert_eq!(store.load().unwrap(), PersistedState::default());
    }

    #[test]
    fn hard_state_and_log_round_trip_across_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            store.load().unwrap();
            store.save_hard_state(7, Some(3)).unwrap();
            store.apply_log_ops(&[LogOp::Append(entry(1, 1)), LogOp::Append(entry(1, 2)), LogOp::Append(entry(2, 3))]).unwrap();
        }
        let mut reopened = FileStore::open(dir.path()).unwrap();
        let loaded = reopened.load().unwrap();
        assert_eq!(loaded.term, 7);
        assert_eq!(loaded.voted_for, Some(3));
        assert_eq!(loaded.entries, vec![entry(1, 1), entry(1, 2), entry(2, 3)]);
    }

    #[test]
    fn truncations_are_replayed_in_order() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            store.load().unwrap();
            store.apply_log_ops(&[LogOp::Append(entry(1, 1)), LogOp::Append(entry(1, 2)), LogOp::Append(entry(1, 3))]).unwrap();
            store.apply_log_ops(&[LogOp::TruncateFrom(2), LogOp::Append(entry(2, 2))]).unwrap();
        }
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.entries, vec![entry(1, 1), entry(2, 2)]);
    }

    #[test]
    fn hard_state_can_be_overwritten_repeatedly() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path()).unwrap();
        store.load().unwrap();
        store.save_hard_state(1, None).unwrap();
        store.save_hard_state(2, Some(9)).unwrap();
        store.save_hard_state(3, None).unwrap();
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!((loaded.term, loaded.voted_for), (3, None));
    }

    #[test]
    fn a_torn_tail_from_a_crash_is_discarded_and_the_prefix_survives() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            store.load().unwrap();
            store.apply_log_ops(&[LogOp::Append(entry(1, 1)), LogOp::Append(entry(1, 2))]).unwrap();
        }
        // Simulate a crash mid-write: a record header promising 100 bytes, with only 10 present.
        let wal = dir.path().join(WAL_FILE);
        let good_len = fs::metadata(&wal).unwrap().len();
        let mut f = OpenOptions::new().append(true).open(&wal).unwrap();
        f.write_all(&100u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.write_all(&[0xAB; 10]).unwrap();
        drop(f);

        let mut store = FileStore::open(dir.path()).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.entries, vec![entry(1, 1), entry(1, 2)]);
        assert_eq!(fs::metadata(&wal).unwrap().len(), good_len, "the torn tail must be cut off");

        // And the log is still writable afterwards, with the new record landing right after the prefix.
        store.apply_log_ops(&[LogOp::Append(entry(1, 3))]).unwrap();
        let again = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(again.entries.len(), 3);
    }

    #[test]
    fn a_checksum_failure_stops_replay_at_that_record() {
        let dir = tempfile::tempdir().unwrap();
        let first_len;
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            store.load().unwrap();
            store.apply_log_ops(&[LogOp::Append(entry(1, 1))]).unwrap();
            first_len = fs::metadata(dir.path().join(WAL_FILE)).unwrap().len();
            store.apply_log_ops(&[LogOp::Append(entry(1, 2))]).unwrap();
        }
        // Flip a byte inside the second record's payload.
        let wal = dir.path().join(WAL_FILE);
        let mut bytes = fs::read(&wal).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        fs::write(&wal, &bytes).unwrap();

        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.entries, vec![entry(1, 1)], "the corrupt record and anything after it is dropped");
        assert_eq!(fs::metadata(&wal).unwrap().len(), first_len);
    }

    #[test]
    fn a_damaged_hard_state_file_is_an_error_not_silently_zero() {
        // Silently resetting term/vote to 0 could allow a double vote, so refuse to start.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            store.load().unwrap();
            store.save_hard_state(5, Some(2)).unwrap();
        }
        let path = dir.path().join(HARD_STATE_FILE);
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(FileStore::open(dir.path()).unwrap().load(), Err(PersistError::Corrupt(_))));
    }

    #[test]
    fn writing_before_load_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path()).unwrap();
        assert!(store.apply_log_ops(&[LogOp::Append(entry(1, 1))]).is_err());
    }

    #[test]
    fn a_non_contiguous_record_is_reported_as_corruption() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FileStore::open(dir.path()).unwrap();
            store.load().unwrap();
            store.apply_log_ops(&[LogOp::Append(entry(1, 1)), LogOp::Append(entry(1, 3))]).unwrap();
        }
        assert!(matches!(FileStore::open(dir.path()).unwrap().load(), Err(PersistError::Corrupt(_))));
    }

    #[test]
    fn memory_store_round_trips_and_can_be_told_to_fail() {
        let mut store = MemoryStore::new();
        store.load().unwrap();
        store.save_hard_state(4, Some(1)).unwrap();
        store.apply_log_ops(&[LogOp::Append(entry(1, 1)), LogOp::Append(entry(1, 2)), LogOp::TruncateFrom(2)]).unwrap();
        let snap = store.snapshot();
        assert_eq!((snap.term, snap.voted_for, snap.entries.len()), (4, Some(1), 1));

        store.set_fail_writes(true);
        assert!(matches!(store.save_hard_state(5, None), Err(PersistError::Injected)));
        assert!(matches!(store.apply_log_ops(&[LogOp::Append(entry(1, 2))]), Err(PersistError::Injected)));
        assert_eq!(store.snapshot().term, 4, "a failed write must change nothing");
    }
}
'@

Write-SentinelFile 'crates\consensus\src\state.rs' @'
use std::collections::{HashMap, HashSet};

use crate::log::{LogEntry, LogError, ReplicatedLog};
use crate::persist::PersistedState;
use crate::rpc::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};
use crate::ConsensusError;

/// Upper bound on entries carried by one AppendEntries message, so a
/// far-behind follower is caught up in bounded chunks rather than one
/// enormous request.
pub const MAX_ENTRIES_PER_APPEND: usize = 64;

/// What the actor should do after the leader processed a follower's reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplicationOutcome {
    /// Send this follower another AppendEntries right away (it either
    /// rejected the last one, so we backed up, or it is still behind).
    pub retry_now: bool,
    /// `commit_index` moved forward as a result of this reply.
    pub commit_advanced: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

/// The deterministic core of Raft: given an RPC (or a locally-triggered
/// election), what should this node's state become, and what should it
/// reply? Nothing here touches the network, a clock, or storage -
/// Phase 6's Tokio actor owns timers and message passing and calls into
/// this type, which makes the actual consensus logic testable without
/// spinning up any async runtime or simulating real time.
#[derive(Debug)]
pub struct RaftState {
    pub node_id: u64,
    pub current_term: u64,
    pub voted_for: Option<u64>,
    pub role: Role,
    pub log: ReplicatedLog,
    pub commit_index: u64,
    pub last_applied: u64,
    votes_received: HashSet<u64>,
    /// Leader-only: the next log index to send to each peer.
    next_index: HashMap<u64, u64>,
    /// Leader-only: the highest index known to be replicated on each peer.
    match_index: HashMap<u64, u64>,
}

impl RaftState {
    pub fn new(node_id: u64) -> Self {
        Self {
            node_id,
            current_term: 0,
            voted_for: None,
            role: Role::Follower,
            log: ReplicatedLog::new(),
            commit_index: 0,
            last_applied: 0,
            votes_received: HashSet::new(),
            next_index: HashMap::new(),
            match_index: HashMap::new(),
        }
    }

    /// Rebuilds a node from what it persisted before a restart. It comes back
    /// as a follower with nothing known to be committed; the leader's next
    /// heartbeat tells it the commit index.
    pub fn restore(node_id: u64, persisted: PersistedState) -> Result<Self, LogError> {
        let mut state = Self::new(node_id);
        state.current_term = persisted.term;
        state.voted_for = persisted.voted_for;
        state.log = ReplicatedLog::from_entries(persisted.entries)?;
        Ok(state)
    }

    fn step_down_if_stale(&mut self, term: u64) {
        if term > self.current_term {
            self.current_term = term;
            self.voted_for = None;
            self.role = Role::Follower;
            self.votes_received.clear();
        }
    }

    pub fn is_log_up_to_date(&self, candidate_last_term: u64, candidate_last_index: u64) -> bool {
        let (my_term, my_index) = (self.log.last_term(), self.log.last_index());
        candidate_last_term > my_term || (candidate_last_term == my_term && candidate_last_index >= my_index)
    }

    pub fn handle_request_vote(&mut self, req: RequestVoteRequest) -> RequestVoteResponse {
        self.step_down_if_stale(req.term);

        if req.term < self.current_term {
            return RequestVoteResponse { term: self.current_term, vote_granted: false };
        }

        let can_vote = match self.voted_for {
            None => true,
            Some(already_voted_for) => already_voted_for == req.candidate_id,
        };
        let log_ok = self.is_log_up_to_date(req.last_log_term, req.last_log_index);

        if can_vote && log_ok {
            self.voted_for = Some(req.candidate_id);
            RequestVoteResponse { term: self.current_term, vote_granted: true }
        } else {
            RequestVoteResponse { term: self.current_term, vote_granted: false }
        }
    }

    pub fn handle_append_entries(&mut self, req: AppendEntriesRequest) -> AppendEntriesResponse {
        self.step_down_if_stale(req.term);

        if req.term < self.current_term {
            return AppendEntriesResponse { term: self.current_term, success: false, match_index: None };
        }

        self.role = Role::Follower;

        match self.log.append_entries(req.prev_log_index, req.prev_log_term, &req.entries) {
            Ok(()) => {
                let new_last_index = req.prev_log_index + req.entries.len() as u64;
                if req.leader_commit > self.commit_index {
                    self.commit_index = req.leader_commit.min(new_last_index);
                }
                AppendEntriesResponse { term: self.current_term, success: true, match_index: Some(new_last_index) }
            }
            Err(_) => AppendEntriesResponse { term: self.current_term, success: false, match_index: None },
        }
    }

    pub fn become_candidate(&mut self) -> RequestVoteRequest {
        self.current_term += 1;
        self.role = Role::Candidate;
        self.voted_for = Some(self.node_id);
        self.votes_received.clear();
        self.votes_received.insert(self.node_id);

        RequestVoteRequest {
            term: self.current_term,
            candidate_id: self.node_id,
            last_log_index: self.log.last_index(),
            last_log_term: self.log.last_term(),
        }
    }

    pub fn record_vote(&mut self, resp: RequestVoteResponse, voter_id: u64, cluster_size: usize) -> bool {
        self.step_down_if_stale(resp.term);
        if self.role != Role::Candidate || resp.term != self.current_term {
            return false;
        }
        if resp.vote_granted {
            self.votes_received.insert(voter_id);
        }
        let majority = cluster_size / 2 + 1;
        self.votes_received.len() >= majority
    }

    pub fn become_leader(&mut self) {
        debug_assert_eq!(self.role, Role::Candidate, "only a candidate can become leader");
        self.role = Role::Leader;
    }

    /// Called by the actor right after winning an election (after
    /// `become_leader`). Resets per-peer replication progress and appends a
    /// no-op entry for the new term, which is what lets entries inherited
    /// from earlier terms become committed.
    pub fn on_elected(&mut self, peers: &[u64]) {
        debug_assert_eq!(self.role, Role::Leader);
        let next = self.log.last_index() + 1;
        self.next_index = peers.iter().map(|&p| (p, next)).collect();
        self.match_index = peers.iter().map(|&p| (p, 0)).collect();
        self.log.append_new(self.current_term, Vec::new());
        self.advance_commit_index();
    }

    /// Number of nodes in the cluster, as known to a leader (peers + self).
    pub fn cluster_size(&self) -> usize {
        self.match_index.len() + 1
    }

    /// Leader-only: appends a client command to the local log. Returns its
    /// index. It is **not** committed yet unless this is a single-node
    /// cluster; the entry commits once a majority has replicated it.
    pub fn append_as_leader(&mut self, command: Vec<u8>) -> Result<u64, ConsensusError> {
        if self.role != Role::Leader {
            return Err(ConsensusError::NotLeader);
        }
        if command.is_empty() {
            return Err(ConsensusError::EmptyCommand);
        }
        let index = self.log.append_new(self.current_term, command);
        self.advance_commit_index();
        Ok(index)
    }

    /// Leader-only: builds the next AppendEntries message for `peer`
    /// (starting at that peer's `next_index`), or `None` if this node is not
    /// the leader or `peer` is unknown.
    pub fn build_append_entries(&self, peer: u64) -> Option<AppendEntriesRequest> {
        if self.role != Role::Leader {
            return None;
        }
        let next = *self.next_index.get(&peer)?;
        let prev_log_index = next.saturating_sub(1);
        Some(AppendEntriesRequest {
            term: self.current_term,
            leader_id: self.node_id,
            prev_log_index,
            prev_log_term: self.log.term_at(prev_log_index),
            entries: self.log.entries_range(next, MAX_ENTRIES_PER_APPEND),
            leader_commit: self.commit_index,
        })
    }

    /// Leader-only: folds a follower's reply into replication progress.
    ///
    /// `sent_term`, `sent_prev_index` and `sent_len` describe the request the
    /// reply answers, so replies that arrive late, duplicated or reordered
    /// are handled correctly (progress only ever moves forward on success,
    /// and a rejection only backs up once per request).
    pub fn handle_append_entries_response(
        &mut self,
        peer: u64,
        sent_term: u64,
        sent_prev_index: u64,
        sent_len: u64,
        resp: AppendEntriesResponse,
    ) -> ReplicationOutcome {
        let mut outcome = ReplicationOutcome::default();

        // A higher term anywhere means we are no longer the leader.
        self.step_down_if_stale(resp.term);
        if self.role != Role::Leader || sent_term != self.current_term || resp.term != self.current_term {
            return outcome;
        }
        let (Some(matched), Some(next)) = (self.match_index.get_mut(&peer), self.next_index.get_mut(&peer)) else {
            return outcome;
        };

        if resp.success {
            let acked = sent_prev_index + sent_len;
            if acked > *matched {
                *matched = acked;
            }
            if *matched + 1 > *next {
                *next = *matched + 1;
            }
            let matched_now = *matched;
            outcome.commit_advanced = self.advance_commit_index();
            outcome.retry_now = self.log.last_index() > matched_now;
        } else if sent_prev_index + 1 == *next && *next > 1 {
            // The follower's log doesn't contain our prev entry: back up one
            // step and try again. (Only if this reply answers the request we
            // most recently built, so duplicates don't over-decrement.)
            *next -= 1;
            outcome.retry_now = true;
        }
        outcome
    }

    /// Leader-only: moves `commit_index` to the highest index replicated on
    /// a majority **whose entry is from the current term**. (Counting
    /// replicas of an older-term entry is not safe; the no-op appended by
    /// `on_elected` is what unlocks committing those.) Returns whether the
    /// index advanced.
    pub fn advance_commit_index(&mut self) -> bool {
        if self.role != Role::Leader {
            return false;
        }
        let majority = self.cluster_size() / 2 + 1;
        let mut n = self.log.last_index();
        while n > self.commit_index {
            if self.log.term_at(n) == self.current_term {
                let replicas = 1 + self.match_index.values().filter(|&&m| m >= n).count();
                if replicas >= majority {
                    self.commit_index = n;
                    return true;
                }
            }
            n -= 1;
        }
        false
    }

    /// Entries that became committed since the last call, in log order,
    /// exactly once each. Advances `last_applied`. This is the "apply loop"
    /// the state machine (the API's storage) consumes.
    pub fn take_newly_committed(&mut self) -> Vec<LogEntry> {
        let mut out = Vec::new();
        while self.last_applied < self.commit_index {
            self.last_applied += 1;
            if let Some(entry) = self.log.get(self.last_applied) {
                out.push(entry.clone());
            }
        }
        out
    }

    /// Leader-only progress for `peer`, exposed for tests and diagnostics.
    pub fn replication_progress(&self, peer: u64) -> Option<(u64, u64)> {
        Some((*self.next_index.get(&peer)?, *self.match_index.get(&peer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::AppendEntriesRequest;

    #[test]
    fn grants_vote_to_first_candidate_in_a_new_term() {
        let mut follower = RaftState::new(1);
        let req = RequestVoteRequest { term: 1, candidate_id: 2, last_log_index: 0, last_log_term: 0 };
        let resp = follower.handle_request_vote(req);
        assert!(resp.vote_granted);
        assert_eq!(follower.voted_for, Some(2));
    }

    #[test]
    fn denies_second_candidate_in_the_same_term() {
        let mut follower = RaftState::new(1);
        follower.handle_request_vote(RequestVoteRequest { term: 1, candidate_id: 2, last_log_index: 0, last_log_term: 0 });
        let resp = follower.handle_request_vote(RequestVoteRequest { term: 1, candidate_id: 3, last_log_index: 0, last_log_term: 0 });
        assert!(!resp.vote_granted);
    }

    #[test]
    fn regrants_vote_to_same_candidate_on_retry() {
        let mut follower = RaftState::new(1);
        follower.handle_request_vote(RequestVoteRequest { term: 1, candidate_id: 2, last_log_index: 0, last_log_term: 0 });
        let resp = follower.handle_request_vote(RequestVoteRequest { term: 1, candidate_id: 2, last_log_index: 0, last_log_term: 0 });
        assert!(resp.vote_granted);
    }

    #[test]
    fn denies_vote_for_stale_term() {
        let mut follower = RaftState::new(1);
        follower.current_term = 5;
        let resp = follower.handle_request_vote(RequestVoteRequest { term: 3, candidate_id: 2, last_log_index: 0, last_log_term: 0 });
        assert!(!resp.vote_granted);
        assert_eq!(resp.term, 5);
    }

    #[test]
    fn denies_vote_when_candidate_log_is_behind() {
        let mut follower = RaftState::new(1);
        follower.log.append_new(1, vec![1]);
        follower.log.append_new(2, vec![2]);
        let req = RequestVoteRequest { term: 3, candidate_id: 2, last_log_index: 5, last_log_term: 1 };
        let resp = follower.handle_request_vote(req);
        assert!(!resp.vote_granted);
    }

    #[test]
    fn higher_term_forces_step_down_and_clears_prior_vote() {
        let mut node = RaftState::new(1);
        node.handle_request_vote(RequestVoteRequest { term: 1, candidate_id: 2, last_log_index: 0, last_log_term: 0 });
        assert_eq!(node.voted_for, Some(2));

        let resp = node.handle_request_vote(RequestVoteRequest { term: 2, candidate_id: 3, last_log_index: 0, last_log_term: 0 });
        assert!(resp.vote_granted);
        assert_eq!(node.current_term, 2);
        assert_eq!(node.voted_for, Some(3));
    }

    #[test]
    fn append_entries_advances_commit_index_up_to_leader_commit() {
        let mut follower = RaftState::new(1);
        let req = AppendEntriesRequest {
            term: 1,
            leader_id: 2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![
                crate::log::LogEntry { term: 1, index: 1, command: vec![1] },
                crate::log::LogEntry { term: 1, index: 2, command: vec![2] },
            ],
            leader_commit: 1,
        };
        let resp = follower.handle_append_entries(req);
        assert!(resp.success);
        assert_eq!(follower.commit_index, 1);
    }

    #[test]
    fn commit_index_never_exceeds_locally_known_entries() {
        let mut follower = RaftState::new(1);
        let req = AppendEntriesRequest {
            term: 1,
            leader_id: 2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![crate::log::LogEntry { term: 1, index: 1, command: vec![1] }],
            leader_commit: 10,
        };
        let resp = follower.handle_append_entries(req);
        assert!(resp.success);
        assert_eq!(follower.commit_index, 1);
    }

    #[test]
    fn append_entries_with_stale_term_is_rejected() {
        let mut follower = RaftState::new(1);
        follower.current_term = 5;
        let req = AppendEntriesRequest {
            term: 3,
            leader_id: 2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };
        let resp = follower.handle_append_entries(req);
        assert!(!resp.success);
        assert_eq!(resp.term, 5);
    }

    #[test]
    fn candidate_steps_down_on_append_entries_from_current_term_leader() {
        let mut node = RaftState::new(1);
        node.become_candidate();
        assert_eq!(node.role, Role::Candidate);

        let req = AppendEntriesRequest {
            term: 1,
            leader_id: 2,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };
        node.handle_append_entries(req);
        assert_eq!(node.role, Role::Follower);
    }

    #[test]
    fn three_node_election_reaches_majority_and_becomes_leader() {
        let mut candidate = RaftState::new(1);
        let vote_req = candidate.become_candidate();
        assert_eq!(candidate.current_term, 1);
        assert_eq!(candidate.role, Role::Candidate);

        let mut follower_a = RaftState::new(2);
        let mut follower_b = RaftState::new(3);

        let resp_a = follower_a.handle_request_vote(vote_req.clone());
        let resp_b = follower_b.handle_request_vote(vote_req.clone());
        assert!(resp_a.vote_granted && resp_b.vote_granted);

        let reached_majority = candidate.record_vote(resp_a, 2, 3);
        assert!(reached_majority);
        candidate.become_leader();
        assert_eq!(candidate.role, Role::Leader);
    }

    #[test]
    fn split_vote_leaves_neither_candidate_with_a_majority() {
        let mut follower_a = RaftState::new(4);
        let mut follower_b = RaftState::new(5);

        let vote_req_2 = RequestVoteRequest { term: 1, candidate_id: 2, last_log_index: 0, last_log_term: 0 };
        follower_a.handle_request_vote(vote_req_2.clone());
        follower_b.handle_request_vote(vote_req_2);

        let mut candidate_3 = RaftState::new(3);
        candidate_3.current_term = 1;
        candidate_3.role = Role::Candidate;
        candidate_3.voted_for = Some(3);

        let vote_req_3 = RequestVoteRequest { term: 1, candidate_id: 3, last_log_index: 0, last_log_term: 0 };
        let resp_a = follower_a.handle_request_vote(vote_req_3.clone());
        let resp_b = follower_b.handle_request_vote(vote_req_3);

        assert!(!resp_a.vote_granted);
        assert!(!resp_b.vote_granted);
    }

    #[test]
    fn restore_brings_back_term_vote_and_log_as_a_fresh_follower() {
        let persisted = PersistedState {
            term: 9,
            voted_for: Some(3),
            entries: vec![
                LogEntry { term: 2, index: 1, command: vec![1] },
                LogEntry { term: 9, index: 2, command: vec![2] },
            ],
        };
        let s = RaftState::restore(1, persisted).unwrap();
        assert_eq!((s.current_term, s.voted_for, s.role), (9, Some(3), Role::Follower));
        assert_eq!((s.log.last_index(), s.log.last_term()), (2, 9));
        assert_eq!((s.commit_index, s.last_applied), (0, 0));
    }

    #[test]
    fn a_restored_node_cannot_vote_twice_in_the_term_it_already_voted_in() {
        let mut s = RaftState::restore(1, PersistedState { term: 4, voted_for: Some(2), entries: vec![] }).unwrap();
        let other = s.handle_request_vote(RequestVoteRequest { term: 4, candidate_id: 3, last_log_index: 0, last_log_term: 0 });
        assert!(!other.vote_granted, "the vote for node 2 in term 4 survived the restart");
        let same = s.handle_request_vote(RequestVoteRequest { term: 4, candidate_id: 2, last_log_index: 0, last_log_term: 0 });
        assert!(same.vote_granted);
    }

    // ---- Phase 14: leader replication ----

    fn leader_of(node_id: u64, term: u64, peers: &[u64]) -> RaftState {
        let mut s = RaftState::new(node_id);
        s.current_term = term - 1;
        s.become_candidate();
        s.become_leader();
        s.on_elected(peers);
        s
    }

    fn ok(match_index: u64, term: u64) -> AppendEntriesResponse {
        AppendEntriesResponse { term, success: true, match_index: Some(match_index) }
    }
    fn rejected(term: u64) -> AppendEntriesResponse {
        AppendEntriesResponse { term, success: false, match_index: None }
    }

    #[test]
    fn on_elected_appends_a_noop_and_starts_every_peer_at_the_log_end() {
        let s = leader_of(1, 1, &[2, 3]);
        assert_eq!(s.log.last_index(), 1);
        assert!(s.log.get(1).unwrap().is_noop());
        assert_eq!(s.log.get(1).unwrap().term, 1);
        assert_eq!(s.replication_progress(2), Some((1, 0)));
        assert_eq!(s.cluster_size(), 3);
        assert_eq!(s.commit_index, 0, "a 3-node leader cannot commit alone");
    }

    #[test]
    fn a_single_node_leader_commits_its_own_entries_immediately() {
        let mut s = leader_of(1, 1, &[]);
        assert_eq!(s.commit_index, 1, "the no-op is committed by the lone node's own vote");
        let idx = s.append_as_leader(b"x".to_vec()).unwrap();
        assert_eq!(idx, 2);
        assert_eq!(s.commit_index, 2);
        let applied: Vec<u64> = s.take_newly_committed().iter().map(|e| e.index).collect();
        assert_eq!(applied, vec![1, 2]);
        assert!(s.take_newly_committed().is_empty(), "each entry is delivered exactly once");
    }

    #[test]
    fn only_the_leader_accepts_commands_and_empty_commands_are_reserved() {
        let mut follower = RaftState::new(2);
        assert!(matches!(follower.append_as_leader(b"x".to_vec()), Err(ConsensusError::NotLeader)));
        let mut leader = leader_of(1, 1, &[2, 3]);
        assert!(matches!(leader.append_as_leader(vec![]), Err(ConsensusError::EmptyCommand)));
    }

    #[test]
    fn the_leader_sends_each_peer_entries_from_its_own_next_index() {
        let mut s = leader_of(1, 1, &[2, 3]);
        s.append_as_leader(b"a".to_vec()).unwrap();
        s.append_as_leader(b"b".to_vec()).unwrap();

        let req = s.build_append_entries(2).unwrap();
        assert_eq!((req.prev_log_index, req.prev_log_term), (0, 0));
        assert_eq!(req.entries.len(), 3, "no-op + a + b");
        assert_eq!(req.leader_commit, 0);

        // After peer 2 acknowledges everything, the next message is a heartbeat.
        s.handle_append_entries_response(2, 1, 0, 3, ok(3, 1));
        let hb = s.build_append_entries(2).unwrap();
        assert_eq!((hb.prev_log_index, hb.prev_log_term), (3, 1));
        assert!(hb.entries.is_empty());

        // Peer 3 hasn't acked anything, so it still gets the full backlog.
        assert_eq!(s.build_append_entries(3).unwrap().entries.len(), 3);
        assert!(s.build_append_entries(99).is_none(), "unknown peer");
        assert!(RaftState::new(1).build_append_entries(2).is_none(), "not a leader");
    }

    #[test]
    fn a_single_append_never_carries_more_than_the_batch_limit() {
        let mut s = leader_of(1, 1, &[2, 3]);
        for i in 0..(MAX_ENTRIES_PER_APPEND + 10) {
            s.append_as_leader(vec![(i % 250) as u8 + 1]).unwrap();
        }
        assert_eq!(s.build_append_entries(2).unwrap().entries.len(), MAX_ENTRIES_PER_APPEND);
    }

    #[test]
    fn an_entry_commits_exactly_when_a_majority_has_it() {
        let mut s = leader_of(1, 1, &[2, 3]);
        s.append_as_leader(b"a".to_vec()).unwrap(); // index 2

        let out = s.handle_append_entries_response(2, 1, 0, 2, ok(2, 1));
        assert!(out.commit_advanced, "leader + one peer is a majority of three");
        assert_eq!(s.commit_index, 2);

        // The second peer acknowledging later changes nothing further.
        let out = s.handle_append_entries_response(3, 1, 0, 2, ok(2, 1));
        assert!(!out.commit_advanced);
        assert_eq!(s.commit_index, 2);
    }

    #[test]
    fn five_node_leader_needs_three_replicas_not_two() {
        let mut s = leader_of(1, 1, &[2, 3, 4, 5]);
        s.append_as_leader(b"a".to_vec()).unwrap(); // index 2
        s.handle_append_entries_response(2, 1, 0, 2, ok(2, 1));
        assert_eq!(s.commit_index, 0, "2 of 5 is not a majority");
        s.handle_append_entries_response(3, 1, 0, 2, ok(2, 1));
        assert_eq!(s.commit_index, 2, "3 of 5 is");
    }

    #[test]
    fn entries_from_an_older_term_are_not_committed_by_counting_replicas() {
        // Raft paper, figure 8: a leader must not treat an old-term entry as
        // committed just because a majority holds it.
        let mut s = RaftState::new(1);
        s.log.append_new(1, b"old".to_vec()); // index 1, term 1
        s.current_term = 1;
        s.become_candidate(); // term 2
        s.become_leader();
        s.on_elected(&[2, 3]); // appends the term-2 no-op at index 2

        // A majority acknowledges only the old entry.
        s.handle_append_entries_response(2, 2, 0, 1, ok(1, 2));
        assert_eq!(s.commit_index, 0, "index 1 is from term 1; it must not commit by replica count");

        // Once a majority holds the current-term no-op, both commit together.
        s.handle_append_entries_response(2, 2, 0, 2, ok(2, 2));
        assert_eq!(s.commit_index, 2);
    }

    #[test]
    fn a_rejection_backs_up_exactly_one_step_and_asks_for_a_retry() {
        let mut s = leader_of(1, 1, &[2, 3]);
        s.append_as_leader(b"a".to_vec()).unwrap();
        s.append_as_leader(b"b".to_vec()).unwrap(); // log: 1..=3, next_index[2] = 1

        // Pretend peer 2 had been caught up to 3, then we learn it lacks entry 3.
        s.handle_append_entries_response(2, 1, 0, 3, ok(3, 1));
        assert_eq!(s.replication_progress(2), Some((4, 3)));
        let out = s.handle_append_entries_response(2, 1, 3, 0, rejected(1));
        assert!(out.retry_now);
        assert_eq!(s.replication_progress(2).unwrap().0, 3);

        // A duplicate of the same rejection must not back up again.
        let out = s.handle_append_entries_response(2, 1, 3, 0, rejected(1));
        assert!(!out.retry_now);
        assert_eq!(s.replication_progress(2).unwrap().0, 3);
    }

    #[test]
    fn next_index_never_drops_below_one() {
        let mut s = leader_of(1, 1, &[2, 3]);
        let out = s.handle_append_entries_response(2, 1, 0, 0, rejected(1));
        assert!(!out.retry_now);
        assert_eq!(s.replication_progress(2).unwrap().0, 1);
    }

    #[test]
    fn late_or_reordered_acks_never_move_progress_backwards() {
        let mut s = leader_of(1, 1, &[2, 3]);
        s.append_as_leader(b"a".to_vec()).unwrap();
        s.append_as_leader(b"b".to_vec()).unwrap();
        s.handle_append_entries_response(2, 1, 0, 3, ok(3, 1));
        // An older, smaller ack arrives afterwards.
        s.handle_append_entries_response(2, 1, 0, 1, ok(1, 1));
        assert_eq!(s.replication_progress(2), Some((4, 3)));
    }

    #[test]
    fn a_reply_with_a_higher_term_deposes_the_leader() {
        let mut s = leader_of(1, 1, &[2, 3]);
        let out = s.handle_append_entries_response(2, 1, 0, 1, AppendEntriesResponse { term: 5, success: false, match_index: None });
        assert_eq!(out, ReplicationOutcome::default());
        assert_eq!(s.role, Role::Follower);
        assert_eq!(s.current_term, 5);
    }

    #[test]
    fn a_reply_to_a_request_from_an_earlier_term_is_ignored() {
        let mut s = leader_of(1, 3, &[2, 3]);
        let before = s.replication_progress(2);
        let out = s.handle_append_entries_response(2, 2, 0, 1, ok(1, 2));
        assert_eq!(out, ReplicationOutcome::default());
        assert_eq!(s.replication_progress(2), before);
        assert_eq!(s.role, Role::Leader);
    }

    #[test]
    fn a_stale_rejection_from_an_earlier_leadership_does_not_back_up_progress() {
        // We lead term 3. A follower now at term 3 answers a request we sent
        // back in term 2 (during an earlier leadership) with a rejection. It
        // says nothing about our current log, so it must not move next_index.
        let mut s = leader_of(1, 3, &[2, 3]);
        s.handle_append_entries_response(2, 3, 0, 1, ok(1, 3));
        assert_eq!(s.replication_progress(2), Some((2, 1)));

        let out = s.handle_append_entries_response(2, 2, 1, 0, rejected(3));
        assert_eq!(out, ReplicationOutcome::default());
        assert_eq!(s.replication_progress(2), Some((2, 1)), "progress must be untouched");
    }

    #[test]
    fn a_follower_that_is_still_behind_is_asked_to_continue() {
        let mut s = leader_of(1, 1, &[2, 3]);
        for i in 0..5u8 {
            s.append_as_leader(vec![i + 1]).unwrap();
        }
        // The peer acknowledged only the first 2 of 6 entries.
        let out = s.handle_append_entries_response(2, 1, 0, 2, ok(2, 1));
        assert!(out.retry_now);
        assert_eq!(s.replication_progress(2), Some((3, 2)));
    }

    #[test]
    fn a_new_leader_forgets_the_previous_terms_replication_progress() {
        let mut s = leader_of(1, 1, &[2, 3]);
        s.append_as_leader(b"a".to_vec()).unwrap();
        s.handle_append_entries_response(2, 1, 0, 2, ok(2, 1));
        // Lose leadership, then win again in a later term.
        s.handle_request_vote(RequestVoteRequest { term: 2, candidate_id: 3, last_log_index: 9, last_log_term: 9 });
        assert_eq!(s.role, Role::Follower);
        s.become_candidate();
        s.become_leader();
        s.on_elected(&[2, 3]);
        assert_eq!(s.replication_progress(2).unwrap().1, 0, "match_index must restart from zero");
    }
}
'@

Write-SentinelFile 'crates\consensus\src\actor.rs' @'
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::log::LogEntry;
use crate::persist::{PersistError, RaftStore};
use crate::rpc::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};
use crate::state::{RaftState, Role};
use crate::ConsensusError;

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("peer {0} unreachable")]
    Unreachable(u64),
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_request_vote(&self, peer_id: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError>;
    async fn send_append_entries(&self, peer_id: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError>;
}

type CommitWaiter = oneshot::Sender<Result<u64, ConsensusError>>;

enum RaftMessage {
    RequestVote(RequestVoteRequest, oneshot::Sender<RequestVoteResponse>),
    AppendEntries(AppendEntriesRequest, oneshot::Sender<AppendEntriesResponse>),
    /// Append a command to the leader's log and report its index at once.
    Propose(Vec<u8>, oneshot::Sender<Result<u64, ConsensusError>>),
    /// Append a command and reply only when a majority has committed it.
    ProposeAndWait(Vec<u8>, CommitWaiter),
    VoteResult(RequestVoteResponse, u64),
    /// A follower's answer to an AppendEntries this leader sent.
    AppendResult {
        peer: u64,
        sent_term: u64,
        sent_prev_index: u64,
        sent_len: u64,
        resp: AppendEntriesResponse,
    },
    Inspect(oneshot::Sender<(Role, u64, u64)>),
    Shutdown,
}

#[derive(Clone)]
pub struct RaftHandle {
    sender: mpsc::Sender<RaftMessage>,
}

impl RaftHandle {
    pub async fn request_vote(&self, req: RequestVoteRequest) -> RequestVoteResponse {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::RequestVote(req, tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    pub async fn append_entries(&self, req: AppendEntriesRequest) -> AppendEntriesResponse {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::AppendEntries(req, tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    /// Appends `command` to the leader's log and returns its index
    /// **without** waiting for it to commit. Fails with `NotLeader` on a
    /// follower. Use [`propose_and_wait`](Self::propose_and_wait) when the
    /// caller needs to know the entry is durable on a majority.
    pub async fn propose(&self, command: Vec<u8>) -> Result<u64, ConsensusError> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::Propose(command, tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    /// Appends `command` and waits until a majority of the cluster has
    /// replicated it (it is *committed*), returning its log index.
    ///
    /// Errors: `NotLeader` (fast, on a follower), `LeadershipLost` (a
    /// different leader overwrote the entry, so it will never commit),
    /// `CommitTimeout` (no answer in `timeout`; the entry may still commit
    /// later, so the outcome is unknown), `EmptyCommand`, `Stopped`.
    pub async fn propose_and_wait(&self, command: Vec<u8>, timeout: Duration) -> Result<u64, ConsensusError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(RaftMessage::ProposeAndWait(command, tx))
            .await
            .map_err(|_| ConsensusError::Stopped)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ConsensusError::Stopped),
            Err(_) => Err(ConsensusError::CommitTimeout),
        }
    }

    /// Stops the actor. Anything already persisted stays persisted; a new
    /// actor started over the same store resumes from it.
    pub async fn shutdown(&self) {
        let _ = self.sender.send(RaftMessage::Shutdown).await;
    }

    pub async fn inspect(&self) -> (Role, u64, u64) {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::Inspect(tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ElectionTimeoutRange {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl Default for ElectionTimeoutRange {
    fn default() -> Self {
        Self { min_ms: 150, max_ms: 300 }
    }
}

fn random_election_timeout(range: ElectionTimeoutRange) -> Duration {
    let ms = rand::thread_rng().gen_range(range.min_ms..=range.max_ms);
    Duration::from_millis(ms)
}

/// Spawns a Raft node whose committed entries are discarded. Fine for tests
/// and tools that only care about leadership; a node that must act on the
/// replicated commands uses [`spawn_raft_actor_with_apply`].
pub fn spawn_raft_actor(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
) -> RaftHandle {
    spawn_inner(RaftState::new(node_id), peers, transport, heartbeat_interval, election_timeout_range, None, None)
}

/// Like [`spawn_raft_actor`], plus a channel that yields every **committed**
/// command, in log order, exactly once, on every node (leader and followers
/// alike). This is the state machine's input: apply what arrives here and
/// nothing else. Leader no-op entries are filtered out.
pub fn spawn_raft_actor_with_apply(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
) -> (RaftHandle, mpsc::UnboundedReceiver<LogEntry>) {
    let (apply_tx, apply_rx) = mpsc::unbounded_channel();
    let handle = spawn_inner(
        RaftState::new(node_id),
        peers,
        transport,
        heartbeat_interval,
        election_timeout_range,
        Some(apply_tx),
        None,
    );
    (handle, apply_rx)
}

/// The production constructor: like [`spawn_raft_actor_with_apply`], but the
/// node's term, vote and log are loaded from `store` at startup and every
/// change is made durable **before** the node replies to a peer, replicates,
/// acknowledges a client, or applies an entry. If the store ever fails the
/// actor stops (fail-stop): a node that can no longer remember what it
/// promised must not keep making promises.
///
/// After a restart the node replays every committed entry (from index 1) to
/// the apply channel once it learns the commit index, so the state machine
/// must tolerate re-application (see `statemachine` in the API crate).
pub fn spawn_raft_actor_persistent(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
    mut store: Box<dyn RaftStore>,
) -> Result<(RaftHandle, mpsc::UnboundedReceiver<LogEntry>), PersistError> {
    let persisted = store.load()?;
    let state = RaftState::restore(node_id, persisted).map_err(|e| PersistError::Corrupt(e.to_string()))?;
    let (apply_tx, apply_rx) = mpsc::unbounded_channel();
    let handle = spawn_inner(
        state,
        peers,
        transport,
        heartbeat_interval,
        election_timeout_range,
        Some(apply_tx),
        Some(store),
    );
    Ok((handle, apply_rx))
}

/// Makes everything that changed since the last call durable: first the log
/// mutations the state recorded, then term/vote if they moved.
fn flush_persistence(
    store: &mut Option<Box<dyn RaftStore>>,
    state: &mut RaftState,
    persisted_hard: &mut (u64, Option<u64>),
) -> Result<(), PersistError> {
    let ops = state.log.drain_journal();
    let hard = (state.current_term, state.voted_for);
    let Some(store) = store else {
        *persisted_hard = hard;
        return Ok(());
    };
    if !ops.is_empty() {
        store.apply_log_ops(&ops)?;
    }
    if hard != *persisted_hard {
        store.save_hard_state(hard.0, hard.1)?;
        *persisted_hard = hard;
    }
    Ok(())
}

/// Hands newly committed entries to the state machine and answers any
/// `propose_and_wait` callers whose entries just committed (or were found
/// to have been replaced by another leader's entry).
fn drain_committed(
    state: &mut RaftState,
    apply_tx: &Option<mpsc::UnboundedSender<LogEntry>>,
    pending: &mut BTreeMap<u64, (u64, CommitWaiter)>,
) {
    for entry in state.take_newly_committed() {
        if let Some((proposed_term, waiter)) = pending.remove(&entry.index) {
            let result = if proposed_term == entry.term { Ok(entry.index) } else { Err(ConsensusError::LeadershipLost) };
            let _ = waiter.send(result);
        }
        if !entry.is_noop() {
            if let Some(tx) = apply_tx {
                let _ = tx.send(entry);
            }
        }
    }
}

/// Sends `peer` its next AppendEntries (entries from that peer's own
/// `next_index`) and routes the reply back into the actor's mailbox.
fn replicate_to(state: &RaftState, peer: u64, transport: &Arc<dyn Transport>, self_tx: &mpsc::Sender<RaftMessage>) {
    let Some(req) = state.build_append_entries(peer) else { return };
    let transport = transport.clone();
    let reply_tx = self_tx.clone();
    tokio::spawn(async move {
        let sent_term = req.term;
        let sent_prev_index = req.prev_log_index;
        let sent_len = req.entries.len() as u64;
        if let Ok(resp) = transport.send_append_entries(peer, req).await {
            let _ = reply_tx.send(RaftMessage::AppendResult { peer, sent_term, sent_prev_index, sent_len, resp }).await;
        }
    });
}

fn spawn_inner(
    initial_state: RaftState,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
    apply_tx: Option<mpsc::UnboundedSender<LogEntry>>,
    store: Option<Box<dyn RaftStore>>,
) -> RaftHandle {
    let (tx, mut rx) = mpsc::channel(256);
    let self_tx = tx.clone();

    tokio::spawn(async move {
        let mut state = initial_state;
        let mut store = store;
        let mut persisted_hard = (state.current_term, state.voted_for);
        let mut pending: BTreeMap<u64, (u64, CommitWaiter)> = BTreeMap::new();
        let mut election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
        let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);

        // Makes all pending state changes durable. On failure the actor stops:
        // dropping every reply channel means callers see an error, never an
        // acknowledgement for data that is not safely stored.
        macro_rules! persist {
            () => {
                if let Err(e) = flush_persistence(&mut store, &mut state, &mut persisted_hard) {
                    tracing::error!(error = %e, "fatal: cannot persist raft state; stopping this node's raft actor");
                    break;
                }
            };
        }

        loop {
            tokio::select! {
                maybe_msg = rx.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    match msg {
                        RaftMessage::RequestVote(req, reply) => {
                            let candidate_term_is_current_or_newer = req.term >= state.current_term;
                            let resp = state.handle_request_vote(req);
                            persist!();
                            if resp.vote_granted || candidate_term_is_current_or_newer {
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            let _ = reply.send(resp);
                        }
                        RaftMessage::AppendEntries(req, reply) => {
                            // Any message from a leader of the current (or a
                            // newer) term proves a live leader exists, even if
                            // the log-consistency check below rejects it. A
                            // lagging follower must keep waiting, not start an
                            // election.
                            let from_live_leader = req.term >= state.current_term;
                            let resp = state.handle_append_entries(req);
                            persist!();
                            if from_live_leader {
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            drain_committed(&mut state, &apply_tx, &mut pending);
                            let _ = reply.send(resp);
                        }
                        RaftMessage::Propose(command, reply) => {
                            let result = state.append_as_leader(command);
                            persist!();
                            if result.is_ok() {
                                for &peer in &peers {
                                    replicate_to(&state, peer, &transport, &self_tx);
                                }
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                            let _ = reply.send(result);
                        }
                        RaftMessage::ProposeAndWait(command, waiter) => {
                            match state.append_as_leader(command) {
                                Ok(index) => {
                                    persist!();
                                    pending.insert(index, (state.current_term, waiter));
                                    for &peer in &peers {
                                        replicate_to(&state, peer, &transport, &self_tx);
                                    }
                                    // A single-node cluster commits instantly.
                                    drain_committed(&mut state, &apply_tx, &mut pending);
                                }
                                Err(e) => {
                                    let _ = waiter.send(Err(e));
                                }
                            }
                        }
                        RaftMessage::VoteResult(resp, peer) => {
                            let cluster_size = peers.len() + 1;
                            let won = state.record_vote(resp, peer, cluster_size);
                            if won {
                                state.become_leader();
                                state.on_elected(&peers);
                            }
                            persist!();
                            if won {
                                // Announce leadership (and start replicating)
                                // immediately rather than at the next tick.
                                for &p in &peers {
                                    replicate_to(&state, p, &transport, &self_tx);
                                }
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                        }
                        RaftMessage::AppendResult { peer, sent_term, sent_prev_index, sent_len, resp } => {
                            let was_leader = state.role == Role::Leader;
                            let outcome = state.handle_append_entries_response(peer, sent_term, sent_prev_index, sent_len, resp);
                            persist!();
                            if was_leader && state.role != Role::Leader {
                                // Deposed by a higher term: restart the
                                // election clock instead of firing at once.
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            if outcome.commit_advanced {
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                            if outcome.retry_now {
                                replicate_to(&state, peer, &transport, &self_tx);
                            }
                        }
                        RaftMessage::Inspect(reply) => {
                            let _ = reply.send((state.role, state.current_term, state.commit_index));
                        }
                        RaftMessage::Shutdown => break,
                    }
                }

                _ = tokio::time::sleep_until(election_deadline), if state.role != Role::Leader => {
                    let vote_req = state.become_candidate();
                    persist!();
                    election_deadline = Instant::now() + random_election_timeout(election_timeout_range);

                    if peers.is_empty() {
                        state.become_leader();
                        state.on_elected(&peers);
                        persist!();
                        drain_committed(&mut state, &apply_tx, &mut pending);
                        continue;
                    }

                    for &peer in &peers {
                        let transport = transport.clone();
                        let vote_req = vote_req.clone();
                        let reply_tx = self_tx.clone();
                        tokio::spawn(async move {
                            if let Ok(resp) = transport.send_request_vote(peer, vote_req).await {
                                let _ = reply_tx.send(RaftMessage::VoteResult(resp, peer)).await;
                            }
                        });
                    }
                }

                _ = heartbeat_tick.tick(), if state.role == Role::Leader => {
                    // The heartbeat doubles as the retry loop: each peer gets
                    // whatever it is still missing (or an empty message if
                    // it is fully caught up).
                    for &peer in &peers {
                        replicate_to(&state, peer, &transport, &self_tx);
                    }
                    // Forget waiters whose callers already gave up.
                    pending.retain(|_, (_, waiter)| !waiter.is_closed());
                }
            }
        }
    });

    RaftHandle { sender: tx }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex as StdMutex;
    use crate::persist::MemoryStore;
    use tokio::sync::Mutex;

    /// An in-process network between Raft actors whose links can be cut:
    /// an isolated node can neither send nor receive anything.
    struct Net {
        handles: Mutex<HashMap<u64, RaftHandle>>,
        isolated: StdMutex<HashSet<u64>>,
    }

    struct NodeTransport {
        from: u64,
        net: Arc<Net>,
    }

    impl NodeTransport {
        async fn route(&self, peer_id: u64) -> Result<RaftHandle, TransportError> {
            {
                let isolated = self.net.isolated.lock().unwrap();
                if isolated.contains(&self.from) || isolated.contains(&peer_id) {
                    return Err(TransportError::Unreachable(peer_id));
                }
            }
            let handles = self.net.handles.lock().await;
            handles.get(&peer_id).cloned().ok_or(TransportError::Unreachable(peer_id))
        }
    }

    #[async_trait::async_trait]
    impl Transport for NodeTransport {
        async fn send_request_vote(&self, peer_id: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
            Ok(self.route(peer_id).await?.request_vote(req).await)
        }
        async fn send_append_entries(&self, peer_id: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
            Ok(self.route(peer_id).await?.append_entries(req).await)
        }
    }

    struct Cluster {
        ids: Vec<u64>,
        handles: HashMap<u64, RaftHandle>,
        net: Arc<Net>,
        applied_rx: HashMap<u64, mpsc::UnboundedReceiver<LogEntry>>,
        /// Commands each node has applied so far, in order.
        seen: HashMap<u64, Vec<Vec<u8>>>,
    }

    async fn spawn_cluster(ids: &[u64], heartbeat: Duration, election_range: ElectionTimeoutRange) -> Cluster {
        spawn_cluster_inner(ids, heartbeat, election_range, None).await
    }

    /// A cluster whose nodes persist to the given stores. Calling this again
    /// with the same stores is a restart of the whole cluster.
    async fn spawn_persistent_cluster(ids: &[u64], stores: &HashMap<u64, MemoryStore>) -> Cluster {
        spawn_cluster_inner(ids, Duration::from_millis(20), FAST, Some(stores)).await
    }

    async fn spawn_cluster_inner(
        ids: &[u64],
        heartbeat: Duration,
        election_range: ElectionTimeoutRange,
        stores: Option<&HashMap<u64, MemoryStore>>,
    ) -> Cluster {
        let net = Arc::new(Net { handles: Mutex::new(HashMap::new()), isolated: StdMutex::new(HashSet::new()) });
        let mut handles = HashMap::new();
        let mut applied_rx = HashMap::new();
        for &id in ids {
            let peers: Vec<u64> = ids.iter().copied().filter(|&p| p != id).collect();
            let transport = Arc::new(NodeTransport { from: id, net: net.clone() });
            let (handle, rx) = match stores {
                Some(stores) => spawn_raft_actor_persistent(id, peers, transport, heartbeat, election_range, Box::new(stores[&id].clone()))
                    .expect("store should load"),
                None => spawn_raft_actor_with_apply(id, peers, transport, heartbeat, election_range),
            };
            net.handles.lock().await.insert(id, handle.clone());
            handles.insert(id, handle);
            applied_rx.insert(id, rx);
        }
        let seen = ids.iter().map(|&id| (id, Vec::new())).collect();
        Cluster { ids: ids.to_vec(), handles, net, applied_rx, seen }
    }

    impl Cluster {
        fn isolate(&self, id: u64) {
            self.net.isolated.lock().unwrap().insert(id);
        }
        fn heal(&self) {
            self.net.isolated.lock().unwrap().clear();
        }

        async fn leader_among(&self, among: &[u64]) -> Option<u64> {
            let mut best: Option<(u64, u64)> = None; // (term, id)
            for &id in among {
                let (role, term, _) = self.handles[&id].inspect().await;
                if role == Role::Leader && best.map_or(true, |(t, _)| term > t) {
                    best = Some((term, id));
                }
            }
            best.map(|(_, id)| id)
        }

        async fn wait_for_leader(&self, among: &[u64]) -> u64 {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(id) = self.leader_among(among).await {
                        return id;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("no leader emerged within 5s")
        }

        /// Proposes through whoever is leader among `among`, retrying across
        /// leadership changes until the entry is committed.
        async fn propose_ok(&self, among: &[u64], command: &[u8]) -> u64 {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(leader) = self.leader_among(among).await {
                        if let Ok(index) = self.handles[&leader].propose_and_wait(command.to_vec(), Duration::from_millis(800)).await {
                            return index;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("could not commit a proposal within 10s")
        }

        fn pump(&mut self) {
            for &id in &self.ids {
                let rx = self.applied_rx.get_mut(&id).unwrap();
                while let Ok(entry) = rx.try_recv() {
                    self.seen.get_mut(&id).unwrap().push(entry.command);
                }
            }
        }

        async fn wait_until_everyone_applied(&mut self, ids: &[u64], count: usize) {
            let result = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    self.pump();
                    if ids.iter().all(|id| self.seen[id].len() >= count) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(
                result.is_ok(),
                "nodes did not all apply {count} entries in time; applied so far: {:?}",
                self.seen.iter().map(|(id, v)| (*id, v.len())).collect::<Vec<_>>()
            );
        }
    }

    fn cmds(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    const FAST: ElectionTimeoutRange = ElectionTimeoutRange { min_ms: 80, max_ms: 150 };

    // ---- the original election tests, unchanged in intent ----

    #[tokio::test]
    async fn single_node_cluster_should_elect_itself_leader() {
        let cluster = spawn_cluster(&[1], Duration::from_millis(20), FAST).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (role, _, _) = cluster.handles[&1].inspect().await;
        assert_eq!(role, Role::Leader, "a lone node with no peers must still become its own leader");
    }

    #[tokio::test]
    async fn three_node_cluster_elects_exactly_one_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        let mut leaders = 0;
        let mut terms = Vec::new();
        for &id in &ids {
            let (role, term, _commit) = cluster.handles[&id].inspect().await;
            terms.push(term);
            if role == Role::Leader {
                leaders += 1;
            }
        }
        assert_eq!(leaders, 1, "expected exactly one leader, roles/terms: {terms:?}");
        assert!(terms.iter().all(|&t| t == terms[0]));
    }

    #[tokio::test]
    async fn heartbeats_prevent_repeated_elections() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;

        tokio::time::sleep(Duration::from_millis(300)).await;
        let (_, term_after_first_election, _) = cluster.handles[&1].inspect().await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut final_terms = Vec::new();
        for &id in &ids {
            let (_, term, _) = cluster.handles[&id].inspect().await;
            final_terms.push(term);
        }
        assert!(
            final_terms.iter().all(|&t| t == term_after_first_election),
            "term should be stable once a leader is established, got {final_terms:?} (was {term_after_first_election})"
        );
    }

    #[tokio::test]
    async fn repeated_elections_do_not_deadlock_under_tight_simultaneous_timeouts() {
        for _ in 0..20 {
            let ids = [1, 2, 3];
            let cluster = spawn_cluster(&ids, Duration::from_millis(5), ElectionTimeoutRange { min_ms: 30, max_ms: 60 }).await;

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let mut leaders = 0;
                    for &id in &ids {
                        let (role, _, _) = cluster.handles[&id].inspect().await;
                        if role == Role::Leader {
                            leaders += 1;
                        }
                    }
                    if leaders == 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;

            assert!(result.is_ok(), "cluster failed to elect a leader within 2s - likely deadlocked");
        }
    }

    #[tokio::test]
    async fn propose_fails_on_a_follower_and_succeeds_on_the_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        let leader_id = cluster.leader_among(&ids).await.expect("cluster should have elected a leader");

        for &id in &ids {
            let result = cluster.handles[&id].propose(b"set x=1".to_vec()).await;
            if id == leader_id {
                assert!(result.is_ok(), "leader should accept a proposal");
            } else {
                assert!(matches!(result, Err(ConsensusError::NotLeader)), "follower should reject a proposal");
            }
        }
    }

    // ---- Phase 14: replication ----

    #[tokio::test]
    async fn committed_entries_reach_every_node_in_the_same_order() {
        let ids = [1, 2, 3];
        let mut cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        cluster.wait_for_leader(&ids).await;

        let sent = ["a", "b", "c", "d", "e"];
        for c in sent {
            cluster.propose_ok(&ids, c.as_bytes()).await;
        }
        cluster.wait_until_everyone_applied(&ids, 5).await;

        for &id in &ids {
            assert_eq!(cluster.seen[&id], cmds(&sent), "node {id} must apply exactly the proposed commands, in order");
        }
        // Followers learn the commit index too, not just the leader.
        for &id in &ids {
            let (_, _, commit) = cluster.handles[&id].inspect().await;
            assert!(commit >= 5, "node {id} commit_index is {commit}");
        }
    }

    #[tokio::test]
    async fn single_node_cluster_commits_its_own_proposals() {
        let mut cluster = spawn_cluster(&[1], Duration::from_millis(20), FAST).await;
        cluster.wait_for_leader(&[1]).await;
        let index = cluster.handles[&1].propose_and_wait(b"solo".to_vec(), Duration::from_secs(2)).await.unwrap();
        assert!(index >= 2, "index 1 is the leader's no-op");
        cluster.wait_until_everyone_applied(&[1], 1).await;
        assert_eq!(cluster.seen[&1], cmds(&["solo"]));
    }

    #[tokio::test]
    async fn propose_and_wait_on_a_follower_fails_fast_with_not_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        let leader = cluster.wait_for_leader(&ids).await;
        let follower = ids.iter().copied().find(|&i| i != leader).unwrap();

        let started = std::time::Instant::now();
        let result = cluster.handles[&follower].propose_and_wait(b"x".to_vec(), Duration::from_secs(5)).await;
        assert!(matches!(result, Err(ConsensusError::NotLeader)));
        assert!(started.elapsed() < Duration::from_secs(1), "must not wait out the timeout");

        let empty = cluster.handles[&leader].propose_and_wait(vec![], Duration::from_secs(1)).await;
        assert!(matches!(empty, Err(ConsensusError::EmptyCommand)));
    }

    #[tokio::test]
    async fn a_follower_that_missed_entries_catches_up_after_reconnecting() {
        let ids = [1, 2, 3];
        let mut cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        let leader = cluster.wait_for_leader(&ids).await;
        let straggler = ids.iter().copied().find(|&i| i != leader).unwrap();
        let majority: Vec<u64> = ids.iter().copied().filter(|&i| i != straggler).collect();

        cluster.propose_ok(&ids, b"before").await;
        cluster.wait_until_everyone_applied(&ids, 1).await;

        // With one node cut off, the other two still form a majority and keep committing.
        cluster.isolate(straggler);
        for c in ["m1", "m2", "m3", "m4"] {
            cluster.propose_ok(&majority, c.as_bytes()).await;
        }
        cluster.wait_until_everyone_applied(&majority, 5).await;
        assert_eq!(cluster.seen[&straggler].len(), 1, "the isolated node must not have received anything new");

        // Reconnect: the straggler is brought fully up to date, in order.
        cluster.heal();
        cluster.wait_until_everyone_applied(&ids, 5).await;
        let expected = cmds(&["before", "m1", "m2", "m3", "m4"]);
        for &id in &ids {
            assert_eq!(cluster.seen[&id], expected, "node {id}");
        }
    }

    #[tokio::test]
    async fn a_deposed_leaders_uncommitted_entry_is_discarded_and_never_applied() {
        let ids = [1, 2, 3];
        let mut cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        let old_leader = cluster.wait_for_leader(&ids).await;
        let others: Vec<u64> = ids.iter().copied().filter(|&i| i != old_leader).collect();

        cluster.propose_ok(&ids, b"committed-before").await;
        cluster.wait_until_everyone_applied(&ids, 1).await;

        // Cut the leader off. It still believes it leads, so it accepts a
        // write, but it can never reach a majority, so the write must not commit.
        cluster.isolate(old_leader);
        let orphan = cluster.handles[&old_leader].propose_and_wait(b"orphan".to_vec(), Duration::from_millis(400)).await;
        assert!(orphan.is_err(), "a minority leader must not be able to commit, got {orphan:?}");

        // The majority elects a new leader and carries on.
        cluster.wait_for_leader(&others).await;
        cluster.propose_ok(&others, b"after-1").await;
        cluster.propose_ok(&others, b"after-2").await;

        // Reconnect: the old leader steps down, drops its orphan entry, and adopts the new log.
        cluster.heal();
        cluster.wait_until_everyone_applied(&ids, 3).await;

        let expected = cmds(&["committed-before", "after-1", "after-2"]);
        for &id in &ids {
            assert_eq!(cluster.seen[&id], expected, "node {id} must never have applied the orphaned write");
        }
        // Give any stray delivery a chance to show up, then re-check.
        tokio::time::sleep(Duration::from_millis(300)).await;
        cluster.pump();
        for &id in &ids {
            assert!(!cluster.seen[&id].contains(&b"orphan".to_vec()), "node {id} applied the orphan");
        }
    }

    #[tokio::test]
    async fn rejected_appends_from_a_live_leader_still_reset_the_election_timer() {
        // A node whose log is behind rejects the leader's append (prev entry
        // missing). That rejection must not make it think the leader died.
        struct Dead;
        #[async_trait::async_trait]
        impl Transport for Dead {
            async fn send_request_vote(&self, p: u64, _: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
                Err(TransportError::Unreachable(p))
            }
            async fn send_append_entries(&self, p: u64, _: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
                Err(TransportError::Unreachable(p))
            }
        }
        let handle = spawn_raft_actor(2, vec![1, 3], Arc::new(Dead), Duration::from_millis(20), ElectionTimeoutRange { min_ms: 150, max_ms: 200 });

        for _ in 0..16 {
            let resp = handle
                .append_entries(AppendEntriesRequest {
                    term: 1,
                    leader_id: 1,
                    prev_log_index: 5, // this node has no entries, so this is rejected
                    prev_log_term: 1,
                    entries: vec![],
                    leader_commit: 0,
                })
                .await;
            assert!(!resp.success);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (role, term, _) = handle.inspect().await;
        assert_eq!((role, term), (Role::Follower, 1), "over 800ms of live-leader contact the node must never time out");
    }

    // ---- Phase 15: durability ----

    struct DeadNet;
    #[async_trait::async_trait]
    impl Transport for DeadNet {
        async fn send_request_vote(&self, p: u64, _: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
            Err(TransportError::Unreachable(p))
        }
        async fn send_append_entries(&self, p: u64, _: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
            Err(TransportError::Unreachable(p))
        }
    }

    const NEVER_ELECT: ElectionTimeoutRange = ElectionTimeoutRange { min_ms: 60_000, max_ms: 61_000 };

    fn persistent_follower(store: &MemoryStore) -> RaftHandle {
        spawn_raft_actor_persistent(2, vec![1, 3], Arc::new(DeadNet), Duration::from_millis(20), NEVER_ELECT, Box::new(store.clone()))
            .unwrap()
            .0
    }

    #[tokio::test]
    async fn a_restarted_node_cannot_vote_twice_in_the_term_it_already_voted_in() {
        let store = MemoryStore::new();
        let node = persistent_follower(&store);
        let first = node.request_vote(RequestVoteRequest { term: 5, candidate_id: 1, last_log_index: 0, last_log_term: 0 }).await;
        assert!(first.vote_granted);
        node.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Brand-new actor, same disk.
        let restarted = persistent_follower(&store);
        let (_, term, _) = restarted.inspect().await;
        assert_eq!(term, 5, "the term must survive a restart");

        let rival = restarted.request_vote(RequestVoteRequest { term: 5, candidate_id: 3, last_log_index: 0, last_log_term: 0 }).await;
        assert!(!rival.vote_granted, "a second vote in term 5 would allow two leaders");
        let same = restarted.request_vote(RequestVoteRequest { term: 5, candidate_id: 1, last_log_index: 0, last_log_term: 0 }).await;
        assert!(same.vote_granted, "re-granting to the same candidate is still fine");
    }

    #[tokio::test]
    async fn without_persistence_the_same_restart_would_double_vote() {
        // Control for the test above: proves it is persistence, not luck, that prevents the second vote.
        let node = spawn_raft_actor(2, vec![1, 3], Arc::new(DeadNet), Duration::from_millis(20), NEVER_ELECT);
        node.request_vote(RequestVoteRequest { term: 5, candidate_id: 1, last_log_index: 0, last_log_term: 0 }).await;
        node.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let restarted = spawn_raft_actor(2, vec![1, 3], Arc::new(DeadNet), Duration::from_millis(20), NEVER_ELECT);
        let rival = restarted.request_vote(RequestVoteRequest { term: 5, candidate_id: 3, last_log_index: 0, last_log_term: 0 }).await;
        assert!(rival.vote_granted, "an amnesiac node grants the second vote; that is the bug persistence prevents");
    }

    #[tokio::test]
    async fn a_follower_only_acknowledges_an_append_after_it_is_durable() {
        let store = MemoryStore::new();
        let node = persistent_follower(&store);
        let e = |term, index| LogEntry { term, index, command: vec![index as u8] };

        let resp = node
            .append_entries(AppendEntriesRequest {
                term: 1,
                leader_id: 1,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![e(1, 1), e(1, 2)],
                leader_commit: 0,
            })
            .await;
        assert!(resp.success);
        // The reply has been received, so the data must already be on "disk".
        let snap = store.snapshot();
        assert_eq!((snap.term, snap.entries.len()), (1, 2));

        // A new leader overwrites index 2; the truncation is persisted too.
        let resp = node
            .append_entries(AppendEntriesRequest {
                term: 2,
                leader_id: 3,
                prev_log_index: 1,
                prev_log_term: 1,
                entries: vec![e(2, 2)],
                leader_commit: 0,
            })
            .await;
        assert!(resp.success);
        let snap = store.snapshot();
        assert_eq!((snap.term, snap.entries[1].term), (2, 2));
    }

    #[tokio::test]
    async fn restarting_the_whole_cluster_loses_no_committed_entry() {
        let ids = [1, 2, 3];
        let stores: HashMap<u64, MemoryStore> = ids.iter().map(|&id| (id, MemoryStore::new())).collect();

        let mut first = spawn_persistent_cluster(&ids, &stores).await;
        first.wait_for_leader(&ids).await;
        for c in ["a", "b", "c"] {
            first.propose_ok(&ids, c.as_bytes()).await;
        }
        first.wait_until_everyone_applied(&ids, 3).await;
        let term_before = first.handles[&1].inspect().await.1;

        // Power off every node at once. Nobody is left to resend anything:
        // whatever survives is exactly what was on disk.
        for &id in &ids {
            first.handles[&id].shutdown().await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for &id in &ids {
            let on_disk: Vec<Vec<u8>> = stores[&id].snapshot().entries.into_iter().filter(|e| !e.is_noop()).map(|e| e.command).collect();
            assert_eq!(on_disk, cmds(&["a", "b", "c"]), "node {id} must have persisted every committed entry");
        }

        let mut second = spawn_persistent_cluster(&ids, &stores).await;
        second.wait_for_leader(&ids).await;
        second.wait_until_everyone_applied(&ids, 3).await;
        for &id in &ids {
            assert_eq!(second.seen[&id], cmds(&["a", "b", "c"]), "node {id} must re-apply the surviving log");
            assert!(second.handles[&id].inspect().await.1 > term_before, "terms must never go backwards across a restart");
        }

        // And the restarted cluster keeps working.
        second.propose_ok(&ids, b"d").await;
        second.wait_until_everyone_applied(&ids, 4).await;
        assert_eq!(second.seen[&1].last().unwrap(), b"d");
    }

    #[tokio::test]
    async fn a_failing_disk_stops_the_node_instead_of_acknowledging_unsaved_data() {
        let store = MemoryStore::new();
        let (node, mut applied) =
            spawn_raft_actor_persistent(1, vec![], Arc::new(DeadNet), Duration::from_millis(20), FAST, Box::new(store.clone())).unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while node.inspect().await.0 != Role::Leader {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("single node should lead");

        store.set_fail_writes(true);
        let result = node.propose_and_wait(b"must-not-be-acked".to_vec(), Duration::from_secs(2)).await;
        assert!(matches!(result, Err(ConsensusError::Stopped)), "got {result:?}");
        assert!(applied.try_recv().is_err(), "an entry that could not be saved must never reach the state machine");
        assert!(store.snapshot().entries.iter().all(|e| e.command != b"must-not-be-acked"));
    }
}
'@

Write-SentinelFile 'crates\api\src\errors.rs' @'
use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("vault is sealed")]
    Sealed,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    // Reserved for a future fine-grained authorization layer. mTLS
    // (`ClientIdentity`) proves WHO is calling with cryptographic
    // certainty; it does not yet gate WHICH secrets that identity is
    // allowed to touch. Every current handler treats any successfully
    // authenticated client as authorized for every operation. This
    // variant exists so that gap has a typed place to land in rather
    // than being bolted on as a stringly-typed error later.
    #[allow(dead_code)]
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("not the raft leader; redirect to node {0:?}")]
    NotLeader(Option<u64>),
    /// The write was proposed but a majority did not confirm it in time. It
    /// may or may not have been applied; the caller should check before retrying.
    #[error("the write was not confirmed by a majority in time; its outcome is unknown")]
    CommitTimeout,
    #[error("leadership changed before the write committed; it was discarded, please retry")]
    LeadershipLost,
    #[error("storage error: {0}")]
    Storage(#[from] sentinel_storage::StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] sentinel_crypto::CryptoError),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Sealed => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::Unauthorized(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotLeader(_) => (StatusCode::MISDIRECTED_REQUEST, self.to_string()),
            AppError::CommitTimeout => (StatusCode::GATEWAY_TIMEOUT, self.to_string()),
            AppError::LeadershipLost => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::Storage(_) | AppError::Crypto(_) | AppError::Internal(_) => {
                tracing::error!(error = ?self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
impl From<sentinel_consensus::ConsensusError> for AppError {
    fn from(e: sentinel_consensus::ConsensusError) -> Self {
        use sentinel_consensus::ConsensusError as C;
        match e {
            C::NotLeader => AppError::NotLeader(None),
            C::CommitTimeout => AppError::CommitTimeout,
            C::LeadershipLost => AppError::LeadershipLost,
            other => AppError::Internal(other.into()),
        }
    }
}
'@

Write-SentinelFile 'crates\api\src\state.rs' @'
use std::sync::Arc;
use std::time::Duration;

use sentinel_anomaly::AnomalyDetector;
use sentinel_audit::AuditChain;
use sentinel_consensus::RaftHandle;
use sentinel_crypto::SecretBytes;
use sentinel_storage::Storage;
use tokio::sync::{watch, Mutex};

use crate::handlers::unseal::UnsealState;

/// Everything a request handler needs. Cloning this is cheap: every
/// field is already an `Arc` or a handle backed by a channel, so
/// `AppState` itself derives `Clone` the way Axum's `State` extractor
/// expects, without cloning any actual data.
#[derive(Clone)]
pub struct AppState {
    pub storage: Arc<dyn Storage>,
    pub raft: RaftHandle,
    pub audit: Arc<Mutex<AuditChain>>,
    /// `None` while sealed. Populated by `POST /sys/unseal` once a quorum
    /// of key-holder shares reconstructs a key that matches the vault's
    /// stored canary; cleared by `POST /sys/seal` or by an auto-seal.
    pub kek: Arc<Mutex<Option<SecretBytes>>>,
    /// Tracks the rate of secret-read access on this node. A single
    /// shared detector across all callers is deliberate: the anomaly
    /// signal is "how much total read traffic is this node seeing right
    /// now," not "how much traffic is any one client generating". A
    /// coordinated attack from multiple identities should still show up
    /// as one spike in the aggregate rate. Per-identity rate limiting is
    /// a different, complementary control this doesn't attempt to be.
    pub anomaly_detector: Arc<Mutex<AnomalyDetector>>,
    /// The in-progress unseal quorum (shares collected so far).
    pub unseal: UnsealState,
    /// Highest Raft log index this node's state machine has applied to
    /// storage. A write handler waits on it so a client reads its own write.
    pub applied: watch::Receiver<u64>,
    /// How long a write waits for a majority commit (and for this node to
    /// apply it) before answering 504.
    pub commit_timeout: Duration,
}

/// Shared fixtures for handler and router tests, so every test module
/// builds `AppState` the same way (and adding a field means touching one
/// place, not four).
#[cfg(test)]
pub mod test_support {
    use super::*;
    use sentinel_storage::SledStorage;

    pub struct NoopTransport;

    #[async_trait::async_trait]
    impl sentinel_consensus::Transport for NoopTransport {
        async fn send_request_vote(
            &self,
            _peer_id: u64,
            _req: sentinel_consensus::RequestVoteRequest,
        ) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
            unreachable!("single-node test cluster has no peers")
        }
        async fn send_append_entries(
            &self,
            _peer_id: u64,
            _req: sentinel_consensus::AppendEntriesRequest,
        ) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
            unreachable!("single-node test cluster has no peers")
        }
    }

    /// A transport that wins every election (grants all votes) but can never
    /// replicate: the shape of a leader that has lost its majority.
    pub struct VotesButNoReplication;

    #[async_trait::async_trait]
    impl sentinel_consensus::Transport for VotesButNoReplication {
        async fn send_request_vote(
            &self,
            _peer_id: u64,
            req: sentinel_consensus::RequestVoteRequest,
        ) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
            Ok(sentinel_consensus::RequestVoteResponse { term: req.term, vote_granted: true })
        }
        async fn send_append_entries(
            &self,
            peer_id: u64,
            _req: sentinel_consensus::AppendEntriesRequest,
        ) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
            Err(sentinel_consensus::TransportError::Unreachable(peer_id))
        }
    }

    pub fn default_detector() -> AnomalyDetector {
        AnomalyDetector::new(std::time::Duration::from_secs(3600), 20, 3.0)
    }

    /// Builds a `AppState` backed by a real Raft actor and the real apply
    /// loop, in a fresh temp dir. By default it is a single-node cluster
    /// (which commits instantly) with a 5 s commit timeout.
    pub async fn build(
        kek: Option<SecretBytes>,
        detector: AnomalyDetector,
        unseal: UnsealState,
        peers: Vec<u64>,
        transport: Arc<dyn sentinel_consensus::Transport>,
        commit_timeout: Duration,
    ) -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        let (raft, committed) = sentinel_consensus::spawn_raft_actor_with_apply(
            1,
            peers,
            transport,
            std::time::Duration::from_millis(20),
            sentinel_consensus::ElectionTimeoutRange { min_ms: 30, max_ms: 60 },
        );
        let kek = Arc::new(Mutex::new(kek));
        let audit = Arc::new(Mutex::new(AuditChain::new()));
        let applied = crate::statemachine::spawn_apply_loop(committed, storage.clone(), kek.clone(), audit.clone());
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let state = AppState {
            storage,
            raft,
            audit,
            kek,
            anomaly_detector: Arc::new(Mutex::new(detector)),
            unseal,
            applied,
            commit_timeout,
        };
        (state, dir)
    }

    /// Builds a single-node `AppState`. `kek` is the initial key (`None` =
    /// sealed). Unseal threshold is 2 (a 2-of-3 test quorum) unless `unseal`
    /// overrides it.
    pub async fn state_with(
        kek: Option<SecretBytes>,
        detector: AnomalyDetector,
        unseal: UnsealState,
    ) -> (AppState, tempfile::TempDir) {
        build(kek, detector, unseal, vec![], Arc::new(NoopTransport), Duration::from_secs(5)).await
    }

    pub async fn unsealed_state() -> (AppState, tempfile::TempDir) {
        let kek = SecretBytes::new(vec![0x42u8; sentinel_crypto::envelope::KEY_LEN]);
        state_with(Some(kek), default_detector(), UnsealState::new(2)).await
    }

    pub async fn sealed_state() -> (AppState, tempfile::TempDir) {
        state_with(None, default_detector(), UnsealState::new(2)).await
    }
}
'@

Write-SentinelFile 'crates\api\src\config.rs' @'
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
}

fn default_unseal_threshold() -> u8 {
    2
}

fn default_commit_timeout_ms() -> u64 {
    5_000
}

impl NodeConfig {
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
'@

Write-SentinelFile 'crates\api\src\main.rs' @'
mod config;
mod errors;
mod handlers;
mod middleware;
mod routes;
mod state;
mod statemachine;
mod transport;

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use config::NodeConfig;
use middleware::mtls::{self, ClientIdentity};
use state::AppState;
use transport::HttpTransport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .json()
        .init();

    mtls::ensure_crypto_provider_installed();

    let cfg = NodeConfig::load()?;
    tracing::info!(node_id = cfg.node_id, "sentinel node starting");

    let storage: Arc<dyn sentinel_storage::Storage> = Arc::new(sentinel_storage::SledStorage::open(&cfg.storage_path)?);
    let audit = Arc::new(tokio::sync::Mutex::new(sentinel_audit::AuditChain::new()));
    // Sealed at startup, always: nothing in this bootstrap path ever
    // populates the KEK. A node that could unseal itself just by starting
    // up would defeat the entire point of the quorum. Unsealing is an
    // explicit operation: key holders submit their shares to
    // `POST /sys/unseal` (see `sentinel-cli unseal`).
    let kek = Arc::new(tokio::sync::Mutex::new(None));
    if cfg.unseal_threshold < 2 {
        anyhow::bail!("unseal_threshold must be at least 2 (got {}); a threshold of 1 is not a quorum", cfg.unseal_threshold);
    }

    let peer_addrs = cfg.parse_peer_addrs()?;
    let peer_ids: Vec<u64> = peer_addrs.keys().copied().collect();

    let http_client = build_mtls_reqwest_client(&cfg)?;
    let raft_transport = Arc::new(HttpTransport::new(http_client, peer_addrs));

    // Raft's term, vote and log live on disk and are fsync'd before this node
    // answers a peer or acknowledges a client, so a crash or restart cannot
    // make it forget a vote or lose an entry it already confirmed.
    let raft_dir = cfg.raft_dir();
    let raft_store = sentinel_consensus::FileStore::open(&raft_dir)?;
    let (raft, committed) = sentinel_consensus::spawn_raft_actor_persistent(
        cfg.node_id,
        peer_ids,
        raft_transport,
        Duration::from_millis(50),
        sentinel_consensus::ElectionTimeoutRange::default(),
        Box::new(raft_store),
    )?;
    tracing::info!(dir = %raft_dir.display(), "raft state loaded");

    // The only code path that changes the secret store: committed log entries.
    let applied = statemachine::spawn_apply_loop(committed, storage.clone(), kek.clone(), audit.clone());

    // 1 bucket/second, 60-second rolling baseline, flag anything more
    // than 3 standard deviations above recent normal traffic. These are
    // reasonable starting defaults, not values proven optimal for any
    // particular deployment's real traffic shape - an operator running
    // this in production should expect to tune bucket width and
    // threshold against their own access patterns before trusting it to
    // seal automatically.
    let anomaly_detector = Arc::new(tokio::sync::Mutex::new(sentinel_anomaly::AnomalyDetector::new(
        Duration::from_secs(1),
        60,
        3.0,
    )));

    let unseal = handlers::unseal::UnsealState::new(cfg.unseal_threshold);
    let app_state = AppState {
        storage,
        raft,
        audit,
        kek,
        anomaly_detector,
        unseal,
        applied,
        commit_timeout: Duration::from_millis(cfg.commit_timeout_ms),
    };
    let router = routes::build_router(app_state);

    let tls_config = mtls::build_server_config(
        std::path::Path::new(&cfg.tls_cert_path),
        std::path::Path::new(&cfg.tls_key_path),
        std::path::Path::new(&cfg.ca_cert_path),
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    let listener = TcpListener::bind(&cfg.api_bind_addr).await?;
    tracing::info!(addr = %cfg.api_bind_addr, "listening for mTLS connections");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let router = router.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(peer = %peer_addr, error = %e, "mTLS handshake failed");
                    return;
                }
            };

            let identity = {
                let (_, conn) = tls_stream.get_ref();
                conn.peer_certificates()
                    .and_then(|certs| certs.first())
                    .and_then(mtls::extract_cn)
                    .map(ClientIdentity)
            };
            let Some(identity) = identity else {
                tracing::warn!(peer = %peer_addr, "handshake succeeded but client cert had no readable CN; refusing connection");
                return;
            };

            let router_with_identity = router.layer(axum::Extension(identity));
            let hyper_service = hyper_util::service::TowerToHyperService::new(router_with_identity);

            if let Err(e) = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(hyper_util::rt::TokioIo::new(tls_stream), hyper_service)
                .await
            {
                tracing::warn!(peer = %peer_addr, error = %e, "connection ended with error");
            }
        });
    }
}

/// Builds the `reqwest::Client` this node uses to call peers, presenting
/// this node's own cert/key as its client identity (peer nodes verify it
/// exactly the same way the API's own mTLS listener verifies any other
/// client - cluster RPCs are not a trusted-by-default side channel).
fn build_mtls_reqwest_client(cfg: &NodeConfig) -> anyhow::Result<reqwest::Client> {
    let mut identity_pem = std::fs::read(&cfg.tls_cert_path)?;
    identity_pem.extend_from_slice(&std::fs::read(&cfg.tls_key_path)?);
    let identity = reqwest::Identity::from_pem(&identity_pem)?;
    let ca_pem = std::fs::read(&cfg.ca_cert_path)?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem)?;

    Ok(reqwest::Client::builder()
        .identity(identity)
        .add_root_certificate(ca_cert)
        .use_rustls_tls()
        .timeout(Duration::from_secs(5))
        .build()?)
}
'@

Write-SentinelFile 'crates\api\src\statemachine.rs' @'
//! The replicated state machine.
//!
//! Every change to the vault's state (writing or deleting a secret, sealing)
//! is a [`Command`] that goes into the Raft log. A node changes its own
//! storage **only** when a command comes back out of the log as *committed*,
//! i.e. after a majority of the cluster has it durably. HTTP handlers never
//! write storage directly; they propose a command and wait. That is what
//! makes "the write succeeded" mean "a majority has it", and what makes every
//! node (leader or follower) end up with the same data and the same sealed
//! state.
//!
//! Commands carry already-encrypted values: the encryption happens on the
//! node that received the request, using the key-encryption key held in its
//! memory, and the log (on disk, on every node) only ever sees ciphertext.
//! Followers therefore apply writes without needing to be unsealed.
//!
//! After a restart a node replays its committed log from the start. Puts and
//! deletes are idempotent, but replaying an old `Seal` into a node that has
//! since been unsealed would wrongly re-seal it, so the loop persists the
//! index it has applied and skips everything at or below it.
//! (Operational rule that follows: never wipe the Raft directory without also
//! wiping the storage directory, or vice versa.)

use std::sync::Arc;

use bincode::Options;
use sentinel_audit::AuditChain;
use sentinel_consensus::LogEntry;
use sentinel_crypto::SecretBytes;
use sentinel_storage::{Storage, StorageError};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch, Mutex};

/// Where the applied-log-index checkpoint lives. Outside `secrets/`, so it is
/// never listed as a secret.
pub const APPLIED_INDEX_KEY: &str = "sys/applied-index";

const WIRE_VERSION: u8 = 1;
const MAX_COMMAND_BYTES: u64 = 8 * 1024 * 1024;

/// Storage key for a secret named `key`.
pub fn storage_key(key: &str) -> String {
    format!("secrets/{key}")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Command {
    /// `value` is a bincode-encoded `EnvelopeCiphertext`, never plaintext.
    Put { key: String, value: Vec<u8> },
    Delete { key: String },
    /// Seal every node. `reason` is free text for the audit log.
    Seal { reason: String },
}

fn codec() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().reject_trailing_bytes().with_limit(MAX_COMMAND_BYTES)
}

impl Command {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![WIRE_VERSION];
        out.extend(codec().serialize(self).expect("a Command always serializes"));
        out
    }

    /// `None` for anything that is not exactly one well-formed command of a
    /// supported version (so a malformed log entry can never panic a node).
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (version, rest) = bytes.split_first()?;
        if *version != WIRE_VERSION {
            return None;
        }
        codec().deserialize(rest).ok()
    }
}

/// Starts the loop that turns committed log entries into storage changes.
///
/// Returns a watch whose value is the highest log index this node has applied,
/// so a handler that just got its entry committed can wait until its own node
/// has applied it too (read-your-writes on the node that took the write).
pub fn spawn_apply_loop(
    mut committed: mpsc::UnboundedReceiver<LogEntry>,
    storage: Arc<dyn Storage>,
    kek: Arc<Mutex<Option<SecretBytes>>>,
    audit: Arc<Mutex<AuditChain>>,
) -> watch::Receiver<u64> {
    let (applied_tx, applied_rx) = watch::channel(0u64);

    tokio::spawn(async move {
        let mut applied = match load_applied_index(&*storage).await {
            Ok(i) => i,
            Err(e) => {
                tracing::error!(error = %e, "cannot read the applied-index checkpoint; the state machine will not run");
                return;
            }
        };
        advance(&applied_tx, applied);

        while let Some(entry) = committed.recv().await {
            if entry.index <= applied {
                // Already reflected in storage (we are replaying after a restart).
                advance(&applied_tx, entry.index);
                continue;
            }
            if let Err(e) = apply_entry(&entry, &*storage, &kek, &audit).await {
                // Fail-stop: carrying on past a failed apply would let this
                // node silently diverge. Writers will see timeouts instead.
                tracing::error!(index = entry.index, error = %e, "failed to apply a committed entry; stopping the state machine");
                break;
            }
            applied = entry.index;
            if let Err(e) = storage.put(APPLIED_INDEX_KEY, applied.to_be_bytes().to_vec()).await {
                tracing::error!(error = %e, "failed to record the applied index; stopping the state machine");
                break;
            }
            advance(&applied_tx, applied);
        }
    });

    applied_rx
}

fn advance(tx: &watch::Sender<u64>, index: u64) {
    tx.send_if_modified(|current| {
        if index > *current {
            *current = index;
            true
        } else {
            false
        }
    });
}

async fn load_applied_index(storage: &dyn Storage) -> Result<u64, StorageError> {
    match storage.get(APPLIED_INDEX_KEY).await {
        Ok(bytes) => {
            let arr: [u8; 8] =
                bytes.try_into().map_err(|_| StorageError::Backend("applied-index checkpoint is not 8 bytes".into()))?;
            Ok(u64::from_be_bytes(arr))
        }
        Err(StorageError::NotFound(_)) => Ok(0),
        Err(e) => Err(e),
    }
}

async fn apply_entry(
    entry: &LogEntry,
    storage: &dyn Storage,
    kek: &Mutex<Option<SecretBytes>>,
    audit: &Mutex<AuditChain>,
) -> Result<(), StorageError> {
    match Command::decode(&entry.command) {
        None => {
            // Committed but unintelligible (corrupt, or from a newer version).
            // It still occupies its slot, so skip it visibly rather than stall.
            audit.lock().await.append(format!("ignored an undecodable committed command at log index {}", entry.index));
        }
        Some(Command::Put { key, value }) => storage.put(&storage_key(&key), value).await?,
        Some(Command::Delete { key }) => match storage.delete(&storage_key(&key)).await {
            Ok(()) | Err(StorageError::NotFound(_)) => {}
            Err(e) => return Err(e),
        },
        Some(Command::Seal { reason }) => {
            *kek.lock().await = None;
            audit
                .lock()
                .await
                .append(format!("vault SEALED by a committed cluster-wide seal command (log index {}): {reason}", entry.index));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_storage::SledStorage;
    use std::time::Duration;

    #[test]
    fn commands_round_trip() {
        let cmds = [
            Command::Put { key: "db".into(), value: vec![1, 2, 3] },
            Command::Delete { key: "db".into() },
            Command::Seal { reason: "anomaly".into() },
        ];
        for c in cmds {
            assert_eq!(Command::decode(&c.encode()), Some(c));
        }
    }

    #[test]
    fn malformed_commands_decode_to_none_and_never_panic() {
        assert_eq!(Command::decode(&[]), None);
        assert_eq!(Command::decode(&[99, 1, 2, 3]), None, "unknown version");
        assert_eq!(Command::decode(&[1]), None, "version byte alone");
        assert_eq!(Command::decode(b"SEAL:garbage"), None);

        let mut trailing = Command::Delete { key: "k".into() }.encode();
        trailing.push(0);
        assert_eq!(Command::decode(&trailing), None, "trailing bytes are rejected");

        // A hostile length prefix must not allocate gigabytes.
        let hostile = [1u8, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        assert_eq!(Command::decode(&hostile), None);
    }

    struct Harness {
        tx: mpsc::UnboundedSender<LogEntry>,
        storage: Arc<dyn Storage>,
        kek: Arc<Mutex<Option<SecretBytes>>>,
        audit: Arc<Mutex<AuditChain>>,
        applied: watch::Receiver<u64>,
        _dir: tempfile::TempDir,
    }

    async fn harness_with_applied(applied_index: Option<u64>) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let storage: Arc<dyn Storage> = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        if let Some(i) = applied_index {
            storage.put(APPLIED_INDEX_KEY, i.to_be_bytes().to_vec()).await.unwrap();
        }
        let kek = Arc::new(Mutex::new(Some(SecretBytes::new(vec![7u8; 32]))));
        let audit = Arc::new(Mutex::new(AuditChain::new()));
        let (tx, rx) = mpsc::unbounded_channel();
        let applied = spawn_apply_loop(rx, storage.clone(), kek.clone(), audit.clone());
        Harness { tx, storage, kek, audit, applied, _dir: dir }
    }

    fn entry(index: u64, cmd: &Command) -> LogEntry {
        LogEntry { term: 1, index, command: cmd.encode() }
    }

    async fn wait_applied(h: &Harness, index: u64) {
        let mut rx = h.applied.clone();
        tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= index)).await.expect("timed out").unwrap();
    }

    #[tokio::test]
    async fn committed_puts_and_deletes_change_storage_and_report_progress() {
        let h = harness_with_applied(None).await;
        h.tx.send(entry(1, &Command::Put { key: "a".into(), value: vec![9, 9] })).unwrap();
        wait_applied(&h, 1).await;
        assert_eq!(h.storage.get("secrets/a").await.unwrap(), vec![9, 9]);

        h.tx.send(entry(2, &Command::Delete { key: "a".into() })).unwrap();
        h.tx.send(entry(3, &Command::Delete { key: "never-existed".into() })).unwrap();
        wait_applied(&h, 3).await;
        assert!(h.storage.get("secrets/a").await.is_err());

        // The checkpoint is durable and lives outside the secrets namespace.
        assert_eq!(load_applied_index(&*h.storage).await.unwrap(), 3);
        assert!(h.storage.list("secrets/").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_committed_seal_command_seals_the_node_and_is_audited() {
        let h = harness_with_applied(None).await;
        assert!(h.kek.lock().await.is_some());
        h.tx.send(entry(1, &Command::Seal { reason: "test anomaly".into() })).unwrap();
        wait_applied(&h, 1).await;

        assert!(h.kek.lock().await.is_none());
        let chain = h.audit.lock().await;
        assert!(chain.verify().is_ok());
        assert!(chain.entries().iter().any(|e| e.event.contains("committed cluster-wide seal command") && e.event.contains("test anomaly")));
    }

    #[tokio::test]
    async fn entries_at_or_below_the_checkpoint_are_skipped_on_replay() {
        // The node already applied up to index 5 before it restarted.
        let h = harness_with_applied(Some(5)).await;
        wait_applied(&h, 5).await;

        // Replay delivers old entries again, including an old Seal. It must NOT
        // re-seal a node that was unsealed since, nor redo the old write.
        h.tx.send(entry(3, &Command::Seal { reason: "ancient".into() })).unwrap();
        h.tx.send(entry(4, &Command::Put { key: "stale".into(), value: vec![1] })).unwrap();
        h.tx.send(entry(6, &Command::Put { key: "fresh".into(), value: vec![2] })).unwrap();
        wait_applied(&h, 6).await;

        assert!(h.kek.lock().await.is_some(), "an old seal must not be replayed");
        assert!(h.storage.get("secrets/stale").await.is_err());
        assert_eq!(h.storage.get("secrets/fresh").await.unwrap(), vec![2]);
    }

    #[tokio::test]
    async fn an_undecodable_committed_entry_is_skipped_visibly_without_stalling() {
        let h = harness_with_applied(None).await;
        h.tx.send(LogEntry { term: 1, index: 1, command: b"not a command".to_vec() }).unwrap();
        h.tx.send(entry(2, &Command::Put { key: "after".into(), value: vec![5] })).unwrap();
        wait_applied(&h, 2).await;

        assert_eq!(h.storage.get("secrets/after").await.unwrap(), vec![5]);
        assert!(h.audit.lock().await.entries().iter().any(|e| e.event.contains("undecodable committed command at log index 1")));
    }

    // ---- three real nodes ----

    use sentinel_consensus::{
        spawn_raft_actor_with_apply, AppendEntriesRequest, AppendEntriesResponse, ElectionTimeoutRange, RaftHandle,
        RequestVoteRequest, RequestVoteResponse, Role, Transport, TransportError,
    };
    use std::collections::HashMap;

    struct Loopback {
        handles: Mutex<HashMap<u64, RaftHandle>>,
    }
    struct LoopTransport(Arc<Loopback>);

    impl LoopTransport {
        async fn peer(&self, id: u64) -> Result<RaftHandle, TransportError> {
            self.0.handles.lock().await.get(&id).cloned().ok_or(TransportError::Unreachable(id))
        }
    }

    #[async_trait::async_trait]
    impl Transport for LoopTransport {
        async fn send_request_vote(&self, p: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
            Ok(self.peer(p).await?.request_vote(req).await)
        }
        async fn send_append_entries(&self, p: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
            Ok(self.peer(p).await?.append_entries(req).await)
        }
    }

    struct Node {
        raft: RaftHandle,
        storage: Arc<dyn Storage>,
        kek: Arc<Mutex<Option<SecretBytes>>>,
        audit: Arc<Mutex<AuditChain>>,
        applied: watch::Receiver<u64>,
        _dir: tempfile::TempDir,
    }

    async fn three_nodes() -> HashMap<u64, Node> {
        let ids = [1u64, 2, 3];
        let net = Arc::new(Loopback { handles: Mutex::new(HashMap::new()) });
        let mut nodes = HashMap::new();
        for &id in &ids {
            let dir = tempfile::tempdir().unwrap();
            let storage: Arc<dyn Storage> = Arc::new(SledStorage::open(dir.path().to_str().unwrap()).unwrap());
            let kek = Arc::new(Mutex::new(Some(SecretBytes::new(vec![7u8; 32]))));
            let audit = Arc::new(Mutex::new(AuditChain::new()));
            let peers: Vec<u64> = ids.iter().copied().filter(|&p| p != id).collect();
            let (raft, rx) = spawn_raft_actor_with_apply(
                id,
                peers,
                Arc::new(LoopTransport(net.clone())),
                Duration::from_millis(20),
                ElectionTimeoutRange { min_ms: 80, max_ms: 150 },
            );
            net.handles.lock().await.insert(id, raft.clone());
            let applied = spawn_apply_loop(rx, storage.clone(), kek.clone(), audit.clone());
            nodes.insert(id, Node { raft, storage, kek, audit, applied, _dir: dir });
        }
        nodes
    }

    async fn leader_of(nodes: &HashMap<u64, Node>) -> u64 {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                for (&id, n) in nodes {
                    if n.raft.inspect().await.0 == Role::Leader {
                        return id;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("no leader")
    }

    #[tokio::test]
    async fn a_committed_write_reaches_every_nodes_storage_and_a_seal_seals_every_node() {
        let nodes = three_nodes().await;
        let leader = leader_of(&nodes).await;

        let put = Command::Put { key: "db-password".into(), value: vec![0xAA, 0xBB] };
        let index = nodes[&leader].raft.propose_and_wait(put.encode(), Duration::from_secs(5)).await.unwrap();

        for (id, node) in &nodes {
            let mut rx = node.applied.clone();
            tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= index))
                .await
                .unwrap_or_else(|_| panic!("node {id} never applied index {index}"))
                .unwrap();
            assert_eq!(node.storage.get("secrets/db-password").await.unwrap(), vec![0xAA, 0xBB], "node {id}");
        }

        // A seal proposed on the leader seals the leader AND both followers.
        let seal = Command::Seal { reason: "cluster-wide test".into() };
        let seal_index = nodes[&leader].raft.propose_and_wait(seal.encode(), Duration::from_secs(5)).await.unwrap();
        for (id, node) in &nodes {
            let mut rx = node.applied.clone();
            tokio::time::timeout(Duration::from_secs(5), rx.wait_for(|&v| v >= seal_index))
                .await
                .unwrap_or_else(|_| panic!("node {id} never applied the seal"))
                .unwrap();
            assert!(node.kek.lock().await.is_none(), "node {id} must be sealed");
            assert!(node.audit.lock().await.entries().iter().any(|e| e.event.contains("cluster-wide seal command")), "node {id}");
        }
    }
}
'@

Write-SentinelFile 'crates\api\src\handlers\secrets.rs' @'
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Extension;
use std::time::Instant;

use crate::middleware::mtls::ClientIdentity;

use sentinel_crypto::envelope;

use crate::errors::AppError;
use crate::state::AppState;
use crate::statemachine::{storage_key, Command};

const MAX_KEY_LEN: usize = 512;

/// Secret names end up in storage keys and the audit log, so keep them sane.
fn validate_key(key: &str) -> Result<(), AppError> {
    if key.is_empty() || key.len() > MAX_KEY_LEN || key.chars().any(|c| c.is_control()) {
        return Err(AppError::BadRequest(format!(
            "secret names must be 1-{MAX_KEY_LEN} bytes with no control characters"
        )));
    }
    Ok(())
}

/// Proposes `command` and returns only once a **majority of the cluster has
/// committed it** and this node's state machine has applied it. Handlers never
/// write storage themselves, so a 2xx from here means the change is durable on
/// a majority, not just accepted by a leader that might be about to lose its
/// majority.
async fn commit(state: &AppState, command: Command) -> Result<(), AppError> {
    let index = state.raft.propose_and_wait(command.encode(), state.commit_timeout).await?;

    let mut applied = state.applied.clone();
    match tokio::time::timeout(state.commit_timeout, applied.wait_for(|&v| v >= index)).await {
        Ok(Ok(_)) => Ok(()),
        _ => Err(AppError::CommitTimeout),
    }
}

/// Every operation that touches the secret store, including listing and
/// deleting, must refuse while sealed. A sealed vault is supposed to be
/// inert: it must not reveal which keys exist, nor accept destructive
/// operations, until a quorum has unsealed it.
async fn require_unsealed(state: &AppState) -> Result<(), AppError> {
    if state.kek.lock().await.is_none() {
        Err(AppError::Sealed)
    } else {
        Ok(())
    }
}

/// Writes a secret. Requires the vault to be unsealed and this node to be
/// the Raft leader. The value is encrypted here, the ciphertext is proposed
/// to the log, and the call returns only after a majority has committed it
/// and this node has applied it (see [`commit`]). On a follower it fails
/// with 421 (`NotLeader`); if the leader cannot reach a majority it fails
/// with 504 and **nothing is written**.
pub async fn put_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<StatusCode, AppError> {
    validate_key(&key)?;

    let kek_guard = state.kek.lock().await;
    let kek = kek_guard.as_ref().ok_or(AppError::Sealed)?;
    let ciphertext = envelope::encrypt(kek, &body)?;
    drop(kek_guard);

    let value = bincode::serialize(&ciphertext).map_err(|e| AppError::Internal(e.into()))?;
    commit(&state, Command::Put { key: key.clone(), value }).await?;

    state.audit.lock().await.append(format!("secret written: {key} (by {})", identity.0));

    Ok(StatusCode::OK)
}

/// Reads a secret. Requires the vault to be unsealed. Does not require
/// leadership - reads are served locally, which is standard practice
/// for a "read your own writes isn't guaranteed on a stale follower"
/// tradeoff; a future phase could add a leader-only strict-read mode for
/// callers that need linearizable reads.
///
/// Every read is recorded against the node's anomaly detector *before*
/// anything else happens. If the resulting access rate is a statistical
/// outlier against this node's own recent baseline, the vault seals
/// itself immediately - including refusing the very request that
/// triggered the detection - and proposes the seal decision to the Raft
/// log so the rest of the cluster converges on the same sealed state
/// rather than leaving other nodes exploitable.
pub async fn get_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key): Path<String>,
) -> Result<Bytes, AppError> {
    let anomaly = state.anomaly_detector.lock().await.record_access(Instant::now());
    if let Some(report) = anomaly {
        // Seal locally first and unconditionally: a node that detects the
        // anomaly must protect itself even if replication is degraded, which
        // is exactly when it is most likely to be.
        *state.kek.lock().await = None;
        // Then ask the cluster to seal too. The command is applied on every
        // node when it commits. Best-effort: only the leader can propose, so
        // an anomaly detected on a follower seals that follower now and is
        // forwarded to the leader by the peer-forwarding added in Phase 16.
        let seal = Command::Seal {
            reason: format!(
                "access rate anomaly detected by {}: count={}, baseline_mean={:.1}, z_score={:.1}",
                identity.0, report.current_count, report.baseline_mean, report.z_score
            ),
        };
        let _ = state.raft.propose(seal.encode()).await;
        state.audit.lock().await.append(format!(
            "AUTO-SEAL triggered by {}: access rate anomaly (count={}, baseline_mean={:.1}, z_score={:.1})",
            identity.0, report.current_count, report.baseline_mean, report.z_score
        ));
        return Err(AppError::Sealed);
    }

    let kek_guard = state.kek.lock().await;
    let kek = kek_guard.as_ref().ok_or(AppError::Sealed)?;

    let blob = state.storage.get(&storage_key(&key)).await.map_err(|_| AppError::NotFound)?;
    let ciphertext: envelope::EnvelopeCiphertext =
        bincode::deserialize(&blob).map_err(|e| AppError::Internal(e.into()))?;
    let plaintext = envelope::decrypt(kek, &ciphertext)?;
    drop(kek_guard);

    state.audit.lock().await.append(format!("secret read: {key} (by {})", identity.0));

    Ok(Bytes::from(plaintext))
}

/// Deletes a secret. Requires the vault to be unsealed and this node to be
/// the leader, and returns only after a majority has committed the deletion
/// (same contract as [`put_secret`]).
pub async fn delete_secret(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Path(key): Path<String>,
) -> Result<StatusCode, AppError> {
    require_unsealed(&state).await?;
    validate_key(&key)?;

    commit(&state, Command::Delete { key: key.clone() }).await?;
    state.audit.lock().await.append(format!("secret deleted: {key} (by {})", identity.0));

    Ok(StatusCode::NO_CONTENT)
}

/// Lists secret keys. Requires the vault to be unsealed. (The storage
/// layer namespaces everything under `secrets/`, so callers see plain key
/// names without that prefix.)
pub async fn list_secrets(State(state): State<AppState>) -> Result<axum::Json<Vec<String>>, AppError> {
    require_unsealed(&state).await?;
    let full_keys = state.storage.list("secrets/").await?;
    let keys = full_keys.into_iter().map(|k| k.trim_start_matches("secrets/").to_string()).collect();
    Ok(axum::Json(keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_support::{sealed_state, state_with, unsealed_state};
    use crate::handlers::unseal::UnsealState;
    use axum::{routing::get, Router};
    use sentinel_crypto::envelope::KEY_LEN;
    use tower::ServiceExt;

    async fn test_state() -> (AppState, tempfile::TempDir) {
        unsealed_state().await
    }

    async fn test_state_with_detector(detector: sentinel_anomaly::AnomalyDetector) -> (AppState, tempfile::TempDir) {
        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        state_with(Some(kek), detector, UnsealState::new(2)).await
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route("/secrets/{key}", get(get_secret).put(put_secret).delete(delete_secret))
            .route("/secrets", get(list_secrets))
            .layer(axum::Extension(ClientIdentity("test-client".to_string())))
            .with_state(state)
    }

    #[tokio::test]
    async fn write_then_read_round_trips_through_encryption() {
        let (state, _dir) = test_state().await;
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/db-password")
            .body(axum::body::Body::from("hunter2"))
            .unwrap();
        let put_resp = router.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_resp.status(), StatusCode::OK);

        let get_req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
        let get_resp = router.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"hunter2");
    }

    #[tokio::test]
    async fn read_missing_key_returns_404() {
        let (state, _dir) = test_state().await;
        let router = app(state);
        let req = axum::http::Request::builder().uri("/secrets/nope").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn read_while_sealed_returns_503() {
        let (state, _dir) = test_state().await;
        *state.kek.lock().await = None;
        let router = app(state);
        let req = axum::http::Request::builder().uri("/secrets/anything").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn write_then_delete_then_read_returns_404() {
        let (state, _dir) = test_state().await;
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/temp")
            .body(axum::body::Body::from("gone-soon"))
            .unwrap();
        router.clone().oneshot(put_req).await.unwrap();

        let del_req = axum::http::Request::builder().method("DELETE").uri("/secrets/temp").body(axum::body::Body::empty()).unwrap();
        let del_resp = router.clone().oneshot(del_req).await.unwrap();
        assert_eq!(del_resp.status(), StatusCode::NO_CONTENT);

        let get_req = axum::http::Request::builder().uri("/secrets/temp").body(axum::body::Body::empty()).unwrap();
        let get_resp = router.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_returns_written_keys_without_the_storage_prefix() {
        let (state, _dir) = test_state().await;
        let router = app(state);

        for key in ["alpha", "beta"] {
            let req = axum::http::Request::builder()
                .method("PUT")
                .uri(format!("/secrets/{key}"))
                .body(axum::body::Body::from("x"))
                .unwrap();
            router.clone().oneshot(req).await.unwrap();
        }

        let list_req = axum::http::Request::builder().uri("/secrets").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(list_req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let mut keys: Vec<String> = serde_json::from_slice(&body).unwrap();
        keys.sort();
        assert_eq!(keys, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[tokio::test]
    async fn audit_log_records_every_operation() {
        let (state, _dir) = test_state().await;
        let audit = state.audit.clone();
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/k")
            .body(axum::body::Body::from("v"))
            .unwrap();
        router.clone().oneshot(put_req).await.unwrap();

        let get_req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
        router.oneshot(get_req).await.unwrap();

        let chain = audit.lock().await;
        assert!(chain.verify().is_ok());
        let events: Vec<&str> = chain.entries().iter().map(|e| e.event.as_str()).collect();
        assert!(events.contains(&"secret written: k (by test-client)"));
        assert!(events.contains(&"secret read: k (by test-client)"));
    }

    #[tokio::test]
    async fn sudden_read_burst_triggers_auto_seal_and_is_audit_logged() {
        let detector = sentinel_anomaly::AnomalyDetector::new(std::time::Duration::from_millis(20), 20, 3.0);
        let (state, _dir) = test_state_with_detector(detector).await;
        let audit = state.audit.clone();
        let kek = state.kek.clone();
        let router = app(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/secrets/db-password")
            .body(axum::body::Body::from("hunter2"))
            .unwrap();
        router.clone().oneshot(put_req).await.unwrap();

        for _ in 0..10 {
            let req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "baseline reads should succeed normally");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let mut sealed = false;
        for _ in 0..40 {
            let req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
            let resp = router.clone().oneshot(req).await.unwrap();
            if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
                sealed = true;
                break;
            }
        }
        assert!(sealed, "a sudden read burst should trigger auto-seal");
        assert!(kek.lock().await.is_none(), "KEK should be cleared once auto-seal fires");

        let chain = audit.lock().await;
        assert!(chain.verify().is_ok(), "audit chain must remain internally consistent even after an auto-seal event");
        assert!(
            chain.entries().iter().any(|e| e.event.starts_with("AUTO-SEAL triggered")),
            "the seal event itself must be audit-logged, not just silently applied"
        );

        drop(chain);
        let req = axum::http::Request::builder().uri("/secrets/db-password").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn list_while_sealed_returns_503() {
        let (state, _dir) = sealed_state().await;
        state.storage.put("secrets/hidden", vec![1]).await.unwrap();
        let router = app(state);
        let req = axum::http::Request::builder().uri("/secrets").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "a sealed vault must not reveal key names");
    }

    #[tokio::test]
    async fn delete_while_sealed_returns_503_and_leaves_the_secret_intact() {
        let (state, _dir) = test_state().await;
        let kek_handle = state.kek.clone();
        let router = app(state);

        let put_req = axum::http::Request::builder().method("PUT").uri("/secrets/keep-me").body(axum::body::Body::from("v")).unwrap();
        assert_eq!(router.clone().oneshot(put_req).await.unwrap().status(), StatusCode::OK);

        let saved_kek = kek_handle.lock().await.take();
        let del_req = axum::http::Request::builder().method("DELETE").uri("/secrets/keep-me").body(axum::body::Body::empty()).unwrap();
        assert_eq!(router.clone().oneshot(del_req).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);

        *kek_handle.lock().await = saved_kek;
        let get_req = axum::http::Request::builder().uri("/secrets/keep-me").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(get_req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "the sealed-state delete must not have removed anything");
    }

    #[tokio::test]
    async fn a_write_on_a_node_that_is_not_leader_is_refused_and_stores_nothing() {
        use crate::state::test_support::{build, default_detector};
        // Peers exist but never answer, so this node can never win an election.
        struct Silent;
        #[async_trait::async_trait]
        impl sentinel_consensus::Transport for Silent {
            async fn send_request_vote(&self, p: u64, _: sentinel_consensus::RequestVoteRequest) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
            async fn send_append_entries(&self, p: u64, _: sentinel_consensus::AppendEntriesRequest) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
        }
        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        let (state, _dir) = build(Some(kek), default_detector(), UnsealState::new(2), vec![2, 3], std::sync::Arc::new(Silent), std::time::Duration::from_secs(1)).await;
        let storage = state.storage.clone();
        let router = app(state);

        let req = axum::http::Request::builder().method("PUT").uri("/secrets/k").body(axum::body::Body::from("v")).unwrap();
        assert_eq!(router.oneshot(req).await.unwrap().status(), StatusCode::MISDIRECTED_REQUEST);
        assert!(storage.get("secrets/k").await.is_err(), "a refused write must leave no trace");
    }

    #[tokio::test]
    async fn a_leader_that_cannot_reach_a_majority_does_not_apply_the_write() {
        // The bug this phase fixes: the old handler proposed and then wrote
        // straight to storage, so a partitioned leader "succeeded" with data
        // no other node had. Now the write waits for a majority, times out,
        // and storage is untouched.
        use crate::state::test_support::{build, default_detector, VotesButNoReplication};
        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; KEY_LEN]);
        let (state, _dir) = build(
            Some(kek),
            default_detector(),
            UnsealState::new(2),
            vec![2, 3],
            std::sync::Arc::new(VotesButNoReplication),
            std::time::Duration::from_millis(400),
        )
        .await;
        // Wait until this node has actually become leader.
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while state.raft.inspect().await.0 != sentinel_consensus::Role::Leader {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("node should win the (fake) election");

        let storage = state.storage.clone();
        let audit = state.audit.clone();
        let router = app(state);

        let put = axum::http::Request::builder().method("PUT").uri("/secrets/orphan").body(axum::body::Body::from("secret")).unwrap();
        let resp = router.clone().oneshot(put).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT, "an unconfirmed write must not report success");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(storage.get("secrets/orphan").await.is_err(), "the write must not have reached storage");
        assert!(
            !audit.lock().await.entries().iter().any(|e| e.event.starts_with("secret written: orphan")),
            "and must not be audited as written"
        );

        let del = axum::http::Request::builder().method("DELETE").uri("/secrets/orphan").body(axum::body::Body::empty()).unwrap();
        assert_eq!(router.oneshot(del).await.unwrap().status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn bad_secret_names_are_rejected_before_anything_is_proposed() {
        let (state, _dir) = test_state().await;
        let router = app(state);
        let long = "a".repeat(513);
        for name in [long.as_str(), "bad%0Aname", "tab%09name"] {
            let req = axum::http::Request::builder().method("PUT").uri(format!("/secrets/{name}")).body(axum::body::Body::from("v")).unwrap();
            assert_eq!(router.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST, "name {name:.12?}");
        }
    }

    #[tokio::test]
    async fn the_anomaly_seal_is_proposed_as_a_replicated_command_and_applied() {
        let detector = sentinel_anomaly::AnomalyDetector::new(std::time::Duration::from_millis(20), 20, 3.0);
        let (state, _dir) = test_state_with_detector(detector).await;
        let audit = state.audit.clone();
        let router = app(state);

        let put = axum::http::Request::builder().method("PUT").uri("/secrets/k").body(axum::body::Body::from("v")).unwrap();
        router.clone().oneshot(put).await.unwrap();
        for _ in 0..10 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            router.clone().oneshot(req).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for _ in 0..40 {
            let req = axum::http::Request::builder().uri("/secrets/k").body(axum::body::Body::empty()).unwrap();
            if router.clone().oneshot(req).await.unwrap().status() == StatusCode::SERVICE_UNAVAILABLE {
                break;
            }
        }

        // The committed seal command comes back out of the log and is applied.
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                if audit.lock().await.entries().iter().any(|e| e.event.contains("committed cluster-wide seal command")) {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the replicated seal command should have been applied");
    }
}
'@

Write-SentinelFile 'crates\api\src\handlers\cluster.rs' @'
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn cluster_status(State(state): State<AppState>) -> Json<Value> {
    let (role, term, commit_index) = state.raft.inspect().await;
    Json(json!({
        "role": format!("{role:?}"),
        "term": term,
        "commit_index": commit_index,
        "applied_index": *state.applied.borrow(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_support::sealed_state;
    use axum::{routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn status_reports_leader_role_for_a_single_node_cluster() {
        let (state, _dir) = sealed_state().await;
        let router = Router::new().route("/cluster/status", get(cluster_status)).with_state(state);

        let req = axum::http::Request::builder().uri("/cluster/status").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["role"], "Leader");
        assert_eq!(json["term"], 1);
        assert!(json["applied_index"].is_u64(), "status must report how far the state machine has applied");
    }
}
'@

Write-SentinelFile '.env.toml.example' @'
# Copy to `.env.toml` in the directory you launch `sentinel-node` from.
# Every key can also be set as an environment variable named
# SENTINEL__<KEY_IN_UPPERCASE>. The environment wins over this file.

node_id        = 1
api_bind_addr  = "127.0.0.1:8443"
storage_path   = "data/node1.sled"

tls_cert_path  = "pki/node1.crt"
tls_key_path   = "pki/node1.key"
ca_cert_path   = "pki/ca.crt"

# Key holders needed to unseal this node ("2" = a 2-of-N quorum). Must match
# the threshold the key shares were created with. Minimum 2.
unseal_threshold = 2

# Where Raft keeps its term, vote and log (fsync'd; must be durable storage).
# Default: "<storage_path>.raft". Never delete this without also deleting
# storage_path, or the reverse; the two are a matched pair.
# raft_dir = "data/node1.raft"

# How long a write waits for a majority of the cluster to commit it (ms).
commit_timeout_ms = 5000

# Other nodes, "<node_id>=<base_url>". Leave empty for a single node.
# From the environment: SENTINEL__PEERS="2=https://127.0.0.1:8444,3=https://127.0.0.1:8445"
peers = [
    # "2=https://127.0.0.1:8444",
    # "3=https://127.0.0.1:8445",
]
'@

# ---- verify ---------------------------------------------------------------
$expected = [ordered]@{
  'crates\consensus\Cargo.toml' = 'a8b3bec9ee91'
  'crates\consensus\src\lib.rs' = '5dd658baa9a8'
  'crates\consensus\src\log.rs' = '73ef6326f584'
  'crates\consensus\src\persist.rs' = '40fe7383048d'
  'crates\consensus\src\state.rs' = '4499effb35c7'
  'crates\consensus\src\actor.rs' = '2cabf02c2927'
  'crates\api\src\errors.rs' = 'd024ebd433ee'
  'crates\api\src\state.rs' = '9225cf067fbf'
  'crates\api\src\config.rs' = '9177f984f51a'
  'crates\api\src\main.rs' = '00d8f57129ad'
  'crates\api\src\statemachine.rs' = '46d792579e1c'
  'crates\api\src\handlers\secrets.rs' = '315a408283d4'
  'crates\api\src\handlers\cluster.rs' = 'cedbd104b52c'
  '.env.toml.example' = '4e4762df3b88'
}
$bad = 0
Write-Host ""
foreach ($rel in $expected.Keys) {
  $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $Root $rel)).Hash.ToLower().Substring(0, 12)
  if ($actual -eq $expected[$rel]) { Write-Host "  OK        $rel" -ForegroundColor Green }
  else { Write-Host "  MISMATCH  $rel (expected $($expected[$rel]), got $actual)" -ForegroundColor Red; $bad++ }
}
Write-Host ""
if ($bad -gt 0) {
  Write-Host "$bad file(s) did not match. Do not build. Run 'git checkout .' to undo and tell me which ones." -ForegroundColor Red
  exit 1
}
Write-Host "All 14 files verified. Next:  cargo test --workspace" -ForegroundColor Green
