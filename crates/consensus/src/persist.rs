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
//!   record length-prefixed and CRC-checked, fsync'd per batch), a tiny
//!   hard-state file replaced atomically, and an optional snapshot file
//!   replaced atomically.
//! * [`MemoryStore`]: for tests, with failure injection.
//!
//! # Snapshots and compaction
//!
//! Compaction is two durable steps, always in this order:
//!
//! 1. [`RaftStore::save_snapshot`] writes the snapshot file (temp file,
//!    fsync, rename, fsync of the directory). From here on the snapshot is
//!    authoritative.
//! 2. [`RaftStore::rewrite_log`] replaces the WAL with only the entries after
//!    the snapshot (same temp-and-rename dance).
//!
//! A crash between the two leaves a snapshot plus a WAL that still holds the
//! old entries. That is safe: `RaftState::restore` reconciles them, and the
//! WAL's first record tells `load` which index the file starts at (a trimmed
//! WAL starts at `snapshot + 1`, an untrimmed one at 1). The opposite order
//! would be unsafe (entries gone, snapshot missing), so a snapshot that is
//! damaged is a refusal to start, never silently ignored: the WAL may no
//! longer hold what it covers.

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
    #[error("snapshot of {size} bytes exceeds the {max} byte limit")]
    SnapshotTooLarge { size: usize, max: usize },
    #[error("injected storage failure")]
    Injected,
}

/// Everything recovered from disk at startup.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PersistedState {
    pub term: u64,
    pub voted_for: Option<u64>,
    /// Index and term of the last entry covered by the durable snapshot
    /// (both 0 if there is none). The snapshot is authoritative: `entries`
    /// may overlap or contradict it after a crash mid-compaction, and
    /// `RaftState::restore` reconciles the two.
    pub snapshot_index: u64,
    pub snapshot_term: u64,
    /// The state machine image the snapshot stands for (empty if none).
    pub snapshot_data: Vec<u8>,
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
    /// Durably stores a snapshot covering the log up to `index` (whose entry
    /// had term `term`). Does not touch the log: that is [`rewrite_log`]'s
    /// job, and it must come second. Refuses a snapshot older than the one
    /// already stored and one larger than [`MAX_SNAPSHOT_BYTES`].
    ///
    /// [`rewrite_log`]: RaftStore::rewrite_log
    fn save_snapshot(&mut self, index: u64, term: u64, data: &[u8]) -> Result<(), PersistError>;
    /// Replaces the stored log with `entries`, which must be contiguous and
    /// start right after the stored snapshot (at index 1 if there is none).
    /// All or nothing: a crash leaves either the old log or the new one.
    fn rewrite_log(&mut self, entries: &[LogEntry]) -> Result<(), PersistError>;
}

/// Largest snapshot image accepted, so that it can travel in one message and
/// a corrupt file can never make a node allocate without bound.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

fn check_snapshot_size(len: usize) -> Result<(), PersistError> {
    if len > MAX_SNAPSHOT_BYTES {
        return Err(PersistError::SnapshotTooLarge {
            size: len,
            max: MAX_SNAPSHOT_BYTES,
        });
    }
    Ok(())
}

/// The retained log must continue exactly where the snapshot stops.
fn check_log_follows(snapshot_index: u64, entries: &[LogEntry]) -> Result<(), PersistError> {
    for (i, e) in entries.iter().enumerate() {
        let expected = snapshot_index + 1 + i as u64;
        if e.index != expected {
            return Err(PersistError::Corrupt(format!(
                "retained log entry {} found where {} was expected (snapshot at {})",
                e.index, expected, snapshot_index
            )));
        }
    }
    Ok(())
}

/// Applies one journaled operation to a stored log whose first entry has
/// index `base + 1` (`base` is 0 until a snapshot has trimmed the log).
fn apply_op_to_vec(entries: &mut Vec<LogEntry>, base: u64, op: &LogOp) -> Result<(), PersistError> {
    match op {
        LogOp::Append(e) => {
            let expected = base + entries.len() as u64 + 1;
            if e.index != expected {
                return Err(PersistError::Corrupt(format!(
                    "append of index {} but log ends at {}",
                    e.index,
                    expected - 1
                )));
            }
            entries.push(e.clone());
        }
        LogOp::TruncateFrom(i) => {
            if *i <= base {
                return Err(PersistError::Corrupt(format!(
                    "truncate from index {i}, which is not above the snapshot base {base}"
                )));
            }
            entries.truncate((*i - base - 1) as usize);
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
        // Between `save_snapshot` and `rewrite_log` the log may still start
        // at 1, so the base comes from the log itself, as in the WAL.
        let base = match inner.state.entries.first() {
            Some(first) => first.index.saturating_sub(1),
            None => inner.state.snapshot_index,
        };
        // All or nothing, like the file store: work on a copy.
        let mut entries = inner.state.entries.clone();
        for op in ops {
            apply_op_to_vec(&mut entries, base, op)?;
        }
        inner.state.entries = entries;
        Ok(())
    }

    fn save_snapshot(&mut self, index: u64, term: u64, data: &[u8]) -> Result<(), PersistError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_writes {
            return Err(PersistError::Injected);
        }
        check_snapshot_size(data.len())?;
        if index < inner.state.snapshot_index {
            return Err(PersistError::Corrupt(format!(
                "snapshot at {index} would replace a newer one at {}",
                inner.state.snapshot_index
            )));
        }
        // The log is left alone, exactly as on disk: until `rewrite_log` it
        // may overlap the snapshot, and `RaftState::restore` copes with that.
        inner.state.snapshot_index = index;
        inner.state.snapshot_term = term;
        inner.state.snapshot_data = data.to_vec();
        Ok(())
    }

    fn rewrite_log(&mut self, entries: &[LogEntry]) -> Result<(), PersistError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.fail_writes {
            return Err(PersistError::Injected);
        }
        check_log_follows(inner.state.snapshot_index, entries)?;
        inner.state.entries = entries.to_vec();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// File store
// ---------------------------------------------------------------------------

const WAL_FILE: &str = "log.wal";
const HARD_STATE_FILE: &str = "hard_state";
const HARD_STATE_TMP: &str = "hard_state.tmp";
const SNAPSHOT_FILE: &str = "snapshot";
const SNAPSHOT_TMP: &str = "snapshot.tmp";
const WAL_TMP: &str = "log.wal.tmp";
const SNAPSHOT_MAGIC: &[u8; 4] = b"SNP1";
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
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .with_limit(MAX_RECORD_BYTES as u64)
}

pub struct FileStore {
    dir: PathBuf,
    wal: Option<File>,
    /// Index of the snapshot on disk (0 if none); set by `load`.
    snapshot_index: u64,
}

impl FileStore {
    /// Opens (creating if needed) a store rooted at `dir`.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, PersistError> {
        fs::create_dir_all(dir.as_ref())?;
        Ok(Self {
            dir: dir.as_ref().to_path_buf(),
            wal: None,
            snapshot_index: 0,
        })
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
        codec()
            .deserialize(payload)
            .map_err(|e| PersistError::Corrupt(format!("hard_state: {e}")))
    }

    /// Writes `bytes` to `name` so that a crash leaves the old file or the
    /// new one, never a mixture: temp file, fsync, rename, fsync the
    /// directory.
    fn write_atomically(&self, name: &str, tmp_name: &str, bytes: &[u8]) -> std::io::Result<()> {
        let tmp = self.dir.join(tmp_name);
        {
            let mut f = File::create(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, self.dir.join(name))?;
        #[cfg(unix)]
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Reads the snapshot file. A missing file means no snapshot; a damaged
    /// one is an error, because the WAL may no longer hold what it covers.
    fn read_snapshot(&self) -> Result<Option<(u64, u64, Vec<u8>)>, PersistError> {
        let bytes = match fs::read(self.dir.join(SNAPSHOT_FILE)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let bad = |why: &str| PersistError::Corrupt(format!("snapshot file: {why}"));
        if bytes.len() < 4 + SNAPSHOT_MAGIC.len() + 16 {
            return Err(bad("truncated"));
        }
        let (crc_bytes, body) = bytes.split_at(4);
        if u32::from_le_bytes(crc_bytes.try_into().unwrap()) != crc32(body) {
            return Err(bad("checksum mismatch"));
        }
        let (magic, rest) = body.split_at(SNAPSHOT_MAGIC.len());
        if magic != SNAPSHOT_MAGIC {
            return Err(bad("unknown format"));
        }
        let index = u64::from_le_bytes(rest[0..8].try_into().unwrap());
        let term = u64::from_le_bytes(rest[8..16].try_into().unwrap());
        let data = rest[16..].to_vec();
        check_snapshot_size(data.len())?;
        if index == 0 {
            return Err(bad("covers no entries"));
        }
        Ok(Some((index, term, data)))
    }

    fn wal(&mut self) -> Result<&mut File, PersistError> {
        self.wal.as_mut().ok_or_else(|| {
            PersistError::Corrupt("FileStore::load must be called before writing".into())
        })
    }
}

impl RaftStore for FileStore {
    fn load(&mut self) -> Result<PersistedState, PersistError> {
        let (term, voted_for) = self.read_hard_state()?;
        let snapshot = self.read_snapshot()?;
        let snapshot_index = snapshot.as_ref().map_or(0, |s| s.0);
        // Leftovers of a compaction that crashed before its rename were never
        // part of the state; the real files are untouched.
        for stale in [SNAPSHOT_TMP, WAL_TMP, HARD_STATE_TMP] {
            match fs::remove_file(self.dir.join(stale)) {
                Ok(()) => tracing::warn!(file = stale, "removed a leftover temporary file"),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.dir.join(WAL_FILE))?;
        let mut raw = Vec::new();
        file.read_to_end(&mut raw)?;

        let mut entries: Vec<LogEntry> = Vec::new();
        // Index the WAL starts after. A WAL trimmed to a snapshot begins at
        // `snapshot + 1`; one never trimmed (or trimmed for an older
        // snapshot) begins earlier. It can never begin after the snapshot,
        // which also means that with no snapshot it must begin at 1.
        let mut wal_base: Option<u64> = None;
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
            let base = *wal_base.get_or_insert(match &op {
                LogOp::Append(e) if e.index >= 1 => e.index - 1,
                _ => 0,
            });
            if base > snapshot_index {
                return Err(PersistError::Corrupt(format!(
                    "the log starts after index {base} but the snapshot only covers {snapshot_index}"
                )));
            }
            apply_op_to_vec(&mut entries, base, &op)?;
            pos = end;
        }

        if pos < raw.len() {
            tracing::warn!(
                discarded_bytes = raw.len() - pos,
                "raft WAL had a torn or corrupt tail; truncating it"
            );
            file.set_len(pos as u64)?;
            file.sync_all()?;
        }
        file.seek(SeekFrom::End(0))?;
        self.wal = Some(file);
        self.snapshot_index = snapshot_index;

        let (snapshot_term, snapshot_data) = snapshot.map_or((0, Vec::new()), |s| (s.1, s.2));
        Ok(PersistedState {
            term,
            voted_for,
            snapshot_index,
            snapshot_term,
            snapshot_data,
            entries,
        })
    }

    fn save_hard_state(&mut self, term: u64, voted_for: Option<u64>) -> Result<(), PersistError> {
        let payload = codec()
            .serialize(&(term, voted_for))
            .map_err(|e| PersistError::Corrupt(e.to_string()))?;
        let mut bytes = crc32(&payload).to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);

        self.write_atomically(HARD_STATE_FILE, HARD_STATE_TMP, &bytes)?;
        Ok(())
    }

    fn apply_log_ops(&mut self, ops: &[LogOp]) -> Result<(), PersistError> {
        if ops.is_empty() {
            return Ok(());
        }
        let mut buf = Vec::new();
        for op in ops {
            let payload = codec()
                .serialize(op)
                .map_err(|e| PersistError::Corrupt(e.to_string()))?;
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&crc32(&payload).to_le_bytes());
            buf.extend_from_slice(&payload);
        }
        let wal = self.wal()?;
        wal.write_all(&buf)?;
        wal.sync_data()?;
        Ok(())
    }

    fn save_snapshot(&mut self, index: u64, term: u64, data: &[u8]) -> Result<(), PersistError> {
        self.wal()?; // refuses before `load`
        check_snapshot_size(data.len())?;
        if index == 0 || index < self.snapshot_index {
            return Err(PersistError::Corrupt(format!(
                "snapshot at {index} would replace the one at {}",
                self.snapshot_index
            )));
        }
        let mut body = Vec::with_capacity(SNAPSHOT_MAGIC.len() + 16 + data.len());
        body.extend_from_slice(SNAPSHOT_MAGIC);
        body.extend_from_slice(&index.to_le_bytes());
        body.extend_from_slice(&term.to_le_bytes());
        body.extend_from_slice(data);
        let mut bytes = crc32(&body).to_le_bytes().to_vec();
        bytes.extend_from_slice(&body);
        self.write_atomically(SNAPSHOT_FILE, SNAPSHOT_TMP, &bytes)?;
        self.snapshot_index = index;
        Ok(())
    }

    fn rewrite_log(&mut self, entries: &[LogEntry]) -> Result<(), PersistError> {
        self.wal()?; // refuses before `load`
        check_log_follows(self.snapshot_index, entries)?;
        let mut buf = Vec::new();
        for e in entries {
            let payload = codec()
                .serialize(&LogOp::Append(e.clone()))
                .map_err(|e| PersistError::Corrupt(e.to_string()))?;
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&crc32(&payload).to_le_bytes());
            buf.extend_from_slice(&payload);
        }
        // Let go of the old file before replacing it (required on Windows),
        // and put the new one in its place only once it is complete.
        self.wal = None;
        let replaced = self.write_atomically(WAL_FILE, WAL_TMP, &buf);
        // Whatever happened, the node must keep a usable WAL handle: reopen
        // whichever file is now in place (the old one if the rename failed).
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.dir.join(WAL_FILE))?;
        file.seek(SeekFrom::End(0))?;
        self.wal = Some(file);
        replaced?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RaftState;

    fn entry(term: u64, index: u64) -> LogEntry {
        LogEntry {
            term,
            index,
            command: vec![index as u8; 3],
        }
    }

    #[test]
    fn replaying_operations_onto_a_log_trimmed_to_a_snapshot_uses_the_base() {
        let entry = |i: u64| LogEntry {
            term: 1,
            index: i,
            command: vec![],
        };
        let mut log: Vec<LogEntry> = Vec::new();
        // A log whose first 3 entries live in a snapshot continues at 4.
        apply_op_to_vec(&mut log, 3, &LogOp::Append(entry(4))).unwrap();
        apply_op_to_vec(&mut log, 3, &LogOp::Append(entry(5))).unwrap();
        assert_eq!(log.len(), 2);
        // A gap, or an index inside the snapshot, is corruption.
        assert!(apply_op_to_vec(&mut log, 3, &LogOp::Append(entry(7))).is_err());
        assert!(apply_op_to_vec(&mut log, 3, &LogOp::Append(entry(2))).is_err());
        // Truncation is relative to the base, and cannot reach into the snapshot.
        apply_op_to_vec(&mut log, 3, &LogOp::TruncateFrom(5)).unwrap();
        assert_eq!(log.len(), 1);
        assert!(apply_op_to_vec(&mut log, 3, &LogOp::TruncateFrom(3)).is_err());
        assert!(apply_op_to_vec(&mut log, 0, &LogOp::TruncateFrom(0)).is_err());
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
            store
                .apply_log_ops(&[
                    LogOp::Append(entry(1, 1)),
                    LogOp::Append(entry(1, 2)),
                    LogOp::Append(entry(2, 3)),
                ])
                .unwrap();
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
            store
                .apply_log_ops(&[
                    LogOp::Append(entry(1, 1)),
                    LogOp::Append(entry(1, 2)),
                    LogOp::Append(entry(1, 3)),
                ])
                .unwrap();
            store
                .apply_log_ops(&[LogOp::TruncateFrom(2), LogOp::Append(entry(2, 2))])
                .unwrap();
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
            store
                .apply_log_ops(&[LogOp::Append(entry(1, 1)), LogOp::Append(entry(1, 2))])
                .unwrap();
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
        assert_eq!(
            fs::metadata(&wal).unwrap().len(),
            good_len,
            "the torn tail must be cut off"
        );

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
        assert_eq!(
            loaded.entries,
            vec![entry(1, 1)],
            "the corrupt record and anything after it is dropped"
        );
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
        assert!(matches!(
            FileStore::open(dir.path()).unwrap().load(),
            Err(PersistError::Corrupt(_))
        ));
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
            store
                .apply_log_ops(&[LogOp::Append(entry(1, 1)), LogOp::Append(entry(1, 3))])
                .unwrap();
        }
        assert!(matches!(
            FileStore::open(dir.path()).unwrap().load(),
            Err(PersistError::Corrupt(_))
        ));
    }

    #[test]
    fn memory_store_round_trips_and_can_be_told_to_fail() {
        let mut store = MemoryStore::new();
        store.load().unwrap();
        store.save_hard_state(4, Some(1)).unwrap();
        store
            .apply_log_ops(&[
                LogOp::Append(entry(1, 1)),
                LogOp::Append(entry(1, 2)),
                LogOp::TruncateFrom(2),
            ])
            .unwrap();
        let snap = store.snapshot();
        assert_eq!(
            (snap.term, snap.voted_for, snap.entries.len()),
            (4, Some(1), 1)
        );

        store.set_fail_writes(true);
        assert!(matches!(
            store.save_hard_state(5, None),
            Err(PersistError::Injected)
        ));
        assert!(matches!(
            store.apply_log_ops(&[LogOp::Append(entry(1, 2))]),
            Err(PersistError::Injected)
        ));
        assert_eq!(
            store.snapshot().term,
            4,
            "a failed write must change nothing"
        );
    }

    // -----------------------------------------------------------------
    // Snapshots and compaction
    // -----------------------------------------------------------------

    fn entries(upto: u64) -> Vec<LogEntry> {
        (1..=upto).map(|i| entry(1 + i / 4, i)).collect()
    }

    fn append_all(store: &mut FileStore, es: &[LogEntry]) {
        let ops: Vec<LogOp> = es.iter().cloned().map(LogOp::Append).collect();
        store.apply_log_ops(&ops).unwrap();
    }

    /// A store holding entries 1..=n, term and index of the snapshot taken
    /// at `at` being (term of entry `at`, `at`).
    fn open_with_log(dir: &Path, n: u64) -> FileStore {
        let mut store = FileStore::open(dir).unwrap();
        store.load().unwrap();
        append_all(&mut store, &entries(n));
        store
    }

    fn copy_dir(from: &Path, to: &Path) {
        for f in fs::read_dir(from).unwrap() {
            let f = f.unwrap();
            fs::copy(f.path(), to.join(f.file_name())).unwrap();
        }
    }

    #[test]
    fn a_snapshot_and_the_trimmed_log_round_trip_and_the_log_keeps_growing() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 6);
        let term4 = entries(6)[3].term;
        store.save_snapshot(4, term4, b"image-at-4").unwrap();
        store.rewrite_log(&entries(6)[4..]).unwrap();
        // The handle is still usable without reopening.
        store.apply_log_ops(&[LogOp::Append(entry(9, 7))]).unwrap();
        drop(store);

        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!((loaded.snapshot_index, loaded.snapshot_term), (4, term4));
        assert_eq!(loaded.snapshot_data, b"image-at-4");
        let mut want = entries(6)[4..].to_vec();
        want.push(entry(9, 7));
        assert_eq!(loaded.entries, want);

        let raft = RaftState::restore(1, loaded).unwrap();
        assert_eq!(
            (
                raft.log.snapshot_index(),
                raft.log.first_index(),
                raft.log.last_index()
            ),
            (4, 5, 7)
        );
        assert_eq!((raft.commit_index, raft.last_applied), (4, 4));
    }

    #[test]
    fn compacting_everything_leaves_an_empty_wal_and_the_log_continues_after_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 5);
        store.save_snapshot(5, entries(5)[4].term, b"all").unwrap();
        store.rewrite_log(&[]).unwrap();
        assert_eq!(fs::metadata(dir.path().join(WAL_FILE)).unwrap().len(), 0);
        let reloaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert!(reloaded.entries.is_empty());
        assert_eq!(reloaded.snapshot_index, 5);

        // New entries land at 6, and truncations work relative to the base.
        store
            .apply_log_ops(&[
                LogOp::Append(entry(3, 6)),
                LogOp::Append(entry(3, 7)),
                LogOp::TruncateFrom(7),
                LogOp::Append(entry(4, 7)),
            ])
            .unwrap();
        drop(store);
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.entries, vec![entry(3, 6), entry(4, 7)]);
    }

    #[test]
    fn truncations_in_a_trimmed_wal_are_relative_to_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 8);
        store.save_snapshot(4, entries(8)[3].term, b"s").unwrap();
        store.rewrite_log(&entries(8)[4..]).unwrap();
        store
            .apply_log_ops(&[LogOp::TruncateFrom(6), LogOp::Append(entry(7, 6))])
            .unwrap();
        drop(store);
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        let mut want = entries(8)[4..5].to_vec();
        want.push(entry(7, 6));
        assert_eq!(loaded.entries, want);
    }

    #[test]
    fn a_crash_between_writing_the_snapshot_and_trimming_the_log_loses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 6);
        let term4 = entries(6)[3].term;
        store.save_snapshot(4, term4, b"s4").unwrap();
        drop(store); // crash: rewrite_log never ran

        let mut store = FileStore::open(dir.path()).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded.snapshot_index, 4);
        assert_eq!(
            loaded.entries,
            entries(6),
            "the untrimmed log is still there"
        );
        let raft = RaftState::restore(1, loaded).unwrap();
        assert_eq!(
            (
                raft.log.snapshot_index(),
                raft.log.first_index(),
                raft.log.last_index()
            ),
            (4, 5, 6),
            "restore lets the snapshot win and keeps the entries after it"
        );

        // The untrimmed WAL stays appendable, and a later restart still agrees.
        store.apply_log_ops(&[LogOp::Append(entry(9, 7))]).unwrap();
        drop(store);
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.entries.len(), 7);
        assert_eq!(RaftState::restore(1, loaded).unwrap().log.last_index(), 7);
    }

    #[test]
    fn a_second_snapshot_whose_trim_never_ran_still_loads_over_the_first_trim() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 10);
        store.save_snapshot(4, entries(10)[3].term, b"s4").unwrap();
        store.rewrite_log(&entries(10)[4..]).unwrap();
        store.save_snapshot(8, entries(10)[7].term, b"s8").unwrap();
        drop(store); // crash before the second trim: the WAL still starts at 5

        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.snapshot_index, 8);
        assert_eq!(loaded.entries.first().map(|e| e.index), Some(5));
        let raft = RaftState::restore(1, loaded).unwrap();
        assert_eq!(
            (
                raft.log.snapshot_index(),
                raft.log.first_index(),
                raft.log.last_index()
            ),
            (8, 9, 10)
        );
    }

    #[test]
    fn leftover_temporary_files_from_a_crashed_compaction_are_ignored_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 5);
        store.save_snapshot(3, entries(5)[2].term, b"good").unwrap();
        drop(store);
        // A newer snapshot and a trimmed log that were still being written.
        fs::write(dir.path().join(SNAPSHOT_TMP), b"half a snapshot").unwrap();
        fs::write(dir.path().join(WAL_TMP), b"half a log").unwrap();

        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.snapshot_data, b"good");
        assert_eq!(loaded.entries, entries(5));
        assert!(!dir.path().join(SNAPSHOT_TMP).exists());
        assert!(!dir.path().join(WAL_TMP).exists());
    }

    #[test]
    fn every_crash_point_of_a_compaction_restores_to_the_same_log() {
        // Build the directory as it is at each step of
        // `save_snapshot` then `rewrite_log`, copy it, and restart from the copy.
        let live = tempfile::tempdir().unwrap();
        let mut store = open_with_log(live.path(), 9);
        let snap_term = entries(9)[5].term;
        let mut stages: Vec<(&str, tempfile::TempDir)> = Vec::new();
        let mut capture = |name: &'static str, extra: &dyn Fn(&Path)| {
            let copy = tempfile::tempdir().unwrap();
            copy_dir(live.path(), copy.path());
            extra(copy.path());
            stages.push((name, copy));
        };

        capture("before anything", &|_| {});
        capture("snapshot temp file written, not renamed", &|d| {
            fs::write(d.join(SNAPSHOT_TMP), b"partial").unwrap();
        });
        store.save_snapshot(6, snap_term, b"image-6").unwrap();
        capture("snapshot durable, log untouched", &|_| {});
        capture("trimmed log temp file written, not renamed", &|d| {
            fs::write(d.join(WAL_TMP), b"partial log").unwrap();
        });
        store.rewrite_log(&entries(9)[6..]).unwrap();
        capture("log trimmed", &|_| {});

        for (name, dir) in &stages {
            let loaded = FileStore::open(dir.path())
                .unwrap()
                .load()
                .unwrap_or_else(|e| {
                    panic!("{name}: load failed: {e}");
                });
            let raft = RaftState::restore(1, loaded.clone())
                .unwrap_or_else(|e| panic!("{name}: restore failed: {e}"));
            let (snap, first) = if loaded.snapshot_index == 0 {
                (0, 1)
            } else {
                (6, 7)
            };
            assert_eq!(
                (raft.log.snapshot_index(), raft.log.first_index()),
                (snap, first),
                "{name}"
            );
            assert_eq!(raft.log.last_index(), 9, "{name}: no entry may be lost");
            assert_eq!(
                raft.log.entries_from(first),
                entries(9)[(first - 1) as usize..].to_vec(),
                "{name}: the retained entries are exactly the same"
            );
            if snap == 6 {
                assert_eq!(loaded.snapshot_data, b"image-6", "{name}");
            }
        }
    }

    #[test]
    fn a_damaged_snapshot_is_a_refusal_to_start_not_a_silent_fresh_start() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 4);
        store
            .save_snapshot(3, entries(4)[2].term, b"precious")
            .unwrap();
        store.rewrite_log(&entries(4)[3..]).unwrap();
        drop(store);
        let path = dir.path().join(SNAPSHOT_FILE);
        let good = fs::read(&path).unwrap();

        let mut flipped = good.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 0x01;
        let truncated = good[..good.len() / 2].to_vec();
        let mut wrong_magic_with_valid_crc = good[4..].to_vec();
        wrong_magic_with_valid_crc[0] = b'X';
        let mut framed = crc32(&wrong_magic_with_valid_crc).to_le_bytes().to_vec();
        framed.extend_from_slice(&wrong_magic_with_valid_crc);
        let mut index_zero = good[4..].to_vec();
        index_zero[4..12].copy_from_slice(&0u64.to_le_bytes());
        let mut zero_framed = crc32(&index_zero).to_le_bytes().to_vec();
        zero_framed.extend_from_slice(&index_zero);

        for (name, bytes) in [
            ("flipped bit", flipped),
            ("truncated", truncated),
            ("empty", Vec::new()),
            ("unknown format", framed),
            ("covers nothing", zero_framed),
        ] {
            fs::write(&path, &bytes).unwrap();
            assert!(
                matches!(
                    FileStore::open(dir.path()).unwrap().load(),
                    Err(PersistError::Corrupt(_))
                ),
                "{name} must be refused"
            );
        }
        fs::write(&path, &good).unwrap();
        assert!(FileStore::open(dir.path()).unwrap().load().is_ok());
    }

    #[test]
    fn a_snapshot_file_that_cannot_be_read_is_an_error_not_no_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be: reading it fails with an I/O
        // error that is not "not found".
        fs::create_dir(dir.path().join(SNAPSHOT_FILE)).unwrap();
        assert!(matches!(
            FileStore::open(dir.path()).unwrap().load(),
            Err(PersistError::Io(_))
        ));
    }

    #[test]
    fn a_snapshot_that_covers_nothing_is_refused_on_its_own_merits() {
        // No WAL at all, so no other check can be what rejects it.
        let dir = tempfile::tempdir().unwrap();
        let mut body = SNAPSHOT_MAGIC.to_vec();
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(b"data");
        let mut bytes = crc32(&body).to_le_bytes().to_vec();
        bytes.extend_from_slice(&body);
        fs::write(dir.path().join(SNAPSHOT_FILE), &bytes).unwrap();
        assert!(matches!(
            FileStore::open(dir.path()).unwrap().load(),
            Err(PersistError::Corrupt(_))
        ));

        // And the same on the way in, with nothing stored yet.
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path()).unwrap();
        store.load().unwrap();
        assert!(matches!(
            store.save_snapshot(0, 0, b"nothing"),
            Err(PersistError::Corrupt(_))
        ));
        assert!(!dir.path().join(SNAPSHOT_FILE).exists());
    }

    #[test]
    fn a_failed_replacement_of_the_log_is_reported_and_the_old_wal_stays_usable() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 6);
        store.save_snapshot(4, entries(6)[3].term, b"s").unwrap();
        let wal_before = fs::read(dir.path().join(WAL_FILE)).unwrap();
        // Something is squatting on the temporary file's name.
        fs::create_dir(dir.path().join(WAL_TMP)).unwrap();
        assert!(matches!(
            store.rewrite_log(&entries(6)[4..]),
            Err(PersistError::Io(_))
        ));
        assert_eq!(fs::read(dir.path().join(WAL_FILE)).unwrap(), wal_before);
        // The node would stop on this error, but the handle is not left broken.
        store.apply_log_ops(&[LogOp::Append(entry(9, 7))]).unwrap();
        drop(store);
        let loaded = FileStore::open(dir.path());
        // (load removes only files; the squatting directory makes it an error.)
        assert!(loaded.unwrap().load().is_err());
        fs::remove_dir(dir.path().join(WAL_TMP)).unwrap();
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.entries.len(), 7);
    }

    #[test]
    fn a_trimmed_log_without_its_snapshot_or_with_a_gap_after_it_is_corruption() {
        // Snapshot file lost: the WAL starts at 5 and nothing explains the first four.
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 6);
        store.save_snapshot(4, entries(6)[3].term, b"s").unwrap();
        store.rewrite_log(&entries(6)[4..]).unwrap();
        drop(store);
        fs::remove_file(dir.path().join(SNAPSHOT_FILE)).unwrap();
        assert!(matches!(
            FileStore::open(dir.path()).unwrap().load(),
            Err(PersistError::Corrupt(_))
        ));

        // Snapshot older than the log's start: entries 5.. are missing.
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 6);
        store.save_snapshot(4, entries(6)[3].term, b"s").unwrap();
        store.rewrite_log(&entries(6)[4..]).unwrap();
        drop(store);
        let mut raw = FileStore::open(dir.path()).unwrap();
        raw.load().unwrap();
        // Replace the WAL by one that starts at 7 while the snapshot is at 4.
        let mut buf = Vec::new();
        for e in [entry(2, 7), entry(2, 8)] {
            let payload = codec().serialize(&LogOp::Append(e)).unwrap();
            buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            buf.extend_from_slice(&crc32(&payload).to_le_bytes());
            buf.extend_from_slice(&payload);
        }
        fs::write(dir.path().join(WAL_FILE), &buf).unwrap();
        assert!(matches!(
            FileStore::open(dir.path()).unwrap().load(),
            Err(PersistError::Corrupt(_))
        ));
    }

    #[test]
    fn a_wal_without_a_snapshot_must_still_start_at_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path()).unwrap();
        store.load().unwrap();
        store
            .apply_log_ops(&[LogOp::Append(entry(1, 5)), LogOp::Append(entry(1, 6))])
            .unwrap();
        drop(store);
        assert!(matches!(
            FileStore::open(dir.path()).unwrap().load(),
            Err(PersistError::Corrupt(_))
        ));
    }

    #[test]
    fn snapshots_that_are_backwards_oversized_or_early_are_refused_and_change_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut early = FileStore::open(dir.path()).unwrap();
        assert!(early.save_snapshot(1, 1, b"x").is_err(), "before load");
        assert!(early.rewrite_log(&[]).is_err(), "before load");

        let mut store = open_with_log(dir.path(), 6);
        store.save_snapshot(5, entries(6)[4].term, b"five").unwrap();
        assert!(matches!(
            store.save_snapshot(4, 1, b"older"),
            Err(PersistError::Corrupt(_))
        ));
        assert!(matches!(
            store.save_snapshot(0, 0, b"nothing"),
            Err(PersistError::Corrupt(_))
        ));
        let huge = vec![0u8; MAX_SNAPSHOT_BYTES + 1];
        assert!(matches!(
            store.save_snapshot(6, 1, &huge),
            Err(PersistError::SnapshotTooLarge { .. })
        ));
        // The same index again (a retry) is fine.
        store.save_snapshot(5, entries(6)[4].term, b"five").unwrap();
        drop(store);
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(
            (loaded.snapshot_index, loaded.snapshot_data),
            (5, b"five".to_vec())
        );
    }

    #[test]
    fn a_retained_log_that_does_not_follow_the_snapshot_is_refused_and_the_old_wal_survives() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = open_with_log(dir.path(), 6);
        store.save_snapshot(4, entries(6)[3].term, b"s").unwrap();
        let wal_before = fs::read(dir.path().join(WAL_FILE)).unwrap();
        // Starts too early, starts too late, and has a hole.
        assert!(store.rewrite_log(&entries(6)[3..]).is_err());
        assert!(store.rewrite_log(&entries(6)[5..]).is_err());
        assert!(store.rewrite_log(&[entry(1, 5), entry(1, 7)]).is_err());
        assert_eq!(fs::read(dir.path().join(WAL_FILE)).unwrap(), wal_before);
        // And the store is still usable afterwards.
        store.apply_log_ops(&[LogOp::Append(entry(2, 7))]).unwrap();
        store.rewrite_log(&entries(6)[4..]).unwrap();
    }

    #[test]
    fn memory_store_snapshots_follow_the_same_two_step_rules() {
        let mut store = MemoryStore::new();
        store.load().unwrap();
        let ops: Vec<LogOp> = entries(6).into_iter().map(LogOp::Append).collect();
        store.apply_log_ops(&ops).unwrap();

        store.save_snapshot(4, 2, b"img").unwrap();
        let mid = store.snapshot();
        assert_eq!(
            mid.entries,
            entries(6),
            "the log is untouched until it is rewritten"
        );
        assert_eq!((mid.snapshot_index, mid.snapshot_term), (4, 2));
        assert_eq!(mid.snapshot_data, b"img");
        // Appends between the two steps still work (the log still starts at 1).
        store.apply_log_ops(&[LogOp::Append(entry(3, 7))]).unwrap();

        store.rewrite_log(&mid.entries[4..]).unwrap();
        store.apply_log_ops(&[LogOp::Append(entry(3, 7))]).unwrap();
        assert_eq!(store.snapshot().entries.len(), 3);

        assert!(store.save_snapshot(3, 1, b"older").is_err());
        assert!(store.rewrite_log(&[entry(1, 9)]).is_err());
        assert!(matches!(
            store.save_snapshot(9, 1, &vec![0u8; MAX_SNAPSHOT_BYTES + 1]),
            Err(PersistError::SnapshotTooLarge { .. })
        ));
        assert_eq!(store.snapshot().snapshot_index, 4);

        store.set_fail_writes(true);
        let before = store.snapshot();
        assert!(matches!(
            store.save_snapshot(8, 3, b"x"),
            Err(PersistError::Injected)
        ));
        assert!(matches!(
            store.rewrite_log(&[]),
            Err(PersistError::Injected)
        ));
        assert_eq!(
            store.snapshot(),
            before,
            "a failed write must change nothing"
        );
    }

    #[test]
    fn the_size_limit_is_inclusive_in_both_stores() {
        let exactly = vec![7u8; MAX_SNAPSHOT_BYTES];
        let mut mem = MemoryStore::new();
        mem.load().unwrap();
        mem.save_snapshot(1, 1, &exactly).unwrap();
        assert!(
            mem.save_snapshot(2, 1, &vec![7u8; MAX_SNAPSHOT_BYTES + 1])
                .is_err()
        );

        let dir = tempfile::tempdir().unwrap();
        let mut file = FileStore::open(dir.path()).unwrap();
        file.load().unwrap();
        file.save_snapshot(1, 1, &exactly).unwrap();
        drop(file);
        let loaded = FileStore::open(dir.path()).unwrap().load().unwrap();
        assert_eq!(loaded.snapshot_data.len(), MAX_SNAPSHOT_BYTES);
    }

    #[test]
    fn a_batch_with_a_bad_operation_changes_nothing_in_the_memory_store() {
        let mut store = MemoryStore::new();
        store.load().unwrap();
        store.apply_log_ops(&[LogOp::Append(entry(1, 1))]).unwrap();
        assert!(
            store
                .apply_log_ops(&[LogOp::Append(entry(1, 2)), LogOp::Append(entry(1, 9))])
                .is_err()
        );
        assert_eq!(store.snapshot().entries, vec![entry(1, 1)]);
    }
}
