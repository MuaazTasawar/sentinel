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