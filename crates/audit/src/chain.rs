use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GENESIS_HASH: [u8; 32] = [0u8; 32];

#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    #[error("chain integrity violation at index {index}: stored hash does not match recomputed hash")]
    HashMismatch { index: u64 },
    #[error("chain integrity violation at index {index}: prev_hash does not link to entry {index_minus_one}'s hash")]
    BrokenLink { index: u64, index_minus_one: u64 },
    #[error("entry indices are not sequential: expected {expected}, found {found}")]
    NonSequentialIndex { expected: u64, found: u64 },
    #[error("chain is empty")]
    EmptyChain,
    #[error("audit log I/O error: {0}")]
    Io(String),
    #[error("audit log line {line} is not a valid entry: {reason}")]
    Malformed { line: usize, reason: String },
}

/// One tamper-evident audit entry. `hash` commits to every other field
/// plus the previous entry's hash, so altering *any* past entry - its
/// event text, its timestamp, or its position - changes that entry's
/// hash and therefore breaks the link every entry after it depends on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub event: String,
    pub prev_hash: [u8; 32],
    pub hash: [u8; 32],
}

fn compute_hash(index: u64, timestamp: &DateTime<Utc>, event: &str, prev_hash: &[u8; 32]) -> [u8; 32] {
    // Explicit, ordered byte concatenation rather than serde_json - this
    // is the artifact that gets hashed and later re-verified, so its
    // encoding needs to be unambiguous and stable by construction, not
    // by accident of a serializer's field ordering.
    let mut hasher = Sha256::new();
    hasher.update(index.to_be_bytes());
    hasher.update(timestamp.to_rfc3339().as_bytes());
    hasher.update(event.as_bytes());
    hasher.update(prev_hash);
    hasher.finalize().into()
}

/// Where an [`AuditChain`] makes each new entry durable. Called once per
/// appended entry, before `append` returns.
pub trait AuditSink: Send + std::fmt::Debug {
    fn persist(&mut self, entry: &AuditEntry) -> Result<(), AuditError>;
}

/// An append-only, hash-chained audit log. Purely in memory by default; give
/// it a sink (see [`crate::open_persistent`]) and every entry is also written
/// durably as it is appended, so the log survives restarts and `sentinel-cli
/// verify` has a real file to check.
///
/// If the sink ever fails, the chain keeps accepting entries in memory but
/// becomes *degraded* (sticky): [`is_healthy`](Self::is_healthy) turns false
/// and callers that must not act without a durable record (the secret
/// handlers) refuse to proceed.
#[derive(Debug, Default)]
pub struct AuditChain {
    entries: Vec<AuditEntry>,
    sink: Option<Box<dyn AuditSink>>,
    degraded: Option<String>,
}

impl AuditChain {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a persistent chain from entries already on disk, verifying them
    /// first. A chain that fails verification is refused outright: starting
    /// on top of a tampered log would launder the tampering.
    pub fn with_sink(entries: Vec<AuditEntry>, sink: Box<dyn AuditSink>) -> Result<Self, AuditError> {
        let chain = Self { entries, sink: Some(sink), degraded: None };
        chain.verify()?;
        Ok(chain)
    }

    /// True while every entry appended so far has reached the sink (always
    /// true for a chain with no sink).
    pub fn is_healthy(&self) -> bool {
        self.degraded.is_none()
    }

    /// Why the chain is degraded, if it is.
    pub fn degradation(&self) -> Option<&str> {
        self.degraded.as_deref()
    }

    /// Whether entries are being written durably.
    pub fn is_persistent(&self) -> bool {
        self.sink.is_some()
    }

    /// Reconstructs a chain from previously persisted entries (e.g. read
    /// back from storage at startup). Does not verify - call `verify()`
    /// explicitly after loading if you need that guarantee up front.
    pub fn from_entries(entries: Vec<AuditEntry>) -> Self {
        Self { entries, sink: None, degraded: None }
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Appends a new event, computing its hash from the current chain
    /// tip. Returns the entry that was appended.
    pub fn append(&mut self, event: impl Into<String>) -> &AuditEntry {
        let index = self.entries.len() as u64;
        let prev_hash = self.entries.last().map(|e| e.hash).unwrap_or(GENESIS_HASH);
        let timestamp = Utc::now();
        let event = event.into();
        let hash = compute_hash(index, &timestamp, &event, &prev_hash);

        self.entries.push(AuditEntry { index, timestamp, event, prev_hash, hash });
        if let Some(sink) = self.sink.as_mut() {
            if let Err(e) = sink.persist(self.entries.last().unwrap()) {
                self.degraded.get_or_insert_with(|| e.to_string());
            }
        }
        self.entries.last().unwrap()
    }

    /// Walks the entire chain, recomputing every entry's hash from its
    /// fields and checking it against the stored hash, and checking each
    /// entry's `prev_hash` matches the previous entry's actual hash.
    /// Returns the specific index and reason on the first break found,
    /// so an operator can see exactly where tampering occurred.
    pub fn verify(&self) -> Result<(), AuditError> {
        if self.entries.is_empty() {
            return Ok(()); // an empty log is trivially valid
        }

        let mut expected_prev = GENESIS_HASH;
        for (i, entry) in self.entries.iter().enumerate() {
            let expected_index = i as u64;
            if entry.index != expected_index {
                return Err(AuditError::NonSequentialIndex { expected: expected_index, found: entry.index });
            }
            if entry.prev_hash != expected_prev {
                return Err(AuditError::BrokenLink {
                    index: entry.index,
                    index_minus_one: entry.index.saturating_sub(1),
                });
            }
            let recomputed = compute_hash(entry.index, &entry.timestamp, &entry.event, &entry.prev_hash);
            if recomputed != entry.hash {
                return Err(AuditError::HashMismatch { index: entry.index });
            }
            expected_prev = entry.hash;
        }
        Ok(())
    }

    pub fn tip_hash(&self) -> [u8; 32] {
        self.entries.last().map(|e| e.hash).unwrap_or(GENESIS_HASH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_verifies() {
        let chain = AuditChain::new();
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn appended_chain_verifies() {
        let mut chain = AuditChain::new();
        chain.append("node started");
        chain.append("secret written: db-password");
        chain.append("secret read: db-password");
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn tampering_with_event_text_breaks_verification() {
        let mut chain = AuditChain::new();
        chain.append("node started");
        chain.append("secret written: db-password");
        chain.entries[1].event = "secret written: totally-different-value".to_string();
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditError::HashMismatch { index: 1 }));
    }

    #[test]
    fn tampering_with_timestamp_breaks_verification() {
        let mut chain = AuditChain::new();
        chain.append("event a");
        chain.entries[0].timestamp = chain.entries[0].timestamp + chrono::Duration::days(1);
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditError::HashMismatch { index: 0 }));
    }

    #[test]
    fn deleting_a_middle_entry_breaks_the_link() {
        let mut chain = AuditChain::new();
        chain.append("event a");
        chain.append("event b");
        chain.append("event c");
        chain.entries.remove(1);
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditError::NonSequentialIndex { expected: 1, found: 2 }));
    }

    #[test]
    fn splicing_in_a_forged_entry_breaks_the_link() {
        let mut chain = AuditChain::new();
        chain.append("event a");
        chain.append("event b");
        let forged_prev = [0xAAu8; 32];
        let forged_hash = compute_hash(1, &chain.entries[1].timestamp, "forged event", &forged_prev);
        chain.entries[1] = AuditEntry {
            index: 1,
            timestamp: chain.entries[1].timestamp,
            event: "forged event".to_string(),
            prev_hash: forged_prev,
            hash: forged_hash,
        };
        let err = chain.verify().unwrap_err();
        assert!(matches!(err, AuditError::BrokenLink { index: 1, .. }));
    }

    #[test]
    fn tip_hash_tracks_last_entry() {
        let mut chain = AuditChain::new();
        assert_eq!(chain.tip_hash(), GENESIS_HASH);
        chain.append("event a");
        let expected = chain.entries()[0].hash;
        assert_eq!(chain.tip_hash(), expected);
    }

    #[test]
    fn from_entries_round_trips_through_verify() {
        let mut chain = AuditChain::new();
        chain.append("event a");
        chain.append("event b");
        let entries = chain.entries().to_vec();
        let reloaded = AuditChain::from_entries(entries);
        assert!(reloaded.verify().is_ok());
    }
}