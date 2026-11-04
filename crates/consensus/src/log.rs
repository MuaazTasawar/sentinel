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