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
    #[error("cannot compact to index {index}: the log only reaches {last}")]
    CompactBeyondLog { index: u64, last: u64 },
    #[error("cannot compact to index {index} with term {given}: the log holds term {local} there")]
    CompactTermMismatch { index: u64, local: u64, given: u64 },
}

/// The replicated log. Indices are 1-based, matching the Raft paper's
/// convention - index 0 is the sentinel "before the log began" position,
/// so `prev_log_index == 0` always trivially satisfies the consistency
/// check (there's nothing to compare against for the very first entry).
///
/// **Compaction.** Once the state machine has taken a snapshot covering the
/// log up to some index, the entries up to there can be discarded. The log
/// then remembers only the index and term of the last discarded entry (the
/// *base*): `entries[i].index == snapshot_index + 1 + i`. With nothing
/// discarded the base is 0 and everything below behaves exactly as before.
///
/// Compaction and snapshot installation are deliberately **not** journaled:
/// they are made durable by the store, which writes the snapshot first and
/// then trims the stored log (see `persist`), and repairs the gap between the
/// two steps at load time with [`ReplicatedLog::reconcile_with_snapshot`].
#[derive(Debug, Default, Clone)]
pub struct ReplicatedLog {
    /// Index and term of the last entry discarded by compaction (the last
    /// entry the snapshot covers). Both are 0 when nothing was discarded.
    snapshot_index: u64,
    snapshot_term: u64,
    entries: Vec<LogEntry>,
    /// Mutations since the last `drain_journal`, oldest first.
    journal: Vec<LogOp>,
}

impl ReplicatedLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds a log from entries loaded off disk. They must be contiguous
    /// from index 1; anything else means the stored log is damaged. Loading
    /// does not count as a mutation (nothing needs persisting).
    pub fn from_entries(entries: Vec<LogEntry>) -> Result<Self, LogError> {
        Self::from_parts(0, 0, entries)
    }

    /// Like [`from_entries`](Self::from_entries) for a log whose first
    /// `snapshot_index` entries were compacted into a snapshot: `entries`
    /// must be contiguous from `snapshot_index + 1`.
    pub fn from_parts(
        snapshot_index: u64,
        snapshot_term: u64,
        entries: Vec<LogEntry>,
    ) -> Result<Self, LogError> {
        for (i, e) in entries.iter().enumerate() {
            let expected = snapshot_index + 1 + i as u64;
            if e.index != expected {
                return Err(LogError::NonContiguous {
                    expected,
                    found: e.index,
                });
            }
        }
        Ok(Self {
            snapshot_index,
            snapshot_term,
            entries,
            journal: Vec::new(),
        })
    }

    /// Joins a stored log to the snapshot that is authoritative for it.
    ///
    /// A crash can land between the two steps of a compaction (snapshot
    /// written, log not yet trimmed) or of a snapshot install (snapshot
    /// written, old log not yet replaced). So what is read back is a snapshot
    /// `(snapshot_index, snapshot_term)` plus whatever log was on disk, which
    /// may overlap the snapshot, stop short of it, or contradict it. The
    /// snapshot wins, and the stored entries are kept only where they
    /// provably agree with it:
    ///
    /// * the log holds the entry at `snapshot_index` with the snapshot's
    ///   term: keep the entries after it;
    /// * the log already starts right after the snapshot (it was trimmed):
    ///   keep it all;
    /// * the log stops before the snapshot, or holds a different term at
    ///   `snapshot_index`: it conflicts with or is subsumed by the snapshot,
    ///   so discard it entirely.
    ///
    /// A log that starts beyond `snapshot_index + 1` cannot be joined to the
    /// snapshot and is reported as damaged.
    pub fn reconcile_with_snapshot(
        snapshot_index: u64,
        snapshot_term: u64,
        entries: Vec<LogEntry>,
    ) -> Result<Self, LogError> {
        if snapshot_index == 0 {
            return Self::from_entries(entries);
        }
        for pair in entries.windows(2) {
            if pair[1].index != pair[0].index + 1 {
                return Err(LogError::NonContiguous {
                    expected: pair[0].index + 1,
                    found: pair[1].index,
                });
            }
        }
        let (Some(first), Some(last)) = (
            entries.first().map(|e| e.index),
            entries.last().map(|e| e.index),
        ) else {
            return Self::from_parts(snapshot_index, snapshot_term, Vec::new());
        };
        if first > snapshot_index + 1 {
            return Err(LogError::NonContiguous {
                expected: snapshot_index + 1,
                found: first,
            });
        }
        if last < snapshot_index {
            return Self::from_parts(snapshot_index, snapshot_term, Vec::new());
        }
        if first == snapshot_index + 1 {
            return Self::from_parts(snapshot_index, snapshot_term, entries);
        }
        let at_snapshot = &entries[(snapshot_index - first) as usize];
        if at_snapshot.term != snapshot_term {
            return Self::from_parts(snapshot_index, snapshot_term, Vec::new());
        }
        let keep: Vec<LogEntry> = entries
            .into_iter()
            .filter(|e| e.index > snapshot_index)
            .collect();
        Self::from_parts(snapshot_index, snapshot_term, keep)
    }

    /// Takes the recorded mutations (oldest first), leaving the journal empty.
    pub fn drain_journal(&mut self) -> Vec<LogOp> {
        std::mem::take(&mut self.journal)
    }

    /// Index of the last entry covered by the snapshot (0 if none).
    pub fn snapshot_index(&self) -> u64 {
        self.snapshot_index
    }

    /// Term of the last entry covered by the snapshot (0 if none).
    pub fn snapshot_term(&self) -> u64 {
        self.snapshot_term
    }

    /// The lowest index this log still holds an entry for.
    pub fn first_index(&self) -> u64 {
        self.snapshot_index + 1
    }

    pub fn last_index(&self) -> u64 {
        self.entries
            .last()
            .map(|e| e.index)
            .unwrap_or(self.snapshot_index)
    }

    pub fn last_term(&self) -> u64 {
        self.entries
            .last()
            .map(|e| e.term)
            .unwrap_or(self.snapshot_term)
    }

    /// The entry at `index`, or `None` if it is compacted away, not yet
    /// written, or `index` is 0.
    pub fn get(&self, index: u64) -> Option<&LogEntry> {
        if index <= self.snapshot_index {
            return None;
        }
        self.entries.get((index - self.snapshot_index - 1) as usize)
    }

    /// The term of the entry at `index`: the snapshot's term at the base,
    /// and 0 for index 0 or any index this log cannot vouch for.
    pub fn term_at(&self, index: u64) -> u64 {
        if index == 0 {
            return 0;
        }
        if index == self.snapshot_index {
            return self.snapshot_term;
        }
        self.get(index).map(|e| e.term).unwrap_or(0)
    }

    /// Leader-side: appends a brand-new entry authored in `term`. Returns
    /// the index it was assigned.
    pub fn append_new(&mut self, term: u64, command: Vec<u8>) -> u64 {
        let index = self.last_index() + 1;
        let entry = LogEntry {
            term,
            index,
            command,
        };
        self.journal.push(LogOp::Append(entry.clone()));
        self.entries.push(entry);
        index
    }

    /// Every entry at or after `index` that this log still holds, for
    /// sending to a follower that's behind. `index == 0` returns everything
    /// retained.
    pub fn entries_from(&self, index: u64) -> Vec<LogEntry> {
        if index == 0 {
            return self.entries.clone();
        }
        self.entries
            .iter()
            .filter(|e| e.index >= index)
            .cloned()
            .collect()
    }

    /// At most `max` entries starting at `index`, in order. Used to bound
    /// the size of a single AppendEntries message. An `index` inside the
    /// compacted prefix starts at the first retained entry; callers that
    /// care (the leader) check [`first_index`](Self::first_index) first.
    pub fn entries_range(&self, index: u64, max: usize) -> Vec<LogEntry> {
        let start = (index.max(self.first_index()) - self.first_index()) as usize;
        self.entries.iter().skip(start).take(max).cloned().collect()
    }

    /// Follower-side: the Raft AppendEntries consistency check (section 5.3) -
    /// reject if the entry immediately before `new_entries` doesn't
    /// match what the leader thinks is there - followed by the
    /// "delete-conflicting-entries-then-append" rule for entries that do
    /// pass the check. `new_entries` must be contiguous, starting at
    /// `prev_log_index + 1`.
    ///
    /// Entries at or below the snapshot are skipped: they are committed (a
    /// snapshot only ever covers committed entries), so they cannot conflict
    /// and there is nothing left to compare them with. That also covers a
    /// leader whose `prev_log_index` is below the snapshot.
    pub fn append_entries(
        &mut self,
        prev_log_index: u64,
        prev_log_term: u64,
        new_entries: &[LogEntry],
    ) -> Result<(), LogError> {
        if prev_log_index >= self.snapshot_index && prev_log_index > 0 {
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
            if entry.index <= self.snapshot_index {
                continue;
            }
            match self.get(entry.index) {
                Some(existing) if existing.term == entry.term => {
                    continue;
                }
                Some(_) => {
                    self.entries
                        .truncate((entry.index - self.snapshot_index - 1) as usize);
                    self.journal.push(LogOp::TruncateFrom(entry.index));
                    self.journal.push(LogOp::Append(entry.clone()));
                    self.entries.push(entry.clone());
                }
                None => {
                    debug_assert_eq!(entry.index, self.last_index() + 1, "appends are contiguous");
                    self.journal.push(LogOp::Append(entry.clone()));
                    self.entries.push(entry.clone());
                }
            }
        }
        Ok(())
    }

    /// Discards every entry up to and including `index` because the state
    /// machine's snapshot now covers them, and remembers `(index, term)` as
    /// the new base. `term` must be the term this log holds at `index`;
    /// asking for an index at or below the current base does nothing.
    pub fn compact_to(&mut self, index: u64, term: u64) -> Result<(), LogError> {
        if index <= self.snapshot_index {
            return Ok(());
        }
        if index > self.last_index() {
            return Err(LogError::CompactBeyondLog {
                index,
                last: self.last_index(),
            });
        }
        let local = self.term_at(index);
        if local != term {
            return Err(LogError::CompactTermMismatch {
                index,
                local,
                given: term,
            });
        }
        let drop = (index - self.snapshot_index) as usize;
        self.entries.drain(..drop);
        self.snapshot_index = index;
        self.snapshot_term = term;
        Ok(())
    }

    /// Follower-side, after accepting a snapshot from the leader: makes
    /// `(index, term)` the new base. If this log already holds that entry,
    /// the entries after it agree with the snapshot and are kept; otherwise
    /// the whole log is discarded, because it either stops short of the
    /// snapshot or contradicts it. Returns whether any entries were kept.
    ///
    /// `index` must be above the current base (the caller ignores snapshots
    /// that are not).
    pub fn install_snapshot_base(&mut self, index: u64, term: u64) -> bool {
        debug_assert!(index > self.snapshot_index, "a snapshot only moves forward");
        let holds_it = index <= self.last_index() && self.term_at(index) == term;
        if holds_it {
            let drop = (index - self.snapshot_index) as usize;
            self.entries.drain(..drop);
        } else {
            self.entries.clear();
        }
        self.snapshot_index = index;
        self.snapshot_term = term;
        holds_it
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(term: u64, index: u64) -> LogEntry {
        LogEntry {
            term,
            index,
            command: vec![index as u8],
        }
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
        assert!(matches!(
            err,
            LogError::PrevTermMismatch {
                index: 1,
                local: 1,
                leader: 2
            }
        ));
    }

    #[test]
    fn append_entries_is_idempotent_for_identical_resend() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)])
            .unwrap();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)])
            .unwrap();
        assert_eq!(log.last_index(), 2);
        assert_eq!(log.get(1).unwrap().command, vec![1]);
    }

    #[test]
    fn append_entries_truncates_conflicting_suffix() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2), entry(1, 3)])
            .unwrap();
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
        assert_eq!(
            log.entries_range(0, 1)[0].index,
            1,
            "index 0 is treated as 'from the start'"
        );
    }

    #[test]
    fn a_log_entry_with_no_command_is_a_noop() {
        assert!(
            LogEntry {
                term: 1,
                index: 1,
                command: vec![]
            }
            .is_noop()
        );
        assert!(
            !LogEntry {
                term: 1,
                index: 1,
                command: vec![0]
            }
            .is_noop()
        );
    }

    #[test]
    fn every_mutation_is_journaled_in_order_and_draining_empties_it() {
        let mut log = ReplicatedLog::new();
        log.append_new(1, vec![1]);
        log.append_entries(1, 1, &[entry(1, 2), entry(1, 3)])
            .unwrap();
        // A conflicting entry at index 2 truncates 2.. and appends the replacement.
        log.append_entries(1, 1, &[entry(2, 2)]).unwrap();

        let ops = log.drain_journal();
        assert_eq!(
            ops,
            vec![
                LogOp::Append(LogEntry {
                    term: 1,
                    index: 1,
                    command: vec![1]
                }),
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
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)])
            .unwrap();
        log.drain_journal();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2)])
            .unwrap();
        assert!(
            log.drain_journal().is_empty(),
            "nothing changed, so nothing to persist"
        );
    }

    #[test]
    fn replaying_the_journal_reproduces_the_log() {
        let mut log = ReplicatedLog::new();
        log.append_entries(0, 0, &[entry(1, 1), entry(1, 2), entry(1, 3)])
            .unwrap();
        log.append_entries(1, 1, &[entry(2, 2), entry(2, 3), entry(2, 4)])
            .unwrap();

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
        assert!(
            ok.clone().drain_journal().is_empty(),
            "loading is not a mutation"
        );

        let gap = ReplicatedLog::from_entries(vec![entry(1, 1), entry(1, 3)]).unwrap_err();
        assert!(matches!(
            gap,
            LogError::NonContiguous {
                expected: 2,
                found: 3
            }
        ));
        assert!(
            ReplicatedLog::from_entries(vec![entry(1, 2)]).is_err(),
            "must start at 1"
        );
    }

    #[test]
    fn entries_from_zero_returns_everything() {
        let mut log = ReplicatedLog::new();
        log.append_new(1, vec![1]);
        log.append_new(1, vec![2]);
        assert_eq!(log.entries_from(0).len(), 2);
    }

    // ---- compaction ---------------------------------------------------

    /// A log with one entry per term given, indices 1.., journal cleared.
    fn log_of(terms: &[u64]) -> ReplicatedLog {
        let mut log = ReplicatedLog::new();
        for &t in terms {
            log.append_new(t, vec![t as u8]);
        }
        log.drain_journal();
        log
    }

    #[test]
    fn compacting_discards_entries_and_remembers_the_base() {
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        log.compact_to(3, 2).unwrap();

        assert_eq!((log.snapshot_index(), log.snapshot_term()), (3, 2));
        assert_eq!(log.first_index(), 4);
        assert_eq!((log.last_index(), log.last_term()), (5, 3));
        assert!(log.get(3).is_none(), "compacted entries are gone");
        assert_eq!(log.get(4).unwrap().index, 4);
        assert_eq!(log.term_at(3), 2, "the base's term is remembered");
        assert_eq!(log.term_at(2), 0, "below the base the term is unknown");
        assert_eq!(log.term_at(0), 0);
        assert_eq!(log.entries_from(0).len(), 2);
    }

    #[test]
    fn compacting_everything_leaves_only_the_base_and_numbering_continues() {
        let mut log = log_of(&[1, 2, 2]);
        log.compact_to(3, 2).unwrap();
        assert_eq!((log.last_index(), log.last_term()), (3, 2));
        assert!(log.entries_from(0).is_empty());
        assert_eq!(
            log.append_new(3, vec![9]),
            4,
            "the next entry follows the base"
        );
        assert_eq!(log.get(4).unwrap().term, 3);
    }

    #[test]
    fn compacting_never_moves_backwards_and_is_idempotent() {
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        log.compact_to(3, 2).unwrap();
        log.compact_to(3, 2).unwrap();
        log.compact_to(2, 1).unwrap(); // already covered: a no-op
        assert_eq!(log.snapshot_index(), 3);
        assert_eq!(log.last_index(), 5);
    }

    #[test]
    fn compacting_beyond_the_log_or_with_the_wrong_term_is_refused_and_changes_nothing() {
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        assert!(matches!(
            log.compact_to(9, 3),
            Err(LogError::CompactBeyondLog { index: 9, last: 5 })
        ));
        assert!(matches!(
            log.compact_to(3, 1),
            Err(LogError::CompactTermMismatch {
                index: 3,
                local: 2,
                given: 1
            })
        ));
        assert_eq!(log.snapshot_index(), 0);
        assert_eq!(log.entries_from(0).len(), 5);
    }

    #[test]
    fn the_consistency_check_uses_the_snapshot_term_at_the_base() {
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        log.compact_to(3, 2).unwrap();
        assert!(log.append_entries(3, 2, &[entry(2, 4)]).is_ok());
        assert!(matches!(
            log.append_entries(3, 9, &[entry(2, 4)]),
            Err(LogError::PrevTermMismatch {
                index: 3,
                local: 2,
                leader: 9
            })
        ));
        assert!(matches!(
            log.append_entries(6, 3, &[entry(3, 7)]),
            Err(LogError::MissingPrevEntry(6))
        ));
    }

    #[test]
    fn entries_at_or_below_the_snapshot_are_skipped_not_compared() {
        // A leader that does not know about our snapshot sends entries we
        // have compacted. They are committed, so they cannot conflict, and
        // there is nothing to compare them with. Even a "conflicting" term
        // for them must be ignored, and the prev check is skipped.
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        log.compact_to(3, 2).unwrap();
        let sent = [
            entry(9, 2),
            entry(9, 3),
            entry(2, 4),
            entry(3, 5),
            entry(3, 6),
        ];
        log.append_entries(1, 77, &sent).unwrap();

        assert_eq!(log.snapshot_index(), 3);
        assert_eq!(log.last_index(), 6);
        assert_eq!(
            log.get(4).unwrap().term,
            2,
            "retained entries are untouched"
        );
        let journal = log.drain_journal();
        assert_eq!(
            journal.len(),
            1,
            "only the genuinely new entry is journaled"
        );
        assert!(matches!(&journal[0], LogOp::Append(e) if e.index == 6));
    }

    #[test]
    fn a_conflict_above_the_snapshot_truncates_down_to_but_never_past_it() {
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        log.compact_to(3, 2).unwrap();
        log.append_entries(3, 2, &[entry(7, 4)]).unwrap();

        assert_eq!(log.snapshot_index(), 3, "the snapshot is never truncated");
        assert_eq!(log.last_index(), 4);
        assert_eq!(log.last_term(), 7);
        let journal = log.drain_journal();
        assert!(matches!(journal[0], LogOp::TruncateFrom(4)));
        assert!(matches!(&journal[1], LogOp::Append(e) if e.index == 4 && e.term == 7));
    }

    #[test]
    fn slices_of_the_log_start_at_the_first_retained_entry() {
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        log.compact_to(3, 2).unwrap();
        let idx = |v: Vec<LogEntry>| v.iter().map(|e| e.index).collect::<Vec<_>>();
        assert_eq!(idx(log.entries_range(1, 10)), vec![4, 5]);
        assert_eq!(idx(log.entries_range(3, 10)), vec![4, 5]);
        assert_eq!(idx(log.entries_range(5, 1)), vec![5]);
        assert_eq!(idx(log.entries_range(6, 4)), Vec::<u64>::new());
        assert_eq!(idx(log.entries_from(0)), vec![4, 5]);
        assert_eq!(idx(log.entries_from(5)), vec![5]);
    }

    #[test]
    fn installing_a_snapshot_keeps_a_suffix_that_agrees_with_it() {
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        assert!(log.install_snapshot_base(3, 2));
        assert_eq!((log.snapshot_index(), log.snapshot_term()), (3, 2));
        assert_eq!(log.last_index(), 5, "entries after the snapshot are kept");
    }

    #[test]
    fn installing_a_snapshot_discards_a_log_that_contradicts_or_falls_short_of_it() {
        // Same index, different term: the log's history disagrees.
        let mut log = log_of(&[1, 1, 2, 2, 3]);
        assert!(!log.install_snapshot_base(3, 9));
        assert!(log.entries_from(0).is_empty());
        assert_eq!((log.last_index(), log.last_term()), (3, 9));

        // The snapshot is beyond everything the log holds.
        let mut short = log_of(&[1, 1]);
        assert!(!short.install_snapshot_base(8, 4));
        assert!(short.entries_from(0).is_empty());
        assert_eq!((short.last_index(), short.last_term()), (8, 4));
        assert_eq!(short.append_new(4, vec![]), 9);
    }

    #[test]
    fn from_parts_requires_entries_to_follow_the_base() {
        assert!(ReplicatedLog::from_parts(3, 2, vec![entry(2, 4), entry(2, 5)]).is_ok());
        assert!(matches!(
            ReplicatedLog::from_parts(3, 2, vec![entry(2, 5)]),
            Err(LogError::NonContiguous {
                expected: 4,
                found: 5
            })
        ));
        assert!(matches!(
            ReplicatedLog::from_entries(vec![entry(1, 2)]),
            Err(LogError::NonContiguous {
                expected: 1,
                found: 2
            })
        ));
    }

    // ---- reconciling a stored log with its snapshot --------------------

    fn stored(terms: &[u64], first_index: u64) -> Vec<LogEntry> {
        terms
            .iter()
            .enumerate()
            .map(|(i, &t)| entry(t, first_index + i as u64))
            .collect()
    }

    fn shape(log: &ReplicatedLog) -> (u64, u64, Vec<u64>) {
        (
            log.snapshot_index(),
            log.snapshot_term(),
            log.entries_from(0).iter().map(|e| e.index).collect(),
        )
    }

    #[test]
    fn reconcile_keeps_the_entries_after_the_snapshot_when_the_log_agrees() {
        // Crash after the snapshot was written but before the log was trimmed.
        let log =
            ReplicatedLog::reconcile_with_snapshot(3, 2, stored(&[1, 1, 2, 2, 3], 1)).unwrap();
        assert_eq!(shape(&log), (3, 2, vec![4, 5]));

        // The log ends exactly at the snapshot.
        let log = ReplicatedLog::reconcile_with_snapshot(3, 2, stored(&[1, 1, 2], 1)).unwrap();
        assert_eq!(shape(&log), (3, 2, vec![]));
    }

    #[test]
    fn reconcile_discards_a_log_that_contradicts_the_snapshot() {
        // Same index, different term: this log is from a different history.
        let log =
            ReplicatedLog::reconcile_with_snapshot(3, 9, stored(&[1, 1, 2, 2, 3], 1)).unwrap();
        assert_eq!(shape(&log), (3, 9, vec![]), "even the entries after it go");
    }

    #[test]
    fn reconcile_discards_a_log_that_stops_before_the_snapshot() {
        let log = ReplicatedLog::reconcile_with_snapshot(5, 3, stored(&[1, 1], 1)).unwrap();
        assert_eq!(shape(&log), (5, 3, vec![]));
        let log = ReplicatedLog::reconcile_with_snapshot(5, 3, vec![]).unwrap();
        assert_eq!(shape(&log), (5, 3, vec![]));
    }

    #[test]
    fn reconcile_accepts_a_log_that_was_already_trimmed_to_follow_the_snapshot() {
        let log = ReplicatedLog::reconcile_with_snapshot(3, 2, stored(&[2, 3], 4)).unwrap();
        assert_eq!(shape(&log), (3, 2, vec![4, 5]));
    }

    #[test]
    fn reconcile_refuses_a_log_it_cannot_join_to_the_snapshot() {
        // Starts beyond snapshot + 1: entries are missing in between.
        assert!(matches!(
            ReplicatedLog::reconcile_with_snapshot(3, 2, stored(&[2, 3], 6)),
            Err(LogError::NonContiguous {
                expected: 4,
                found: 6
            })
        ));
        // A hole inside the stored entries.
        let mut holey = stored(&[1, 1, 2], 1);
        holey.remove(1);
        assert!(matches!(
            ReplicatedLog::reconcile_with_snapshot(3, 2, holey),
            Err(LogError::NonContiguous { .. })
        ));
    }

    #[test]
    fn reconcile_without_a_snapshot_is_exactly_from_entries() {
        let log = ReplicatedLog::reconcile_with_snapshot(0, 0, stored(&[1, 1], 1)).unwrap();
        assert_eq!(shape(&log), (0, 0, vec![1, 2]));
        assert!(ReplicatedLog::reconcile_with_snapshot(0, 0, stored(&[1], 2)).is_err());
    }
}
