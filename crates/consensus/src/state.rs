use std::collections::{HashMap, HashSet};

use crate::log::{LogEntry, ReplicatedLog};
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