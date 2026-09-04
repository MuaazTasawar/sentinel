use std::collections::HashSet;

use crate::log::ReplicatedLog;
use crate::rpc::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    Candidate,
    Leader,
}

/// The deterministic core of Raft: given an RPC (or a locally-triggered
/// election), what should this node's state become, and what should it
/// reply? Nothing here touches the network, a clock, or storage —
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
}