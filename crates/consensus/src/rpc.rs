use serde::{Deserialize, Serialize};

use crate::log::LogEntry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    pub term: u64,
    pub candidate_id: u64,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    pub term: u64,
    pub leader_id: u64,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_vote_round_trips_through_json() {
        let req = RequestVoteRequest { term: 3, candidate_id: 2, last_log_index: 5, last_log_term: 2 };
        let json = serde_json::to_string(&req).unwrap();
        let back: RequestVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.term, 3);
        assert_eq!(back.candidate_id, 2);
    }

    #[test]
    fn append_entries_round_trips_through_json() {
        let req = AppendEntriesRequest {
            term: 4,
            leader_id: 1,
            prev_log_index: 2,
            prev_log_term: 3,
            entries: vec![LogEntry { term: 4, index: 3, command: vec![9, 9] }],
            leader_commit: 2,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: AppendEntriesRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].command, vec![9, 9]);
    }
}