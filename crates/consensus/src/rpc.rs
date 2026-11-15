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

/// A leader sends this to a follower that has fallen so far behind that the
/// log entries it needs have been compacted away. It carries the whole state
/// machine as of `last_included_index`; `data` is opaque to Raft.
///
/// The snapshot travels in one message. That is simple, and bounded by the
/// caller: it is meant for state that is small enough to send at once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotRequest {
    pub term: u64,
    pub leader_id: u64,
    /// The snapshot replaces every log entry up to and including this index.
    pub last_included_index: u64,
    /// The term of the entry at `last_included_index`.
    pub last_included_term: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallSnapshotResponse {
    pub term: u64,
    /// `false` only when the request came from a stale term.
    pub success: bool,
    /// The leader may treat the follower as holding everything up to here.
    pub match_index: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_vote_round_trips_through_json() {
        let req = RequestVoteRequest {
            term: 3,
            candidate_id: 2,
            last_log_index: 5,
            last_log_term: 2,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: RequestVoteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.term, 3);
        assert_eq!(back.candidate_id, 2);
    }

    #[test]
    fn install_snapshot_round_trips_through_json() {
        let req = InstallSnapshotRequest {
            term: 5,
            leader_id: 2,
            last_included_index: 100,
            last_included_term: 4,
            data: vec![0, 1, 2, 255],
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: InstallSnapshotRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.last_included_index, 100);
        assert_eq!(back.last_included_term, 4);
        assert_eq!(back.data, vec![0, 1, 2, 255]);
        let resp = InstallSnapshotResponse {
            term: 5,
            success: true,
            match_index: 100,
        };
        let back: InstallSnapshotResponse =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert!(back.success && back.match_index == 100);
    }

    #[test]
    fn append_entries_round_trips_through_json() {
        let req = AppendEntriesRequest {
            term: 4,
            leader_id: 1,
            prev_log_index: 2,
            prev_log_term: 3,
            entries: vec![LogEntry {
                term: 4,
                index: 3,
                command: vec![9, 9],
            }],
            leader_commit: 2,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: AppendEntriesRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].command, vec![9, 9]);
    }
}
