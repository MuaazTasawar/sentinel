pub mod actor;
pub mod log;
pub mod rpc;
pub mod state;

pub use actor::{
    spawn_raft_actor, spawn_raft_actor_with_apply, ElectionTimeoutRange, RaftHandle, Transport, TransportError,
};
pub use log::{LogEntry, LogError, ReplicatedLog};
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