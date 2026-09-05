pub mod actor;
pub mod log;
pub mod rpc;
pub mod state;

pub use actor::{spawn_raft_actor, ElectionTimeoutRange, RaftHandle, Transport, TransportError};
pub use log::{LogEntry, LogError, ReplicatedLog};
pub use rpc::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};
pub use state::{RaftState, Role};

#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("not the leader")]
    NotLeader,
    #[error("term mismatch: local {local}, remote {remote}")]
    TermMismatch { local: u64, remote: u64 },
}