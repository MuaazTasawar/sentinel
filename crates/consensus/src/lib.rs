#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("not the leader")]
    NotLeader,
    #[error("term mismatch: local {local}, remote {remote}")]
    TermMismatch { local: u64, remote: u64 },
}

// mod log;        // Phase 5
// mod rpc;        // Phase 5
// mod state;      // Phase 5
// mod election;   // Phase 6
// mod actor;      // Phase 6