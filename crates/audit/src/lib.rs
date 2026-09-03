#[derive(thiserror::Error, Debug)]
pub enum AuditError {
    #[error("chain integrity violation at index {0}: hash mismatch")]
    ChainBroken(u64),
}

// mod chain;   // Phase 3