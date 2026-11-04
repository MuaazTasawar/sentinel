use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("vault is sealed")]
    Sealed,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("conflict: {0}")]
    Conflict(String),
    // Reserved for a future fine-grained authorization layer. mTLS
    // (`ClientIdentity`) proves WHO is calling with cryptographic
    // certainty; it does not yet gate WHICH secrets that identity is
    // allowed to touch. Every current handler treats any successfully
    // authenticated client as authorized for every operation. This
    // variant exists so that gap has a typed place to land in rather
    // than being bolted on as a stringly-typed error later.
    #[allow(dead_code)]
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("not the raft leader; redirect to node {0:?}")]
    NotLeader(Option<u64>),
    /// The write was proposed but a majority did not confirm it in time. It
    /// may or may not have been applied; the caller should check before retrying.
    #[error("the write was not confirmed by a majority in time; its outcome is unknown")]
    CommitTimeout,
    #[error("leadership changed before the write committed; it was discarded, please retry")]
    LeadershipLost,
    /// The audit log could not be written. Secret operations are refused
    /// rather than performed without a durable record of them.
    #[error("the audit log is not writable, so secret operations are refused until it is restored")]
    AuditUnavailable,
    #[error("storage error: {0}")]
    Storage(#[from] sentinel_storage::StorageError),
    #[error("crypto error: {0}")]
    Crypto(#[from] sentinel_crypto::CryptoError),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Sealed => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::Conflict(_) => (StatusCode::CONFLICT, self.to_string()),
            AppError::Unauthorized(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotLeader(_) => (StatusCode::MISDIRECTED_REQUEST, self.to_string()),
            AppError::CommitTimeout => (StatusCode::GATEWAY_TIMEOUT, self.to_string()),
            AppError::LeadershipLost => (StatusCode::SERVICE_UNAVAILABLE, self.to_string()),
            AppError::AuditUnavailable => {
                tracing::error!("refusing a secret operation: the audit log is degraded");
                (StatusCode::SERVICE_UNAVAILABLE, self.to_string())
            }
            AppError::Storage(_) | AppError::Crypto(_) | AppError::Internal(_) => {
                tracing::error!(error = ?self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
impl From<sentinel_consensus::ConsensusError> for AppError {
    fn from(e: sentinel_consensus::ConsensusError) -> Self {
        use sentinel_consensus::ConsensusError as C;
        match e {
            C::NotLeader => AppError::NotLeader(None),
            C::CommitTimeout => AppError::CommitTimeout,
            C::LeadershipLost => AppError::LeadershipLost,
            other => AppError::Internal(other.into()),
        }
    }
}