use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    #[error("vault is sealed")]
    Sealed,
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("not the raft leader; redirect to: {0:?}")]
    NotLeader(Option<String>),
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
            AppError::Unauthorized(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotLeader(_) => (StatusCode::MISDIRECTED_REQUEST, self.to_string()),
            AppError::Storage(_) | AppError::Crypto(_) | AppError::Internal(_) => {
                tracing::error!(error = ?self, "internal error");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string())
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}