use axum::extract::State;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;

use sentinel_consensus::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};

use crate::errors::AppError;
use crate::middleware::mtls::ClientIdentity;
use crate::state::AppState;
use crate::statemachine::Command;

/// Receives a `RequestVote` RPC from a peer. The route is guarded by the
/// `peer` role (see `middleware::authz`): only configured cluster identities
/// reach this, not every client that holds a valid certificate.
pub async fn raft_vote(State(state): State<AppState>, Json(req): Json<RequestVoteRequest>) -> Json<RequestVoteResponse> {
    Json(state.raft.request_vote(req).await)
}

pub async fn raft_append_entries(
    State(state): State<AppState>,
    Json(req): Json<AppendEntriesRequest>,
) -> Json<AppendEntriesResponse> {
    Json(state.raft.append_entries(req).await)
}

const MAX_REASON_LEN: usize = 512;

#[derive(Deserialize)]
pub struct SealRequest {
    pub reason: String,
}

/// A peer that detected an anomaly but is not the leader asks us to propose a
/// cluster-wide seal. Only the leader can, so a follower answers 421 and the
/// sender tries the next peer. Peer-only, like the other `/raft/*` routes.
pub async fn seal_request(
    State(state): State<AppState>,
    Extension(identity): Extension<ClientIdentity>,
    Json(req): Json<SealRequest>,
) -> Result<StatusCode, AppError> {
    let reason: String = req.reason.chars().filter(|c| !c.is_control()).take(MAX_REASON_LEN).collect();
    let seal = Command::Seal { reason: format!("requested by peer {}: {reason}", identity.0) };
    state.raft.propose(seal.encode()).await?;
    state.audit.lock().await.append(format!("cluster-wide seal requested by peer {}: {reason}", identity.0));
    Ok(StatusCode::ACCEPTED)
}