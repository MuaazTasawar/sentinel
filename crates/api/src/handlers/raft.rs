use axum::extract::State;
use axum::Json;

use sentinel_consensus::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};

use crate::state::AppState;

/// Receives a `RequestVote` RPC from a peer over the same mTLS listener
/// everything else in this API uses — cluster traffic gets exactly the
/// same authentication guarantee as client traffic, not a separate,
/// possibly-weaker internal channel.
pub async fn raft_vote(State(state): State<AppState>, Json(req): Json<RequestVoteRequest>) -> Json<RequestVoteResponse> {
    Json(state.raft.request_vote(req).await)
}

pub async fn raft_append_entries(
    State(state): State<AppState>,
    Json(req): Json<AppendEntriesRequest>,
) -> Json<AppendEntriesResponse> {
    Json(state.raft.append_entries(req).await)
}