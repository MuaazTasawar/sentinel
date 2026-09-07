use axum::routing::{get, post};
use axum::Router;

use crate::handlers::{cluster, raft, secrets};
use crate::state::AppState;

/// The full client-facing router. Every route here is served only over
/// the mTLS listener built in `main.rs` — there is no plaintext HTTP
/// path into any of this, by construction (main.rs never binds a
/// non-TLS listener at all).
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/secrets", get(secrets::list_secrets))
        .route(
            "/secrets/{key}",
            get(secrets::get_secret).put(secrets::put_secret).delete(secrets::delete_secret),
        )
        .route("/cluster/status", get(cluster::cluster_status))
        .route("/raft/vote", post(raft::raft_vote))
        .route("/raft/append-entries", post(raft::raft_append_entries))
        .with_state(state)
}