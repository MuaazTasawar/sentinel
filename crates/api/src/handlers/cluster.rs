use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

pub async fn cluster_status(State(state): State<AppState>) -> Json<Value> {
    let (role, term, commit_index) = state.raft.inspect().await;
    Json(json!({
        "role": format!("{role:?}"),
        "term": term,
        "commit_index": commit_index,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use std::sync::Arc;
    use tower::ServiceExt;

    struct NoopTransport;
    #[async_trait::async_trait]
    impl sentinel_consensus::Transport for NoopTransport {
        async fn send_request_vote(
            &self,
            _peer_id: u64,
            _req: sentinel_consensus::RequestVoteRequest,
        ) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
            unreachable!()
        }
        async fn send_append_entries(
            &self,
            _peer_id: u64,
            _req: sentinel_consensus::AppendEntriesRequest,
        ) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn status_reports_leader_role_for_a_single_node_cluster() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(sentinel_storage::SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        let raft = sentinel_consensus::spawn_raft_actor(
            1,
            vec![],
            Arc::new(NoopTransport),
            std::time::Duration::from_millis(20),
            sentinel_consensus::ElectionTimeoutRange { min_ms: 30, max_ms: 60 },
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let state = AppState {
            storage,
            raft,
            audit: Arc::new(tokio::sync::Mutex::new(sentinel_audit::AuditChain::new())),
            kek: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let router = Router::new().route("/cluster/status", get(cluster_status)).with_state(state);

        let req = axum::http::Request::builder().uri("/cluster/status").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["role"], "Leader");
        assert_eq!(json["term"], 1);
    }
}