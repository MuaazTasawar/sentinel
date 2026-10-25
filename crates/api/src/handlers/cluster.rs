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
    use crate::state::test_support::sealed_state;
    use axum::{routing::get, Router};
    use tower::ServiceExt;

    #[tokio::test]
    async fn status_reports_leader_role_for_a_single_node_cluster() {
        let (state, _dir) = sealed_state().await;
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