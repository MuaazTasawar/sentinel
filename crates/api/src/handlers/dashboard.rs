use axum::response::Html;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use crate::state::AppState;

/// A single aggregated status payload for the dashboard to poll, rather
/// than making it stitch together several separate round trips. Every
/// field here comes from a real, already-built subsystem — Raft's own
/// `inspect()`, the actual audit chain's `verify()`, the real anomaly
/// detector's `snapshot()` — nothing on this page is synthesized for
/// display purposes.
pub async fn dashboard_status(State(state): State<AppState>) -> Json<Value> {
    let (role, term, commit_index) = state.raft.inspect().await;

    let sealed = state.kek.lock().await.is_none();

    let (audit_verified, audit_entry_count, audit_tip_hash, recent_events) = {
        let chain = state.audit.lock().await;
        let verified = chain.verify().is_ok();
        let tip_hash = chain.tip_hash().iter().map(|b| format!("{b:02x}")).collect::<String>();
        let recent: Vec<Value> = chain
            .entries()
            .iter()
            .rev()
            .take(10)
            .map(|e| json!({ "index": e.index, "timestamp": e.timestamp.to_rfc3339(), "event": e.event }))
            .collect();
        (verified, chain.entries().len(), tip_hash, recent)
    };

    let anomaly_snapshot = state.anomaly_detector.lock().await.snapshot();

    Json(json!({
        "role": format!("{role:?}"),
        "term": term,
        "commit_index": commit_index,
        "sealed": sealed,
        "audit": {
            "verified": audit_verified,
            "entry_count": audit_entry_count,
            "tip_hash": audit_tip_hash,
            "recent_events": recent_events,
        },
        "anomaly": {
            "current_count": anomaly_snapshot.current_count,
            "recent_history": anomaly_snapshot.recent_history,
            "baseline_mean": anomaly_snapshot.baseline_mean,
            "baseline_stddev": anomaly_snapshot.baseline_stddev,
        },
    }))
}

/// Serves the dashboard's single HTML page. Reached through the exact
/// same mTLS listener as every other route — there's no separate,
/// possibly-weaker path to view cluster/audit state, consistent with
/// `main.rs` never binding a plaintext listener at all.
pub async fn dashboard_page() -> Html<&'static str> {
    Html(include_str!("../../dashboard/index.html"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::get, Router};
    use sentinel_consensus::spawn_raft_actor;
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

    async fn test_state() -> (AppState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(sentinel_storage::SledStorage::open(dir.path().to_str().unwrap()).unwrap());
        let raft = spawn_raft_actor(
            1,
            vec![],
            Arc::new(NoopTransport),
            std::time::Duration::from_millis(20),
            sentinel_consensus::ElectionTimeoutRange { min_ms: 30, max_ms: 60 },
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let mut audit = sentinel_audit::AuditChain::new();
        audit.append("node started");

        let state = AppState {
            storage,
            raft,
            audit: Arc::new(tokio::sync::Mutex::new(audit)),
            kek: Arc::new(tokio::sync::Mutex::new(None)),
            anomaly_detector: Arc::new(tokio::sync::Mutex::new(sentinel_anomaly::AnomalyDetector::new(
                std::time::Duration::from_secs(3600),
                20,
                3.0,
            ))),
        };
        (state, dir)
    }

    #[tokio::test]
    async fn status_payload_reflects_real_subsystem_state() {
        let (state, _dir) = test_state().await;
        let router = Router::new().route("/api/status", get(dashboard_status)).with_state(state);

        let req = axum::http::Request::builder().uri("/api/status").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["role"], "Leader");
        assert_eq!(json["term"], 1);
        assert_eq!(json["sealed"], true);
        assert_eq!(json["audit"]["verified"], true);
        assert_eq!(json["audit"]["entry_count"], 1);
        assert_eq!(json["audit"]["recent_events"][0]["event"], "node started");
        assert_eq!(json["anomaly"]["current_count"], 0);
    }

    #[tokio::test]
    async fn dashboard_page_serves_html() {
        let router: Router = Router::new().route("/", get(dashboard_page));
        let req = axum::http::Request::builder().uri("/").body(axum::body::Body::empty()).unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), 200);
        let content_type = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert!(content_type.contains("text/html"));
    }
}