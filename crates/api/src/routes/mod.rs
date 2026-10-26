use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;

use crate::handlers::{cluster, dashboard, raft, secrets, unseal};
use crate::middleware::authz::{require_admin, require_cluster_rpc, require_read, require_view, require_write};
use crate::state::AppState;

/// The full client-facing router. Every route here is served only over the
/// mTLS listener built in `main.rs` (there is no plaintext path), and every
/// route group is additionally guarded by an authorization role; see
/// `middleware::authz`. A valid certificate alone gets you nowhere.
pub fn build_router(state: AppState) -> Router {
    // Dashboard and status: any admin, reader or writer.
    let status = Router::new()
        .route("/", get(dashboard::dashboard_page))
        .route("/api/status", get(dashboard::dashboard_status))
        .route("/cluster/status", get(cluster::cluster_status))
        .route_layer(from_fn_with_state(state.clone(), require_view));

    let reads = Router::new()
        .route("/secrets", get(secrets::list_secrets))
        .route("/secrets/{key}", get(secrets::get_secret))
        .route_layer(from_fn_with_state(state.clone(), require_read));

    let writes = Router::new()
        .route("/secrets/{key}", axum::routing::put(secrets::put_secret).delete(secrets::delete_secret))
        .route_layer(from_fn_with_state(state.clone(), require_write));

    // Seal / unseal controls: admins only.
    let sys = Router::new()
        .route("/sys/unseal", post(unseal::submit_share).delete(unseal::reset_session))
        .route("/sys/seal", post(unseal::seal))
        .route_layer(from_fn_with_state(state.clone(), require_admin));

    // Cluster-internal RPCs: peers only.
    let cluster_rpc = Router::new()
        .route("/raft/vote", post(raft::raft_vote))
        .route("/raft/append-entries", post(raft::raft_append_entries))
        .route("/raft/seal-request", post(raft::seal_request))
        .route_layer(from_fn_with_state(state.clone(), require_cluster_rpc));

    Router::new().merge(status).merge(reads).merge(writes).merge(sys).merge(cluster_rpc).with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::authz::{Policy, PolicyConfig};
    use crate::middleware::mtls::ClientIdentity;
    use crate::state::test_support::{sealed_state, unsealed_state};
    use axum::http::{Method, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn real_policy() -> Policy {
        Policy::new(
            &PolicyConfig {
                peer_cns: list(&["node2"]),
                admin_cns: list(&["root"]),
                writer_cns: list(&["app-w"]),
                reader_cns: list(&["app-r"]),
                ..Default::default()
            },
            true,
        )
        .unwrap()
    }

    /// Sends one request as the given certificate identity.
    async fn call(state: &AppState, cn: Option<&str>, method: Method, uri: &str, body: &str) -> StatusCode {
        let mut router = build_router(state.clone());
        if let Some(cn) = cn {
            router = router.layer(axum::Extension(ClientIdentity(cn.to_string())));
        }
        let req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap();
        router.oneshot(req).await.unwrap().status()
    }

    const VOTE: &str = r#"{"term":1,"candidate_id":9,"last_log_index":0,"last_log_term":0}"#;

    async fn get_status(router: &Router, uri: &str) -> (StatusCode, String) {
        let req = axum::http::Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    #[tokio::test]
    async fn the_real_router_serves_the_dashboard_and_its_status_api() {
        let (state, _dir) = sealed_state().await;
        let router = build_router(state).layer(axum::Extension(ClientIdentity("tester".into())));

        let (status, body) = get_status(&router, "/").await;
        assert_eq!(status, 200, "GET / used to be a 404 because the route was never mounted");
        assert!(body.to_lowercase().contains("<html"));

        let (status, body) = get_status(&router, "/api/status").await;
        assert_eq!(status, 200);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["sealed"], true);
    }

    #[tokio::test]
    async fn sealed_vault_exposes_neither_listing_nor_deletion_through_the_real_router() {
        let (state, _dir) = sealed_state().await;
        let router = build_router(state).layer(axum::Extension(ClientIdentity("tester".into())));

        let (status, _) = get_status(&router, "/secrets").await;
        assert_eq!(status, 503);

        let del = axum::http::Request::builder().method("DELETE").uri("/secrets/x").body(axum::body::Body::empty()).unwrap();
        assert_eq!(router.clone().oneshot(del).await.unwrap().status(), 503);
    }

    #[tokio::test]
    async fn secrets_follow_the_reader_and_writer_roles() {
        let (mut state, _dir) = unsealed_state().await;
        state.policy = Arc::new(real_policy());

        assert_eq!(call(&state, Some("app-w"), Method::PUT, "/secrets/k", "v").await, StatusCode::OK);
        assert_eq!(call(&state, Some("app-r"), Method::PUT, "/secrets/k", "v").await, StatusCode::FORBIDDEN, "readers cannot write");
        assert_eq!(call(&state, Some("app-r"), Method::DELETE, "/secrets/k", "").await, StatusCode::FORBIDDEN, "readers cannot delete");

        assert_eq!(call(&state, Some("app-r"), Method::GET, "/secrets/k", "").await, StatusCode::OK);
        assert_eq!(call(&state, Some("app-r"), Method::GET, "/secrets", "").await, StatusCode::OK);
        assert_eq!(call(&state, Some("app-w"), Method::GET, "/secrets/k", "").await, StatusCode::OK, "writers can read too");

        assert_eq!(call(&state, Some("root"), Method::GET, "/secrets/k", "").await, StatusCode::FORBIDDEN, "admins cannot read secrets");
        assert_eq!(call(&state, Some("node2"), Method::GET, "/secrets/k", "").await, StatusCode::FORBIDDEN, "a node certificate cannot read secrets");
        assert_eq!(call(&state, Some("node2"), Method::PUT, "/secrets/k", "v").await, StatusCode::FORBIDDEN);

        assert_eq!(call(&state, Some("app-w"), Method::DELETE, "/secrets/k", "").await, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn only_peers_may_call_the_cluster_protocol_which_was_the_original_hole() {
        let (mut state, _dir) = unsealed_state().await;
        state.policy = Arc::new(real_policy());

        assert_eq!(call(&state, Some("node2"), Method::POST, "/raft/vote", VOTE).await, StatusCode::OK);
        for intruder in ["app-w", "app-r", "root", "stranger"] {
            assert_eq!(call(&state, Some(intruder), Method::POST, "/raft/vote", VOTE).await, StatusCode::FORBIDDEN, "{intruder}");
            assert_eq!(call(&state, Some(intruder), Method::POST, "/raft/append-entries", "{}").await, StatusCode::FORBIDDEN, "{intruder}");
            assert_eq!(call(&state, Some(intruder), Method::POST, "/raft/seal-request", r#"{"reason":"x"}"#).await, StatusCode::FORBIDDEN, "{intruder}");
        }
    }

    #[tokio::test]
    async fn only_admins_may_seal_unseal_or_reset() {
        let (mut state, _dir) = unsealed_state().await;
        state.policy = Arc::new(real_policy());
        let kek = state.kek.clone();

        for who in ["app-w", "app-r", "node2", "stranger"] {
            assert_eq!(call(&state, Some(who), Method::POST, "/sys/seal", "").await, StatusCode::FORBIDDEN, "{who}");
            assert_eq!(call(&state, Some(who), Method::DELETE, "/sys/unseal", "").await, StatusCode::FORBIDDEN, "{who}");
            assert_eq!(call(&state, Some(who), Method::POST, "/sys/unseal", r#"{"holder_id":"x","share":"00"}"#).await, StatusCode::FORBIDDEN, "{who}");
        }
        assert!(kek.lock().await.is_some(), "a refused seal request must leave the vault unsealed");

        assert_eq!(call(&state, Some("root"), Method::POST, "/sys/seal", "").await, StatusCode::NO_CONTENT);
        assert!(kek.lock().await.is_none());
    }

    #[tokio::test]
    async fn the_dashboard_and_status_need_a_role_and_peers_do_not_qualify() {
        let (mut state, _dir) = unsealed_state().await;
        state.policy = Arc::new(real_policy());
        for ok in ["root", "app-r", "app-w"] {
            assert_eq!(call(&state, Some(ok), Method::GET, "/api/status", "").await, StatusCode::OK, "{ok}");
            assert_eq!(call(&state, Some(ok), Method::GET, "/cluster/status", "").await, StatusCode::OK, "{ok}");
            assert_eq!(call(&state, Some(ok), Method::GET, "/", "").await, StatusCode::OK, "{ok}");
        }
        for no in ["node2", "stranger"] {
            assert_eq!(call(&state, Some(no), Method::GET, "/api/status", "").await, StatusCode::FORBIDDEN, "{no}");
        }
    }

    #[tokio::test]
    async fn a_request_with_no_identity_at_all_is_refused_everywhere() {
        let (mut state, _dir) = unsealed_state().await;
        state.policy = Arc::new(real_policy());
        for (m, uri) in [(Method::GET, "/secrets"), (Method::GET, "/api/status"), (Method::POST, "/raft/vote"), (Method::POST, "/sys/seal")] {
            assert_eq!(call(&state, None, m, uri, "{}").await, StatusCode::FORBIDDEN, "{uri}");
        }
    }

    #[tokio::test]
    async fn denials_are_audited_once_not_once_per_request_and_the_chain_stays_valid() {
        let (mut state, _dir) = unsealed_state().await;
        state.policy = Arc::new(real_policy());
        let audit = state.audit.clone();

        for _ in 0..50 {
            assert_eq!(call(&state, Some("mallory"), Method::POST, "/raft/vote", VOTE).await, StatusCode::FORBIDDEN);
        }
        let chain = audit.lock().await;
        let denials: Vec<_> = chain.entries().iter().filter(|e| e.event.starts_with("ACCESS DENIED: mallory")).collect();
        assert_eq!(denials.len(), 1, "50 identical denials must not grow the in-memory audit chain by 50");
        assert!(denials[0].event.contains("POST /raft/vote") && denials[0].event.contains("ClusterRpc"));
        assert!(chain.verify().is_ok());
    }

    #[tokio::test]
    async fn a_peer_can_ask_the_leader_to_seal_the_whole_cluster() {
        let (mut state, _dir) = unsealed_state().await;
        state.policy = Arc::new(real_policy());
        let kek = state.kek.clone();
        let audit = state.audit.clone();

        assert_eq!(call(&state, Some("node2"), Method::POST, "/raft/seal-request", r#"{"reason":"anomaly on node 2"}"#).await, StatusCode::ACCEPTED);

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while kek.lock().await.is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the committed seal should have been applied");
        let chain = audit.lock().await;
        assert!(chain.entries().iter().any(|e| e.event.contains("requested by peer node2") && e.event.contains("anomaly on node 2")));
    }

    #[tokio::test]
    async fn a_seal_request_sent_to_a_node_that_is_not_the_leader_is_answered_421() {
        use crate::handlers::unseal::UnsealState;
        use crate::state::test_support::{build, default_detector};
        struct Silent;
        #[async_trait::async_trait]
        impl sentinel_consensus::Transport for Silent {
            async fn send_request_vote(&self, p: u64, _: sentinel_consensus::RequestVoteRequest) -> Result<sentinel_consensus::RequestVoteResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
            async fn send_append_entries(&self, p: u64, _: sentinel_consensus::AppendEntriesRequest) -> Result<sentinel_consensus::AppendEntriesResponse, sentinel_consensus::TransportError> {
                Err(sentinel_consensus::TransportError::Unreachable(p))
            }
        }
        let kek = sentinel_crypto::SecretBytes::new(vec![0x42u8; 32]);
        let (mut state, _dir) =
            build(Some(kek), default_detector(), UnsealState::new(2), vec![2, 3], Arc::new(Silent), std::time::Duration::from_secs(1)).await;
        state.policy = Arc::new(real_policy());
        assert_eq!(call(&state, Some("node2"), Method::POST, "/raft/seal-request", r#"{"reason":"x"}"#).await, StatusCode::MISDIRECTED_REQUEST);
    }
}