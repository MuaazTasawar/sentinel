use axum::routing::{get, post};
use axum::Router;

use crate::handlers::{cluster, dashboard, raft, secrets, unseal};
use crate::state::AppState;

/// The full client-facing router. Every route here is served only over
/// the mTLS listener built in `main.rs`: there is no plaintext HTTP
/// path into any of this, by construction (main.rs never binds a
/// non-TLS listener at all).
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::dashboard_page))
        .route("/api/status", get(dashboard::dashboard_status))
        .route("/secrets", get(secrets::list_secrets))
        .route(
            "/secrets/{key}",
            get(secrets::get_secret).put(secrets::put_secret).delete(secrets::delete_secret),
        )
        .route("/cluster/status", get(cluster::cluster_status))
        .route("/sys/unseal", post(unseal::submit_share).delete(unseal::reset_session))
        .route("/sys/seal", post(unseal::seal))
        .route("/raft/vote", post(raft::raft_vote))
        .route("/raft/append-entries", post(raft::raft_append_entries))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::mtls::ClientIdentity;
    use crate::state::test_support::sealed_state;
    use tower::ServiceExt;

    async fn get_status(router: &Router, uri: &str) -> (axum::http::StatusCode, String) {
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
}