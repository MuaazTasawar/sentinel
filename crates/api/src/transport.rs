use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sentinel_consensus::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    RequestVoteRequest, RequestVoteResponse, Transport, TransportError,
};

/// Sends Raft RPCs to peers over mTLS using the same client identity
/// this node presents for everything else. Peer addresses are resolved
/// once at construction from config (`node_id -> base URL`), not looked
/// up dynamically, so a config error surfaces at startup rather than as
/// a mysterious runtime failure the first time an election happens.
pub struct HttpTransport {
    client: reqwest::Client,
    peer_addrs: HashMap<u64, String>,
}

impl HttpTransport {
    pub fn new(client: reqwest::Client, peer_addrs: HashMap<u64, String>) -> Self {
        Self { client, peer_addrs }
    }

    fn base_url(&self, peer_id: u64) -> Result<&str, TransportError> {
        self.peer_addrs
            .get(&peer_id)
            .map(|s| s.as_str())
            .ok_or(TransportError::Unreachable(peer_id))
    }
}

/// Asks the rest of the cluster to seal. Used when this node detects an
/// anomaly but is not the Raft leader and so cannot propose the seal itself.
#[async_trait::async_trait]
pub trait SealForwarder: Send + Sync {
    /// Sends the request to every peer; returns how many accepted it (only the
    /// current leader does). Best-effort: failures are logged, never raised.
    async fn forward_seal(&self, reason: &str) -> usize;
}

/// Test fixtures only: there is nobody to forward to. (A real single-node
/// deployment uses `HttpTransport` with no peers, which also forwards to nobody.)
#[cfg(test)]
pub struct NoForwarder;

#[cfg(test)]
#[async_trait::async_trait]
impl SealForwarder for NoForwarder {
    async fn forward_seal(&self, _reason: &str) -> usize {
        0
    }
}

#[async_trait::async_trait]
impl SealForwarder for HttpTransport {
    async fn forward_seal(&self, reason: &str) -> usize {
        let mut tasks = Vec::new();
        for (&peer_id, base) in &self.peer_addrs {
            let client = self.client.clone();
            let url = format!("{base}/raft/seal-request");
            let body = serde_json::json!({ "reason": reason });
            tasks.push(tokio::spawn(async move {
                match client.post(&url).json(&body).send().await {
                    Ok(resp) if resp.status().is_success() => true,
                    Ok(resp) => {
                        tracing::debug!(peer = peer_id, status = %resp.status(), "peer did not accept the forwarded seal (not the leader?)");
                        false
                    }
                    Err(e) => {
                        tracing::warn!(peer = peer_id, error = %e, "could not forward the seal request to peer");
                        false
                    }
                }
            }));
        }
        let mut accepted = 0;
        for t in tasks {
            if matches!(t.await, Ok(true)) {
                accepted += 1;
            }
        }
        accepted
    }
}

#[async_trait::async_trait]
impl<T: SealForwarder + ?Sized> SealForwarder for Arc<T> {
    async fn forward_seal(&self, reason: &str) -> usize {
        (**self).forward_seal(reason).await
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    async fn send_request_vote(
        &self,
        peer_id: u64,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, TransportError> {
        let url = format!("{}/raft/vote", self.base_url(peer_id)?);
        self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(peer_id))?
            .json()
            .await
            .map_err(|_| TransportError::Unreachable(peer_id))
    }

    async fn send_append_entries(
        &self,
        peer_id: u64,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, TransportError> {
        let url = format!("{}/raft/append-entries", self.base_url(peer_id)?);
        self.client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|_| TransportError::Unreachable(peer_id))?
            .json()
            .await
            .map_err(|_| TransportError::Unreachable(peer_id))
    }

    async fn send_install_snapshot(
        &self,
        peer_id: u64,
        req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, TransportError> {
        let unreachable = |_| TransportError::Unreachable(peer_id);
        let url = format!("{}/raft/install-snapshot", self.base_url(peer_id)?);
        let body = crate::snapshot::encode_request(&req)
            .map_err(|_| TransportError::Unreachable(peer_id))?;
        let resp = self
            .client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            // The shared client gives a request five seconds; a snapshot is
            // much bigger than an append and gets its own allowance.
            .timeout(SNAPSHOT_REQUEST_TIMEOUT)
            .body(body)
            .send()
            .await
            .map_err(unreachable)?;
        if !resp.status().is_success() {
            tracing::warn!(peer = peer_id, status = %resp.status(), "peer refused a snapshot");
            return Err(TransportError::Unreachable(peer_id));
        }
        resp.json().await.map_err(unreachable)
    }
}

/// How long one snapshot upload may take before it is abandoned.
const SNAPSHOT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A tiny plain-HTTP stand-in for a peer's `/raft/seal-request`.
    async fn fake_peer(
        status: StatusCode,
        hits: Arc<AtomicUsize>,
        last_reason: Arc<std::sync::Mutex<String>>,
    ) -> String {
        let app = Router::new().route(
            "/raft/seal-request",
            post(move |Json(body): Json<serde_json::Value>| {
                let hits = hits.clone();
                let last_reason = last_reason.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    *last_reason.lock().unwrap() =
                        body["reason"].as_str().unwrap_or("").to_string();
                    status
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn forwarding_reaches_every_peer_and_counts_only_those_that_accept() {
        let hits = Arc::new(AtomicUsize::new(0));
        let reason = Arc::new(std::sync::Mutex::new(String::new()));
        let leader = fake_peer(StatusCode::ACCEPTED, hits.clone(), reason.clone()).await;
        let follower = fake_peer(
            StatusCode::MISDIRECTED_REQUEST,
            hits.clone(),
            reason.clone(),
        )
        .await;

        let peers: HashMap<u64, String> = [
            (2, leader),
            (3, follower),
            (4, "http://127.0.0.1:1".to_string()),
        ]
        .into_iter()
        .collect();
        let transport = HttpTransport::new(reqwest::Client::new(), peers);

        let accepted = transport.forward_seal("anomaly on node 1").await;
        assert_eq!(
            accepted, 1,
            "only the leader accepts; the follower and the dead peer do not"
        );
        assert_eq!(
            hits.load(Ordering::SeqCst),
            2,
            "both reachable peers were asked"
        );
        assert_eq!(&*reason.lock().unwrap(), "anomaly on node 1");
    }

    #[tokio::test]
    async fn no_forwarder_accepts_nothing() {
        assert_eq!(NoForwarder.forward_seal("x").await, 0);
    }

    // ---- snapshots over real HTTP ----

    use crate::middleware::mtls::ClientIdentity;
    use crate::state::test_support::unsealed_state;

    /// The node's real router (real snapshot route and body limits) served on
    /// a local socket, with every request authenticated as peer "node2".
    async fn serve_real_node() -> (String, crate::state::AppState, tempfile::TempDir) {
        let (state, dir) = unsealed_state().await;
        let app = crate::routes::build_router(state.clone())
            .layer(axum::Extension(ClientIdentity("node2".into())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), state, dir)
    }

    fn snapshot_request(value_len: usize) -> InstallSnapshotRequest {
        use crate::snapshot::{Image, encode_image};
        InstallSnapshotRequest {
            term: 99,
            leader_id: 2,
            last_included_index: 5,
            last_included_term: 1,
            data: encode_image(
                &Image {
                    last_seal_index: 0,
                    secrets: vec![("secrets/big".into(), vec![9u8; value_len])],
                },
                sentinel_consensus::MAX_SNAPSHOT_BYTES,
            )
            .unwrap(),
        }
    }

    #[tokio::test]
    async fn a_snapshot_larger_than_the_default_body_limit_travels_to_the_real_route() {
        let (url, state, _dir) = serve_real_node().await;
        let transport = HttpTransport::new(reqwest::Client::new(), HashMap::from([(7, url)]));
        let resp = transport
            .send_install_snapshot(7, snapshot_request(5 * 1024 * 1024))
            .await
            .expect("delivered");
        assert!(resp.success);
        assert_eq!(resp.match_index, 5);
        assert_eq!(state.raft.snapshot_status().await.unwrap().installed, 1);
        // The reply means "durable and handed over"; the state machine
        // installs it a moment later. Let it finish before the test (and its
        // data directory) goes away.
        let mut applied = state.applied.clone();
        tokio::time::timeout(Duration::from_secs(30), applied.wait_for(|&v| v >= 5))
            .await
            .expect("the state machine installs the snapshot")
            .unwrap();
    }

    #[tokio::test]
    async fn a_peer_that_refuses_a_snapshot_or_is_not_there_is_reported_as_unreachable() {
        // An HTTP error answer is a failure even when its body looks like
        // a success.
        let app = Router::new().route(
            "/raft/install-snapshot",
            post(|| async {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(InstallSnapshotResponse {
                        term: 1,
                        success: true,
                        match_index: 5,
                    }),
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let transport = HttpTransport::new(
            reqwest::Client::new(),
            HashMap::from([(7, format!("http://{addr}"))]),
        );
        assert!(matches!(
            transport
                .send_install_snapshot(7, snapshot_request(10))
                .await,
            Err(TransportError::Unreachable(7))
        ));
        // An unknown peer id.
        assert!(
            transport
                .send_install_snapshot(8, snapshot_request(10))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_snapshot_upload_gets_longer_than_the_shared_clients_timeout() {
        // The node's shared client allows a request 5 s; a snapshot must not
        // be held to that. Same shape, scaled down: 300 ms against a peer
        // that takes 800 ms to answer.
        let app = Router::new().route(
            "/raft/install-snapshot",
            post(|| async {
                tokio::time::sleep(Duration::from_millis(800)).await;
                axum::Json(InstallSnapshotResponse {
                    term: 1,
                    success: true,
                    match_index: 5,
                })
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(300))
            .build()
            .unwrap();
        let transport = HttpTransport::new(client, HashMap::from([(7, format!("http://{addr}"))]));
        // An append is held to the client's timeout...
        let append = AppendEntriesRequest {
            term: 1,
            leader_id: 1,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };
        assert!(transport.send_append_entries(7, append).await.is_err());
        // ...a snapshot is not.
        let resp = transport
            .send_install_snapshot(7, snapshot_request(10))
            .await
            .expect("the slow upload is waited for");
        assert!(resp.success);
    }
}
