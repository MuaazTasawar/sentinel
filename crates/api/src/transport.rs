use std::collections::HashMap;
use std::sync::Arc;

use sentinel_consensus::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse, Transport, TransportError};

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
        self.peer_addrs.get(&peer_id).map(|s| s.as_str()).ok_or(TransportError::Unreachable(peer_id))
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
    async fn send_request_vote(&self, peer_id: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A tiny plain-HTTP stand-in for a peer's `/raft/seal-request`.
    async fn fake_peer(status: StatusCode, hits: Arc<AtomicUsize>, last_reason: Arc<std::sync::Mutex<String>>) -> String {
        let app = Router::new().route(
            "/raft/seal-request",
            post(move |Json(body): Json<serde_json::Value>| {
                let hits = hits.clone();
                let last_reason = last_reason.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    *last_reason.lock().unwrap() = body["reason"].as_str().unwrap_or("").to_string();
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
        let follower = fake_peer(StatusCode::MISDIRECTED_REQUEST, hits.clone(), reason.clone()).await;

        let peers: HashMap<u64, String> = [(2, leader), (3, follower), (4, "http://127.0.0.1:1".to_string())].into_iter().collect();
        let transport = HttpTransport::new(reqwest::Client::new(), peers);

        let accepted = transport.forward_seal("anomaly on node 1").await;
        assert_eq!(accepted, 1, "only the leader accepts; the follower and the dead peer do not");
        assert_eq!(hits.load(Ordering::SeqCst), 2, "both reachable peers were asked");
        assert_eq!(&*reason.lock().unwrap(), "anomaly on node 1");
    }

    #[tokio::test]
    async fn no_forwarder_accepts_nothing() {
        assert_eq!(NoForwarder.forward_seal("x").await, 0);
    }
}