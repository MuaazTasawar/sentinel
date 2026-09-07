use std::collections::HashMap;

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