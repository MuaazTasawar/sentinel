use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::rpc::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};
use crate::state::{RaftState, Role};
use crate::ConsensusError;

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("peer {0} unreachable")]
    Unreachable(u64),
}

/// Abstracts sending RPCs to peers, so the actor's timer/message logic
/// can be tested against an in-process loopback transport instead of
/// real sockets (which is exactly what this file's tests do) — and so
/// Phase 7 can swap in an mTLS-over-Tokio implementation without
/// touching anything in this file.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_request_vote(&self, peer_id: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError>;
    async fn send_append_entries(&self, peer_id: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError>;
}

enum RaftMessage {
    RequestVote(RequestVoteRequest, oneshot::Sender<RequestVoteResponse>),
    AppendEntries(AppendEntriesRequest, oneshot::Sender<AppendEntriesResponse>),
    /// Submit a new command for replication. Only succeeds if this node
    /// is currently the leader.
    Propose(Vec<u8>, oneshot::Sender<Result<u64, ConsensusError>>),
    /// Internal: a vote response arriving from a spawned RPC task. This
    /// is what lets the actor collect votes without ever awaiting a
    /// peer's response inside its own message loop — see the comment
    /// on the election-timeout arm below for why that distinction is
    /// load-bearing, not stylistic.
    VoteResult(RequestVoteResponse, u64),
    /// Test/ops inspection hook: current (role, term, commit_index).
    Inspect(oneshot::Sender<(Role, u64, u64)>),
}

#[derive(Clone)]
pub struct RaftHandle {
    sender: mpsc::Sender<RaftMessage>,
}

impl RaftHandle {
    pub async fn request_vote(&self, req: RequestVoteRequest) -> RequestVoteResponse {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::RequestVote(req, tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    pub async fn append_entries(&self, req: AppendEntriesRequest) -> AppendEntriesResponse {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::AppendEntries(req, tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    pub async fn propose(&self, command: Vec<u8>) -> Result<u64, ConsensusError> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::Propose(command, tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    pub async fn inspect(&self) -> (Role, u64, u64) {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::Inspect(tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ElectionTimeoutRange {
    pub min_ms: u64,
    pub max_ms: u64,
}

impl Default for ElectionTimeoutRange {
    fn default() -> Self {
        Self { min_ms: 150, max_ms: 300 }
    }
}

fn random_election_timeout(range: ElectionTimeoutRange) -> Duration {
    let ms = rand::thread_rng().gen_range(range.min_ms..=range.max_ms);
    Duration::from_millis(ms)
}

pub fn spawn_raft_actor(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
) -> RaftHandle {
    let (tx, mut rx) = mpsc::channel(64);
    let self_tx = tx.clone();

    tokio::spawn(async move {
        let mut state = RaftState::new(node_id);
        let mut election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
        let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);

        loop {
            tokio::select! {
                maybe_msg = rx.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    match msg {
                        RaftMessage::RequestVote(req, reply) => {
                            let candidate_term_is_current_or_newer = req.term >= state.current_term;
                            let resp = state.handle_request_vote(req);
                            if resp.vote_granted || candidate_term_is_current_or_newer {
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            let _ = reply.send(resp);
                        }
                        RaftMessage::AppendEntries(req, reply) => {
                            let resp = state.handle_append_entries(req);
                            if resp.success {
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            let _ = reply.send(resp);
                        }
                        RaftMessage::Propose(command, reply) => {
                            if state.role != Role::Leader {
                                let _ = reply.send(Err(ConsensusError::NotLeader));
                            } else {
                                let index = state.log.append_new(state.current_term, command);
                                let _ = reply.send(Ok(index));
                            }
                        }
                        RaftMessage::VoteResult(resp, peer) => {
                            let cluster_size = peers.len() + 1;
                            if state.record_vote(resp, peer, cluster_size) {
                                state.become_leader();
                            }
                        }
                        RaftMessage::Inspect(reply) => {
                            let _ = reply.send((state.role, state.current_term, state.commit_index));
                        }
                    }
                }

                _ = tokio::time::sleep_until(election_deadline), if state.role != Role::Leader => {
                    let vote_req = state.become_candidate();
                    election_deadline = Instant::now() + random_election_timeout(election_timeout_range);

                    // CRITICAL: these RPCs are spawned, not awaited here.
                    // Awaiting peer responses directly inside this
                    // select! arm would block this actor's own rx.recv()
                    // branch for as long as the election takes — and if
                    // two nodes' timers fire close together, each would
                    // be blocked waiting on the other's vote while unable
                    // to answer the other's RequestVote, deadlocking both
                    // (this is not hypothetical: an earlier version of
                    // this file did exactly that and hung real clusters
                    // under real timing). Reporting results back through
                    // our own mailbox as a `VoteResult` message is what
                    // keeps the actor responsive to incoming RPCs for the
                    // entire duration of its own campaign.
                    for &peer in &peers {
                        let transport = transport.clone();
                        let vote_req = vote_req.clone();
                        let reply_tx = self_tx.clone();
                        tokio::spawn(async move {
                            if let Ok(resp) = transport.send_request_vote(peer, vote_req).await {
                                let _ = reply_tx.send(RaftMessage::VoteResult(resp, peer)).await;
                            }
                        });
                    }
                }

                _ = heartbeat_tick.tick(), if state.role == Role::Leader => {
                    let req = AppendEntriesRequest {
                        term: state.current_term,
                        leader_id: state.node_id,
                        prev_log_index: state.log.last_index(),
                        prev_log_term: state.log.last_term(),
                        entries: vec![],
                        leader_commit: state.commit_index,
                    };
                    for &peer in &peers {
                        let transport = transport.clone();
                        let req = req.clone();
                        tokio::spawn(async move {
                            let _ = transport.send_append_entries(peer, req).await;
                        });
                    }
                }
            }
        }
    });

    RaftHandle { sender: tx }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    struct LoopbackTransport {
        handles: Mutex<HashMap<u64, RaftHandle>>,
    }

    impl LoopbackTransport {
        fn new() -> Arc<Self> {
            Arc::new(Self { handles: Mutex::new(HashMap::new()) })
        }
        async fn register(&self, id: u64, handle: RaftHandle) {
            self.handles.lock().await.insert(id, handle);
        }
    }

    #[async_trait::async_trait]
    impl Transport for LoopbackTransport {
        async fn send_request_vote(&self, peer_id: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
            let handle = {
                let handles = self.handles.lock().await;
                handles.get(&peer_id).cloned().ok_or(TransportError::Unreachable(peer_id))?
            };
            Ok(handle.request_vote(req).await)
        }
        async fn send_append_entries(&self, peer_id: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
            let handle = {
                let handles = self.handles.lock().await;
                handles.get(&peer_id).cloned().ok_or(TransportError::Unreachable(peer_id))?
            };
            Ok(handle.append_entries(req).await)
        }
    }

    async fn spawn_cluster(
        ids: &[u64],
        heartbeat: Duration,
        election_range: ElectionTimeoutRange,
    ) -> (Arc<LoopbackTransport>, HashMap<u64, RaftHandle>) {
        let transport = LoopbackTransport::new();
        let mut handles = HashMap::new();
        for &id in ids {
            let peers: Vec<u64> = ids.iter().copied().filter(|&p| p != id).collect();
            let handle = spawn_raft_actor(id, peers, transport.clone(), heartbeat, election_range);
            transport.register(id, handle.clone()).await;
            handles.insert(id, handle);
        }
        (transport, handles)
    }

    #[tokio::test]
    async fn three_node_cluster_elects_exactly_one_leader() {
        let ids = [1, 2, 3];
        let (_transport, handles) = spawn_cluster(
            &ids,
            Duration::from_millis(20),
            ElectionTimeoutRange { min_ms: 80, max_ms: 150 },
        )
        .await;

        tokio::time::sleep(Duration::from_millis(400)).await;

        let mut leaders = 0;
        let mut terms = Vec::new();
        for &id in &ids {
            let (role, term, _commit) = handles[&id].inspect().await;
            terms.push(term);
            if role == Role::Leader {
                leaders += 1;
            }
        }
        assert_eq!(leaders, 1, "expected exactly one leader, roles/terms: {terms:?}");
        assert!(terms.iter().all(|&t| t == terms[0]));
    }

    #[tokio::test]
    async fn heartbeats_prevent_repeated_elections() {
        let ids = [1, 2, 3];
        let (_transport, handles) = spawn_cluster(
            &ids,
            Duration::from_millis(20),
            ElectionTimeoutRange { min_ms: 80, max_ms: 150 },
        )
        .await;

        tokio::time::sleep(Duration::from_millis(300)).await;
        let (_, term_after_first_election, _) = handles[&1].inspect().await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut final_terms = Vec::new();
        for &id in &ids {
            let (_, term, _) = handles[&id].inspect().await;
            final_terms.push(term);
        }
        assert!(
            final_terms.iter().all(|&t| t == term_after_first_election),
            "term should be stable once a leader is established, got {final_terms:?} (was {term_after_first_election})"
        );
    }

    #[tokio::test]
    async fn repeated_elections_do_not_deadlock_under_tight_simultaneous_timeouts() {
        // A narrow, tight election-timeout window makes near-simultaneous
        // candidacies far more likely than the wider default range — this
        // is deliberately adversarial timing designed to reproduce the
        // mutual-deadlock failure mode (two nodes each campaigning and
        // each blocked awaiting the other's vote) rather than avoid it.
        // Every iteration is wrapped in a hard timeout: if the deadlock
        // this test targets ever regresses, this test fails in ~1s
        // instead of hanging the whole suite indefinitely the way the
        // original bug did against a real cluster.
        for _ in 0..20 {
            let ids = [1, 2, 3];
            let (_transport, handles) = spawn_cluster(
                &ids,
                Duration::from_millis(5),
                ElectionTimeoutRange { min_ms: 10, max_ms: 12 },
            )
            .await;

            let result = tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    let mut leaders = 0;
                    for &id in &ids {
                        let (role, _, _) = handles[&id].inspect().await;
                        if role == Role::Leader {
                            leaders += 1;
                        }
                    }
                    if leaders == 1 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await;

            assert!(result.is_ok(), "cluster failed to elect a leader within 1s — likely deadlocked");
        }
    }

    #[tokio::test]
    async fn propose_fails_on_a_follower_and_succeeds_on_the_leader() {
        let ids = [1, 2, 3];
        let (_transport, handles) = spawn_cluster(
            &ids,
            Duration::from_millis(20),
            ElectionTimeoutRange { min_ms: 80, max_ms: 150 },
        )
        .await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        let mut leader_id = None;
        for &id in &ids {
            let (role, _, _) = handles[&id].inspect().await;
            if role == Role::Leader {
                leader_id = Some(id);
            }
        }
        let leader_id = leader_id.expect("cluster should have elected a leader");

        for &id in &ids {
            let result = handles[&id].propose(b"set x=1".to_vec()).await;
            if id == leader_id {
                assert!(result.is_ok(), "leader should accept a proposal");
            } else {
                assert!(matches!(result, Err(ConsensusError::NotLeader)), "follower should reject a proposal");
            }
        }
    }
}