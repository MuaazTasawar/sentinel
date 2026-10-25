use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::log::LogEntry;
use crate::rpc::{AppendEntriesRequest, AppendEntriesResponse, RequestVoteRequest, RequestVoteResponse};
use crate::state::{RaftState, Role};
use crate::ConsensusError;

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("peer {0} unreachable")]
    Unreachable(u64),
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_request_vote(&self, peer_id: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError>;
    async fn send_append_entries(&self, peer_id: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError>;
}

type CommitWaiter = oneshot::Sender<Result<u64, ConsensusError>>;

enum RaftMessage {
    RequestVote(RequestVoteRequest, oneshot::Sender<RequestVoteResponse>),
    AppendEntries(AppendEntriesRequest, oneshot::Sender<AppendEntriesResponse>),
    /// Append a command to the leader's log and report its index at once.
    Propose(Vec<u8>, oneshot::Sender<Result<u64, ConsensusError>>),
    /// Append a command and reply only when a majority has committed it.
    ProposeAndWait(Vec<u8>, CommitWaiter),
    VoteResult(RequestVoteResponse, u64),
    /// A follower's answer to an AppendEntries this leader sent.
    AppendResult {
        peer: u64,
        sent_term: u64,
        sent_prev_index: u64,
        sent_len: u64,
        resp: AppendEntriesResponse,
    },
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

    /// Appends `command` to the leader's log and returns its index
    /// **without** waiting for it to commit. Fails with `NotLeader` on a
    /// follower. Use [`propose_and_wait`](Self::propose_and_wait) when the
    /// caller needs to know the entry is durable on a majority.
    pub async fn propose(&self, command: Vec<u8>) -> Result<u64, ConsensusError> {
        let (tx, rx) = oneshot::channel();
        let _ = self.sender.send(RaftMessage::Propose(command, tx)).await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    /// Appends `command` and waits until a majority of the cluster has
    /// replicated it (it is *committed*), returning its log index.
    ///
    /// Errors: `NotLeader` (fast, on a follower), `LeadershipLost` (a
    /// different leader overwrote the entry, so it will never commit),
    /// `CommitTimeout` (no answer in `timeout`; the entry may still commit
    /// later, so the outcome is unknown), `EmptyCommand`, `Stopped`.
    pub async fn propose_and_wait(&self, command: Vec<u8>, timeout: Duration) -> Result<u64, ConsensusError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(RaftMessage::ProposeAndWait(command, tx))
            .await
            .map_err(|_| ConsensusError::Stopped)?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(ConsensusError::Stopped),
            Err(_) => Err(ConsensusError::CommitTimeout),
        }
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

/// Spawns a Raft node whose committed entries are discarded. Fine for tests
/// and tools that only care about leadership; a node that must act on the
/// replicated commands uses [`spawn_raft_actor_with_apply`].
pub fn spawn_raft_actor(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
) -> RaftHandle {
    spawn_inner(node_id, peers, transport, heartbeat_interval, election_timeout_range, None)
}

/// Like [`spawn_raft_actor`], plus a channel that yields every **committed**
/// command, in log order, exactly once, on every node (leader and followers
/// alike). This is the state machine's input: apply what arrives here and
/// nothing else. Leader no-op entries are filtered out.
pub fn spawn_raft_actor_with_apply(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
) -> (RaftHandle, mpsc::UnboundedReceiver<LogEntry>) {
    let (apply_tx, apply_rx) = mpsc::unbounded_channel();
    let handle = spawn_inner(node_id, peers, transport, heartbeat_interval, election_timeout_range, Some(apply_tx));
    (handle, apply_rx)
}

/// Hands newly committed entries to the state machine and answers any
/// `propose_and_wait` callers whose entries just committed (or were found
/// to have been replaced by another leader's entry).
fn drain_committed(
    state: &mut RaftState,
    apply_tx: &Option<mpsc::UnboundedSender<LogEntry>>,
    pending: &mut BTreeMap<u64, (u64, CommitWaiter)>,
) {
    for entry in state.take_newly_committed() {
        if let Some((proposed_term, waiter)) = pending.remove(&entry.index) {
            let result = if proposed_term == entry.term { Ok(entry.index) } else { Err(ConsensusError::LeadershipLost) };
            let _ = waiter.send(result);
        }
        if !entry.is_noop() {
            if let Some(tx) = apply_tx {
                let _ = tx.send(entry);
            }
        }
    }
}

/// Sends `peer` its next AppendEntries (entries from that peer's own
/// `next_index`) and routes the reply back into the actor's mailbox.
fn replicate_to(state: &RaftState, peer: u64, transport: &Arc<dyn Transport>, self_tx: &mpsc::Sender<RaftMessage>) {
    let Some(req) = state.build_append_entries(peer) else { return };
    let transport = transport.clone();
    let reply_tx = self_tx.clone();
    tokio::spawn(async move {
        let sent_term = req.term;
        let sent_prev_index = req.prev_log_index;
        let sent_len = req.entries.len() as u64;
        if let Ok(resp) = transport.send_append_entries(peer, req).await {
            let _ = reply_tx.send(RaftMessage::AppendResult { peer, sent_term, sent_prev_index, sent_len, resp }).await;
        }
    });
}

fn spawn_inner(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
    apply_tx: Option<mpsc::UnboundedSender<LogEntry>>,
) -> RaftHandle {
    let (tx, mut rx) = mpsc::channel(256);
    let self_tx = tx.clone();

    tokio::spawn(async move {
        let mut state = RaftState::new(node_id);
        let mut pending: BTreeMap<u64, (u64, CommitWaiter)> = BTreeMap::new();
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
                            // Any message from a leader of the current (or a
                            // newer) term proves a live leader exists, even if
                            // the log-consistency check below rejects it. A
                            // lagging follower must keep waiting, not start an
                            // election.
                            let from_live_leader = req.term >= state.current_term;
                            let resp = state.handle_append_entries(req);
                            if from_live_leader {
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            drain_committed(&mut state, &apply_tx, &mut pending);
                            let _ = reply.send(resp);
                        }
                        RaftMessage::Propose(command, reply) => {
                            let result = state.append_as_leader(command);
                            if result.is_ok() {
                                for &peer in &peers {
                                    replicate_to(&state, peer, &transport, &self_tx);
                                }
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                            let _ = reply.send(result);
                        }
                        RaftMessage::ProposeAndWait(command, waiter) => {
                            match state.append_as_leader(command) {
                                Ok(index) => {
                                    pending.insert(index, (state.current_term, waiter));
                                    for &peer in &peers {
                                        replicate_to(&state, peer, &transport, &self_tx);
                                    }
                                    // A single-node cluster commits instantly.
                                    drain_committed(&mut state, &apply_tx, &mut pending);
                                }
                                Err(e) => {
                                    let _ = waiter.send(Err(e));
                                }
                            }
                        }
                        RaftMessage::VoteResult(resp, peer) => {
                            let cluster_size = peers.len() + 1;
                            if state.record_vote(resp, peer, cluster_size) {
                                state.become_leader();
                                state.on_elected(&peers);
                                // Announce leadership (and start replicating)
                                // immediately rather than at the next tick.
                                for &p in &peers {
                                    replicate_to(&state, p, &transport, &self_tx);
                                }
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                        }
                        RaftMessage::AppendResult { peer, sent_term, sent_prev_index, sent_len, resp } => {
                            let was_leader = state.role == Role::Leader;
                            let outcome = state.handle_append_entries_response(peer, sent_term, sent_prev_index, sent_len, resp);
                            if was_leader && state.role != Role::Leader {
                                // Deposed by a higher term: restart the
                                // election clock instead of firing at once.
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            if outcome.commit_advanced {
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                            if outcome.retry_now {
                                replicate_to(&state, peer, &transport, &self_tx);
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

                    if peers.is_empty() {
                        state.become_leader();
                        state.on_elected(&peers);
                        drain_committed(&mut state, &apply_tx, &mut pending);
                        continue;
                    }

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
                    // The heartbeat doubles as the retry loop: each peer gets
                    // whatever it is still missing (or an empty message if
                    // it is fully caught up).
                    for &peer in &peers {
                        replicate_to(&state, peer, &transport, &self_tx);
                    }
                    // Forget waiters whose callers already gave up.
                    pending.retain(|_, (_, waiter)| !waiter.is_closed());
                }
            }
        }
    });

    RaftHandle { sender: tx }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex as StdMutex;
    use tokio::sync::Mutex;

    /// An in-process network between Raft actors whose links can be cut:
    /// an isolated node can neither send nor receive anything.
    struct Net {
        handles: Mutex<HashMap<u64, RaftHandle>>,
        isolated: StdMutex<HashSet<u64>>,
    }

    struct NodeTransport {
        from: u64,
        net: Arc<Net>,
    }

    impl NodeTransport {
        async fn route(&self, peer_id: u64) -> Result<RaftHandle, TransportError> {
            {
                let isolated = self.net.isolated.lock().unwrap();
                if isolated.contains(&self.from) || isolated.contains(&peer_id) {
                    return Err(TransportError::Unreachable(peer_id));
                }
            }
            let handles = self.net.handles.lock().await;
            handles.get(&peer_id).cloned().ok_or(TransportError::Unreachable(peer_id))
        }
    }

    #[async_trait::async_trait]
    impl Transport for NodeTransport {
        async fn send_request_vote(&self, peer_id: u64, req: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
            Ok(self.route(peer_id).await?.request_vote(req).await)
        }
        async fn send_append_entries(&self, peer_id: u64, req: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
            Ok(self.route(peer_id).await?.append_entries(req).await)
        }
    }

    struct Cluster {
        ids: Vec<u64>,
        handles: HashMap<u64, RaftHandle>,
        net: Arc<Net>,
        applied_rx: HashMap<u64, mpsc::UnboundedReceiver<LogEntry>>,
        /// Commands each node has applied so far, in order.
        seen: HashMap<u64, Vec<Vec<u8>>>,
    }

    async fn spawn_cluster(ids: &[u64], heartbeat: Duration, election_range: ElectionTimeoutRange) -> Cluster {
        let net = Arc::new(Net { handles: Mutex::new(HashMap::new()), isolated: StdMutex::new(HashSet::new()) });
        let mut handles = HashMap::new();
        let mut applied_rx = HashMap::new();
        for &id in ids {
            let peers: Vec<u64> = ids.iter().copied().filter(|&p| p != id).collect();
            let transport = Arc::new(NodeTransport { from: id, net: net.clone() });
            let (handle, rx) = spawn_raft_actor_with_apply(id, peers, transport, heartbeat, election_range);
            net.handles.lock().await.insert(id, handle.clone());
            handles.insert(id, handle);
            applied_rx.insert(id, rx);
        }
        let seen = ids.iter().map(|&id| (id, Vec::new())).collect();
        Cluster { ids: ids.to_vec(), handles, net, applied_rx, seen }
    }

    impl Cluster {
        fn isolate(&self, id: u64) {
            self.net.isolated.lock().unwrap().insert(id);
        }
        fn heal(&self) {
            self.net.isolated.lock().unwrap().clear();
        }

        async fn leader_among(&self, among: &[u64]) -> Option<u64> {
            let mut best: Option<(u64, u64)> = None; // (term, id)
            for &id in among {
                let (role, term, _) = self.handles[&id].inspect().await;
                if role == Role::Leader && best.map_or(true, |(t, _)| term > t) {
                    best = Some((term, id));
                }
            }
            best.map(|(_, id)| id)
        }

        async fn wait_for_leader(&self, among: &[u64]) -> u64 {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(id) = self.leader_among(among).await {
                        return id;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("no leader emerged within 5s")
        }

        /// Proposes through whoever is leader among `among`, retrying across
        /// leadership changes until the entry is committed.
        async fn propose_ok(&self, among: &[u64], command: &[u8]) -> u64 {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(leader) = self.leader_among(among).await {
                        if let Ok(index) = self.handles[&leader].propose_and_wait(command.to_vec(), Duration::from_millis(800)).await {
                            return index;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("could not commit a proposal within 10s")
        }

        fn pump(&mut self) {
            for &id in &self.ids {
                let rx = self.applied_rx.get_mut(&id).unwrap();
                while let Ok(entry) = rx.try_recv() {
                    self.seen.get_mut(&id).unwrap().push(entry.command);
                }
            }
        }

        async fn wait_until_everyone_applied(&mut self, ids: &[u64], count: usize) {
            let result = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    self.pump();
                    if ids.iter().all(|id| self.seen[id].len() >= count) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await;
            assert!(
                result.is_ok(),
                "nodes did not all apply {count} entries in time; applied so far: {:?}",
                self.seen.iter().map(|(id, v)| (*id, v.len())).collect::<Vec<_>>()
            );
        }
    }

    fn cmds(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    const FAST: ElectionTimeoutRange = ElectionTimeoutRange { min_ms: 80, max_ms: 150 };

    // ---- the original election tests, unchanged in intent ----

    #[tokio::test]
    async fn single_node_cluster_should_elect_itself_leader() {
        let cluster = spawn_cluster(&[1], Duration::from_millis(20), FAST).await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let (role, _, _) = cluster.handles[&1].inspect().await;
        assert_eq!(role, Role::Leader, "a lone node with no peers must still become its own leader");
    }

    #[tokio::test]
    async fn three_node_cluster_elects_exactly_one_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        let mut leaders = 0;
        let mut terms = Vec::new();
        for &id in &ids {
            let (role, term, _commit) = cluster.handles[&id].inspect().await;
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
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;

        tokio::time::sleep(Duration::from_millis(300)).await;
        let (_, term_after_first_election, _) = cluster.handles[&1].inspect().await;

        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut final_terms = Vec::new();
        for &id in &ids {
            let (_, term, _) = cluster.handles[&id].inspect().await;
            final_terms.push(term);
        }
        assert!(
            final_terms.iter().all(|&t| t == term_after_first_election),
            "term should be stable once a leader is established, got {final_terms:?} (was {term_after_first_election})"
        );
    }

    #[tokio::test]
    async fn repeated_elections_do_not_deadlock_under_tight_simultaneous_timeouts() {
        for _ in 0..20 {
            let ids = [1, 2, 3];
            let cluster = spawn_cluster(&ids, Duration::from_millis(5), ElectionTimeoutRange { min_ms: 30, max_ms: 60 }).await;

            let result = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let mut leaders = 0;
                    for &id in &ids {
                        let (role, _, _) = cluster.handles[&id].inspect().await;
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

            assert!(result.is_ok(), "cluster failed to elect a leader within 2s - likely deadlocked");
        }
    }

    #[tokio::test]
    async fn propose_fails_on_a_follower_and_succeeds_on_the_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        tokio::time::sleep(Duration::from_millis(400)).await;

        let leader_id = cluster.leader_among(&ids).await.expect("cluster should have elected a leader");

        for &id in &ids {
            let result = cluster.handles[&id].propose(b"set x=1".to_vec()).await;
            if id == leader_id {
                assert!(result.is_ok(), "leader should accept a proposal");
            } else {
                assert!(matches!(result, Err(ConsensusError::NotLeader)), "follower should reject a proposal");
            }
        }
    }

    // ---- Phase 14: replication ----

    #[tokio::test]
    async fn committed_entries_reach_every_node_in_the_same_order() {
        let ids = [1, 2, 3];
        let mut cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        cluster.wait_for_leader(&ids).await;

        let sent = ["a", "b", "c", "d", "e"];
        for c in sent {
            cluster.propose_ok(&ids, c.as_bytes()).await;
        }
        cluster.wait_until_everyone_applied(&ids, 5).await;

        for &id in &ids {
            assert_eq!(cluster.seen[&id], cmds(&sent), "node {id} must apply exactly the proposed commands, in order");
        }
        // Followers learn the commit index too, not just the leader.
        for &id in &ids {
            let (_, _, commit) = cluster.handles[&id].inspect().await;
            assert!(commit >= 5, "node {id} commit_index is {commit}");
        }
    }

    #[tokio::test]
    async fn single_node_cluster_commits_its_own_proposals() {
        let mut cluster = spawn_cluster(&[1], Duration::from_millis(20), FAST).await;
        cluster.wait_for_leader(&[1]).await;
        let index = cluster.handles[&1].propose_and_wait(b"solo".to_vec(), Duration::from_secs(2)).await.unwrap();
        assert!(index >= 2, "index 1 is the leader's no-op");
        cluster.wait_until_everyone_applied(&[1], 1).await;
        assert_eq!(cluster.seen[&1], cmds(&["solo"]));
    }

    #[tokio::test]
    async fn propose_and_wait_on_a_follower_fails_fast_with_not_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        let leader = cluster.wait_for_leader(&ids).await;
        let follower = ids.iter().copied().find(|&i| i != leader).unwrap();

        let started = std::time::Instant::now();
        let result = cluster.handles[&follower].propose_and_wait(b"x".to_vec(), Duration::from_secs(5)).await;
        assert!(matches!(result, Err(ConsensusError::NotLeader)));
        assert!(started.elapsed() < Duration::from_secs(1), "must not wait out the timeout");

        let empty = cluster.handles[&leader].propose_and_wait(vec![], Duration::from_secs(1)).await;
        assert!(matches!(empty, Err(ConsensusError::EmptyCommand)));
    }

    #[tokio::test]
    async fn a_follower_that_missed_entries_catches_up_after_reconnecting() {
        let ids = [1, 2, 3];
        let mut cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        let leader = cluster.wait_for_leader(&ids).await;
        let straggler = ids.iter().copied().find(|&i| i != leader).unwrap();
        let majority: Vec<u64> = ids.iter().copied().filter(|&i| i != straggler).collect();

        cluster.propose_ok(&ids, b"before").await;
        cluster.wait_until_everyone_applied(&ids, 1).await;

        // With one node cut off, the other two still form a majority and keep committing.
        cluster.isolate(straggler);
        for c in ["m1", "m2", "m3", "m4"] {
            cluster.propose_ok(&majority, c.as_bytes()).await;
        }
        cluster.wait_until_everyone_applied(&majority, 5).await;
        assert_eq!(cluster.seen[&straggler].len(), 1, "the isolated node must not have received anything new");

        // Reconnect: the straggler is brought fully up to date, in order.
        cluster.heal();
        cluster.wait_until_everyone_applied(&ids, 5).await;
        let expected = cmds(&["before", "m1", "m2", "m3", "m4"]);
        for &id in &ids {
            assert_eq!(cluster.seen[&id], expected, "node {id}");
        }
    }

    #[tokio::test]
    async fn a_deposed_leaders_uncommitted_entry_is_discarded_and_never_applied() {
        let ids = [1, 2, 3];
        let mut cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        let old_leader = cluster.wait_for_leader(&ids).await;
        let others: Vec<u64> = ids.iter().copied().filter(|&i| i != old_leader).collect();

        cluster.propose_ok(&ids, b"committed-before").await;
        cluster.wait_until_everyone_applied(&ids, 1).await;

        // Cut the leader off. It still believes it leads, so it accepts a
        // write, but it can never reach a majority, so the write must not commit.
        cluster.isolate(old_leader);
        let orphan = cluster.handles[&old_leader].propose_and_wait(b"orphan".to_vec(), Duration::from_millis(400)).await;
        assert!(orphan.is_err(), "a minority leader must not be able to commit, got {orphan:?}");

        // The majority elects a new leader and carries on.
        cluster.wait_for_leader(&others).await;
        cluster.propose_ok(&others, b"after-1").await;
        cluster.propose_ok(&others, b"after-2").await;

        // Reconnect: the old leader steps down, drops its orphan entry, and adopts the new log.
        cluster.heal();
        cluster.wait_until_everyone_applied(&ids, 3).await;

        let expected = cmds(&["committed-before", "after-1", "after-2"]);
        for &id in &ids {
            assert_eq!(cluster.seen[&id], expected, "node {id} must never have applied the orphaned write");
        }
        // Give any stray delivery a chance to show up, then re-check.
        tokio::time::sleep(Duration::from_millis(300)).await;
        cluster.pump();
        for &id in &ids {
            assert!(!cluster.seen[&id].contains(&b"orphan".to_vec()), "node {id} applied the orphan");
        }
    }

    #[tokio::test]
    async fn rejected_appends_from_a_live_leader_still_reset_the_election_timer() {
        // A node whose log is behind rejects the leader's append (prev entry
        // missing). That rejection must not make it think the leader died.
        struct Dead;
        #[async_trait::async_trait]
        impl Transport for Dead {
            async fn send_request_vote(&self, p: u64, _: RequestVoteRequest) -> Result<RequestVoteResponse, TransportError> {
                Err(TransportError::Unreachable(p))
            }
            async fn send_append_entries(&self, p: u64, _: AppendEntriesRequest) -> Result<AppendEntriesResponse, TransportError> {
                Err(TransportError::Unreachable(p))
            }
        }
        let handle = spawn_raft_actor(2, vec![1, 3], Arc::new(Dead), Duration::from_millis(20), ElectionTimeoutRange { min_ms: 150, max_ms: 200 });

        for _ in 0..16 {
            let resp = handle
                .append_entries(AppendEntriesRequest {
                    term: 1,
                    leader_id: 1,
                    prev_log_index: 5, // this node has no entries, so this is rejected
                    prev_log_term: 1,
                    entries: vec![],
                    leader_commit: 0,
                })
                .await;
            assert!(!resp.success);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let (role, term, _) = handle.inspect().await;
        assert_eq!((role, term), (Role::Follower, 1), "over 800ms of live-leader contact the node must never time out");
    }
}