use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::ConsensusError;
use crate::log::LogEntry;
use crate::persist::{MAX_SNAPSHOT_BYTES, PersistError, RaftStore};
use crate::rpc::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    RequestVoteRequest, RequestVoteResponse,
};
use crate::state::{RaftState, Role};

#[derive(thiserror::Error, Debug)]
pub enum TransportError {
    #[error("peer {0} unreachable")]
    Unreachable(u64),
    #[error("peer {0}: this transport cannot carry snapshots")]
    SnapshotsUnsupported(u64),
}

#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn send_request_vote(
        &self,
        peer_id: u64,
        req: RequestVoteRequest,
    ) -> Result<RequestVoteResponse, TransportError>;
    async fn send_append_entries(
        &self,
        peer_id: u64,
        req: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse, TransportError>;
    /// Sends a whole snapshot to a follower that has fallen behind the
    /// leader's compacted log. A transport that cannot do this says so (the
    /// default), and the leader keeps the follower on its list to retry; the
    /// follower is not served until a transport that can is in place.
    async fn send_install_snapshot(
        &self,
        peer_id: u64,
        _req: InstallSnapshotRequest,
    ) -> Result<InstallSnapshotResponse, TransportError> {
        Err(TransportError::SnapshotsUnsupported(peer_id))
    }
}

/// What the state machine receives, in this order and no other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyItem {
    /// A committed command (leader no-ops are filtered out).
    Entry(LogEntry),
    /// Replace the state with this image. It stands for the whole log up to
    /// and including `index` (whose entry had term `term`); entries up to
    /// there will never be delivered. It arrives at startup if the node has
    /// a snapshot on disk (the state machine may not have installed it
    /// before the last crash), and when a leader sends one to catch this node
    /// up. A state machine that is already at or past `index` ignores it.
    Snapshot {
        index: u64,
        term: u64,
        data: Vec<u8>,
    },
}

/// Counters and position of this node's snapshots, for metrics and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SnapshotStatus {
    /// Index the log is compacted to (0 = never).
    pub snapshot_index: u64,
    /// Snapshots this node took itself (`RaftHandle::compact`).
    pub taken: u64,
    /// Snapshots this node installed because a leader sent them.
    pub installed: u64,
    /// Snapshots this node sent as leader and the follower acknowledged.
    pub sent: u64,
}

/// A snapshot is large and heartbeats are frequent: give up on one send
/// after this long, and wait this long before trying the same peer again.
const SNAPSHOT_SEND_TIMEOUT: Duration = Duration::from_secs(60);
const SNAPSHOT_RETRY_DELAY: Duration = Duration::from_secs(1);

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
    /// A leader sends this node a snapshot.
    InstallSnapshot(
        InstallSnapshotRequest,
        oneshot::Sender<InstallSnapshotResponse>,
    ),
    /// The state machine has an image at `index`: compact the log to it.
    Compact {
        index: u64,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<(), ConsensusError>>,
    },
    /// The outcome of a snapshot this leader sent (`None`: it did not arrive).
    SnapshotResult {
        peer: u64,
        sent_term: u64,
        sent_index: u64,
        resp: Option<InstallSnapshotResponse>,
    },
    SnapshotStatus(oneshot::Sender<SnapshotStatus>),
    Shutdown,
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
    pub async fn propose_and_wait(
        &self,
        command: Vec<u8>,
        timeout: Duration,
    ) -> Result<u64, ConsensusError> {
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

    /// A leader's snapshot for this node. The reply says whether it was
    /// accepted; when it was, the snapshot is already on disk and on its way
    /// to the state machine.
    pub async fn install_snapshot(&self, req: InstallSnapshotRequest) -> InstallSnapshotResponse {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .sender
            .send(RaftMessage::InstallSnapshot(req, tx))
            .await;
        rx.await.expect("raft actor task ended unexpectedly")
    }

    /// Tells the actor that the state machine holds `data`, its complete
    /// state **after applying entry `index`** and no later one. The log is
    /// then discarded up to `index`, and the image is what the leader sends
    /// to followers that fall behind it.
    ///
    /// `index` must already have been delivered on the apply channel. An
    /// index at or below the current snapshot is a no-op; an image over
    /// [`MAX_SNAPSHOT_BYTES`] is refused and nothing changes (the log just
    /// keeps growing, which the caller should make visible). If the disk
    /// fails the node stops, as for any other write, and this returns
    /// `Stopped`.
    pub async fn compact(&self, index: u64, data: Vec<u8>) -> Result<(), ConsensusError> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(RaftMessage::Compact {
                index,
                data,
                reply: tx,
            })
            .await
            .map_err(|_| ConsensusError::Stopped)?;
        rx.await.map_err(|_| ConsensusError::Stopped)?
    }

    /// Snapshot position and counters; `None` if the actor has stopped.
    pub async fn snapshot_status(&self) -> Option<SnapshotStatus> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(RaftMessage::SnapshotStatus(tx))
            .await
            .ok()?;
        rx.await.ok()
    }

    /// Stops the actor. Anything already persisted stays persisted; a new
    /// actor started over the same store resumes from it.
    pub async fn shutdown(&self) {
        let _ = self.sender.send(RaftMessage::Shutdown).await;
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
        Self {
            min_ms: 150,
            max_ms: 300,
        }
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
    spawn_inner(
        RaftState::new(node_id),
        peers,
        transport,
        heartbeat_interval,
        election_timeout_range,
        None,
        None,
    )
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
) -> (RaftHandle, mpsc::UnboundedReceiver<ApplyItem>) {
    let (apply_tx, apply_rx) = mpsc::unbounded_channel();
    let handle = spawn_inner(
        RaftState::new(node_id),
        peers,
        transport,
        heartbeat_interval,
        election_timeout_range,
        Some(apply_tx),
        None,
    );
    (handle, apply_rx)
}

/// The production constructor: like [`spawn_raft_actor_with_apply`], but the
/// node's term, vote and log are loaded from `store` at startup and every
/// change is made durable **before** the node replies to a peer, replicates,
/// acknowledges a client, or applies an entry. If the store ever fails the
/// actor stops (fail-stop): a node that can no longer remember what it
/// promised must not keep making promises.
///
/// After a restart the node first hands the state machine its snapshot (if
/// it has one) and then replays every committed entry after it once it learns
/// the commit index, so the state machine must tolerate re-application (see
/// `statemachine` in the API crate).
pub fn spawn_raft_actor_persistent(
    node_id: u64,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
    mut store: Box<dyn RaftStore>,
) -> Result<(RaftHandle, mpsc::UnboundedReceiver<ApplyItem>), PersistError> {
    let persisted = store.load()?;
    // The state machine may not have installed this before the last crash, so
    // it is handed over again (first, before any entry) and the state machine
    // skips it if it is already there.
    let initial_snapshot = (persisted.snapshot_index > 0).then(|| {
        (
            persisted.snapshot_index,
            persisted.snapshot_term,
            persisted.snapshot_data.clone(),
        )
    });
    let state =
        RaftState::restore(node_id, persisted).map_err(|e| PersistError::Corrupt(e.to_string()))?;
    let (apply_tx, apply_rx) = mpsc::unbounded_channel();
    let handle = spawn_inner(
        state,
        peers,
        transport,
        heartbeat_interval,
        election_timeout_range,
        Some(apply_tx),
        Some(Durability {
            store,
            initial_snapshot,
        }),
    );
    Ok((handle, apply_rx))
}

/// Makes everything that changed since the last call durable: first the log
/// mutations the state recorded, then term/vote if they moved.
fn flush_persistence(
    store: &mut Option<Box<dyn RaftStore>>,
    state: &mut RaftState,
    persisted_hard: &mut (u64, Option<u64>),
) -> Result<(), PersistError> {
    let ops = state.log.drain_journal();
    let hard = (state.current_term, state.voted_for);
    let Some(store) = store else {
        *persisted_hard = hard;
        return Ok(());
    };
    if !ops.is_empty() {
        store.apply_log_ops(&ops)?;
    }
    if hard != *persisted_hard {
        store.save_hard_state(hard.0, hard.1)?;
        *persisted_hard = hard;
    }
    Ok(())
}

/// Makes a snapshot durable and trims the stored log to match, in that
/// order: a crash in between leaves a snapshot and a log that still holds
/// older entries, which `RaftState::restore` reconciles; the other order
/// could lose entries that nothing else holds.
fn persist_snapshot(
    store: &mut Option<Box<dyn RaftStore>>,
    state: &mut RaftState,
    index: u64,
    term: u64,
    data: &[u8],
) -> Result<(), PersistError> {
    if let Some(store) = store {
        store.save_snapshot(index, term, data)?;
        store.rewrite_log(&state.log.entries_from(0))?;
    }
    // The rewritten log is the whole truth: anything the journal still holds
    // is already in it, and replaying it on top would apply it twice.
    state.log.drain_journal();
    Ok(())
}

/// Per-peer bookkeeping for snapshots this node, as leader, is sending.
#[derive(Default)]
struct SnapshotSender {
    in_flight: HashSet<u64>,
    retry_after: HashMap<u64, Instant>,
    failing: HashSet<u64>,
}

/// What a node that persists its state starts from.
struct Durability {
    store: Box<dyn RaftStore>,
    /// The snapshot found on disk: (index, term, data).
    initial_snapshot: Option<(u64, u64, Vec<u8>)>,
}

/// The snapshot this node can serve to followers: the image and the index it
/// stands for (always the index the log is compacted to).
type HeldSnapshot = Option<(u64, Arc<Vec<u8>>)>;

/// Hands newly committed entries to the state machine and answers any
/// `propose_and_wait` callers whose entries just committed (or were found
/// to have been replaced by another leader's entry).
fn drain_committed(
    state: &mut RaftState,
    apply_tx: &Option<mpsc::UnboundedSender<ApplyItem>>,
    pending: &mut BTreeMap<u64, (u64, CommitWaiter)>,
) {
    for entry in state.take_newly_committed() {
        if let Some((proposed_term, waiter)) = pending.remove(&entry.index) {
            let result = if proposed_term == entry.term {
                Ok(entry.index)
            } else {
                Err(ConsensusError::LeadershipLost)
            };
            let _ = waiter.send(result);
        }
        if !entry.is_noop()
            && let Some(tx) = apply_tx
        {
            let _ = tx.send(ApplyItem::Entry(entry));
        }
    }
}

/// Sends `peer` what it is missing: its next AppendEntries, or, if the
/// entries it needs were compacted away, the snapshot (one at a time per
/// peer, and not again straight after a failure). Replies are routed back
/// into the actor's mailbox.
fn replicate_to(
    state: &RaftState,
    peer: u64,
    transport: &Arc<dyn Transport>,
    self_tx: &mpsc::Sender<RaftMessage>,
    held: &HeldSnapshot,
    snapshots: &mut SnapshotSender,
) {
    let Some(req) = state.build_append_entries(peer) else {
        send_snapshot(state, peer, transport, self_tx, held, snapshots);
        return;
    };
    let transport = transport.clone();
    let reply_tx = self_tx.clone();
    tokio::spawn(async move {
        let sent_term = req.term;
        let sent_prev_index = req.prev_log_index;
        let sent_len = req.entries.len() as u64;
        if let Ok(resp) = transport.send_append_entries(peer, req).await {
            let _ = reply_tx
                .send(RaftMessage::AppendResult {
                    peer,
                    sent_term,
                    sent_prev_index,
                    sent_len,
                    resp,
                })
                .await;
        }
    });
}

fn send_snapshot(
    state: &RaftState,
    peer: u64,
    transport: &Arc<dyn Transport>,
    self_tx: &mpsc::Sender<RaftMessage>,
    held: &HeldSnapshot,
    snapshots: &mut SnapshotSender,
) {
    if !state.needs_snapshot(peer) || snapshots.in_flight.contains(&peer) {
        return;
    }
    if snapshots
        .retry_after
        .get(&peer)
        .is_some_and(|at| Instant::now() < *at)
    {
        return;
    }
    let Some((index, data)) = held else {
        tracing::error!(peer, "peer needs a snapshot but this node holds none");
        return;
    };
    if *index != state.log.snapshot_index() {
        tracing::error!(
            peer,
            held = *index,
            log = state.log.snapshot_index(),
            "the snapshot held does not match the compacted log; not sending it"
        );
        return;
    }
    let Some(req) = state.build_install_snapshot(peer, data.as_ref().clone()) else {
        return;
    };
    snapshots.in_flight.insert(peer);
    let transport = transport.clone();
    let reply_tx = self_tx.clone();
    tokio::spawn(async move {
        let sent_term = req.term;
        let sent_index = req.last_included_index;
        let outcome = tokio::time::timeout(
            SNAPSHOT_SEND_TIMEOUT,
            transport.send_install_snapshot(peer, req),
        )
        .await;
        let resp = match outcome {
            Ok(Ok(resp)) => Some(resp),
            _ => None,
        };
        let _ = reply_tx
            .send(RaftMessage::SnapshotResult {
                peer,
                sent_term,
                sent_index,
                resp,
            })
            .await;
    });
}

fn spawn_inner(
    initial_state: RaftState,
    peers: Vec<u64>,
    transport: Arc<dyn Transport>,
    heartbeat_interval: Duration,
    election_timeout_range: ElectionTimeoutRange,
    apply_tx: Option<mpsc::UnboundedSender<ApplyItem>>,
    durability: Option<Durability>,
) -> RaftHandle {
    let (store, initial_snapshot) = match durability {
        Some(d) => (Some(d.store), d.initial_snapshot),
        None => (None, None),
    };
    let (tx, mut rx) = mpsc::channel(256);
    let self_tx = tx.clone();

    tokio::spawn(async move {
        let mut state = initial_state;
        let mut store = store;
        let mut persisted_hard = (state.current_term, state.voted_for);
        let mut pending: BTreeMap<u64, (u64, CommitWaiter)> = BTreeMap::new();
        let mut held: HeldSnapshot = None;
        let mut snapshot_sender = SnapshotSender::default();
        let mut status = SnapshotStatus::default();
        if let Some((index, term, data)) = initial_snapshot {
            if let Some(tx) = &apply_tx {
                let _ = tx.send(ApplyItem::Snapshot {
                    index,
                    term,
                    data: data.clone(),
                });
            }
            held = Some((index, Arc::new(data)));
        }
        let mut election_deadline =
            Instant::now() + random_election_timeout(election_timeout_range);
        let mut heartbeat_tick = tokio::time::interval(heartbeat_interval);

        // Makes all pending state changes durable. On failure the actor stops:
        // dropping every reply channel means callers see an error, never an
        // acknowledgement for data that is not safely stored.
        macro_rules! persist {
            () => {
                if let Err(e) = flush_persistence(&mut store, &mut state, &mut persisted_hard) {
                    tracing::error!(error = %e, "fatal: cannot persist raft state; stopping this node's raft actor");
                    break;
                }
            };
        }

        macro_rules! replicate {
            ($peer:expr) => {
                replicate_to(
                    &state,
                    $peer,
                    &transport,
                    &self_tx,
                    &held,
                    &mut snapshot_sender,
                )
            };
        }

        loop {
            tokio::select! {
                maybe_msg = rx.recv() => {
                    let Some(msg) = maybe_msg else { break; };
                    match msg {
                        RaftMessage::RequestVote(req, reply) => {
                            let candidate_term_is_current_or_newer = req.term >= state.current_term;
                            let resp = state.handle_request_vote(req);
                            persist!();
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
                            persist!();
                            if from_live_leader {
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            drain_committed(&mut state, &apply_tx, &mut pending);
                            let _ = reply.send(resp);
                        }
                        RaftMessage::Propose(command, reply) => {
                            let result = state.append_as_leader(command);
                            persist!();
                            if result.is_ok() {
                                for &peer in &peers {
                                    replicate!(peer);
                                }
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                            let _ = reply.send(result);
                        }
                        RaftMessage::ProposeAndWait(command, waiter) => {
                            match state.append_as_leader(command) {
                                Ok(index) => {
                                    persist!();
                                    pending.insert(index, (state.current_term, waiter));
                                    for &peer in &peers {
                                        replicate!(peer);
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
                            let won = state.record_vote(resp, peer, cluster_size);
                            if won {
                                state.become_leader();
                                state.on_elected(&peers);
                            }
                            persist!();
                            if won {
                                // Announce leadership (and start replicating)
                                // immediately rather than at the next tick.
                                for &p in &peers {
                                    replicate!(p);
                                }
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                        }
                        RaftMessage::AppendResult { peer, sent_term, sent_prev_index, sent_len, resp } => {
                            let was_leader = state.role == Role::Leader;
                            let outcome = state.handle_append_entries_response(peer, sent_term, sent_prev_index, sent_len, resp);
                            persist!();
                            if was_leader && state.role != Role::Leader {
                                // Deposed by a higher term: restart the
                                // election clock instead of firing at once.
                                election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                            }
                            if outcome.commit_advanced {
                                drain_committed(&mut state, &apply_tx, &mut pending);
                            }
                            if outcome.retry_now {
                                replicate!(peer);
                            }
                        }
                        RaftMessage::InstallSnapshot(req, reply) => {
                            if req.data.len() > MAX_SNAPSHOT_BYTES {
                                tracing::error!(size = req.data.len(), "refusing an oversized snapshot from the leader");
                                let _ = reply.send(InstallSnapshotResponse {
                                    term: state.current_term,
                                    success: false,
                                    match_index: 0,
                                });
                            } else {
                                let from_live_leader = req.term >= state.current_term;
                                let decision = state.handle_install_snapshot(&req);
                                if decision.install {
                                    // Durable first, then to the state machine,
                                    // and only then does the leader hear yes.
                                    if let Err(e) = persist_snapshot(
                                        &mut store,
                                        &mut state,
                                        req.last_included_index,
                                        req.last_included_term,
                                        &req.data,
                                    ) {
                                        tracing::error!(error = %e, "fatal: cannot persist a snapshot; stopping this node's raft actor");
                                        break;
                                    }
                                    if let Some(tx) = &apply_tx {
                                        let _ = tx.send(ApplyItem::Snapshot {
                                            index: req.last_included_index,
                                            term: req.last_included_term,
                                            data: req.data.clone(),
                                        });
                                    }
                                    held = Some((req.last_included_index, Arc::new(req.data)));
                                    status.installed += 1;
                                }
                                persist!();
                                if from_live_leader {
                                    election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                                }
                                drain_committed(&mut state, &apply_tx, &mut pending);
                                let _ = reply.send(decision.response);
                            }
                        }
                        RaftMessage::Compact { index, data, reply } => {
                            let result = if index <= state.log.snapshot_index() {
                                // Already covered by a snapshot at least this new.
                                Ok(())
                            } else if data.len() > MAX_SNAPSHOT_BYTES {
                                Err(ConsensusError::SnapshotRefused(format!(
                                    "the snapshot is {} bytes, over the {} byte limit",
                                    data.len(),
                                    MAX_SNAPSHOT_BYTES
                                )))
                            } else {
                                match state.compact(index) {
                                    Err(e) => Err(ConsensusError::SnapshotRefused(e.to_string())),
                                    Ok(()) => {
                                        let term = state.log.snapshot_term();
                                        if let Err(e) = persist_snapshot(&mut store, &mut state, index, term, &data) {
                                            tracing::error!(error = %e, "fatal: cannot persist a snapshot; stopping this node's raft actor");
                                            break;
                                        }
                                        held = Some((index, Arc::new(data)));
                                        status.taken += 1;
                                        Ok(())
                                    }
                                }
                            };
                            let _ = reply.send(result);
                        }
                        RaftMessage::SnapshotResult { peer, sent_term, sent_index, resp } => {
                            snapshot_sender.in_flight.remove(&peer);
                            match resp {
                                None => {
                                    snapshot_sender.retry_after.insert(peer, Instant::now() + SNAPSHOT_RETRY_DELAY);
                                    if snapshot_sender.failing.insert(peer) {
                                        tracing::warn!(peer, "could not deliver a snapshot to a peer; will keep retrying");
                                    }
                                }
                                Some(resp) => {
                                    snapshot_sender.failing.remove(&peer);
                                    snapshot_sender.retry_after.remove(&peer);
                                    let acked = resp.success;
                                    let was_leader = state.role == Role::Leader;
                                    let outcome = state.handle_install_snapshot_response(peer, sent_term, sent_index, resp);
                                    persist!();
                                    if acked {
                                        status.sent += 1;
                                    }
                                    if was_leader && state.role != Role::Leader {
                                        election_deadline = Instant::now() + random_election_timeout(election_timeout_range);
                                    }
                                    if outcome.commit_advanced {
                                        drain_committed(&mut state, &apply_tx, &mut pending);
                                    }
                                    if outcome.retry_now {
                                        replicate!(peer);
                                    }
                                }
                            }
                        }
                        RaftMessage::SnapshotStatus(reply) => {
                            let _ = reply.send(SnapshotStatus {
                                snapshot_index: state.log.snapshot_index(),
                                ..status
                            });
                        }
                        RaftMessage::Inspect(reply) => {
                            let _ = reply.send((state.role, state.current_term, state.commit_index));
                        }
                        RaftMessage::Shutdown => break,
                    }
                }

                _ = tokio::time::sleep_until(election_deadline), if state.role != Role::Leader => {
                    let vote_req = state.become_candidate();
                    persist!();
                    election_deadline = Instant::now() + random_election_timeout(election_timeout_range);

                    if peers.is_empty() {
                        state.become_leader();
                        state.on_elected(&peers);
                        persist!();
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
                        replicate!(peer);
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
    use crate::persist::MemoryStore;
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
            handles
                .get(&peer_id)
                .cloned()
                .ok_or(TransportError::Unreachable(peer_id))
        }
    }

    #[async_trait::async_trait]
    impl Transport for NodeTransport {
        async fn send_request_vote(
            &self,
            peer_id: u64,
            req: RequestVoteRequest,
        ) -> Result<RequestVoteResponse, TransportError> {
            Ok(self.route(peer_id).await?.request_vote(req).await)
        }
        async fn send_append_entries(
            &self,
            peer_id: u64,
            req: AppendEntriesRequest,
        ) -> Result<AppendEntriesResponse, TransportError> {
            Ok(self.route(peer_id).await?.append_entries(req).await)
        }
        async fn send_install_snapshot(
            &self,
            peer_id: u64,
            req: InstallSnapshotRequest,
        ) -> Result<InstallSnapshotResponse, TransportError> {
            Ok(self.route(peer_id).await?.install_snapshot(req).await)
        }
    }

    struct Cluster {
        ids: Vec<u64>,
        handles: HashMap<u64, RaftHandle>,
        net: Arc<Net>,
        applied_rx: HashMap<u64, mpsc::UnboundedReceiver<ApplyItem>>,
        /// Commands each node has applied so far, in order.
        seen: HashMap<u64, Vec<Vec<u8>>>,
        /// Everything each node's state machine was handed, in order.
        items: HashMap<u64, Vec<ApplyItem>>,
    }

    async fn spawn_cluster(
        ids: &[u64],
        heartbeat: Duration,
        election_range: ElectionTimeoutRange,
    ) -> Cluster {
        spawn_cluster_inner(ids, heartbeat, election_range, None).await
    }

    /// A cluster whose nodes persist to the given stores. Calling this again
    /// with the same stores is a restart of the whole cluster.
    async fn spawn_persistent_cluster(ids: &[u64], stores: &HashMap<u64, MemoryStore>) -> Cluster {
        spawn_cluster_inner(ids, Duration::from_millis(20), FAST, Some(stores)).await
    }

    async fn spawn_cluster_inner(
        ids: &[u64],
        heartbeat: Duration,
        election_range: ElectionTimeoutRange,
        stores: Option<&HashMap<u64, MemoryStore>>,
    ) -> Cluster {
        let net = Arc::new(Net {
            handles: Mutex::new(HashMap::new()),
            isolated: StdMutex::new(HashSet::new()),
        });
        let mut handles = HashMap::new();
        let mut applied_rx = HashMap::new();
        for &id in ids {
            let peers: Vec<u64> = ids.iter().copied().filter(|&p| p != id).collect();
            let transport = Arc::new(NodeTransport {
                from: id,
                net: net.clone(),
            });
            let (handle, rx) = match stores {
                Some(stores) => spawn_raft_actor_persistent(
                    id,
                    peers,
                    transport,
                    heartbeat,
                    election_range,
                    Box::new(stores[&id].clone()),
                )
                .expect("store should load"),
                None => {
                    spawn_raft_actor_with_apply(id, peers, transport, heartbeat, election_range)
                }
            };
            net.handles.lock().await.insert(id, handle.clone());
            handles.insert(id, handle);
            applied_rx.insert(id, rx);
        }
        let seen = ids.iter().map(|&id| (id, Vec::new())).collect();
        let items = ids.iter().map(|&id| (id, Vec::new())).collect();
        Cluster {
            ids: ids.to_vec(),
            handles,
            net,
            applied_rx,
            seen,
            items,
        }
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
                if role == Role::Leader && best.is_none_or(|(t, _)| term > t) {
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
                    if let Some(leader) = self.leader_among(among).await
                        && let Ok(index) = self.handles[&leader]
                            .propose_and_wait(command.to_vec(), Duration::from_millis(800))
                            .await
                    {
                        return index;
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
                while let Ok(item) = rx.try_recv() {
                    if let ApplyItem::Entry(entry) = &item {
                        self.seen.get_mut(&id).unwrap().push(entry.command.clone());
                    }
                    self.items.get_mut(&id).unwrap().push(item);
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
                self.seen
                    .iter()
                    .map(|(id, v)| (*id, v.len()))
                    .collect::<Vec<_>>()
            );
        }
    }

    fn cmds(items: &[&str]) -> Vec<Vec<u8>> {
        items.iter().map(|s| s.as_bytes().to_vec()).collect()
    }

    const FAST: ElectionTimeoutRange = ElectionTimeoutRange {
        min_ms: 80,
        max_ms: 150,
    };

    // ---- the original election tests, unchanged in intent ----

    #[tokio::test]
    async fn single_node_cluster_should_elect_itself_leader() {
        let cluster = spawn_cluster(&[1], Duration::from_millis(20), FAST).await;
        // Wait for the election rather than guessing how long it takes: on a
        // loaded machine a fixed sleep is a coin flip.
        cluster.wait_for_leader(&[1]).await;
        let (role, _, _) = cluster.handles[&1].inspect().await;
        assert_eq!(
            role,
            Role::Leader,
            "a lone node with no peers must still become its own leader"
        );
    }

    #[tokio::test]
    async fn three_node_cluster_elects_exactly_one_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;

        // Liveness: the cluster settles on exactly one leader, all in one term.
        // (A single snapshot after a fixed sleep is not a valid test: a leader
        // from term 1 may briefly coexist with a newly elected leader of term 2
        // until it hears about it. That is legal Raft; only one leader *per
        // term* is guaranteed.)
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let mut leaders = 0;
                let mut terms = Vec::new();
                for &id in &ids {
                    let (role, term, _) = cluster.handles[&id].inspect().await;
                    terms.push(term);
                    if role == Role::Leader {
                        leaders += 1;
                    }
                }
                if leaders == 1 && terms.iter().all(|&t| t == terms[0]) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the cluster never settled on exactly one leader in a single term");

        // Safety, the actual Raft invariant: at no moment do two different
        // nodes lead the same term.
        let mut leaders_by_term: HashMap<u64, HashSet<u64>> = HashMap::new();
        for _ in 0..40 {
            for &id in &ids {
                let (role, term, _) = cluster.handles[&id].inspect().await;
                if role == Role::Leader {
                    leaders_by_term.entry(term).or_default().insert(id);
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for (term, who) in &leaders_by_term {
            assert!(
                who.len() <= 1,
                "election safety violated: term {term} had leaders {who:?}"
            );
        }
    }

    #[tokio::test]
    async fn heartbeats_prevent_repeated_elections() {
        let ids = [1, 2, 3];
        // Election timeout 20-35x the heartbeat interval: a test thread that is
        // starved for a while cannot cause a spurious election, so any term
        // change here would mean heartbeats genuinely failed to suppress one.
        let cluster = spawn_cluster(
            &ids,
            Duration::from_millis(20),
            ElectionTimeoutRange {
                min_ms: 400,
                max_ms: 700,
            },
        )
        .await;
        cluster.wait_for_leader(&ids).await;
        tokio::time::sleep(Duration::from_millis(150)).await; // let followers adopt the term

        let mut terms_after_election = Vec::new();
        for &id in &ids {
            terms_after_election.push(cluster.handles[&id].inspect().await.1);
        }
        assert!(
            terms_after_election
                .iter()
                .all(|&t| t == terms_after_election[0]),
            "nodes disagree: {terms_after_election:?}"
        );

        tokio::time::sleep(Duration::from_millis(500)).await;

        let mut final_terms = Vec::new();
        for &id in &ids {
            final_terms.push(cluster.handles[&id].inspect().await.1);
        }
        assert_eq!(
            final_terms, terms_after_election,
            "term should be stable once a leader is established"
        );
    }

    /// Regression test for a real deadlock: the actor used to await its vote
    /// replies inline, so two nodes campaigning at once could each wait for
    /// the other forever. Tight election timeouts make simultaneous campaigns
    /// likely.
    ///
    /// The deadline is deliberately generous. A deadlock never recovers, so
    /// it fails this test at any deadline; a merely slow machine does not.
    /// With a 2 s deadline the test failed 8 of 8 runs on a machine slowed
    /// about 20x, because heartbeats later than the 30 ms election timeout
    /// make leadership change continuously, which is not a deadlock.
    #[tokio::test]
    async fn repeated_elections_do_not_deadlock_under_tight_simultaneous_timeouts() {
        const DEADLINE: Duration = Duration::from_secs(20);

        for _ in 0..20 {
            let ids = [1, 2, 3];
            let cluster = spawn_cluster(
                &ids,
                Duration::from_millis(5),
                ElectionTimeoutRange {
                    min_ms: 30,
                    max_ms: 60,
                },
            )
            .await;

            let result = tokio::time::timeout(DEADLINE, async {
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

            assert!(
                result.is_ok(),
                "cluster failed to elect a leader within {DEADLINE:?} - likely deadlocked"
            );
        }
    }

    #[tokio::test]
    async fn propose_fails_on_a_follower_and_succeeds_on_the_leader() {
        let ids = [1, 2, 3];
        let cluster = spawn_cluster(&ids, Duration::from_millis(20), FAST).await;
        let leader_id = cluster.wait_for_leader(&ids).await;

        for &id in &ids {
            let result = cluster.handles[&id].propose(b"set x=1".to_vec()).await;
            if id == leader_id {
                assert!(result.is_ok(), "leader should accept a proposal");
            } else {
                assert!(
                    matches!(result, Err(ConsensusError::NotLeader)),
                    "follower should reject a proposal"
                );
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
            assert_eq!(
                cluster.seen[&id],
                cmds(&sent),
                "node {id} must apply exactly the proposed commands, in order"
            );
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
        let index = cluster.handles[&1]
            .propose_and_wait(b"solo".to_vec(), Duration::from_secs(2))
            .await
            .unwrap();
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
        let result = cluster.handles[&follower]
            .propose_and_wait(b"x".to_vec(), Duration::from_secs(5))
            .await;
        assert!(matches!(result, Err(ConsensusError::NotLeader)));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "must not wait out the timeout"
        );

        let empty = cluster.handles[&leader]
            .propose_and_wait(vec![], Duration::from_secs(1))
            .await;
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
        assert_eq!(
            cluster.seen[&straggler].len(),
            1,
            "the isolated node must not have received anything new"
        );

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
        let orphan = cluster.handles[&old_leader]
            .propose_and_wait(b"orphan".to_vec(), Duration::from_millis(400))
            .await;
        assert!(
            orphan.is_err(),
            "a minority leader must not be able to commit, got {orphan:?}"
        );

        // The majority elects a new leader and carries on.
        cluster.wait_for_leader(&others).await;
        cluster.propose_ok(&others, b"after-1").await;
        cluster.propose_ok(&others, b"after-2").await;

        // Reconnect: the old leader steps down, drops its orphan entry, and adopts the new log.
        cluster.heal();
        cluster.wait_until_everyone_applied(&ids, 3).await;

        let expected = cmds(&["committed-before", "after-1", "after-2"]);
        for &id in &ids {
            assert_eq!(
                cluster.seen[&id], expected,
                "node {id} must never have applied the orphaned write"
            );
        }
        // Give any stray delivery a chance to show up, then re-check.
        tokio::time::sleep(Duration::from_millis(300)).await;
        cluster.pump();
        for &id in &ids {
            assert!(
                !cluster.seen[&id].contains(&b"orphan".to_vec()),
                "node {id} applied the orphan"
            );
        }
    }

    #[tokio::test]
    async fn rejected_appends_from_a_live_leader_still_reset_the_election_timer() {
        // A node whose log is behind rejects the leader's append (prev entry
        // missing). That rejection must not make it think the leader died.
        struct Dead;
        #[async_trait::async_trait]
        impl Transport for Dead {
            async fn send_request_vote(
                &self,
                p: u64,
                _: RequestVoteRequest,
            ) -> Result<RequestVoteResponse, TransportError> {
                Err(TransportError::Unreachable(p))
            }
            async fn send_append_entries(
                &self,
                p: u64,
                _: AppendEntriesRequest,
            ) -> Result<AppendEntriesResponse, TransportError> {
                Err(TransportError::Unreachable(p))
            }
        }
        let handle = spawn_raft_actor(
            2,
            vec![1, 3],
            Arc::new(Dead),
            Duration::from_millis(20),
            ElectionTimeoutRange {
                min_ms: 600,
                max_ms: 800,
            },
        );

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
        assert_eq!(
            (role, term),
            (Role::Follower, 1),
            "over 800ms of live-leader contact (a rejected append every 50ms) the node must never time out"
        );
    }

    // ---- Phase 15: durability ----

    struct DeadNet;
    #[async_trait::async_trait]
    impl Transport for DeadNet {
        async fn send_request_vote(
            &self,
            p: u64,
            _: RequestVoteRequest,
        ) -> Result<RequestVoteResponse, TransportError> {
            Err(TransportError::Unreachable(p))
        }
        async fn send_append_entries(
            &self,
            p: u64,
            _: AppendEntriesRequest,
        ) -> Result<AppendEntriesResponse, TransportError> {
            Err(TransportError::Unreachable(p))
        }
    }

    const NEVER_ELECT: ElectionTimeoutRange = ElectionTimeoutRange {
        min_ms: 60_000,
        max_ms: 61_000,
    };

    fn persistent_follower(store: &MemoryStore) -> RaftHandle {
        spawn_raft_actor_persistent(
            2,
            vec![1, 3],
            Arc::new(DeadNet),
            Duration::from_millis(20),
            NEVER_ELECT,
            Box::new(store.clone()),
        )
        .unwrap()
        .0
    }

    #[tokio::test]
    async fn a_restarted_node_cannot_vote_twice_in_the_term_it_already_voted_in() {
        let store = MemoryStore::new();
        let node = persistent_follower(&store);
        let first = node
            .request_vote(RequestVoteRequest {
                term: 5,
                candidate_id: 1,
                last_log_index: 0,
                last_log_term: 0,
            })
            .await;
        assert!(first.vote_granted);
        node.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Brand-new actor, same disk.
        let restarted = persistent_follower(&store);
        let (_, term, _) = restarted.inspect().await;
        assert_eq!(term, 5, "the term must survive a restart");

        let rival = restarted
            .request_vote(RequestVoteRequest {
                term: 5,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            })
            .await;
        assert!(
            !rival.vote_granted,
            "a second vote in term 5 would allow two leaders"
        );
        let same = restarted
            .request_vote(RequestVoteRequest {
                term: 5,
                candidate_id: 1,
                last_log_index: 0,
                last_log_term: 0,
            })
            .await;
        assert!(
            same.vote_granted,
            "re-granting to the same candidate is still fine"
        );
    }

    #[tokio::test]
    async fn without_persistence_the_same_restart_would_double_vote() {
        // Control for the test above: proves it is persistence, not luck, that prevents the second vote.
        let node = spawn_raft_actor(
            2,
            vec![1, 3],
            Arc::new(DeadNet),
            Duration::from_millis(20),
            NEVER_ELECT,
        );
        node.request_vote(RequestVoteRequest {
            term: 5,
            candidate_id: 1,
            last_log_index: 0,
            last_log_term: 0,
        })
        .await;
        node.shutdown().await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let restarted = spawn_raft_actor(
            2,
            vec![1, 3],
            Arc::new(DeadNet),
            Duration::from_millis(20),
            NEVER_ELECT,
        );
        let rival = restarted
            .request_vote(RequestVoteRequest {
                term: 5,
                candidate_id: 3,
                last_log_index: 0,
                last_log_term: 0,
            })
            .await;
        assert!(
            rival.vote_granted,
            "an amnesiac node grants the second vote; that is the bug persistence prevents"
        );
    }

    #[tokio::test]
    async fn a_follower_only_acknowledges_an_append_after_it_is_durable() {
        let store = MemoryStore::new();
        let node = persistent_follower(&store);
        let e = |term, index| LogEntry {
            term,
            index,
            command: vec![index as u8],
        };

        let resp = node
            .append_entries(AppendEntriesRequest {
                term: 1,
                leader_id: 1,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: vec![e(1, 1), e(1, 2)],
                leader_commit: 0,
            })
            .await;
        assert!(resp.success);
        // The reply has been received, so the data must already be on "disk".
        let snap = store.snapshot();
        assert_eq!((snap.term, snap.entries.len()), (1, 2));

        // A new leader overwrites index 2; the truncation is persisted too.
        let resp = node
            .append_entries(AppendEntriesRequest {
                term: 2,
                leader_id: 3,
                prev_log_index: 1,
                prev_log_term: 1,
                entries: vec![e(2, 2)],
                leader_commit: 0,
            })
            .await;
        assert!(resp.success);
        let snap = store.snapshot();
        assert_eq!((snap.term, snap.entries[1].term), (2, 2));
    }

    #[tokio::test]
    async fn restarting_the_whole_cluster_loses_no_committed_entry() {
        let ids = [1, 2, 3];
        let stores: HashMap<u64, MemoryStore> =
            ids.iter().map(|&id| (id, MemoryStore::new())).collect();

        let mut first = spawn_persistent_cluster(&ids, &stores).await;
        first.wait_for_leader(&ids).await;
        for c in ["a", "b", "c"] {
            first.propose_ok(&ids, c.as_bytes()).await;
        }
        first.wait_until_everyone_applied(&ids, 3).await;
        let term_before = first.handles[&1].inspect().await.1;

        // Power off every node at once. Nobody is left to resend anything:
        // whatever survives is exactly what was on disk.
        for &id in &ids {
            first.handles[&id].shutdown().await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        for &id in &ids {
            let on_disk: Vec<Vec<u8>> = stores[&id]
                .snapshot()
                .entries
                .into_iter()
                .filter(|e| !e.is_noop())
                .map(|e| e.command)
                .collect();
            assert_eq!(
                on_disk,
                cmds(&["a", "b", "c"]),
                "node {id} must have persisted every committed entry"
            );
        }

        let mut second = spawn_persistent_cluster(&ids, &stores).await;
        second.wait_for_leader(&ids).await;
        second.wait_until_everyone_applied(&ids, 3).await;
        for &id in &ids {
            assert_eq!(
                second.seen[&id],
                cmds(&["a", "b", "c"]),
                "node {id} must re-apply the surviving log"
            );
            assert!(
                second.handles[&id].inspect().await.1 > term_before,
                "terms must never go backwards across a restart"
            );
        }

        // And the restarted cluster keeps working.
        second.propose_ok(&ids, b"d").await;
        second.wait_until_everyone_applied(&ids, 4).await;
        assert_eq!(second.seen[&1].last().unwrap(), b"d");
    }

    #[tokio::test]
    async fn a_failing_disk_stops_the_node_instead_of_acknowledging_unsaved_data() {
        let store = MemoryStore::new();
        let (node, mut applied) = spawn_raft_actor_persistent(
            1,
            vec![],
            Arc::new(DeadNet),
            Duration::from_millis(20),
            FAST,
            Box::new(store.clone()),
        )
        .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while node.inspect().await.0 != Role::Leader {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("single node should lead");

        store.set_fail_writes(true);
        let result = node
            .propose_and_wait(b"must-not-be-acked".to_vec(), Duration::from_secs(2))
            .await;
        assert!(
            matches!(result, Err(ConsensusError::Stopped)),
            "got {result:?}"
        );
        assert!(
            applied.try_recv().is_err(),
            "an entry that could not be saved must never reach the state machine"
        );
        assert!(
            store
                .snapshot()
                .entries
                .iter()
                .all(|e| e.command != b"must-not-be-acked")
        );
    }

    // -----------------------------------------------------------------
    // Snapshots in the actor
    // -----------------------------------------------------------------

    use std::sync::atomic::{AtomicBool, Ordering};

    fn kinds(items: &[ApplyItem]) -> Vec<String> {
        items
            .iter()
            .map(|i| match i {
                ApplyItem::Entry(e) => {
                    format!("E{}:{}", e.index, String::from_utf8_lossy(&e.command))
                }
                ApplyItem::Snapshot { index, data, .. } => {
                    format!("S{}:{}", index, String::from_utf8_lossy(data))
                }
            })
            .collect()
    }

    async fn next_items(rx: &mut mpsc::UnboundedReceiver<ApplyItem>, n: usize) -> Vec<ApplyItem> {
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), async {
            while out.len() < n {
                out.push(rx.recv().await.expect("apply channel closed"));
            }
        })
        .await
        .unwrap_or_else(|_| panic!("expected {n} items, got {:?}", kinds(&out)));
        out
    }

    async fn wait_leader(node: &RaftHandle) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while node.inspect().await.0 != Role::Leader {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("node should lead");
    }

    fn single_node(store: &MemoryStore) -> (RaftHandle, mpsc::UnboundedReceiver<ApplyItem>) {
        spawn_raft_actor_persistent(
            1,
            vec![],
            Arc::new(DeadNet),
            Duration::from_millis(20),
            FAST,
            Box::new(store.clone()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn the_default_transport_says_it_cannot_carry_snapshots() {
        let req = InstallSnapshotRequest {
            term: 1,
            leader_id: 1,
            last_included_index: 1,
            last_included_term: 1,
            data: vec![],
        };
        assert!(matches!(
            DeadNet.send_install_snapshot(7, req).await,
            Err(TransportError::SnapshotsUnsupported(7))
        ));
    }

    #[tokio::test]
    async fn compacting_trims_the_stored_log_and_a_restart_starts_from_the_snapshot() {
        let store = MemoryStore::new();
        let (node, mut applied) = single_node(&store);
        wait_leader(&node).await;
        for i in 1..=8 {
            node.propose_and_wait(format!("c{i}").into_bytes(), Duration::from_secs(10))
                .await
                .unwrap();
        }
        // The no-op took index 1, so c4 is entry 5.
        let first = next_items(&mut applied, 8).await;
        assert_eq!(kinds(&first)[0], "E2:c1");

        node.compact(5, b"image-5".to_vec()).await.unwrap();
        let on_disk = store.snapshot();
        assert_eq!(
            (on_disk.snapshot_index, on_disk.snapshot_data.as_slice()),
            (5, &b"image-5"[..])
        );
        assert!(on_disk.snapshot_term >= 1);
        assert_eq!(on_disk.entries.first().map(|e| e.index), Some(6));
        assert_eq!(on_disk.entries.last().map(|e| e.index), Some(9));
        let status = node.snapshot_status().await.unwrap();
        assert_eq!(
            (status.snapshot_index, status.taken, status.installed),
            (5, 1, 0)
        );

        // Restart over the same store: the snapshot comes first, then only
        // the entries after it, and nothing before it is ever replayed.
        node.shutdown().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (node, mut applied) = single_node(&store);
        let items = next_items(&mut applied, 5).await;
        assert_eq!(
            kinds(&items),
            ["S5:image-5", "E6:c5", "E7:c6", "E8:c7", "E9:c8"]
        );
        // And it keeps working.
        wait_leader(&node).await;
        let index = node
            .propose_and_wait(b"after".to_vec(), Duration::from_secs(10))
            .await
            .unwrap();
        assert!(index > 9);
        assert_eq!(
            kinds(&next_items(&mut applied, 1).await)[0],
            format!("E{index}:after")
        );
    }

    #[tokio::test]
    async fn a_snapshot_on_disk_whose_log_was_never_trimmed_is_delivered_first_and_nothing_before_it_is()
     {
        // The crash window between "snapshot written" and "log trimmed".
        let mut store = MemoryStore::new();
        store.load().unwrap();
        let ops: Vec<crate::log::LogOp> = (1..=6)
            .map(|i| {
                crate::log::LogOp::Append(LogEntry {
                    term: 1,
                    index: i,
                    command: format!("c{i}").into_bytes(),
                })
            })
            .collect();
        store.apply_log_ops(&ops).unwrap();
        store.save_snapshot(4, 1, b"img4").unwrap();

        let (node, mut applied) = single_node(&store);
        let items = next_items(&mut applied, 3).await;
        assert_eq!(kinds(&items), ["S4:img4", "E5:c5", "E6:c6"]);
        wait_leader(&node).await;
    }

    #[tokio::test]
    async fn compaction_that_makes_no_sense_is_refused_or_ignored_and_the_node_carries_on() {
        let store = MemoryStore::new();
        let (node, mut applied) = single_node(&store);
        wait_leader(&node).await;
        for i in 1..=3 {
            node.propose_and_wait(format!("c{i}").into_bytes(), Duration::from_secs(10))
                .await
                .unwrap();
        }
        next_items(&mut applied, 3).await;

        // Ahead of what was applied.
        assert!(matches!(
            node.compact(100, b"x".to_vec()).await,
            Err(ConsensusError::SnapshotRefused(_))
        ));
        assert_eq!(store.snapshot().snapshot_index, 0);

        node.compact(3, b"first".to_vec()).await.unwrap();
        // Older or equal: ignored, and the stored image is not replaced.
        node.compact(3, b"again".to_vec()).await.unwrap();
        node.compact(2, b"older".to_vec()).await.unwrap();
        node.compact(0, b"zero".to_vec()).await.unwrap();
        assert_eq!(store.snapshot().snapshot_data, b"first");

        // Too big: refused, nothing changes.
        let huge = vec![0u8; MAX_SNAPSHOT_BYTES + 1];
        let index = node
            .propose_and_wait(b"c4".to_vec(), Duration::from_secs(10))
            .await
            .unwrap();
        next_items(&mut applied, 1).await;
        assert!(matches!(
            node.compact(index, huge).await,
            Err(ConsensusError::SnapshotRefused(_))
        ));
        assert_eq!(store.snapshot().snapshot_index, 3);

        // Still alive, still counted correctly.
        node.propose_and_wait(b"c5".to_vec(), Duration::from_secs(10))
            .await
            .unwrap();
        let status = node.snapshot_status().await.unwrap();
        assert_eq!((status.snapshot_index, status.taken), (3, 1));
    }

    #[tokio::test]
    async fn a_disk_failure_while_compacting_stops_the_node_and_changes_nothing() {
        let store = MemoryStore::new();
        let (node, mut applied) = single_node(&store);
        wait_leader(&node).await;
        for i in 1..=3 {
            node.propose_and_wait(format!("c{i}").into_bytes(), Duration::from_secs(10))
                .await
                .unwrap();
        }
        next_items(&mut applied, 3).await;
        let before = store.snapshot();
        store.set_fail_writes(true);
        assert!(matches!(
            node.compact(3, b"x".to_vec()).await,
            Err(ConsensusError::Stopped)
        ));
        assert_eq!(store.snapshot(), before);
        assert!(node.snapshot_status().await.is_none(), "the actor stopped");
    }

    fn snapshot_req(term: u64, index: u64, data: &[u8]) -> InstallSnapshotRequest {
        InstallSnapshotRequest {
            term,
            leader_id: 1,
            last_included_index: index,
            last_included_term: 1,
            data: data.to_vec(),
        }
    }

    fn follower_with_apply(
        store: &MemoryStore,
    ) -> (RaftHandle, mpsc::UnboundedReceiver<ApplyItem>) {
        spawn_raft_actor_persistent(
            2,
            vec![1, 3],
            Arc::new(DeadNet),
            Duration::from_millis(20),
            NEVER_ELECT,
            Box::new(store.clone()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn an_installed_snapshot_is_on_disk_and_with_the_state_machine_when_the_leader_hears_yes()
    {
        let store = MemoryStore::new();
        let (node, mut applied) = follower_with_apply(&store);
        let resp = node.install_snapshot(snapshot_req(3, 5, b"img5")).await;
        assert!(resp.success);
        assert_eq!(resp.match_index, 5);
        assert_eq!(resp.term, 3);

        // The reply has been received, so everything must already be done.
        let disk = store.snapshot();
        assert_eq!((disk.snapshot_index, disk.snapshot_term), (5, 1));
        assert_eq!(disk.snapshot_data, b"img5");
        assert!(disk.entries.is_empty());
        assert_eq!(disk.term, 3, "the leader's term is persisted too");
        let first = applied.try_recv().expect("already delivered");
        assert_eq!(kinds(&[first]), ["S5:img5"]);
        let status = node.snapshot_status().await.unwrap();
        assert_eq!((status.snapshot_index, status.installed), (5, 1));

        // And the log carries on from the snapshot.
        let resp = node
            .append_entries(AppendEntriesRequest {
                term: 3,
                leader_id: 1,
                prev_log_index: 5,
                prev_log_term: 1,
                entries: vec![LogEntry {
                    term: 3,
                    index: 6,
                    command: b"six".to_vec(),
                }],
                leader_commit: 6,
            })
            .await;
        assert!(resp.success);
        assert_eq!(kinds(&next_items(&mut applied, 1).await), ["E6:six"]);
    }

    #[tokio::test]
    async fn a_snapshot_that_cannot_be_saved_is_never_acknowledged_or_delivered() {
        let store = MemoryStore::new();
        let (node, mut applied) = follower_with_apply(&store);
        store.set_fail_writes(true);
        let join =
            tokio::spawn(async move { node.install_snapshot(snapshot_req(3, 5, b"img")).await });
        assert!(
            join.await.is_err(),
            "the actor stops, so there is no reply to give"
        );
        assert!(
            applied.try_recv().is_err(),
            "nothing reaches the state machine"
        );
        assert_eq!(store.snapshot().snapshot_index, 0);
    }

    #[tokio::test]
    async fn a_snapshot_the_node_has_already_applied_past_is_acknowledged_and_ignored() {
        let store = MemoryStore::new();
        let (node, mut applied) = follower_with_apply(&store);
        let e = |index: u64| LogEntry {
            term: 1,
            index,
            command: vec![index as u8],
        };
        let resp = node
            .append_entries(AppendEntriesRequest {
                term: 1,
                leader_id: 1,
                prev_log_index: 0,
                prev_log_term: 0,
                entries: (1..=5).map(e).collect(),
                leader_commit: 5,
            })
            .await;
        assert!(resp.success);
        next_items(&mut applied, 5).await;

        let resp = node.install_snapshot(snapshot_req(1, 3, b"old")).await;
        assert!(resp.success);
        assert_eq!(resp.match_index, 3);
        assert!(
            applied.try_recv().is_err(),
            "installing it would roll the state back"
        );
        let status = node.snapshot_status().await.unwrap();
        assert_eq!((status.snapshot_index, status.installed), (0, 0));
        assert_eq!(store.snapshot().snapshot_index, 0);
    }

    #[tokio::test]
    async fn an_oversized_snapshot_from_a_leader_is_refused_and_the_node_carries_on() {
        let store = MemoryStore::new();
        let (node, mut applied) = follower_with_apply(&store);
        let resp = node
            .install_snapshot(snapshot_req(1, 5, &vec![0u8; MAX_SNAPSHOT_BYTES + 1]))
            .await;
        assert!(!resp.success);
        assert!(applied.try_recv().is_err());
        assert_eq!(store.snapshot().snapshot_index, 0);
        let status = node.snapshot_status().await.expect("still alive");
        assert_eq!(status.installed, 0);
        // A reasonable one right after is accepted.
        assert!(
            node.install_snapshot(snapshot_req(1, 5, b"ok"))
                .await
                .success
        );
    }

    /// A peer whose answers are scripted: node 2 behaves, node 3 never has
    /// the entries (so it needs a snapshot once the leader has compacted),
    /// and what happens to a snapshot sent to node 3 is up to the test.
    #[derive(Clone, Copy, PartialEq)]
    enum SnapMode {
        Hang,
        Fail,
        Ack,
    }

    struct Probe {
        mode: SnapMode,
        three_has_caught_up: AtomicBool,
        snapshots: StdMutex<Vec<(std::time::Instant, InstallSnapshotRequest)>>,
        appends: StdMutex<Vec<(u64, u64)>>, // (peer, prev_log_index)
    }

    impl Probe {
        fn new(mode: SnapMode) -> Arc<Self> {
            Arc::new(Self {
                mode,
                three_has_caught_up: AtomicBool::new(false),
                snapshots: StdMutex::new(Vec::new()),
                appends: StdMutex::new(Vec::new()),
            })
        }
        fn snapshot_calls(&self) -> usize {
            self.snapshots.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl Transport for Probe {
        async fn send_request_vote(
            &self,
            _: u64,
            req: RequestVoteRequest,
        ) -> Result<RequestVoteResponse, TransportError> {
            Ok(RequestVoteResponse {
                term: req.term,
                vote_granted: true,
            })
        }
        async fn send_append_entries(
            &self,
            peer: u64,
            req: AppendEntriesRequest,
        ) -> Result<AppendEntriesResponse, TransportError> {
            self.appends
                .lock()
                .unwrap()
                .push((peer, req.prev_log_index));
            let behind = peer == 3 && !self.three_has_caught_up.load(Ordering::SeqCst);
            Ok(AppendEntriesResponse {
                term: req.term,
                success: !behind,
                match_index: (!behind).then(|| req.prev_log_index + req.entries.len() as u64),
            })
        }
        async fn send_install_snapshot(
            &self,
            peer: u64,
            req: InstallSnapshotRequest,
        ) -> Result<InstallSnapshotResponse, TransportError> {
            self.snapshots
                .lock()
                .unwrap()
                .push((std::time::Instant::now(), req.clone()));
            match self.mode {
                SnapMode::Hang => std::future::pending().await,
                SnapMode::Fail => Err(TransportError::Unreachable(peer)),
                SnapMode::Ack => {
                    self.three_has_caught_up.store(true, Ordering::SeqCst);
                    Ok(InstallSnapshotResponse {
                        term: req.term,
                        success: true,
                        match_index: req.last_included_index,
                    })
                }
            }
        }
    }

    /// A leader of {1, 2, 3} that has committed five commands with node 2
    /// and compacted its log, while node 3 has acknowledged nothing.
    async fn leader_that_compacted(
        probe: &Arc<Probe>,
    ) -> (RaftHandle, u64, mpsc::UnboundedReceiver<ApplyItem>) {
        let (node, applied) = spawn_raft_actor_persistent(
            1,
            vec![2, 3],
            probe.clone(),
            Duration::from_millis(20),
            FAST,
            Box::new(MemoryStore::new()),
        )
        .unwrap();
        wait_leader(&node).await;
        let mut last = 0;
        for i in 1..=5 {
            last = node
                .propose_and_wait(format!("c{i}").into_bytes(), Duration::from_secs(10))
                .await
                .unwrap();
        }
        node.compact(last, b"image".to_vec()).await.unwrap();
        (node, last, applied)
    }

    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !cond() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"));
    }

    #[tokio::test]
    async fn a_follower_behind_the_compacted_log_is_sent_the_snapshot_once_at_a_time() {
        let probe = Probe::new(SnapMode::Hang);
        let (node, last, _applied) = leader_that_compacted(&probe).await;
        wait_for("the first snapshot", || probe.snapshot_calls() >= 1).await;
        // Twenty heartbeats later it is still the same single, unanswered send.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(probe.snapshot_calls(), 1);
        let (_, req) = probe.snapshots.lock().unwrap()[0].clone();
        assert_eq!(req.last_included_index, last);
        assert_eq!(req.leader_id, 1);
        assert_eq!(req.data, b"image");
        // Node 2 was never in trouble and the leader still commits with it.
        node.propose_and_wait(b"more".to_vec(), Duration::from_secs(10))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_failed_snapshot_send_is_retried_but_not_at_heartbeat_speed() {
        let probe = Probe::new(SnapMode::Fail);
        let (_node, _last, _applied) = leader_that_compacted(&probe).await;
        wait_for("two snapshot attempts", || probe.snapshot_calls() >= 2).await;
        let calls = probe.snapshots.lock().unwrap();
        let gap = calls[1].0.duration_since(calls[0].0);
        assert!(
            gap >= Duration::from_millis(950),
            "the retry came after only {gap:?}"
        );
    }

    #[tokio::test]
    async fn an_acknowledged_snapshot_puts_the_follower_back_on_ordinary_replication() {
        let probe = Probe::new(SnapMode::Ack);
        let (node, last, _applied) = leader_that_compacted(&probe).await;
        wait_for("replication to resume after the snapshot", || {
            probe
                .appends
                .lock()
                .unwrap()
                .iter()
                .any(|&(peer, prev)| peer == 3 && prev >= last)
                && probe.snapshot_calls() >= 1
        })
        .await;
        assert_eq!(probe.snapshot_calls(), 1, "one snapshot was enough");
        let status = node.snapshot_status().await.unwrap();
        assert_eq!((status.snapshot_index, status.sent), (last, 1));
    }

    #[tokio::test]
    async fn a_node_that_fell_behind_a_compaction_is_caught_up_by_a_snapshot_and_keeps_it_on_disk()
    {
        let ids = [1, 2, 3];
        let stores: HashMap<u64, MemoryStore> =
            ids.iter().map(|&id| (id, MemoryStore::new())).collect();
        let mut cluster = spawn_persistent_cluster(&ids, &stores).await;
        let leader = cluster.wait_for_leader(&ids).await;
        let victim = ids.iter().copied().find(|&i| i != leader).unwrap();
        let others: Vec<u64> = ids.iter().copied().filter(|&i| i != victim).collect();

        cluster.isolate(victim);
        let mut last = 0;
        for i in 1..=10 {
            last = cluster
                .propose_ok(&others, format!("c{i}").as_bytes())
                .await;
        }
        cluster.wait_until_everyone_applied(&others, 10).await;
        // Both reachable nodes compact, so whichever leads afterwards can serve it.
        for &id in &others {
            cluster.handles[&id]
                .compact(last, b"IMAGE".to_vec())
                .await
                .unwrap();
        }
        cluster.propose_ok(&others, b"after-1").await;
        cluster.propose_ok(&others, b"after-2").await;
        cluster.wait_until_everyone_applied(&others, 12).await;

        cluster.heal();
        cluster.wait_until_everyone_applied(&[victim], 2).await;
        let items = kinds(&cluster.items[&victim]);
        assert_eq!(items[0], format!("S{last}:IMAGE"), "{items:?}");
        assert_eq!(
            &items[1..],
            [
                format!("E{}:after-1", last + 1),
                format!("E{}:after-2", last + 2)
            ],
            "{items:?}"
        );
        assert_eq!(
            cluster.seen[&victim],
            cmds(&["after-1", "after-2"]),
            "entries the snapshot covers are never replayed to the state machine"
        );

        let disk = stores[&victim].snapshot();
        assert_eq!(disk.snapshot_index, last);
        assert_eq!(disk.snapshot_data, b"IMAGE");
        assert!(disk.entries.iter().all(|e| e.index > last));
        let status = cluster.handles[&victim].snapshot_status().await.unwrap();
        assert_eq!((status.snapshot_index, status.installed), (last, 1));
    }

    #[tokio::test]
    async fn a_node_caught_up_by_a_snapshot_can_serve_it_to_others_once_it_leads() {
        let probe = Probe::new(SnapMode::Hang);
        let (node, _applied) = spawn_raft_actor_persistent(
            2,
            vec![1, 3],
            probe.clone(),
            Duration::from_millis(20),
            ElectionTimeoutRange {
                min_ms: 300,
                max_ms: 400,
            },
            Box::new(MemoryStore::new()),
        )
        .unwrap();
        assert!(
            node.install_snapshot(snapshot_req(1, 5, b"img"))
                .await
                .success
        );
        wait_for("the new leader to send the snapshot on", || {
            probe.snapshot_calls() >= 1
        })
        .await;
        let (_, req) = probe.snapshots.lock().unwrap()[0].clone();
        assert_eq!(
            (req.leader_id, req.last_included_index, req.data.as_slice()),
            (2, 5, &b"img"[..])
        );
    }

    #[tokio::test]
    async fn a_restarted_leader_serves_the_snapshot_it_loaded_from_disk() {
        let mut store = MemoryStore::new();
        store.load().unwrap();
        let ops: Vec<crate::log::LogOp> = (1..=5)
            .map(|i| {
                crate::log::LogOp::Append(LogEntry {
                    term: 1,
                    index: i,
                    command: vec![i as u8],
                })
            })
            .collect();
        store.apply_log_ops(&ops).unwrap();
        store.save_snapshot(5, 1, b"disk-img").unwrap();
        store.rewrite_log(&[]).unwrap();

        let probe = Probe::new(SnapMode::Hang);
        let (_node, _applied) = spawn_raft_actor_persistent(
            1,
            vec![2, 3],
            probe.clone(),
            Duration::from_millis(20),
            FAST,
            Box::new(store),
        )
        .unwrap();
        wait_for("the leader to send its on-disk snapshot", || {
            probe.snapshot_calls() >= 1
        })
        .await;
        let (_, req) = probe.snapshots.lock().unwrap()[0].clone();
        assert_eq!(
            (req.last_included_index, req.data.as_slice()),
            (5, &b"disk-img"[..])
        );
    }

    #[tokio::test]
    async fn a_leader_that_only_sends_snapshots_still_keeps_its_follower_from_starting_an_election()
    {
        let store = MemoryStore::new();
        let (node, _applied) = spawn_raft_actor_persistent(
            2,
            vec![1, 3],
            Arc::new(DeadNet),
            Duration::from_millis(20),
            FAST,
            Box::new(store),
        )
        .unwrap();
        assert!(
            node.install_snapshot(snapshot_req(1, 5, b"img"))
                .await
                .success
        );
        // Several election timeouts' worth of nothing but snapshot messages
        // (re-sends the node already has): the leader is alive, so no election.
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(40)).await;
            assert!(
                node.install_snapshot(snapshot_req(1, 5, b"img"))
                    .await
                    .success
            );
        }
        let (role, term, _) = node.inspect().await;
        assert_eq!((role, term), (Role::Follower, 1), "it started an election");
    }
}
