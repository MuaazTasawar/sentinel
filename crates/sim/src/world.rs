use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use sentinel_consensus::{
    AppendEntriesRequest, AppendEntriesResponse, ConsensusError, InstallSnapshotRequest,
    InstallSnapshotResponse, LogEntry, PersistedState, RaftState, RequestVoteRequest,
    RequestVoteResponse, Role,
};

use crate::mock_clock::SimTime;
use crate::mock_network::NetworkConditions;

#[derive(Debug, Clone)]
enum Event {
    ElectionTimeout {
        node: u64,
        generation: u64,
    },
    HeartbeatTick {
        node: u64,
    },
    RequestVote {
        to: u64,
        from: u64,
        req: RequestVoteRequest,
    },
    RequestVoteResp {
        to: u64,
        from: u64,
        resp: RequestVoteResponse,
    },
    AppendEntries {
        to: u64,
        from: u64,
        req: AppendEntriesRequest,
    },
    /// Carries a description of the request it answers, exactly as the real
    /// actor does, so late, duplicated and reordered replies are handled the
    /// same way here as in production.
    AppendEntriesResp {
        to: u64,
        from: u64,
        resp: AppendEntriesResponse,
        sent_term: u64,
        sent_prev: u64,
        sent_len: u64,
    },
    InstallSnapshot {
        to: u64,
        from: u64,
        req: InstallSnapshotRequest,
    },
    InstallSnapshotResp {
        to: u64,
        from: u64,
        resp: InstallSnapshotResponse,
        sent_term: u64,
        sent_index: u64,
    },
}

/// A node's durable snapshot: its state machine as of `index`. In the
/// simulator the state machine is the ordered list of entries applied, so the
/// image is simply the first `index` of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotImage {
    pub index: u64,
    pub term: u64,
    pub entries: Vec<LogEntry>,
}

/// A tiny explicit encoding for the snapshot payload that travels in
/// `InstallSnapshot` (the real node serializes its store; the simulator only
/// needs bytes that round-trip exactly).
fn encode_snapshot(entries: &[LogEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend((entries.len() as u64).to_le_bytes());
    for e in entries {
        out.extend(e.term.to_le_bytes());
        out.extend(e.index.to_le_bytes());
        out.extend((e.command.len() as u32).to_le_bytes());
        out.extend(&e.command);
    }
    out
}

fn decode_snapshot(bytes: &[u8]) -> Result<Vec<LogEntry>, String> {
    fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], String> {
        let end = at.checked_add(n).filter(|&e| e <= bytes.len());
        let end = end.ok_or("snapshot payload is truncated")?;
        let slice = &bytes[*at..end];
        *at = end;
        Ok(slice)
    }
    let mut at = 0;
    let count = u64::from_le_bytes(take(bytes, &mut at, 8)?.try_into().unwrap());
    let mut entries = Vec::new();
    for _ in 0..count {
        let term = u64::from_le_bytes(take(bytes, &mut at, 8)?.try_into().unwrap());
        let index = u64::from_le_bytes(take(bytes, &mut at, 8)?.try_into().unwrap());
        let len = u32::from_le_bytes(take(bytes, &mut at, 4)?.try_into().unwrap()) as usize;
        let command = take(bytes, &mut at, len)?.to_vec();
        entries.push(LogEntry {
            term,
            index,
            command,
        });
    }
    if at != bytes.len() {
        return Err("snapshot payload has trailing bytes".into());
    }
    Ok(entries)
}

struct Scheduled {
    time: SimTime,
    seq: u64,
    event: Event,
}

impl PartialEq for Scheduled {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time && self.seq == other.seq
    }
}
impl Eq for Scheduled {}
impl PartialOrd for Scheduled {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Scheduled {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .time
            .cmp(&self.time)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

/// A fully deterministic, discrete-event simulation of a Raft cluster.
///
/// Every node runs the *exact same* `RaftState` the production actor drives:
/// elections, replication (`next_index`/`match_index`), majority commit with
/// the current-term rule, and in-order delivery of committed entries. This
/// file only supplies a different scheduler (virtual time, a network that can
/// partition, lose, duplicate and reorder messages, and nodes that can crash
/// and restart from what they had persisted). Nothing about Raft itself is
/// reimplemented here, so a bug found in the simulator is a bug in the real
/// code, and a fix lands in both at once.
///
/// What it checks, continuously (see [`check_all`](Self::check_all)):
/// * **Election Safety**: at most one leader per term.
/// * **Log Matching**: if two logs agree on an entry they agree on everything before it.
/// * **State Machine Safety**: no two nodes ever apply different commands at the same index.
/// * **Leader Completeness**: every new leader already holds every entry any node has applied.
pub struct SimWorld {
    nodes: BTreeMap<u64, RaftState>,
    up: HashSet<u64>,
    /// What a crashed node had "on disk" when it went down.
    persisted: HashMap<u64, PersistedState>,
    peers_of: HashMap<u64, Vec<u64>>,
    election_timer_gen: HashMap<u64, u64>,
    now: SimTime,
    queue: BinaryHeap<Scheduled>,
    seq: u64,
    rng: StdRng,
    pub network: NetworkConditions,
    election_timeout_range: (u64, u64),
    heartbeat_interval_ms: u64,
    cluster_size: usize,
    /// Every (time, node, term) a node became leader, in order.
    pub leadership_log: Vec<(SimTime, u64, u64)>,
    pub events_processed: u64,
    /// Commands each node has delivered to its state machine since it last started.
    applied: BTreeMap<u64, Vec<LogEntry>>,
    /// The first entry anyone applied at each index. Every later application,
    /// by any node, including replays after a restart, must match it.
    committed: BTreeMap<u64, LogEntry>,
    violations: Vec<String>,
    /// Each node's durable snapshot (survives a crash, like the real snapshot file).
    snapshots: HashMap<u64, SnapshotImage>,
    /// Nodes that will crash in the middle of installing the next snapshot
    /// they are sent: the snapshot reaches disk, the old log is not yet replaced.
    crash_on_next_install: HashSet<u64>,
    pub snapshots_taken: u64,
    pub snapshots_installed: u64,
    /// Nodes that crashed in the middle of installing a snapshot.
    pub install_crashes: u64,
}

impl SimWorld {
    pub fn new(
        node_ids: &[u64],
        seed: u64,
        election_timeout_range: (u64, u64),
        heartbeat_interval_ms: u64,
        base_latency_ms: u64,
    ) -> Self {
        let mut nodes = BTreeMap::new();
        let mut peers_of = HashMap::new();
        for &id in node_ids {
            nodes.insert(id, RaftState::new(id));
            peers_of.insert(id, node_ids.iter().copied().filter(|&p| p != id).collect());
        }

        let mut world = Self {
            nodes,
            up: node_ids.iter().copied().collect(),
            persisted: HashMap::new(),
            peers_of,
            election_timer_gen: HashMap::new(),
            now: SimTime::ZERO,
            queue: BinaryHeap::new(),
            seq: 0,
            rng: StdRng::seed_from_u64(seed),
            network: NetworkConditions::new(base_latency_ms),
            election_timeout_range,
            heartbeat_interval_ms,
            cluster_size: node_ids.len(),
            leadership_log: Vec::new(),
            events_processed: 0,
            applied: node_ids.iter().map(|&id| (id, Vec::new())).collect(),
            committed: BTreeMap::new(),
            violations: Vec::new(),
            snapshots: HashMap::new(),
            crash_on_next_install: HashSet::new(),
            snapshots_taken: 0,
            snapshots_installed: 0,
            install_crashes: 0,
        };
        for &id in node_ids {
            world.reset_election_timer(id);
        }
        world
    }

    pub fn now(&self) -> SimTime {
        self.now
    }

    pub fn state_of(&self, node: u64) -> &RaftState {
        &self.nodes[&node]
    }

    pub fn is_up(&self, node: u64) -> bool {
        self.up.contains(&node)
    }

    /// Gives `node` an artificially skewed starting point for its election
    /// timer: a crude but effective model of clock skew. Intended to be
    /// called right after `new`, before running the simulation.
    pub fn skew_node_clock(&mut self, node: u64, offset_ms: i64) {
        self.election_timer_gen
            .entry(node)
            .and_modify(|g| *g += 1)
            .or_insert(0);
        let generation = self.election_timer_gen[&node];
        let base = self.random_timeout();
        let skewed = (base as i64 + offset_ms).max(1) as u64;
        self.schedule(
            self.now.advance(skewed),
            Event::ElectionTimeout { node, generation },
        );
    }

    fn random_timeout(&mut self) -> u64 {
        self.rng
            .gen_range(self.election_timeout_range.0..=self.election_timeout_range.1)
    }

    fn schedule(&mut self, time: SimTime, event: Event) {
        self.seq += 1;
        self.queue.push(Scheduled {
            time,
            seq: self.seq,
            event,
        });
    }

    fn reset_election_timer(&mut self, node: u64) {
        let generation = self
            .election_timer_gen
            .entry(node)
            .and_modify(|g| *g += 1)
            .or_insert(0);
        let generation = *generation;
        let timeout = self.random_timeout();
        self.schedule(
            self.now.advance(timeout),
            Event::ElectionTimeout { node, generation },
        );
    }

    fn schedule_heartbeat(&mut self, node: u64) {
        self.schedule(
            self.now.advance(self.heartbeat_interval_ms),
            Event::HeartbeatTick { node },
        );
    }

    /// Sends a message. Dropped if the pair is partitioned or the network
    /// loses it; otherwise delivered after the base latency plus random
    /// jitter (which is what makes reordering happen), and possibly twice.
    fn send(&mut self, from: u64, to: u64, event: Event) {
        if self.network.is_partitioned(from, to) {
            return;
        }
        let jitter = self.rng.gen_range(0..=3);
        if self.network.loss_percent > 0
            && self.rng.gen_range(0..100) < self.network.loss_percent as u32
        {
            return;
        }
        let deliver_at = self.now.advance(self.network.base_latency_ms + jitter);
        if self.network.duplicate_percent > 0
            && self.rng.gen_range(0..100) < self.network.duplicate_percent as u32
        {
            let extra = self.rng.gen_range(0..=6);
            self.schedule(
                self.now.advance(self.network.base_latency_ms + extra),
                event.clone(),
            );
        }
        self.schedule(deliver_at, event);
    }

    fn record_leadership(&mut self, node: u64) {
        let term = self.nodes[&node].current_term;
        self.leadership_log.push((self.now, node, term));
    }

    // ------------------------------------------------------------------
    // Faults and client operations
    // ------------------------------------------------------------------

    /// Powers a node off. Whatever it had persisted (term, vote, log) is kept;
    /// everything else is lost, exactly as in the real system.
    pub fn crash(&mut self, node: u64) {
        if !self.up.remove(&node) {
            return;
        }
        let persisted = self.persist_of(node);
        self.persisted.insert(node, persisted);
    }

    /// What is durable for `node` right now: hard state, whatever log it still
    /// holds, and its snapshot. After a crash in the middle of a compaction
    /// the log and the snapshot overlap or disagree; `RaftState::restore`
    /// reconciles them, exactly as the real node does at startup.
    fn persist_of(&self, node: u64) -> PersistedState {
        let state = &self.nodes[&node];
        let (snapshot_index, snapshot_term) = self
            .snapshots
            .get(&node)
            .map(|i| (i.index, i.term))
            .unwrap_or((0, 0));
        PersistedState {
            term: state.current_term,
            voted_for: state.voted_for,
            snapshot_index,
            snapshot_term,
            entries: state.log.entries_from(0),
        }
    }

    /// Boots a crashed node from its persisted state. It comes back as a
    /// follower that knows nothing is committed yet, and replays the log it
    /// learns is committed.
    pub fn restart(&mut self, node: u64) {
        if self.up.contains(&node) {
            return;
        }
        let persisted = self
            .persisted
            .remove(&node)
            .expect("a crashed node always has persisted state");
        let state = RaftState::restore(node, persisted)
            .expect("what a node persisted is always a valid log");
        self.nodes.insert(node, state);
        // The state machine comes back from its snapshot, then replays the
        // log entries it learns are committed.
        let restored = self
            .snapshots
            .get(&node)
            .map(|image| image.entries.clone())
            .unwrap_or_default();
        self.applied.insert(node, restored);
        self.up.insert(node);
        self.reset_election_timer(node);
    }

    /// A client command sent to `node`. Fails unless that node is up and
    /// currently believes it is the leader. Acceptance means "appended to the
    /// leader's log", not "committed".
    pub fn propose(&mut self, node: u64, command: Vec<u8>) -> Result<u64, ConsensusError> {
        if !self.up.contains(&node) {
            return Err(ConsensusError::Stopped);
        }
        let index = self
            .nodes
            .get_mut(&node)
            .unwrap()
            .append_as_leader(command)?;
        for peer in self.peers_of[&node].clone() {
            self.replicate_to(node, peer);
        }
        self.drain_applied(node);
        Ok(index)
    }

    /// Sends a command to whichever up node currently has the highest-term
    /// leader role. `None` if there is no leader right now.
    pub fn propose_to_leader(&mut self, command: Vec<u8>) -> Option<u64> {
        let leader = self
            .nodes
            .iter()
            .filter(|(id, s)| self.up.contains(id) && s.role == Role::Leader)
            .max_by_key(|(_, s)| s.current_term)
            .map(|(&id, _)| id)?;
        self.propose(leader, command).ok()
    }

    // ------------------------------------------------------------------
    // Snapshots
    // ------------------------------------------------------------------

    /// The snapshot `node` would take now: its state machine up to
    /// `last_applied - keep_tail` (so the last `keep_tail` applied entries stay
    /// in the log for slightly-behind followers).
    fn prepare_snapshot(&self, node: u64, keep_tail: u64) -> Result<SnapshotImage, String> {
        if !self.up.contains(&node) {
            return Err(format!("node {node} is down"));
        }
        let state = &self.nodes[&node];
        let upto = state.last_applied.saturating_sub(keep_tail);
        if upto <= state.snapshot_index() {
            return Err(format!(
                "node {node} has nothing new to snapshot (applied {}, snapshot at {})",
                state.last_applied,
                state.snapshot_index()
            ));
        }
        let applied = &self.applied[&node];
        if (applied.len() as u64) < upto {
            return Err(format!("node {node}: state machine model is behind {upto}"));
        }
        Ok(SnapshotImage {
            index: upto,
            term: state.log.term_at(upto),
            entries: applied[..upto as usize].to_vec(),
        })
    }

    /// Takes a snapshot of `node`'s state machine and compacts its log, in the
    /// real order: the snapshot is made durable first, then the log is trimmed.
    /// Returns the index the snapshot covers.
    pub fn snapshot(&mut self, node: u64, keep_tail: u64) -> Result<u64, String> {
        let image = self.prepare_snapshot(node, keep_tail)?;
        let upto = image.index;
        self.snapshots.insert(node, image);
        self.nodes
            .get_mut(&node)
            .unwrap()
            .compact(upto)
            .map_err(|e| e.to_string())?;
        self.snapshots_taken += 1;
        Ok(upto)
    }

    /// The nasty half of a compaction: the snapshot reaches disk, and the node
    /// dies before it trims its log. The restart must cope with a log that
    /// still holds entries the snapshot already covers.
    pub fn snapshot_then_crash(&mut self, node: u64, keep_tail: u64) -> Result<u64, String> {
        let image = self.prepare_snapshot(node, keep_tail)?;
        let upto = image.index;
        self.snapshots.insert(node, image);
        self.snapshots_taken += 1;
        self.crash(node);
        Ok(upto)
    }

    /// Arranges for `node` to crash while installing the next snapshot a
    /// leader sends it: the snapshot reaches disk, but the old log is not yet
    /// replaced, and no acknowledgement is sent.
    pub fn crash_on_next_install(&mut self, node: u64) {
        self.crash_on_next_install.insert(node);
    }

    /// Cancels every pending `crash_on_next_install`. Used when a test's
    /// faults stop, so that a crash armed earlier cannot fire during recovery.
    pub fn disarm_install_crashes(&mut self) {
        self.crash_on_next_install.clear();
    }

    /// Decodes an incoming snapshot and checks it against everything the
    /// cluster has committed. Returns `None` (after recording a violation) if
    /// it is malformed or contradicts a committed entry.
    fn check_incoming_snapshot(
        &mut self,
        to: u64,
        req: &InstallSnapshotRequest,
    ) -> Option<SnapshotImage> {
        let entries = match decode_snapshot(&req.data) {
            Ok(entries) => entries,
            Err(e) => {
                self.violations
                    .push(format!("snapshot to node {to} is malformed: {e}"));
                return None;
            }
        };
        if entries.len() as u64 != req.last_included_index
            || entries.last().map(|e| e.term).unwrap_or(0) != req.last_included_term
        {
            self.violations.push(format!(
                "snapshot to node {to} claims index {} term {} but carries {} entries ending in term {}",
                req.last_included_index,
                req.last_included_term,
                entries.len(),
                entries.last().map(|e| e.term).unwrap_or(0)
            ));
            return None;
        }
        for (pos, entry) in entries.iter().enumerate() {
            if entry.index != pos as u64 + 1 {
                self.violations.push(format!(
                    "snapshot to node {to} is not contiguous at position {pos} (index {})",
                    entry.index
                ));
                return None;
            }
            match self.committed.get(&entry.index) {
                Some(existing) if existing != entry => {
                    self.violations.push(format!(
                        "state machine safety: a snapshot installed on node {to} holds {:?} at index {} but the cluster committed {:?}",
                        String::from_utf8_lossy(&entry.command),
                        entry.index,
                        String::from_utf8_lossy(&existing.command)
                    ));
                    return None;
                }
                Some(_) => {}
                None => {
                    self.committed.insert(entry.index, entry.clone());
                }
            }
        }
        Some(SnapshotImage {
            index: req.last_included_index,
            term: req.last_included_term,
            entries,
        })
    }

    // ------------------------------------------------------------------
    // The event loop
    // ------------------------------------------------------------------

    /// Runs the simulation forward until virtual time `end`. Every event is
    /// processed in strict (time, schedule-order) order, so two runs with the
    /// same seed and the same external calls produce identical results.
    pub fn run_until(&mut self, end: SimTime) {
        while let Some(top) = self.queue.peek() {
            if top.time > end {
                break;
            }
            let Scheduled { time, event, .. } = self.queue.pop().unwrap();
            self.now = time;
            self.events_processed += 1;
            self.process(event);
        }
        if self.now < end {
            self.now = end;
        }
    }

    fn replicate_to(&mut self, leader: u64, peer: u64) {
        if self.nodes[&leader].needs_snapshot(peer) {
            // The entries this peer needs were compacted away.
            let sent = match self.snapshots.get(&leader) {
                Some(image) if image.index == self.nodes[&leader].snapshot_index() => {
                    let data = encode_snapshot(&image.entries);
                    self.nodes[&leader].build_install_snapshot(peer, data)
                }
                _ => {
                    self.violations.push(format!(
                        "snapshot bookkeeping: leader {leader} must send {peer} a snapshot but its stored snapshot does not match its log base"
                    ));
                    None
                }
            };
            if let Some(req) = sent {
                self.send(
                    leader,
                    peer,
                    Event::InstallSnapshot {
                        to: peer,
                        from: leader,
                        req,
                    },
                );
            }
            return;
        }
        let Some(req) = self.nodes[&leader].build_append_entries(peer) else {
            return;
        };
        self.send(
            leader,
            peer,
            Event::AppendEntries {
                to: peer,
                from: leader,
                req,
            },
        );
    }

    /// Hands newly committed entries to the node's state machine and checks
    /// each one against what every other node applied at that index.
    fn drain_applied(&mut self, node: u64) {
        let entries = self.nodes.get_mut(&node).unwrap().take_newly_committed();
        for entry in entries {
            match self.committed.get(&entry.index) {
                Some(existing) if existing != &entry => self.violations.push(format!(
                    "state machine safety: node {node} applied {:?} at index {} but another node applied {:?}",
                    String::from_utf8_lossy(&entry.command),
                    entry.index,
                    String::from_utf8_lossy(&existing.command)
                )),
                Some(_) => {}
                None => {
                    self.committed.insert(entry.index, entry.clone());
                }
            }
            self.applied.get_mut(&node).unwrap().push(entry);
        }
    }

    /// Leader Completeness, checked at the moment of election: a new leader's
    /// log must already contain everything any node has applied.
    fn check_leader_completeness(&mut self, leader: u64) {
        let state = &self.nodes[&leader];
        for (index, entry) in &self.committed {
            // Entries the leader has compacted live in its snapshot instead.
            let held = if *index <= state.log.snapshot_index() {
                self.snapshots
                    .get(&leader)
                    .and_then(|image| image.entries.get(*index as usize - 1))
            } else {
                state.log.get(*index)
            };
            if held != Some(entry) {
                self.violations.push(format!(
                    "leader completeness: node {leader} won term {} without committed entry {index} ({:?})",
                    state.current_term,
                    String::from_utf8_lossy(&entry.command)
                ));
            }
        }
    }

    fn win_election(&mut self, node: u64) {
        let peers = self.peers_of[&node].clone();
        self.check_leader_completeness(node);
        let state = self.nodes.get_mut(&node).unwrap();
        state.become_leader();
        state.on_elected(&peers);
        self.record_leadership(node);
        self.drain_applied(node);
        for peer in peers {
            self.replicate_to(node, peer);
        }
        self.schedule_heartbeat(node);
    }

    fn process(&mut self, event: Event) {
        match event {
            Event::ElectionTimeout { node, generation } => {
                if !self.up.contains(&node)
                    || self.election_timer_gen.get(&node) != Some(&generation)
                {
                    return;
                }
                if self.nodes[&node].role == Role::Leader {
                    return;
                }
                let vote_req = self.nodes.get_mut(&node).unwrap().become_candidate();
                self.reset_election_timer(node);

                let peers = self.peers_of[&node].clone();
                if peers.is_empty() {
                    self.win_election(node);
                    return;
                }
                for peer in peers {
                    let req = vote_req.clone();
                    self.send(
                        node,
                        peer,
                        Event::RequestVote {
                            to: peer,
                            from: node,
                            req,
                        },
                    );
                }
            }

            Event::RequestVote { to, from, req } => {
                if !self.up.contains(&to) {
                    return;
                }
                let term_current_or_newer = req.term >= self.nodes[&to].current_term;
                let resp = self.nodes.get_mut(&to).unwrap().handle_request_vote(req);
                if resp.vote_granted || term_current_or_newer {
                    self.reset_election_timer(to);
                }
                self.send(
                    to,
                    from,
                    Event::RequestVoteResp {
                        to: from,
                        from: to,
                        resp,
                    },
                );
            }

            Event::RequestVoteResp { to, from, resp } => {
                if !self.up.contains(&to) {
                    return;
                }
                let cluster_size = self.cluster_size;
                if self
                    .nodes
                    .get_mut(&to)
                    .unwrap()
                    .record_vote(resp, from, cluster_size)
                {
                    self.win_election(to);
                }
            }

            Event::AppendEntries { to, from, req } => {
                if !self.up.contains(&to) {
                    return;
                }
                let (sent_term, sent_prev, sent_len) =
                    (req.term, req.prev_log_index, req.entries.len() as u64);
                // Contact from a live leader resets the election clock even if
                // the consistency check rejects it (matches the real actor).
                let from_live_leader = req.term >= self.nodes[&to].current_term;
                let resp = self.nodes.get_mut(&to).unwrap().handle_append_entries(req);
                if from_live_leader {
                    self.reset_election_timer(to);
                }
                self.drain_applied(to);
                self.send(
                    to,
                    from,
                    Event::AppendEntriesResp {
                        to: from,
                        from: to,
                        resp,
                        sent_term,
                        sent_prev,
                        sent_len,
                    },
                );
            }

            Event::AppendEntriesResp {
                to,
                from,
                resp,
                sent_term,
                sent_prev,
                sent_len,
            } => {
                if !self.up.contains(&to) {
                    return;
                }
                let was_leader = self.nodes[&to].role == Role::Leader;
                let outcome = self
                    .nodes
                    .get_mut(&to)
                    .unwrap()
                    .handle_append_entries_response(from, sent_term, sent_prev, sent_len, resp);
                if was_leader && self.nodes[&to].role != Role::Leader {
                    self.reset_election_timer(to);
                }
                if outcome.commit_advanced {
                    self.drain_applied(to);
                }
                if outcome.retry_now {
                    self.replicate_to(to, from);
                }
            }

            Event::InstallSnapshot { to, from, req } => {
                if !self.up.contains(&to) {
                    return;
                }
                let (sent_term, sent_index) = (req.term, req.last_included_index);
                let from_live_leader = req.term >= self.nodes[&to].current_term;
                // What is on disk before this message is processed.
                let before = self.persist_of(to);
                let decision = self
                    .nodes
                    .get_mut(&to)
                    .unwrap()
                    .handle_install_snapshot(&req);
                if from_live_leader {
                    self.reset_election_timer(to);
                }
                if decision.install {
                    let Some(image) = self.check_incoming_snapshot(to, &req) else {
                        return;
                    };
                    if self.crash_on_next_install.remove(&to) {
                        // The snapshot was written; the node died before it
                        // replaced its log or acknowledged anything.
                        let state = &self.nodes[&to];
                        let mut persisted = before;
                        persisted.term = state.current_term;
                        persisted.voted_for = state.voted_for;
                        persisted.snapshot_index = image.index;
                        persisted.snapshot_term = image.term;
                        self.snapshots.insert(to, image);
                        self.up.remove(&to);
                        self.persisted.insert(to, persisted);
                        self.install_crashes += 1;
                        return;
                    }
                    self.applied.insert(to, image.entries.clone());
                    self.snapshots.insert(to, image);
                    self.snapshots_installed += 1;
                    self.drain_applied(to);
                }
                self.send(
                    to,
                    from,
                    Event::InstallSnapshotResp {
                        to: from,
                        from: to,
                        resp: decision.response,
                        sent_term,
                        sent_index,
                    },
                );
            }

            Event::InstallSnapshotResp {
                to,
                from,
                resp,
                sent_term,
                sent_index,
            } => {
                if !self.up.contains(&to) {
                    return;
                }
                let was_leader = self.nodes[&to].role == Role::Leader;
                let outcome = self
                    .nodes
                    .get_mut(&to)
                    .unwrap()
                    .handle_install_snapshot_response(from, sent_term, sent_index, resp);
                if was_leader && self.nodes[&to].role != Role::Leader {
                    self.reset_election_timer(to);
                }
                if outcome.commit_advanced {
                    self.drain_applied(to);
                }
                if outcome.retry_now {
                    self.replicate_to(to, from);
                }
            }

            Event::HeartbeatTick { node } => {
                if !self.up.contains(&node) || self.nodes[&node].role != Role::Leader {
                    return;
                }
                for peer in self.peers_of[&node].clone() {
                    self.replicate_to(node, peer);
                }
                self.schedule_heartbeat(node);
            }
        }
    }

    // ------------------------------------------------------------------
    // Observations
    // ------------------------------------------------------------------

    /// Node ids currently up and in the `Leader` role.
    pub fn current_leaders(&self) -> Vec<u64> {
        self.nodes
            .iter()
            .filter(|(id, s)| self.up.contains(id) && s.role == Role::Leader)
            .map(|(&id, _)| id)
            .collect()
    }

    /// The commands a node has delivered to its state machine since it last
    /// started, in order (leader no-ops excluded).
    pub fn applied_commands(&self, node: u64) -> Vec<Vec<u8>> {
        self.applied[&node]
            .iter()
            .filter(|e| !e.is_noop())
            .map(|e| e.command.clone())
            .collect()
    }

    /// Every command any node has applied, in log order (no-ops excluded).
    pub fn committed_commands(&self) -> Vec<Vec<u8>> {
        self.committed
            .values()
            .filter(|e| !e.is_noop())
            .map(|e| e.command.clone())
            .collect()
    }

    /// Invariant violations recorded so far during the run.
    pub fn violations(&self) -> &[String] {
        &self.violations
    }

    /// Test hook: direct mutable access to a node's Raft state. Exists so
    /// tests can deliberately break an invariant and prove the checkers
    /// notice. Nothing in the simulator itself uses it.
    pub fn state_mut_for_tests(&mut self, node: u64) -> &mut RaftState {
        self.nodes.get_mut(&node).unwrap()
    }

    /// Test hook: applies `node`'s newly committed entries through the same
    /// checks the event loop uses.
    pub fn drain_applied_for_tests(&mut self, node: u64) {
        self.drain_applied(node);
    }

    /// Test hook: the first `n` entries the cluster committed, in order.
    pub fn committed_prefix_for_tests(&self, n: u64) -> Vec<LogEntry> {
        (1..=n).map(|i| self.committed[&i].clone()).collect()
    }

    /// Raft's Election Safety property: at most one leader per term,
    /// cluster-wide, for the entire run.
    pub fn check_election_safety(&self) -> Result<(), String> {
        let mut seen: HashMap<u64, u64> = HashMap::new();
        for &(_, node, term) in &self.leadership_log {
            match seen.get(&term) {
                Some(&existing) if existing != node => {
                    return Err(format!(
                        "term {term} had two different leaders: node {existing} and node {node}"
                    ));
                }
                _ => {
                    seen.insert(term, node);
                }
            }
        }
        Ok(())
    }

    /// Log Matching: for every pair of nodes, once their logs differ at some
    /// index they must never agree again at a later one; and an index+term
    /// pair always identifies one command.
    pub fn check_log_matching(&self) -> Result<(), String> {
        let ids: Vec<u64> = self.nodes.keys().copied().collect();
        for (i, &a) in ids.iter().enumerate() {
            for &b in &ids[i + 1..] {
                let (la, lb) = (&self.nodes[&a].log, &self.nodes[&b].log);
                let shared = la.last_index().min(lb.last_index());
                let mut diverged_at: Option<u64> = None;
                // Compacted entries can no longer be compared here; they are
                // covered by the snapshot checks.
                let lowest = la.first_index().max(lb.first_index());
                for idx in lowest..=shared {
                    let (ea, eb) = (la.get(idx).unwrap(), lb.get(idx).unwrap());
                    if ea.term == eb.term && ea.command != eb.command {
                        return Err(format!(
                            "log matching: nodes {a} and {b} hold different commands at index {idx} in the same term {}",
                            ea.term
                        ));
                    }
                    if ea == eb {
                        if let Some(d) = diverged_at {
                            return Err(format!(
                                "log matching: nodes {a} and {b} differ at index {d} yet agree again at index {idx}"
                            ));
                        }
                    } else if diverged_at.is_none() {
                        diverged_at = Some(idx);
                    }
                }
            }
        }
        Ok(())
    }

    /// State Machine Safety plus basic bookkeeping sanity.
    pub fn check_state_machine_safety(&self) -> Result<(), String> {
        if let Some(v) = self.violations.first() {
            return Err(v.clone());
        }
        for (&node, state) in &self.nodes {
            if state.commit_index > state.log.last_index() {
                return Err(format!(
                    "node {node}: commit_index {} is beyond its log ({})",
                    state.commit_index,
                    state.log.last_index()
                ));
            }
            if state.last_applied > state.commit_index {
                return Err(format!(
                    "node {node}: applied {} but only {} committed",
                    state.last_applied, state.commit_index
                ));
            }
            for (pos, entry) in self.applied[&node].iter().enumerate() {
                if entry.index != pos as u64 + 1 {
                    return Err(format!(
                        "node {node}: applied entries are not contiguous at position {pos} (index {})",
                        entry.index
                    ));
                }
            }
        }
        Ok(())
    }

    /// Snapshot consistency: every stored snapshot holds exactly the entries
    /// the cluster committed, is well formed, and agrees with the node's log.
    pub fn check_snapshot_consistency(&self) -> Result<(), String> {
        // A node's state machine has applied exactly what Raft says it has: no
        // more, no fewer. (A snapshot install replaces the state machine and
        // must move Raft's applied index with it.)
        let mut up: Vec<u64> = self.up.iter().copied().collect();
        up.sort_unstable();
        for node in up {
            let held = self.applied[&node].len() as u64;
            let applied = self.nodes[&node].last_applied;
            if held != applied {
                return Err(format!(
                    "node {node}: its state machine holds {held} entries but Raft says {applied} are applied"
                ));
            }
        }
        for (&node, image) in &self.snapshots {
            if image.entries.len() as u64 != image.index {
                return Err(format!(
                    "snapshot of node {node} claims index {} but holds {} entries",
                    image.index,
                    image.entries.len()
                ));
            }
            for (pos, entry) in image.entries.iter().enumerate() {
                if entry.index != pos as u64 + 1 {
                    return Err(format!(
                        "snapshot of node {node} is not contiguous at position {pos} (index {})",
                        entry.index
                    ));
                }
                match self.committed.get(&entry.index) {
                    Some(c) if c == entry => {}
                    Some(c) => {
                        return Err(format!(
                            "snapshot of node {node} holds {:?} at index {} but the cluster committed {:?}",
                            String::from_utf8_lossy(&entry.command),
                            entry.index,
                            String::from_utf8_lossy(&c.command)
                        ));
                    }
                    None => {
                        return Err(format!(
                            "snapshot of node {node} holds index {}, which the cluster never committed",
                            entry.index
                        ));
                    }
                }
            }
            if image.entries.last().map(|e| e.term).unwrap_or(0) != image.term {
                return Err(format!(
                    "snapshot of node {node}: recorded term {} is not the term of its last entry",
                    image.term
                ));
            }
            if self.up.contains(&node) {
                let state = &self.nodes[&node];
                if state.log.snapshot_index() != image.index {
                    return Err(format!(
                        "node {node}: its log is compacted to {} but its snapshot covers {}",
                        state.log.snapshot_index(),
                        image.index
                    ));
                }
                if state.last_applied < image.index {
                    return Err(format!(
                        "node {node}: applied {} which is behind its own snapshot ({})",
                        state.last_applied, image.index
                    ));
                }
            }
        }
        for (&node, state) in &self.nodes {
            if self.up.contains(&node)
                && state.log.snapshot_index() > 0
                && !self.snapshots.contains_key(&node)
            {
                return Err(format!(
                    "node {node}: its log is compacted to {} but it has no snapshot",
                    state.log.snapshot_index()
                ));
            }
        }
        Ok(())
    }

    /// The snapshot `node` holds, if any.
    pub fn snapshot_image(&self, node: u64) -> Option<&SnapshotImage> {
        self.snapshots.get(&node)
    }

    /// How many log entries `node` still holds (compacted ones do not count).
    pub fn retained_log_entries(&self, node: u64) -> usize {
        let log = &self.nodes[&node].log;
        (log.last_index() - log.snapshot_index()) as usize
    }

    /// The index `node`'s log has been compacted up to (0 if never).
    pub fn log_base(&self, node: u64) -> u64 {
        self.nodes[&node].log.snapshot_index()
    }

    /// Every safety property at once.
    pub fn check_all(&self) -> Result<(), String> {
        self.check_election_safety()?;
        self.check_log_matching()?;
        self.check_state_machine_safety()?;
        self.check_snapshot_consistency()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(term: u64, index: u64, cmd: &str) -> LogEntry {
        LogEntry {
            term,
            index,
            command: cmd.as_bytes().to_vec(),
        }
    }

    fn quiet_world() -> SimWorld {
        SimWorld::new(&[1, 2, 3], 1, (50, 100), 20, 5)
    }

    // These tests prove the checkers can FAIL. A safety checker that has never
    // been shown to catch a violation proves nothing when it stays silent.

    #[test]
    fn a_healthy_world_passes_every_check() {
        let mut w = quiet_world();
        w.run_until(SimTime(1000));
        assert!(w.check_all().is_ok());
    }

    #[test]
    fn log_matching_catches_two_commands_at_the_same_index_and_term() {
        let mut w = quiet_world();
        w.state_mut_for_tests(1)
            .log
            .append_new(1, b"alpha".to_vec());
        w.state_mut_for_tests(2).log.append_new(1, b"beta".to_vec());
        let err = w.check_log_matching().unwrap_err();
        assert!(err.contains("different commands at index 1"), "{err}");
    }

    #[test]
    fn log_matching_catches_logs_that_diverge_and_then_agree_again() {
        let mut w = quiet_world();
        for (node, cmd) in [(1u64, "a"), (2, "b")] {
            w.state_mut_for_tests(node)
                .log
                .append_new(1, cmd.as_bytes().to_vec()); // index 1 differs (same term -> caught first)
        }
        // Make index 1 differ by TERM instead, then give both an identical index 2.
        let mut w = quiet_world();
        w.state_mut_for_tests(1).log.append_new(1, b"a".to_vec());
        w.state_mut_for_tests(2).log.append_new(2, b"a".to_vec());
        w.state_mut_for_tests(1).log.append_new(3, b"same".to_vec());
        w.state_mut_for_tests(2).log.append_new(3, b"same".to_vec());
        let err = w.check_log_matching().unwrap_err();
        assert!(err.contains("agree again"), "{err}");
    }

    #[test]
    fn state_machine_safety_catches_two_nodes_applying_different_commands() {
        let mut w = quiet_world();
        for (node, cmd) in [(1u64, "alpha"), (2, "beta")] {
            let s = w.state_mut_for_tests(node);
            s.log.append_new(1, cmd.as_bytes().to_vec());
            s.commit_index = 1;
            w.drain_applied_for_tests(node);
        }
        let err = w.check_state_machine_safety().unwrap_err();
        assert!(
            err.contains("state machine safety") && err.contains("index 1"),
            "{err}"
        );
        assert!(w.check_all().is_err());
    }

    #[test]
    fn bookkeeping_checks_catch_a_commit_index_beyond_the_log() {
        let mut w = quiet_world();
        w.state_mut_for_tests(1).commit_index = 5;
        assert!(
            w.check_state_machine_safety()
                .unwrap_err()
                .contains("beyond its log")
        );
    }

    #[test]
    fn leader_completeness_catches_a_new_leader_that_lacks_a_committed_entry() {
        let mut w = quiet_world();
        // Pretend entry 1 was committed and applied somewhere.
        w.committed.insert(1, entry(1, 1, "precious"));
        // Node 3's log does not have it, and node 3 then "wins".
        w.check_leader_completeness(3);
        assert!(
            w.violations()[0].contains("leader completeness"),
            "{:?}",
            w.violations()
        );
        assert!(w.check_state_machine_safety().is_err());
    }

    #[test]
    fn election_safety_catches_two_leaders_in_one_term() {
        let mut w = quiet_world();
        w.leadership_log.push((SimTime(1), 1, 4));
        w.leadership_log.push((SimTime(2), 2, 4));
        assert!(w.check_election_safety().unwrap_err().contains("term 4"));
    }

    #[test]
    fn a_crashed_node_comes_back_with_its_persisted_term_vote_and_log() {
        let mut w = SimWorld::new(&[1, 2, 3], 5, (50, 100), 20, 5);
        w.run_until(SimTime(600));
        let leader = w.current_leaders()[0];
        w.propose(leader, b"x".to_vec()).unwrap();
        w.run_until(SimTime(900));
        let victim = [1u64, 2, 3].into_iter().find(|&n| n != leader).unwrap();
        let (term, last) = (
            w.state_of(victim).current_term,
            w.state_of(victim).log.last_index(),
        );
        assert!(
            last >= 2,
            "the follower should have replicated the no-op and the command"
        );

        w.crash(victim);
        assert!(!w.is_up(victim));
        w.restart(victim);
        assert!(w.is_up(victim));
        assert_eq!(w.state_of(victim).current_term, term);
        assert_eq!(w.state_of(victim).log.last_index(), last);
        assert_eq!(
            w.state_of(victim).commit_index,
            0,
            "commit knowledge is volatile and relearned"
        );
    }

    #[test]
    fn a_proposal_to_a_follower_or_a_dead_node_is_refused() {
        let mut w = quiet_world();
        assert!(matches!(
            w.propose(1, b"x".to_vec()),
            Err(ConsensusError::NotLeader)
        ));
        w.crash(2);
        assert!(matches!(
            w.propose(2, b"x".to_vec()),
            Err(ConsensusError::Stopped)
        ));
    }

    // ---- snapshot checkers ------------------------------------------------

    /// A 3-node world with `n` commands committed and applied everywhere.
    fn world_with_commits(n: usize) -> SimWorld {
        let mut w = quiet_world();
        w.run_until(SimTime(600));
        for i in 0..n {
            w.propose_to_leader(format!("cmd{i}").into_bytes())
                .expect("a leader exists");
            let t = w.now().advance(100);
            w.run_until(t);
        }
        let t = w.now().advance(1_500);
        w.run_until(t);
        assert!(w.check_all().is_ok(), "{:?}", w.check_all());
        w
    }

    #[test]
    fn a_healthy_snapshot_passes_every_check_including_the_leaders_compacted_entries() {
        let mut w = world_with_commits(6);
        let leader = w.current_leaders()[0];
        let upto = w.snapshot(leader, 1).unwrap();
        assert!(upto > 1);
        assert_eq!(w.log_base(leader), upto);
        assert!(w.check_all().is_ok());

        // The leader no longer holds entries 1..=upto in its log, but they
        // live in its snapshot, so winning an election with them is fine.
        w.check_leader_completeness(leader);
        assert!(w.violations().is_empty(), "{:?}", w.violations());
    }

    #[test]
    fn snapshot_consistency_catches_a_snapshot_that_disagrees_with_what_was_committed() {
        let mut w = world_with_commits(6);
        w.snapshot(2, 1).unwrap();
        w.snapshots.get_mut(&2).unwrap().entries[0].command = b"forged".to_vec();
        let err = w.check_snapshot_consistency().unwrap_err();
        assert!(err.contains("committed") && err.contains("forged"), "{err}");
        assert!(w.check_all().is_err());
    }

    #[test]
    fn snapshot_consistency_catches_a_state_machine_that_disagrees_with_rafts_applied_index() {
        let mut w = world_with_commits(6);
        assert!(w.check_snapshot_consistency().is_ok());
        w.state_mut_for_tests(1).last_applied -= 1;
        let err = w.check_snapshot_consistency().unwrap_err();
        assert!(err.contains("state machine holds"), "{err}");
    }

    #[test]
    fn snapshot_consistency_catches_a_wrong_length_or_term() {
        let mut w = world_with_commits(6);
        w.snapshot(2, 1).unwrap();
        w.snapshots.get_mut(&2).unwrap().index += 1;
        assert!(
            w.check_snapshot_consistency()
                .unwrap_err()
                .contains("claims index")
        );
        w.snapshots.get_mut(&2).unwrap().index -= 1;
        w.snapshots.get_mut(&2).unwrap().term += 1;
        assert!(
            w.check_snapshot_consistency()
                .unwrap_err()
                .contains("recorded term")
        );
    }

    #[test]
    fn snapshot_consistency_catches_a_log_that_is_not_compacted_to_its_snapshot() {
        let mut w = world_with_commits(6);
        let upto = w.snapshot(2, 1).unwrap();

        // A snapshot one entry shorter than the log's base is well formed on
        // its own, but the node's log says otherwise.
        let image = w.snapshots.get_mut(&2).unwrap();
        image.entries.pop();
        image.index = upto - 1;
        image.term = image.entries.last().unwrap().term;
        let err = w.check_snapshot_consistency().unwrap_err();
        assert!(err.contains("log is compacted to"), "{err}");

        // And a compacted log with no snapshot at all.
        w.snapshots.remove(&2);
        assert!(
            w.check_snapshot_consistency()
                .unwrap_err()
                .contains("no snapshot")
        );
    }

    #[test]
    fn leader_completeness_catches_a_leader_whose_snapshot_lacks_a_committed_entry() {
        let mut w = world_with_commits(6);
        let leader = w.current_leaders()[0];
        w.snapshot(leader, 1).unwrap();
        w.snapshots.get_mut(&leader).unwrap().entries[0].command = b"forged".to_vec();
        w.check_leader_completeness(leader);
        assert!(
            w.violations()
                .iter()
                .any(|v| v.contains("leader completeness")),
            "{:?}",
            w.violations()
        );
    }

    #[test]
    fn an_incoming_snapshot_that_contradicts_a_committed_entry_is_refused_and_recorded() {
        let mut w = world_with_commits(4);
        let mut entries = w.committed_prefix_for_tests(3);
        entries[0].command = b"forged".to_vec();
        let last_term = entries.last().unwrap().term;
        let req = InstallSnapshotRequest {
            term: 1,
            leader_id: 1,
            last_included_index: 3,
            last_included_term: last_term,
            data: encode_snapshot(&entries),
        };
        assert!(w.check_incoming_snapshot(2, &req).is_none());
        assert!(
            w.violations()
                .iter()
                .any(|v| v.contains("state machine safety") && v.contains("forged")),
            "{:?}",
            w.violations()
        );
    }

    #[test]
    fn a_malformed_or_misdescribed_incoming_snapshot_is_refused_and_recorded() {
        let mut w = world_with_commits(4);
        let entries = w.committed_prefix_for_tests(3);
        let garbage = InstallSnapshotRequest {
            term: 1,
            leader_id: 1,
            last_included_index: 3,
            last_included_term: 1,
            data: vec![1, 2, 3],
        };
        assert!(w.check_incoming_snapshot(2, &garbage).is_none());
        assert!(w.violations().last().unwrap().contains("malformed"));

        // The request claims index 5 but carries 3 entries.
        let lying = InstallSnapshotRequest {
            last_included_index: 5,
            last_included_term: entries.last().unwrap().term,
            data: encode_snapshot(&entries),
            ..garbage
        };
        assert!(w.check_incoming_snapshot(2, &lying).is_none());
        assert!(w.violations().last().unwrap().contains("claims index 5"));
    }

    #[test]
    fn the_snapshot_encoding_round_trips_and_rejects_damage() {
        let entries = vec![entry(1, 1, "a"), entry(2, 2, ""), entry(2, 3, "ccc")];
        let bytes = encode_snapshot(&entries);
        assert_eq!(decode_snapshot(&bytes).unwrap(), entries);
        assert_eq!(decode_snapshot(&encode_snapshot(&[])).unwrap(), vec![]);
        assert!(decode_snapshot(&bytes[..bytes.len() - 1]).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_snapshot(&trailing).is_err());
        assert!(decode_snapshot(&[]).is_err());
    }

    #[test]
    fn a_crash_between_writing_a_snapshot_and_trimming_the_log_restarts_with_the_snapshot_in_charge()
     {
        let mut w = world_with_commits(8);
        let victim = [1u64, 2, 3]
            .into_iter()
            .find(|n| !w.current_leaders().contains(n))
            .unwrap();
        let before_applied = w.applied_commands(victim);
        let upto = w.snapshot_then_crash(victim, 2).unwrap();
        w.restart(victim);

        // The log was never trimmed before the crash; the restart trims it.
        assert_eq!(w.log_base(victim), upto);
        assert_eq!(
            w.applied_commands(victim).len() as u64,
            upto - 1,
            "the state machine is restored from the snapshot (no-ops are not counted)"
        );
        let t = w.now().advance(1_500);
        w.run_until(t);
        assert!(w.check_all().is_ok(), "{:?}", w.check_all());
        assert_eq!(w.applied_commands(victim), before_applied);
    }
}
