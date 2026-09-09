use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use sentinel_consensus::{
    AppendEntriesRequest, AppendEntriesResponse, RaftState, RequestVoteRequest, RequestVoteResponse, Role,
};

use crate::mock_clock::SimTime;
use crate::mock_network::NetworkConditions;

#[derive(Debug, Clone)]
#[allow(dead_code)] // AppendEntriesResp's fields aren't consumed yet — see the match arm's comment
enum Event {
    ElectionTimeout { node: u64, generation: u64 },
    HeartbeatTick { node: u64 },
    RequestVote { to: u64, from: u64, req: RequestVoteRequest },
    RequestVoteResp { to: u64, from: u64, resp: RequestVoteResponse },
    AppendEntries { to: u64, from: u64, req: AppendEntriesRequest },
    AppendEntriesResp { to: u64, from: u64, resp: AppendEntriesResponse },
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
        other.time.cmp(&self.time).then_with(|| other.seq.cmp(&self.seq))
    }
}

/// A fully deterministic, discrete-event simulation of a Raft cluster.
/// Every node runs the *exact same* `RaftState` type Phase 5/6 unit-test
/// and the real Tokio actor drive — this file only supplies a different
/// (virtual-time, fully controllable) scheduler around it, rather than
/// reimplementing Raft's logic a second time for testing purposes. That
/// matters: a bug fixed here would otherwise risk not being fixed in the
/// real actor, or vice versa, if the two used separate implementations.
pub struct SimWorld {
    nodes: HashMap<u64, RaftState>,
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
    /// Every (time, node, term) a node became leader, in order. The
    /// primary tool tests use to assert Election Safety: Raft's
    /// guarantee that at most one leader can exist for any given term.
    pub leadership_log: Vec<(SimTime, u64, u64)>,
    pub events_processed: u64,
}

impl SimWorld {
    pub fn new(
        node_ids: &[u64],
        seed: u64,
        election_timeout_range: (u64, u64),
        heartbeat_interval_ms: u64,
        base_latency_ms: u64,
    ) -> Self {
        let mut nodes = HashMap::new();
        let mut peers_of = HashMap::new();
        for &id in node_ids {
            nodes.insert(id, RaftState::new(id));
            peers_of.insert(id, node_ids.iter().copied().filter(|&p| p != id).collect());
        }

        let mut world = Self {
            nodes,
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

    /// Gives `node` an artificially skewed starting point for its
    /// election timer — a crude but effective way to model clock skew:
    /// a node whose local clock runs fast or slow will fire its timers
    /// at the "wrong" virtual moment relative to its peers, which is
    /// exactly what this shifts. Intended to be called right after
    /// `new`, before running the simulation.
    pub fn skew_node_clock(&mut self, node: u64, offset_ms: i64) {
        self.election_timer_gen.entry(node).and_modify(|g| *g += 1).or_insert(0);
        let generation = self.election_timer_gen[&node];
        let base = self.random_timeout();
        let skewed = (base as i64 + offset_ms).max(1) as u64;
        self.schedule(self.now.advance(skewed), Event::ElectionTimeout { node, generation });
    }

    fn random_timeout(&mut self) -> u64 {
        self.rng.gen_range(self.election_timeout_range.0..=self.election_timeout_range.1)
    }

    fn schedule(&mut self, time: SimTime, event: Event) {
        self.seq += 1;
        self.queue.push(Scheduled { time, seq: self.seq, event });
    }

    fn reset_election_timer(&mut self, node: u64) {
        let generation = self.election_timer_gen.entry(node).and_modify(|g| *g += 1).or_insert(0);
        let generation = *generation;
        let timeout = self.random_timeout();
        self.schedule(self.now.advance(timeout), Event::ElectionTimeout { node, generation });
    }

    fn schedule_heartbeat(&mut self, node: u64) {
        self.schedule(self.now.advance(self.heartbeat_interval_ms), Event::HeartbeatTick { node });
    }

    /// Sends a message from `from` to `to`. Dropped entirely (never
    /// delivered, at any time) if the pair is currently partitioned —
    /// modeling a real network split rather than a merely slow one.
    /// Otherwise scheduled to arrive after the network's base latency
    /// plus a small random jitter, which is what makes message
    /// reordering happen naturally across a run with many in-flight
    /// messages, the same way it does on a real, imperfect network.
    fn send(&mut self, from: u64, to: u64, build_event: impl FnOnce(u64, u64) -> Event) {
        if self.network.is_partitioned(from, to) {
            return;
        }
        let jitter = self.rng.gen_range(0..=3);
        let deliver_at = self.now.advance(self.network.base_latency_ms + jitter);
        self.schedule(deliver_at, build_event(to, from));
    }

    fn record_leadership(&mut self, node: u64) {
        let term = self.nodes[&node].current_term;
        self.leadership_log.push((self.now, node, term));
    }

    /// Runs the simulation forward until virtual time `end` (or the
    /// event queue empties, if that happens first). Every event popped
    /// is processed in strict (time, schedule-order) order, so two runs
    /// with the same seed and the same sequence of external calls
    /// (partition/heal/skew) always produce byte-identical results —
    /// the entire point of a *deterministic* simulation.
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

    fn process(&mut self, event: Event) {
        match event {
            Event::ElectionTimeout { node, generation } => {
                if self.election_timer_gen.get(&node) != Some(&generation) {
                    return;
                }
                if self.nodes[&node].role == Role::Leader {
                    return;
                }
                let vote_req = self.nodes.get_mut(&node).unwrap().become_candidate();
                self.reset_election_timer(node);

                let peers = self.peers_of[&node].clone();
                if peers.is_empty() {
                    self.nodes.get_mut(&node).unwrap().become_leader();
                    self.record_leadership(node);
                    self.schedule_heartbeat(node);
                    return;
                }
                for peer in peers {
                    let req = vote_req.clone();
                    self.send(node, peer, move |to, from| Event::RequestVote { to, from, req });
                }
            }

            Event::RequestVote { to, from, req } => {
                let resp = self.nodes.get_mut(&to).unwrap().handle_request_vote(req);
                if resp.vote_granted {
                    self.reset_election_timer(to);
                }
                self.send(to, from, move |to2, from2| Event::RequestVoteResp { to: to2, from: from2, resp });
            }

            Event::RequestVoteResp { to, from, resp } => {
                let cluster_size = self.cluster_size;
                let reached_majority = self.nodes.get_mut(&to).unwrap().record_vote(resp, from, cluster_size);
                if reached_majority {
                    self.nodes.get_mut(&to).unwrap().become_leader();
                    self.record_leadership(to);
                    self.schedule_heartbeat(to);
                }
            }

            Event::AppendEntries { to, from, req } => {
                let resp = self.nodes.get_mut(&to).unwrap().handle_append_entries(req);
                if resp.success {
                    self.reset_election_timer(to);
                }
                self.send(to, from, move |to2, from2| Event::AppendEntriesResp { to: to2, from: from2, resp });
            }

            Event::AppendEntriesResp { .. } => {
                // The sim mirrors Phase 7's own documented simplification:
                // the leader doesn't yet track per-follower match_index
                // from these responses. Real replication-progress
                // tracking is future work in both the sim and the actor.
            }

            Event::HeartbeatTick { node } => {
                let state = &self.nodes[&node];
                if state.role != Role::Leader {
                    return;
                }
                let req = AppendEntriesRequest {
                    term: state.current_term,
                    leader_id: state.node_id,
                    prev_log_index: state.log.last_index(),
                    prev_log_term: state.log.last_term(),
                    entries: vec![],
                    leader_commit: state.commit_index,
                };
                for peer in self.peers_of[&node].clone() {
                    let req = req.clone();
                    self.send(node, peer, move |to, from| Event::AppendEntries { to, from, req });
                }
                self.schedule_heartbeat(node);
            }
        }
    }

    /// Raft's Election Safety property: at most one leader per term,
    /// cluster-wide, for the entire run. Returns the offending term and
    /// both node ids on violation.
    pub fn check_election_safety(&self) -> Result<(), String> {
        let mut seen: HashMap<u64, u64> = HashMap::new();
        for &(_, node, term) in &self.leadership_log {
            match seen.get(&term) {
                Some(&existing) if existing != node => {
                    return Err(format!("term {term} had two different leaders: node {existing} and node {node}"));
                }
                _ => {
                    seen.insert(term, node);
                }
            }
        }
        Ok(())
    }

    /// Node ids currently in the `Leader` role, per each node's own
    /// local state (not the historical log) — the "who's in charge right
    /// now" view, as opposed to `check_election_safety`'s "was the
    /// history ever inconsistent" view.
    pub fn current_leaders(&self) -> Vec<u64> {
        self.nodes.iter().filter(|(_, s)| s.role == Role::Leader).map(|(&id, _)| id).collect()
    }
}