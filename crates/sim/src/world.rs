use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use sentinel_consensus::{
    AppendEntriesRequest, AppendEntriesResponse, ConsensusError, LogEntry, PersistedState, RaftState,
    RequestVoteRequest, RequestVoteResponse, Role,
};

use crate::mock_clock::SimTime;
use crate::mock_network::NetworkConditions;

#[derive(Debug, Clone)]
enum Event {
    ElectionTimeout { node: u64, generation: u64 },
    HeartbeatTick { node: u64 },
    RequestVote { to: u64, from: u64, req: RequestVoteRequest },
    RequestVoteResp { to: u64, from: u64, resp: RequestVoteResponse },
    AppendEntries { to: u64, from: u64, req: AppendEntriesRequest },
    /// Carries a description of the request it answers, exactly as the real
    /// actor does, so late, duplicated and reordered replies are handled the
    /// same way here as in production.
    AppendEntriesResp { to: u64, from: u64, resp: AppendEntriesResponse, sent_term: u64, sent_prev: u64, sent_len: u64 },
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

    /// Sends a message. Dropped if the pair is partitioned or the network
    /// loses it; otherwise delivered after the base latency plus random
    /// jitter (which is what makes reordering happen), and possibly twice.
    fn send(&mut self, from: u64, to: u64, event: Event) {
        if self.network.is_partitioned(from, to) {
            return;
        }
        let jitter = self.rng.gen_range(0..=3);
        if self.network.loss_percent > 0 && self.rng.gen_range(0..100) < self.network.loss_percent as u32 {
            return;
        }
        let deliver_at = self.now.advance(self.network.base_latency_ms + jitter);
        if self.network.duplicate_percent > 0 && self.rng.gen_range(0..100) < self.network.duplicate_percent as u32 {
            let extra = self.rng.gen_range(0..=6);
            self.schedule(self.now.advance(self.network.base_latency_ms + extra), event.clone());
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
        let state = &self.nodes[&node];
        self.persisted.insert(
            node,
            PersistedState { term: state.current_term, voted_for: state.voted_for, entries: state.log.entries_from(0) },
        );
    }

    /// Boots a crashed node from its persisted state. It comes back as a
    /// follower that knows nothing is committed yet, and replays the log it
    /// learns is committed.
    pub fn restart(&mut self, node: u64) {
        if self.up.contains(&node) {
            return;
        }
        let persisted = self.persisted.remove(&node).expect("a crashed node always has persisted state");
        let state = RaftState::restore(node, persisted).expect("what a node persisted is always a valid log");
        self.nodes.insert(node, state);
        self.applied.insert(node, Vec::new());
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
        let index = self.nodes.get_mut(&node).unwrap().append_as_leader(command)?;
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
        let Some(req) = self.nodes[&leader].build_append_entries(peer) else { return };
        self.send(leader, peer, Event::AppendEntries { to: peer, from: leader, req });
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
            if state.log.get(*index) != Some(entry) {
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
                if !self.up.contains(&node) || self.election_timer_gen.get(&node) != Some(&generation) {
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
                    self.send(node, peer, Event::RequestVote { to: peer, from: node, req });
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
                self.send(to, from, Event::RequestVoteResp { to: from, from: to, resp });
            }

            Event::RequestVoteResp { to, from, resp } => {
                if !self.up.contains(&to) {
                    return;
                }
                let cluster_size = self.cluster_size;
                if self.nodes.get_mut(&to).unwrap().record_vote(resp, from, cluster_size) {
                    self.win_election(to);
                }
            }

            Event::AppendEntries { to, from, req } => {
                if !self.up.contains(&to) {
                    return;
                }
                let (sent_term, sent_prev, sent_len) = (req.term, req.prev_log_index, req.entries.len() as u64);
                // Contact from a live leader resets the election clock even if
                // the consistency check rejects it (matches the real actor).
                let from_live_leader = req.term >= self.nodes[&to].current_term;
                let resp = self.nodes.get_mut(&to).unwrap().handle_append_entries(req);
                if from_live_leader {
                    self.reset_election_timer(to);
                }
                self.drain_applied(to);
                self.send(to, from, Event::AppendEntriesResp { to: from, from: to, resp, sent_term, sent_prev, sent_len });
            }

            Event::AppendEntriesResp { to, from, resp, sent_term, sent_prev, sent_len } => {
                if !self.up.contains(&to) {
                    return;
                }
                let was_leader = self.nodes[&to].role == Role::Leader;
                let outcome =
                    self.nodes.get_mut(&to).unwrap().handle_append_entries_response(from, sent_term, sent_prev, sent_len, resp);
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
        self.nodes.iter().filter(|(id, s)| self.up.contains(id) && s.role == Role::Leader).map(|(&id, _)| id).collect()
    }

    /// The commands a node has delivered to its state machine since it last
    /// started, in order (leader no-ops excluded).
    pub fn applied_commands(&self, node: u64) -> Vec<Vec<u8>> {
        self.applied[&node].iter().filter(|e| !e.is_noop()).map(|e| e.command.clone()).collect()
    }

    /// Every command any node has applied, in log order (no-ops excluded).
    pub fn committed_commands(&self) -> Vec<Vec<u8>> {
        self.committed.values().filter(|e| !e.is_noop()).map(|e| e.command.clone()).collect()
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

    /// Raft's Election Safety property: at most one leader per term,
    /// cluster-wide, for the entire run.
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
                for idx in 1..=shared {
                    let (ea, eb) = (la.get(idx).unwrap(), lb.get(idx).unwrap());
                    if ea.term == eb.term && ea.command != eb.command {
                        return Err(format!("log matching: nodes {a} and {b} hold different commands at index {idx} in the same term {}", ea.term));
                    }
                    if ea == eb {
                        if let Some(d) = diverged_at {
                            return Err(format!("log matching: nodes {a} and {b} differ at index {d} yet agree again at index {idx}"));
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
                return Err(format!("node {node}: commit_index {} is beyond its log ({})", state.commit_index, state.log.last_index()));
            }
            if state.last_applied > state.commit_index {
                return Err(format!("node {node}: applied {} but only {} committed", state.last_applied, state.commit_index));
            }
            for (pos, entry) in self.applied[&node].iter().enumerate() {
                if entry.index != pos as u64 + 1 {
                    return Err(format!("node {node}: applied entries are not contiguous at position {pos} (index {})", entry.index));
                }
            }
        }
        Ok(())
    }

    /// Every safety property at once.
    pub fn check_all(&self) -> Result<(), String> {
        self.check_election_safety()?;
        self.check_log_matching()?;
        self.check_state_machine_safety()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(term: u64, index: u64, cmd: &str) -> LogEntry {
        LogEntry { term, index, command: cmd.as_bytes().to_vec() }
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
        w.state_mut_for_tests(1).log.append_new(1, b"alpha".to_vec());
        w.state_mut_for_tests(2).log.append_new(1, b"beta".to_vec());
        let err = w.check_log_matching().unwrap_err();
        assert!(err.contains("different commands at index 1"), "{err}");
    }

    #[test]
    fn log_matching_catches_logs_that_diverge_and_then_agree_again() {
        let mut w = quiet_world();
        for (node, cmd) in [(1u64, "a"), (2, "b")] {
            w.state_mut_for_tests(node).log.append_new(1, cmd.as_bytes().to_vec()); // index 1 differs (same term -> caught first)
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
        assert!(err.contains("state machine safety") && err.contains("index 1"), "{err}");
        assert!(w.check_all().is_err());
    }

    #[test]
    fn bookkeeping_checks_catch_a_commit_index_beyond_the_log() {
        let mut w = quiet_world();
        w.state_mut_for_tests(1).commit_index = 5;
        assert!(w.check_state_machine_safety().unwrap_err().contains("beyond its log"));
    }

    #[test]
    fn leader_completeness_catches_a_new_leader_that_lacks_a_committed_entry() {
        let mut w = quiet_world();
        // Pretend entry 1 was committed and applied somewhere.
        w.committed.insert(1, entry(1, 1, "precious"));
        // Node 3's log does not have it, and node 3 then "wins".
        w.check_leader_completeness(3);
        assert!(w.violations()[0].contains("leader completeness"), "{:?}", w.violations());
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
        let (term, last) = (w.state_of(victim).current_term, w.state_of(victim).log.last_index());
        assert!(last >= 2, "the follower should have replicated the no-op and the command");

        w.crash(victim);
        assert!(!w.is_up(victim));
        w.restart(victim);
        assert!(w.is_up(victim));
        assert_eq!(w.state_of(victim).current_term, term);
        assert_eq!(w.state_of(victim).log.last_index(), last);
        assert_eq!(w.state_of(victim).commit_index, 0, "commit knowledge is volatile and relearned");
    }

    #[test]
    fn a_proposal_to_a_follower_or_a_dead_node_is_refused() {
        let mut w = quiet_world();
        assert!(matches!(w.propose(1, b"x".to_vec()), Err(ConsensusError::NotLeader)));
        w.crash(2);
        assert!(matches!(w.propose(2, b"x".to_vec()), Err(ConsensusError::Stopped)));
    }
}