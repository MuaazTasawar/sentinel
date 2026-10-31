//! Replication safety under faults, on the deterministic simulator.
//!
//! These drive the same `RaftState` the production actor uses, through
//! partitions, message loss, duplication, reordering, crashes and restarts, and
//! check Raft's safety properties (election safety, log matching, state
//! machine safety, leader completeness) after every step.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sentinel_sim::SimWorld;

const ELECTION_RANGE: (u64, u64) = (50, 100);
const HEARTBEAT_MS: u64 = 20;
const LATENCY_MS: u64 = 5;
const NODES: [u64; 5] = [1, 2, 3, 4, 5];

fn cmd(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn cmds(items: &[&str]) -> Vec<Vec<u8>> {
    items.iter().map(|s| cmd(s)).collect()
}

fn advance(world: &mut SimWorld, ms: u64) {
    let target = world.now().advance(ms);
    world.run_until(target);
}

fn settle(world: &mut SimWorld) {
    advance(world, 8_000);
}

fn world(seed: u64) -> SimWorld {
    SimWorld::new(&NODES, seed, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS)
}

fn assert_everyone_applied(world: &SimWorld, expected: &[Vec<u8>]) {
    for &n in &NODES {
        assert_eq!(world.applied_commands(n), expected, "node {n} must have applied exactly the committed commands, in order");
    }
}

#[test]
fn commands_replicate_to_every_node_in_order_with_no_faults() {
    let mut w = world(1);
    advance(&mut w, 500);
    for c in ["a", "b", "c", "d", "e"] {
        w.propose_to_leader(cmd(c)).expect("a leader should exist");
        advance(&mut w, 100);
    }
    settle(&mut w);
    w.check_all().unwrap();
    assert_eq!(w.committed_commands(), cmds(&["a", "b", "c", "d", "e"]));
    assert_everyone_applied(&w, &cmds(&["a", "b", "c", "d", "e"]));
}

#[test]
fn a_deposed_leaders_uncommitted_write_is_discarded_everywhere() {
    let mut w = world(2);
    advance(&mut w, 600);
    let old_leader = w.current_leaders()[0];
    w.propose(old_leader, cmd("committed-before")).unwrap();
    advance(&mut w, 300);

    // Cut the leader off from everyone. It still believes it leads, so it accepts a write that can never commit.
    for &n in NODES.iter().filter(|&&n| n != old_leader) {
        w.network.partition(old_leader, n);
    }
    w.propose(old_leader, cmd("orphan")).unwrap();
    advance(&mut w, 3_000);

    // The majority elects a new leader and carries on.
    let new_leader = *w.current_leaders().iter().find(|&&l| l != old_leader).expect("majority side should elect a leader");
    w.propose(new_leader, cmd("after-1")).unwrap();
    advance(&mut w, 300);
    w.propose(new_leader, cmd("after-2")).unwrap();
    advance(&mut w, 300);

    w.network.heal_all();
    settle(&mut w);

    w.check_all().unwrap();
    let expected = cmds(&["committed-before", "after-1", "after-2"]);
    assert_eq!(w.committed_commands(), expected, "the orphaned write must never commit");
    assert_everyone_applied(&w, &expected);
    assert!(!w.state_of(old_leader).log.entries_from(0).iter().any(|e| e.command == cmd("orphan")), "and it must be gone from the old leader's log too");
}

#[test]
fn a_node_that_misses_a_lot_catches_up_after_healing() {
    let mut w = world(3);
    advance(&mut w, 600);
    let straggler = *NODES.iter().find(|n| !w.current_leaders().contains(n)).unwrap();
    for &n in NODES.iter().filter(|&&n| n != straggler) {
        w.network.partition(straggler, n);
    }
    for i in 0..30 {
        w.propose_to_leader(cmd(&format!("c{i}"))).expect("the majority side still has a leader");
        advance(&mut w, 40);
    }
    settle(&mut w);
    assert!(w.applied_commands(straggler).is_empty(), "the isolated node must not have applied anything");

    w.network.heal_all();
    settle(&mut w);
    w.check_all().unwrap();
    assert_eq!(w.applied_commands(straggler).len(), 30);
    assert_everyone_applied(&w, &w.committed_commands());
}

#[test]
fn heavy_message_loss_duplication_and_reordering_never_breaks_safety_and_still_makes_progress() {
    let mut w = world(4);
    w.network.loss_percent = 30;
    w.network.duplicate_percent = 25;
    advance(&mut w, 1_500);
    for i in 0..20 {
        w.propose_to_leader(cmd(&format!("lossy-{i}")));
        advance(&mut w, 150);
        w.check_all().unwrap_or_else(|e| panic!("step {i}: {e}"));
    }
    // Faults end; the cluster must converge on one history.
    w.network.loss_percent = 0;
    w.network.duplicate_percent = 0;
    settle(&mut w);
    w.check_all().unwrap();
    assert!(!w.committed_commands().is_empty(), "even at 30% loss some commands must have committed");
    assert_everyone_applied(&w, &w.committed_commands());
}

#[test]
fn restarting_every_node_at_once_loses_no_committed_command() {
    let mut w = world(5);
    advance(&mut w, 600);
    for c in ["one", "two", "three"] {
        w.propose_to_leader(cmd(c)).unwrap();
        advance(&mut w, 200);
    }
    settle(&mut w);
    assert_eq!(w.committed_commands(), cmds(&["one", "two", "three"]));

    // Total power loss: nothing survives except what each node had persisted.
    for &n in &NODES {
        w.crash(n);
    }
    advance(&mut w, 500);
    for &n in &NODES {
        w.restart(n);
    }
    settle(&mut w);

    w.check_all().unwrap();
    assert_eq!(w.committed_commands(), cmds(&["one", "two", "three"]), "nothing committed may be lost or reordered");
    assert_everyone_applied(&w, &cmds(&["one", "two", "three"]));

    // And the cluster keeps working afterwards.
    w.propose_to_leader(cmd("four")).expect("a leader after the restart");
    settle(&mut w);
    assert_everyone_applied(&w, &cmds(&["one", "two", "three", "four"]));
}

#[test]
fn crashing_the_leader_repeatedly_never_loses_acknowledged_commits() {
    let mut w = world(6);
    advance(&mut w, 600);
    let mut expected: Vec<Vec<u8>> = Vec::new();
    for round in 0..6 {
        let c = cmd(&format!("round-{round}"));
        w.propose_to_leader(c.clone()).expect("leader");
        advance(&mut w, 400); // long enough to commit on a healthy majority
        if w.committed_commands().contains(&c) {
            expected.push(c);
        }
        let leader = w.current_leaders()[0];
        w.crash(leader);
        advance(&mut w, 700);
        w.restart(leader);
        advance(&mut w, 300);
        w.check_all().unwrap_or_else(|e| panic!("round {round}: {e}"));
    }
    settle(&mut w);
    w.check_all().unwrap();
    assert!(expected.len() >= 4, "most rounds should have committed before the crash, got {expected:?}");
    let committed = w.committed_commands();
    let mut cursor = 0;
    for c in &expected {
        cursor += committed[cursor..].iter().position(|x| x == c).expect("an acknowledged commit disappeared") + 1;
    }
    assert_everyone_applied(&w, &committed);
}

/// One randomized run: a stream of client commands interleaved with random
/// partitions, heals, crashes, restarts and changes in message loss. Safety is
/// checked after every step; liveness once the faults stop.
fn random_run(seed: u64) -> SimWorld {
    let mut w = world(seed);
    let mut rng = StdRng::seed_from_u64(seed ^ 0xFA17_u64);
    let mut counter = 0u32;
    for step in 0..100 {
        match rng.gen_range(0..11) {
            0..=3 => {
                w.propose_to_leader(cmd(&format!("s{seed}-{counter}")));
                counter += 1;
            }
            4 => {
                let (a, b) = (NODES[rng.gen_range(0..5)], NODES[rng.gen_range(0..5)]);
                if a != b {
                    w.network.partition(a, b);
                }
            }
            5 => w.network.heal_all(),
            6 => {
                let n = NODES[rng.gen_range(0..5)];
                w.crash(n);
            }
            7 | 8 => {
                let n = NODES[rng.gen_range(0..5)];
                w.restart(n);
            }
            9 => {
                w.network.loss_percent = [0, 10, 30][rng.gen_range(0..3)];
                w.network.duplicate_percent = [0, 15][rng.gen_range(0..2)];
            }
            _ => {}
        }
        advance(&mut w, rng.gen_range(10..140));
        w.check_all().unwrap_or_else(|e| panic!("seed {seed}, step {step}: {e}"));
    }

    // Faults stop: heal everything, boot everyone, no loss.
    w.network.heal_all();
    w.network.loss_percent = 0;
    w.network.duplicate_percent = 0;
    for &n in &NODES {
        w.restart(n);
    }
    settle(&mut w);
    w.check_all().unwrap_or_else(|e| panic!("seed {seed}, after recovery: {e}"));

    // Liveness: a healthy cluster commits a fresh command and converges.
    let probe = cmd(&format!("probe-{seed}"));
    w.propose_to_leader(probe.clone()).unwrap_or_else(|| panic!("seed {seed}: no leader after recovery"));
    settle(&mut w);
    w.check_all().unwrap_or_else(|e| panic!("seed {seed}, after probe: {e}"));
    assert!(w.committed_commands().contains(&probe), "seed {seed}: a healthy cluster must commit a new command");
    let committed = w.committed_commands();
    for &n in &NODES {
        assert_eq!(w.applied_commands(n), committed, "seed {seed}: node {n} did not converge on the committed history");
    }
    w
}

#[test]
fn two_hundred_random_fault_schedules_never_violate_safety_and_always_recover() {
    for seed in 0..200 {
        random_run(seed);
    }
}

#[test]
fn the_same_seed_produces_the_identical_history_including_faults() {
    let (a, b) = (random_run(77), random_run(77));
    assert_eq!(a.committed_commands(), b.committed_commands());
    assert_eq!(a.leadership_log, b.leadership_log);
    assert_eq!(a.events_processed, b.events_processed);
    let c = random_run(78);
    assert_ne!(a.events_processed, c.events_processed, "different seeds should explore different schedules");
}