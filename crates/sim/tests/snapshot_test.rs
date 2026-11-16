//! Log compaction and snapshot installation, on the deterministic simulator.
//!
//! The simulator drives the same `RaftState` the production actor uses. Here
//! it adds snapshots: nodes take them and trim their logs, followers that fall
//! behind the compacted prefix are caught up by `InstallSnapshot`, and nodes
//! crash at the two dangerous moments (a snapshot written but the log not yet
//! trimmed; a snapshot installed but the old log not yet replaced). All of
//! Raft's safety properties, plus snapshot consistency, are checked after
//! every step.

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

/// Proposes `count` commands named `{tag}{i}`, letting each commit.
fn propose_many(w: &mut SimWorld, tag: &str, count: usize) -> Vec<Vec<u8>> {
    let mut proposed = Vec::new();
    for i in 0..count {
        let c = cmd(&format!("{tag}{i}"));
        w.propose_to_leader(c.clone())
            .expect("a leader should exist");
        proposed.push(c);
        advance(w, 60);
    }
    proposed
}

/// Snapshots every up node, keeping `keep_tail` entries; "nothing new to
/// snapshot" is fine.
fn snapshot_everyone(w: &mut SimWorld, keep_tail: u64) {
    for &n in &NODES {
        let _ = w.snapshot(n, keep_tail);
    }
}

fn assert_everyone_applied(w: &SimWorld, expected: &[Vec<u8>]) {
    for &n in &NODES {
        assert_eq!(
            w.applied_commands(n),
            expected,
            "node {n} must have applied exactly the committed commands, in order"
        );
    }
}

#[test]
fn snapshots_do_not_change_what_the_cluster_commits_or_applies() {
    let mut w = world(1);
    advance(&mut w, 600);
    let mut expected = Vec::new();
    for round in 0..6 {
        expected.extend(propose_many(&mut w, &format!("r{round}-"), 5));
        advance(&mut w, 300);
        snapshot_everyone(&mut w, 2);
        w.check_all()
            .unwrap_or_else(|e| panic!("round {round}: {e}"));
    }
    settle(&mut w);
    w.check_all().unwrap();

    assert_eq!(w.committed_commands(), expected);
    assert_everyone_applied(&w, &expected);
    assert!(w.snapshots_taken >= 10, "snapshots were really taken");
    for &n in &NODES {
        assert!(w.log_base(n) > 0, "node {n} compacted its log");
        assert!(
            w.retained_log_entries(n) <= 8,
            "node {n} keeps only a short tail, not all {} entries",
            expected.len()
        );
    }
}

#[test]
fn a_follower_that_missed_compacted_entries_is_caught_up_by_a_snapshot() {
    let mut w = world(2);
    advance(&mut w, 600);
    let mut expected = propose_many(&mut w, "before-", 4);
    advance(&mut w, 300);

    // Node 5 is cut off while the rest of the cluster moves on and compacts.
    for &n in &NODES[..4] {
        w.network.partition(5, n);
    }
    expected.extend(propose_many(&mut w, "while-away-", 30));
    advance(&mut w, 500);
    for &n in &NODES[..4] {
        w.snapshot(n, 2).expect("a snapshot");
    }
    assert!(w.log_base(1) > w.state_of(5).log.last_index());

    w.network.heal_all();
    settle(&mut w);
    w.check_all().unwrap();

    assert!(w.snapshots_installed >= 1, "node 5 needed a real snapshot");
    assert_eq!(w.applied_commands(5), expected);
    assert!(w.snapshot_image(5).is_some());
    assert_everyone_applied(&w, &expected);
}

#[test]
fn a_follower_that_is_only_slightly_behind_is_served_from_the_retained_tail() {
    let mut w = world(3);
    advance(&mut w, 600);
    let mut expected = propose_many(&mut w, "a-", 20);
    advance(&mut w, 300);

    for &n in &NODES[..4] {
        w.network.partition(5, n);
    }
    expected.extend(propose_many(&mut w, "b-", 3));
    advance(&mut w, 300);
    // Keep a tail long enough to cover what node 5 missed.
    for &n in &NODES[..4] {
        w.snapshot(n, 12).expect("a snapshot");
    }
    w.network.heal_all();
    settle(&mut w);
    w.check_all().unwrap();

    assert_eq!(
        w.snapshots_installed, 0,
        "nothing was compacted that node 5 still needed"
    );
    assert_everyone_applied(&w, &expected);
}

#[test]
fn a_crash_between_writing_a_snapshot_and_trimming_the_log_loses_nothing() {
    let mut w = world(4);
    advance(&mut w, 600);
    let mut expected = propose_many(&mut w, "x-", 20);
    advance(&mut w, 500);
    let victim = NODES
        .iter()
        .copied()
        .find(|n| !w.current_leaders().contains(n))
        .unwrap();

    w.snapshot_then_crash(victim, 3).expect("a snapshot");
    advance(&mut w, 200);
    w.restart(victim);
    expected.extend(propose_many(&mut w, "y-", 10));
    settle(&mut w);
    w.check_all().unwrap();

    assert!(
        w.log_base(victim) > 0,
        "the restart finished the compaction"
    );
    assert_everyone_applied(&w, &expected);
}

#[test]
fn a_crash_in_the_middle_of_installing_a_snapshot_is_repaired_on_restart() {
    let mut w = world(5);
    advance(&mut w, 600);
    let mut expected = propose_many(&mut w, "a-", 3);
    advance(&mut w, 300);

    for &n in &NODES[..4] {
        w.network.partition(5, n);
    }
    expected.extend(propose_many(&mut w, "b-", 30));
    advance(&mut w, 500);
    for &n in &NODES[..4] {
        w.snapshot(n, 2).expect("a snapshot");
    }

    // Node 5 will crash after the snapshot reaches its disk but before it
    // replaces its (short, stale) log.
    w.crash_on_next_install(5);
    w.network.heal_all();
    advance(&mut w, 3_000);
    assert_eq!(w.install_crashes, 1, "the crash really happened");
    assert!(!w.is_up(5));
    assert!(w.snapshot_image(5).is_some(), "the snapshot is on its disk");

    w.restart(5);
    settle(&mut w);
    w.check_all().unwrap();
    assert_eq!(w.applied_commands(5), expected);
    assert_everyone_applied(&w, &expected);
}

#[test]
fn restarting_every_node_after_compaction_loses_no_committed_command() {
    let mut w = world(6);
    advance(&mut w, 600);
    let mut expected = propose_many(&mut w, "p-", 25);
    advance(&mut w, 500);
    snapshot_everyone(&mut w, 2);
    assert!(NODES.iter().all(|&n| w.log_base(n) > 0));

    for &n in &NODES {
        w.crash(n);
    }
    advance(&mut w, 100);
    for &n in &NODES {
        w.restart(n);
    }
    settle(&mut w);
    expected.extend(propose_many(&mut w, "q-", 5));
    settle(&mut w);
    w.check_all().unwrap();
    assert_everyone_applied(&w, &expected);
}

/// The full chaos run: proposals, partitions, crashes, loss, duplication,
/// reordering, snapshots at random moments with random retained tails, nodes
/// that die mid-compaction, and nodes that die mid-install. Every safety
/// property and snapshot consistency are checked after every step.
fn random_run(seed: u64) -> SimWorld {
    let mut w = world(seed);
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5A9_5407);
    let mut counter = 0u32;
    for step in 0..140 {
        match rng.gen_range(0..16) {
            0..=4 => {
                w.propose_to_leader(cmd(&format!("s{seed}-{counter}")));
                counter += 1;
            }
            5 => {
                let (a, b) = (NODES[rng.gen_range(0..5)], NODES[rng.gen_range(0..5)]);
                if a != b {
                    w.network.partition(a, b);
                }
            }
            6 => w.network.heal_all(),
            7 => w.crash(NODES[rng.gen_range(0..5)]),
            8 | 9 => w.restart(NODES[rng.gen_range(0..5)]),
            10 => {
                w.network.loss_percent = [0, 10, 25][rng.gen_range(0..3)];
                w.network.duplicate_percent = [0, 15][rng.gen_range(0..2)];
            }
            11 | 12 => {
                let _ = w.snapshot(
                    NODES[rng.gen_range(0..5)],
                    [0, 1, 3, 8][rng.gen_range(0..4)],
                );
            }
            13 => {
                let _ =
                    w.snapshot_then_crash(NODES[rng.gen_range(0..5)], [0, 2][rng.gen_range(0..2)]);
            }
            14 => w.crash_on_next_install(NODES[rng.gen_range(0..5)]),
            _ => {}
        }
        advance(&mut w, rng.gen_range(10..140));
        w.check_all()
            .unwrap_or_else(|e| panic!("seed {seed}, step {step}: {e}"));
    }

    // Faults stop: heal everything, boot everyone, no loss.
    w.network.heal_all();
    w.network.loss_percent = 0;
    w.network.duplicate_percent = 0;
    w.disarm_install_crashes();
    for &n in &NODES {
        w.restart(n);
    }
    settle(&mut w);
    w.check_all()
        .unwrap_or_else(|e| panic!("seed {seed}, after recovery: {e}"));

    // Liveness: a healthy cluster commits a fresh command and converges.
    let probe = cmd(&format!("probe-{seed}"));
    w.propose_to_leader(probe.clone())
        .unwrap_or_else(|| panic!("seed {seed}: no leader after recovery"));
    settle(&mut w);
    w.check_all()
        .unwrap_or_else(|e| panic!("seed {seed}, after probe: {e}"));
    assert!(
        w.committed_commands().contains(&probe),
        "seed {seed}: a healthy cluster must commit a new command"
    );
    let committed = w.committed_commands();
    for &n in &NODES {
        assert_eq!(
            w.applied_commands(n),
            committed,
            "seed {seed}: node {n} did not converge on the committed history"
        );
    }
    w
}

#[test]
fn two_hundred_random_fault_schedules_with_snapshots_never_violate_safety_and_always_recover() {
    let (mut taken, mut installed, mut install_crashes) = (0, 0, 0);
    for seed in 0..200 {
        let w = random_run(seed);
        taken += w.snapshots_taken;
        installed += w.snapshots_installed;
        install_crashes += w.install_crashes;
    }
    // A chaos run that never exercised snapshots would prove nothing.
    assert!(taken >= 400, "snapshots were taken in the runs ({taken})");
    assert!(
        installed >= 20,
        "followers were caught up by snapshot ({installed})"
    );
    assert!(
        install_crashes >= 5,
        "nodes crashed mid-install ({install_crashes})"
    );
}

#[test]
fn the_same_seed_produces_the_identical_history_with_snapshots() {
    let (a, b) = (random_run(31), random_run(31));
    assert_eq!(a.committed_commands(), b.committed_commands());
    assert_eq!(a.leadership_log, b.leadership_log);
    assert_eq!(a.events_processed, b.events_processed);
    assert_eq!(
        (a.snapshots_taken, a.snapshots_installed, a.install_crashes),
        (b.snapshots_taken, b.snapshots_installed, b.install_crashes)
    );
}
