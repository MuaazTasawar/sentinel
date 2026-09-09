use sentinel_consensus::Role;
use sentinel_sim::{SimTime, SimWorld};

const ELECTION_RANGE: (u64, u64) = (50, 100);
const HEARTBEAT_MS: u64 = 20;
const LATENCY_MS: u64 = 5;

#[test]
fn five_node_cluster_elects_exactly_one_leader_with_no_faults() {
    let mut world = SimWorld::new(&[1, 2, 3, 4, 5], 42, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS);
    world.run_until(SimTime(2000));

    world.check_election_safety().expect("election safety must hold");
    let leaders = world.current_leaders();
    assert_eq!(leaders.len(), 1, "expected exactly one current leader, got {leaders:?}");
}

#[test]
fn minority_partition_cannot_elect_a_leader() {
    let mut world = SimWorld::new(&[1, 2, 3, 4, 5], 7, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS);
    world.network.partition(1, 3);
    world.network.partition(1, 4);
    world.network.partition(1, 5);
    world.network.partition(2, 3);
    world.network.partition(2, 4);
    world.network.partition(2, 5);

    world.run_until(SimTime(3000));

    world.check_election_safety().expect("election safety must hold even under partition");
    let leaders = world.current_leaders();
    assert_eq!(leaders.len(), 1, "exactly one leader should exist, on the majority side");
    assert!(
        leaders[0] == 3 || leaders[0] == 4 || leaders[0] == 5,
        "the leader must be a majority-side node, got {:?}",
        leaders[0]
    );
}

#[test]
fn leader_cut_off_from_majority_is_replaced_and_steps_down_after_healing() {
    let mut world = SimWorld::new(&[1, 2, 3, 4, 5], 99, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS);

    world.run_until(SimTime(500));
    let initial_leaders = world.current_leaders();
    assert_eq!(initial_leaders.len(), 1, "should have an initial leader before the partition");
    let old_leader = initial_leaders[0];
    let other_nodes: Vec<u64> = [1u64, 2, 3, 4, 5].into_iter().filter(|&n| n != old_leader).collect();

    for &peer in &other_nodes {
        world.network.partition(old_leader, peer);
    }

    world.run_until(SimTime(3000));
    world.check_election_safety().expect("election safety must hold during the partition");

    let majority_leaders: Vec<u64> =
        world.current_leaders().into_iter().filter(|&id| other_nodes.contains(&id)).collect();
    assert_eq!(majority_leaders.len(), 1, "the majority side must elect exactly one new leader");
    let new_leader = majority_leaders[0];
    assert_ne!(new_leader, old_leader, "the isolated old leader must not count as the majority's leader");

    let old_leader_term = world.state_of(old_leader).current_term;
    let new_leader_term = world.state_of(new_leader).current_term;
    assert!(new_leader_term > old_leader_term, "the new leader's term must have advanced past the old leader's");

    world.network.heal_all();
    world.run_until(SimTime(6000));

    world.check_election_safety().expect("election safety must hold after healing");
    let final_leaders = world.current_leaders();
    assert_eq!(final_leaders.len(), 1, "exactly one leader must remain once the cluster reconverges");
    assert_eq!(
        world.state_of(old_leader).role,
        Role::Follower,
        "the old, now-stale leader must have stepped down to follower after healing"
    );
}

#[test]
fn skewed_clock_on_one_node_does_not_break_convergence() {
    let mut world = SimWorld::new(&[1, 2, 3, 4, 5], 123, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS);
    world.skew_node_clock(1, -1000);

    world.run_until(SimTime(3000));

    world.check_election_safety().expect("election safety must hold despite clock skew");
    let leaders = world.current_leaders();
    assert_eq!(leaders.len(), 1, "cluster must still converge to exactly one leader");
}

#[test]
fn high_jitter_causing_message_reordering_does_not_break_correctness() {
    let mut world = SimWorld::new(&[1, 2, 3, 4, 5], 555, ELECTION_RANGE, HEARTBEAT_MS, 15);
    world.run_until(SimTime(5000));

    world.check_election_safety().expect("election safety must hold under heavy reordering");
    let leaders = world.current_leaders();
    assert_eq!(leaders.len(), 1, "cluster must still converge despite message reordering");
}

#[test]
fn identical_seed_and_actions_produce_byte_identical_leadership_history() {
    let mut world_a = SimWorld::new(&[1, 2, 3], 2024, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS);
    world_a.run_until(SimTime(1000));

    let mut world_b = SimWorld::new(&[1, 2, 3], 2024, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS);
    world_b.run_until(SimTime(1000));

    assert_eq!(world_a.leadership_log, world_b.leadership_log, "identical seed must produce identical leadership history");
    assert_eq!(
        world_a.events_processed, world_b.events_processed,
        "identical seed must process the exact same number of events"
    );
}

#[test]
fn repeated_partition_and_heal_cycles_never_violate_election_safety() {
    let mut world = SimWorld::new(&[1, 2, 3, 4, 5], 8080, ELECTION_RANGE, HEARTBEAT_MS, LATENCY_MS);

    for cycle in 0..4 {
        let t = SimTime(1000 + cycle * 1500);
        world.run_until(t);
        let leader = world.current_leaders().first().copied();
        if let Some(leader) = leader {
            let others: Vec<u64> = [1u64, 2, 3, 4, 5].into_iter().filter(|&n| n != leader).collect();
            for &peer in &others {
                world.network.partition(leader, peer);
            }
        }
        world.run_until(SimTime(1000 + (cycle + 1) * 1500 - 500));
        world.network.heal_all();
    }

    world.run_until(SimTime(9000));
    world.check_election_safety().expect("election safety must hold across repeated partition/heal cycles");
    assert_eq!(world.current_leaders().len(), 1, "cluster must settle back to exactly one leader");
}