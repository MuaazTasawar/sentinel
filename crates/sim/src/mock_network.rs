use std::collections::HashSet;

/// Controllable, fully deterministic network conditions between
/// simulated nodes. A "partition" here is total and symmetric - neither
/// side of a partitioned pair can reach the other in either direction,
/// matching a real network split rather than a one-way packet-loss
/// scenario (which is a different, narrower fault this type doesn't
/// model).
#[derive(Debug, Default)]
pub struct NetworkConditions {
    partitioned_pairs: HashSet<(u64, u64)>,
    pub base_latency_ms: u64,
    /// Percentage (0-100) of messages silently lost in transit.
    pub loss_percent: u8,
    /// Percentage (0-100) of messages delivered twice.
    pub duplicate_percent: u8,
}

fn normalize(a: u64, b: u64) -> (u64, u64) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

impl NetworkConditions {
    pub fn new(base_latency_ms: u64) -> Self {
        Self { partitioned_pairs: HashSet::new(), base_latency_ms, loss_percent: 0, duplicate_percent: 0 }
    }

    /// Cuts all communication between `a` and `b` in both directions.
    pub fn partition(&mut self, a: u64, b: u64) {
        self.partitioned_pairs.insert(normalize(a, b));
    }

    /// Restores communication between `a` and `b`.
    pub fn heal(&mut self, a: u64, b: u64) {
        self.partitioned_pairs.remove(&normalize(a, b));
    }

    /// Heals every partition at once - simulates a network-wide outage
    /// resolving.
    pub fn heal_all(&mut self) {
        self.partitioned_pairs.clear();
    }

    pub fn is_partitioned(&self, a: u64, b: u64) -> bool {
        self.partitioned_pairs.contains(&normalize(a, b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_network_loses_and_duplicates_nothing() {
        let net = NetworkConditions::new(5);
        assert_eq!((net.loss_percent, net.duplicate_percent), (0, 0));
    }

    #[test]
    fn partition_is_symmetric() {
        let mut net = NetworkConditions::new(10);
        net.partition(1, 2);
        assert!(net.is_partitioned(1, 2));
        assert!(net.is_partitioned(2, 1), "a partition must block both directions");
    }

    #[test]
    fn heal_restores_communication() {
        let mut net = NetworkConditions::new(10);
        net.partition(1, 2);
        net.heal(1, 2);
        assert!(!net.is_partitioned(1, 2));
    }

    #[test]
    fn unrelated_pairs_are_unaffected() {
        let mut net = NetworkConditions::new(10);
        net.partition(1, 2);
        assert!(!net.is_partitioned(1, 3));
        assert!(!net.is_partitioned(2, 3));
    }

    #[test]
    fn heal_all_clears_every_partition() {
        let mut net = NetworkConditions::new(10);
        net.partition(1, 2);
        net.partition(2, 3);
        net.heal_all();
        assert!(!net.is_partitioned(1, 2));
        assert!(!net.is_partitioned(2, 3));
    }
}