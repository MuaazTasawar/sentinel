/// A point in virtual simulation time, in whole milliseconds since the
/// simulation began. Deliberately not `std::time::Instant` — `Instant`
/// can only ever be "now" or derived from "now" via arithmetic, which
/// makes it impossible to construct arbitrary points in time or jump a
/// clock forward by hours in zero wall-clock time. `SimTime` is just a
/// number the simulation driver controls completely, which is what
/// makes chaos scenarios (long partitions, clock skew) run in
/// milliseconds of real test time instead of the hours they'd represent
/// if actually waited out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SimTime(pub u64);

impl SimTime {
    pub const ZERO: SimTime = SimTime(0);

    pub fn advance(self, ms: u64) -> Self {
        SimTime(self.0 + ms)
    }
}

impl std::ops::Add<u64> for SimTime {
    type Output = SimTime;
    fn add(self, ms: u64) -> SimTime {
        self.advance(ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advance_adds_milliseconds() {
        assert_eq!(SimTime::ZERO.advance(500), SimTime(500));
    }

    #[test]
    fn ordering_matches_underlying_value() {
        assert!(SimTime(100) < SimTime(200));
        assert!(SimTime(0) == SimTime::ZERO);
    }
}