use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// The result of a detection check: the current bucket's raw count
/// alongside the historical baseline it was compared against, so a
/// caller (or an audit-log entry) can explain *why* something looked
/// anomalous, not just that it did.
#[derive(Debug, Clone, PartialEq)]
pub struct AnomalyReport {
    pub current_count: u32,
    pub baseline_mean: f64,
    pub baseline_stddev: f64,
    pub z_score: f64,
}

/// A read-only, display-oriented view of a detector's current state —
/// separate from `AnomalyReport` because a snapshot is taken on demand
/// for observability (e.g. a dashboard poll) and always returns
/// something, even during warm-up before enough history exists to ever
/// flag an anomaly; `AnomalyReport` only ever exists at the moment a
/// real detection fires.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DetectorSnapshot {
    pub current_count: u32,
    pub recent_history: Vec<u32>,
    pub baseline_mean: f64,
    pub baseline_stddev: f64,
}

/// A rolling-window anomaly detector for access-pattern rates. Time is
/// divided into fixed-size buckets; each closed bucket's count feeds a
/// rolling history, and the *current, still-open* bucket is flagged the
/// moment its count is a statistical outlier (more than `z_threshold`
/// standard deviations above the historical mean) relative to that
/// history — a classic rolling z-score. Deliberately simple: no ML
/// model, no external dependency, cheap enough to run on every single
/// access.
///
/// Time is passed in explicitly (`now: Instant`) rather than read via
/// `Instant::now()` internally, which is what makes this fully
/// deterministic to test — callers in production pass the real clock,
/// tests pass synthetic instants advanced by exact `Duration`s.
pub struct AnomalyDetector {
    bucket_duration: Duration,
    max_history: usize,
    min_history_for_detection: usize,
    z_threshold: f64,
    min_burst: u32,
    history: VecDeque<u32>,
    current_bucket_start: Option<Instant>,
    current_count: u32,
}

impl AnomalyDetector {
    /// `bucket_duration`: how wide each time bucket is (e.g. 1 second).
    /// `max_history`: how many past buckets feed the rolling baseline.
    /// `z_threshold`: how many standard deviations above the mean counts
    /// as anomalous — 3.0 is a common starting point (roughly a 1-in-370
    /// false-positive rate under a normal-ish distribution, though real
    /// access patterns are rarely perfectly normal, so this is a tuning
    /// knob more than a statistical guarantee).
    pub fn new(bucket_duration: Duration, max_history: usize, z_threshold: f64) -> Self {
        Self {
            bucket_duration,
            max_history,
            min_history_for_detection: 5,
            z_threshold,
            min_burst: 1,
            history: VecDeque::new(),
            current_bucket_start: None,
            current_count: 0,
        }
    }

    /// Sets an absolute floor on the current bucket's count: a bucket with
    /// fewer than `n` accesses is never flagged, whatever the z-score says.
    ///
    /// Why this exists: after a quiet spell the baseline is all-zero
    /// buckets (mean 0, stddev 0), and the bare rule "any count above a
    /// flat baseline is anomalous" then flags a single, perfectly ordinary
    /// read. With 1 s buckets and a 60-bucket window, two reads 20 s apart
    /// score z = 4.36 against a threshold of 3.0. Statistics alone cannot
    /// tell "one read after silence" from "an attack", so a count floor
    /// says how many reads in one bucket it takes to be worth flagging.
    ///
    /// The default is 1, which keeps the original behaviour (no floor).
    /// Values below 1 are clamped to 1.
    pub fn with_min_burst(mut self, n: u32) -> Self {
        self.min_burst = n.max(1);
        self
    }

    /// Records one access at time `now`. Returns `Some(report)` if,
    /// after recording this access, the current bucket's count is
    /// anomalous relative to history — `None` otherwise, including
    /// during the initial warm-up period before enough history has
    /// accumulated (a documented limitation: this detector cannot flag
    /// anomalies before it has a baseline to compare against, so an
    /// attack starting the instant a node comes online would not be
    /// caught until `min_history_for_detection` buckets have elapsed).
    pub fn record_access(&mut self, now: Instant) -> Option<AnomalyReport> {
        self.roll_to(now);
        self.current_count += 1;
        self.check_anomaly()
    }

    /// Closes out every bucket that has fully elapsed as of `now`,
    /// pushing each into history (including buckets with zero accesses
    /// during an idle gap — silence is part of the baseline too, not
    /// something to skip over).
    fn roll_to(&mut self, now: Instant) {
        let mut bucket_start = *self.current_bucket_start.get_or_insert(now);
        while now.duration_since(bucket_start) >= self.bucket_duration {
            self.push_history(self.current_count);
            self.current_count = 0;
            bucket_start += self.bucket_duration;
        }
        self.current_bucket_start = Some(bucket_start);
    }

    fn push_history(&mut self, count: u32) {
        if self.history.len() == self.max_history {
            self.history.pop_front();
        }
        self.history.push_back(count);
    }

    /// A point-in-time view for display purposes — safe to call as often
    /// as needed (e.g. every dashboard poll), and never mutates state or
    /// affects detection logic. Always returns real numbers, even before
    /// `min_history_for_detection` buckets have accumulated (mean/stddev
    /// are simply computed over however much history exists so far,
    /// which may be zero, in which case both are 0.0).
    pub fn snapshot(&self) -> DetectorSnapshot {
        let n = self.history.len() as f64;
        let (mean, stddev) = if n == 0.0 {
            (0.0, 0.0)
        } else {
            let mean = self.history.iter().map(|&c| c as f64).sum::<f64>() / n;
            let variance = self.history.iter().map(|&c| { let d = c as f64 - mean; d * d }).sum::<f64>() / n;
            (mean, variance.sqrt())
        };
        DetectorSnapshot {
            current_count: self.current_count,
            recent_history: self.history.iter().copied().collect(),
            baseline_mean: mean,
            baseline_stddev: stddev,
        }
    }

    fn check_anomaly(&self) -> Option<AnomalyReport> {
        if self.history.len() < self.min_history_for_detection {
            return None;
        }
        if self.current_count < self.min_burst {
            return None;
        }
        let n = self.history.len() as f64;
        let mean = self.history.iter().map(|&c| c as f64).sum::<f64>() / n;
        let variance = self.history.iter().map(|&c| { let d = c as f64 - mean; d * d }).sum::<f64>() / n;
        let stddev = variance.sqrt();

        if stddev == 0.0 {
            return if self.current_count as f64 > mean {
                Some(AnomalyReport { current_count: self.current_count, baseline_mean: mean, baseline_stddev: stddev, z_score: f64::INFINITY })
            } else {
                None
            };
        }

        let z = (self.current_count as f64 - mean) / stddev;
        if z > self.z_threshold {
            Some(AnomalyReport { current_count: self.current_count, baseline_mean: mean, baseline_stddev: stddev, z_score: z })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Instant {
        Instant::now()
    }

    #[test]
    fn no_detection_during_warmup_regardless_of_count() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 10, 3.0);
        let t0 = base();
        for _ in 0..100 {
            assert!(d.record_access(t0).is_none());
        }
    }

    #[test]
    fn steady_traffic_does_not_trigger_false_positives() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 20, 3.0);
        let t0 = base();
        for bucket in 0..20 {
            let bucket_time = t0 + Duration::from_secs(bucket);
            for _ in 0..5 {
                d.record_access(bucket_time);
            }
        }
        let next_bucket = t0 + Duration::from_secs(20);
        for _ in 0..5 {
            assert!(d.record_access(next_bucket).is_none());
        }
    }

    #[test]
    fn sudden_burst_after_steady_baseline_is_detected() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 20, 3.0);
        let t0 = base();
        for bucket in 0..10 {
            let bucket_time = t0 + Duration::from_secs(bucket);
            d.record_access(bucket_time);
            d.record_access(bucket_time);
        }
        let burst_time = t0 + Duration::from_secs(10);
        let mut fired = false;
        for _ in 0..40 {
            if d.record_access(burst_time).is_some() {
                fired = true;
            }
        }
        assert!(fired, "a 40x burst against a steady 2/sec baseline should be flagged");
    }

    #[test]
    fn detection_fires_early_in_the_burst_not_only_at_the_end() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 20, 3.0);
        let t0 = base();
        for bucket in 0..10 {
            let bucket_time = t0 + Duration::from_secs(bucket);
            d.record_access(bucket_time);
            d.record_access(bucket_time);
        }
        let burst_time = t0 + Duration::from_secs(10);
        let mut first_detection_at = None;
        for i in 1..=40 {
            if d.record_access(burst_time).is_some() {
                first_detection_at = Some(i);
                break;
            }
        }
        let first_detection_at = first_detection_at.expect("should detect at some point in the burst");
        assert!(first_detection_at <= 10, "expected detection well before all 40 requests landed, got request #{first_detection_at}");
    }

    #[test]
    fn idle_gap_is_recorded_as_zero_count_buckets() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 5, 3.0);
        let t0 = base();
        d.record_access(t0);
        let t_later = t0 + Duration::from_secs(5);
        d.record_access(t_later);
        assert!(d.history.contains(&0), "idle buckets should be recorded as zero-count history entries");
    }

    #[test]
    fn flat_zero_stddev_baseline_flags_any_increase() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 10, 3.0);
        let t0 = base();
        for bucket in 0..6 {
            let bucket_time = t0 + Duration::from_secs(bucket);
            for _ in 0..3 {
                d.record_access(bucket_time);
            }
        }
        let next_bucket = t0 + Duration::from_secs(6);
        d.record_access(next_bucket);
        d.record_access(next_bucket);
        d.record_access(next_bucket);
        let result = d.record_access(next_bucket);
        assert!(result.is_some(), "any increase over a perfectly flat baseline should be flagged");
        assert_eq!(result.unwrap().z_score, f64::INFINITY);
    }

    #[test]
    fn matching_the_flat_baseline_exactly_does_not_flag() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 10, 3.0);
        let t0 = base();
        for bucket in 0..6 {
            let bucket_time = t0 + Duration::from_secs(bucket);
            for _ in 0..3 {
                d.record_access(bucket_time);
            }
        }
        let next_bucket = t0 + Duration::from_secs(6);
        assert!(d.record_access(next_bucket).is_none());
        assert!(d.record_access(next_bucket).is_none());
        assert!(d.record_access(next_bucket).is_none());
    }

    #[test]
    fn report_carries_accurate_baseline_numbers() {
        let t0 = base();
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 10, 2.0);
        let counts = [2u32, 4, 2, 4, 2, 4, 2, 4, 2, 4];
        for (bucket, &count) in counts.iter().enumerate() {
            let bucket_time = t0 + Duration::from_secs(bucket as u64);
            for _ in 0..count {
                d.record_access(bucket_time);
            }
        }
        let next_bucket = t0 + Duration::from_secs(counts.len() as u64);
        let mut last_report = None;
        for _ in 0..20 {
            if let Some(r) = d.record_access(next_bucket) {
                last_report = Some(r);
            }
        }
        let report = last_report.expect("a 20x burst against this baseline should be flagged");
        assert_eq!(report.baseline_mean, 3.0);
        assert!(report.baseline_stddev > 0.0);
        assert!(report.z_score > 2.0);
    }

    #[test]
    fn snapshot_reflects_current_state_without_mutating_it() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 10, 3.0);
        let t0 = base();
        d.record_access(t0);
        d.record_access(t0);

        let snap = d.snapshot();
        assert_eq!(snap.current_count, 2);
        assert!(snap.recent_history.is_empty(), "current (still-open) bucket isn't in history yet");

        let snap2 = d.snapshot();
        assert_eq!(snap.current_count, snap2.current_count);
    }

    #[test]
    fn snapshot_before_any_access_is_all_zeros_not_a_panic() {
        let d = AnomalyDetector::new(Duration::from_secs(1), 10, 3.0);
        let snap = d.snapshot();
        assert_eq!(snap.current_count, 0);
        assert_eq!(snap.baseline_mean, 0.0);
        assert_eq!(snap.baseline_stddev, 0.0);
    }

    // ---- count floor (`with_min_burst`) --------------------------------

    /// Feed one read at each of the given offsets (seconds from t0).
    fn reads_at(d: &mut AnomalyDetector, t0: Instant, offsets: &[u64]) -> Vec<bool> {
        offsets
            .iter()
            .map(|&s| d.record_access(t0 + Duration::from_secs(s)).is_some())
            .collect()
    }

    #[test]
    fn bare_rule_flags_a_lone_read_after_a_quiet_spell() {
        // Documents the flaw the floor exists to fix: with the node's real
        // settings (1 s buckets, 60-bucket window, z = 3.0) and no floor,
        // two ordinary reads 20 s apart trip the detector.
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 60, 3.0);
        let t0 = base();
        let flagged = reads_at(&mut d, t0, &[0, 20]);
        assert_eq!(flagged, vec![false, true], "the bare rule flags the second, lone read");
    }

    #[test]
    fn a_floor_of_ten_never_flags_sparse_reads() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 60, 3.0).with_min_burst(10);
        let t0 = base();
        // Gaps of 6 s up to 180 s between single reads.
        let mut t = 0u64;
        for gap in [6u64, 7, 10, 20, 30, 45, 60, 90, 120, 180, 6, 6, 6, 6, 6, 6] {
            t += gap;
            assert!(
                d.record_access(t0 + Duration::from_secs(t)).is_none(),
                "a lone read {gap}s after the previous one must not be flagged"
            );
        }
    }

    #[test]
    fn a_floor_of_ten_flags_exactly_the_tenth_read_in_a_bucket() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 60, 3.0).with_min_burst(10);
        let t0 = base();
        // Quiet baseline: one read per second for 10 s, then silence.
        for s in 0..10 {
            d.record_access(t0 + Duration::from_secs(s));
        }
        let burst = t0 + Duration::from_secs(40);
        for i in 1..=9 {
            assert!(d.record_access(burst).is_none(), "read #{i} in the bucket is below the floor");
        }
        let tenth = d.record_access(burst);
        assert!(tenth.is_some(), "the 10th read in one bucket reaches the floor and is flagged");
        assert_eq!(tenth.unwrap().current_count, 10);
    }

    #[test]
    fn the_floor_does_not_hide_a_real_burst_over_a_busy_baseline() {
        let mut d = AnomalyDetector::new(Duration::from_secs(1), 20, 3.0).with_min_burst(10);
        let t0 = base();
        for bucket in 0..10 {
            let bucket_time = t0 + Duration::from_secs(bucket);
            d.record_access(bucket_time);
            d.record_access(bucket_time);
        }
        let burst_time = t0 + Duration::from_secs(10);
        let fired = (0..40).any(|_| d.record_access(burst_time).is_some());
        assert!(fired, "a 40x burst over a steady 2/sec baseline is still flagged with a floor of 10");
    }

    #[test]
    fn the_floor_is_clamped_to_at_least_one() {
        // 0 would mean "flag even an empty bucket"; it behaves as 1 instead,
        // i.e. exactly the bare rule.
        let mut zero = AnomalyDetector::new(Duration::from_secs(1), 60, 3.0).with_min_burst(0);
        let mut bare = AnomalyDetector::new(Duration::from_secs(1), 60, 3.0);
        let t0 = base();
        assert_eq!(reads_at(&mut zero, t0, &[0, 20]), reads_at(&mut bare, t0, &[0, 20]));
    }
}
