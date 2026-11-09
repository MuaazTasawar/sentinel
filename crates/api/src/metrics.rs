//! Event counters for `/metrics`.
//!
//! These are plain atomics bumped at the point where the event really happens
//! (a secret is returned, a write commits, a request is denied...). They hold
//! only numbers: no identity, no secret name, and no label whose value comes
//! from a client, so the metrics endpoint cannot leak who asked for what, and
//! a client cannot make the number of time series grow.
//!
//! Counters reset when the node restarts, which Prometheus handles (it treats
//! a decrease as a reset).

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct Metrics {
    /// Secrets actually returned to a client (not 404s, not sealed refusals).
    pub secret_reads: AtomicU64,
    /// Writes acknowledged after a majority commit.
    pub secret_writes: AtomicU64,
    /// Deletions acknowledged after a majority commit.
    pub secret_deletes: AtomicU64,
    /// Requests refused by the authorization policy. Every denial counts here,
    /// unlike the audit chain, which records only the first per minute.
    pub authz_denials: AtomicU64,
    /// Times this node sealed itself because read traffic looked like exfiltration.
    pub auto_seals: AtomicU64,
    /// Successful quorum unseals.
    pub unseals: AtomicU64,
    /// Quorums that completed but did not rebuild the vault's key.
    pub unseal_failures: AtomicU64,
}

impl Metrics {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}
