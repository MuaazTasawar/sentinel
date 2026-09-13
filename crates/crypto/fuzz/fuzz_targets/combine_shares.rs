#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use sentinel_crypto::shamir::{self, ShamirShare};

#[derive(Debug, Arbitrary)]
struct FuzzShare {
    x: u8,
    y: Vec<u8>,
}

// `combine_shares` is reachable from Phase 4's hardware-unseal flow with
// shares that (once PIV decryption exists on real hardware) come from
// physical devices this process doesn't fully control the input shape
// of. It must never panic on a malformed, mismatched-length, or
// duplicate-x share set — only ever return `Err` or an (unverified,
// possibly garbage) reconstructed secret.
fuzz_target!(|shares: Vec<FuzzShare>| {
    let shares: Vec<ShamirShare> = shares.into_iter().map(|s| ShamirShare { x: s.x, y: s.y }).collect();
    let _ = shamir::combine_shares(&shares);
});