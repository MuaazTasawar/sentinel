#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use sentinel_crypto::kdf;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    input: Vec<u8>,
    salt: Vec<u8>,
    hkdf_master: Vec<u8>,
    hkdf_info: Vec<u8>,
    // Kept as a single byte (not usize) so fuzzing can't spend unbounded
    // time/memory asking HKDF to expand to an enormous output length —
    // that would be a resource-exhaustion finding worth its own,
    // separately-bounded target, not noise drowning out this one.
    out_len: u8,
}

// KDF inputs are attacker-influenced at the boundary where a low-entropy
// unseal-reconstructed value feeds `derive_kek_argon2`, and wherever a
// context string feeds HKDF's `info` parameter. Neither should panic
// regardless of input/salt length, including zero-length edge cases.
fuzz_target!(|input: FuzzInput| {
    let _ = kdf::derive_kek_argon2(&input.input, &input.salt);
    let _ = kdf::derive_key_hkdf(&input.hkdf_master, &input.hkdf_info, input.out_len as usize);
});