//! Property-based tests targeting the same boundaries as the real
//! libFuzzer harnesses in `fuzz/fuzz_targets/`. These run on stable Rust
//! and are verified on every `cargo test`, unlike the fuzz targets
//! (which need a nightly toolchain and `cargo fuzz run`, and are meant
//! for long, coverage-guided runs rather than a quick CI check) — the
//! two are complementary, not redundant: this file catches regressions
//! immediately on every commit; `cargo fuzz` finds inputs a human
//! wouldn't think to write by hand.

use proptest::prelude::*;
use sentinel_crypto::envelope::{self, EnvelopeCiphertext, KEY_LEN, NONCE_LEN};
use sentinel_crypto::shamir::{self, ShamirShare};
use sentinel_crypto::{kdf, SecretBytes};

fn arb_nonce() -> impl Strategy<Value = [u8; NONCE_LEN]> {
    proptest::array::uniform12(any::<u8>())
}

proptest! {
    /// The canonical crypto fuzz property: decrypting arbitrary,
    /// almost-certainly-malformed ciphertext must NEVER panic. It must
    /// return `Err`, every time, no matter what garbage is fed in. A
    /// panic here would mean a network-facing decrypt call could be
    /// used to crash a node — `get_secret` (Phase 7) deserializes
    /// exactly this type from storage before decrypting it, so this is
    /// a remotely-reachable boundary, not an internal-only one.
    #[test]
    fn decrypt_never_panics_on_arbitrary_bytes(
        encrypted_dek in proptest::collection::vec(any::<u8>(), 0..128),
        dek_nonce in arb_nonce(),
        ciphertext in proptest::collection::vec(any::<u8>(), 0..256),
        data_nonce in arb_nonce(),
        kek_bytes in proptest::collection::vec(any::<u8>(), 0..64),
    ) {
        let kek = SecretBytes::new(kek_bytes);
        let env = EnvelopeCiphertext { encrypted_dek, dek_nonce, ciphertext, data_nonce };
        let _ = envelope::decrypt(&kek, &env);
    }

    /// Same property, but specifically for well-formed-length garbage —
    /// a 32-byte KEK and correctly-sized nonces, only the tag/ciphertext
    /// bytes are random. This is the input shape most likely to slip
    /// past a naive length check and reach the actual AEAD tag
    /// verification.
    #[test]
    fn decrypt_never_panics_with_correct_lengths_but_garbage_content(
        encrypted_dek in proptest::collection::vec(any::<u8>(), 32..64),
        dek_nonce in arb_nonce(),
        ciphertext in proptest::collection::vec(any::<u8>(), 16..64),
        data_nonce in arb_nonce(),
    ) {
        let kek = SecretBytes::new(vec![0x11u8; KEY_LEN]);
        let env = EnvelopeCiphertext { encrypted_dek, dek_nonce, ciphertext, data_nonce };
        let _ = envelope::decrypt(&kek, &env);
    }

    /// Encrypting arbitrary plaintext (including empty and large inputs)
    /// under a valid KEK must never panic, and must always round-trip
    /// correctly back through decrypt.
    #[test]
    fn encrypt_decrypt_round_trips_for_arbitrary_plaintext(
        plaintext in proptest::collection::vec(any::<u8>(), 0..2048),
        kek_seed in any::<u8>(),
    ) {
        let kek = SecretBytes::new(vec![kek_seed; KEY_LEN]);
        let env = envelope::encrypt(&kek, &plaintext).expect("encrypt with a valid-length KEK must not fail");
        let decrypted = envelope::decrypt(&kek, &env).expect("decrypting what we just encrypted must succeed");
        prop_assert_eq!(decrypted, plaintext);
    }

    /// Combining arbitrary garbage "shares" (random x/y pairs, not
    /// produced by `split_secret`) must never panic, regardless of how
    /// many are supplied or what their lengths are.
    #[test]
    fn combine_shares_never_panics_on_arbitrary_shares(
        shares in proptest::collection::vec(
            (any::<u8>(), proptest::collection::vec(any::<u8>(), 0..32)),
            0..10,
        ),
    ) {
        let shares: Vec<ShamirShare> = shares.into_iter().map(|(x, y)| ShamirShare { x, y }).collect();
        let _ = shamir::combine_shares(&shares);
    }

    /// `split_secret` must never panic for any in-range threshold/total
    /// combination and any secret content, and whatever it returns (Ok
    /// or Err) must be internally consistent — an Ok result must always
    /// have exactly `total_shares` entries, each the same length as the
    /// input secret.
    #[test]
    fn split_secret_never_panics_and_returns_consistent_share_count(
        secret in proptest::collection::vec(any::<u8>(), 0..128),
        threshold in 0u8..=255,
        total in 0u8..=255,
    ) {
        let mut rng = rand::rngs::mock::StepRng::new(0, 1);
        let result = shamir::split_secret(&secret, threshold, total, &mut rng);
        if let Ok(shares) = result {
            prop_assert_eq!(shares.len(), total as usize);
            for share in &shares {
                prop_assert_eq!(share.y.len(), secret.len());
            }
        }
    }

    /// HKDF must never panic regardless of master/info length, including
    /// zero-length inputs, or output-length requests within a
    /// reasonable range.
    #[test]
    fn hkdf_never_panics_on_arbitrary_master_and_info(
        master in proptest::collection::vec(any::<u8>(), 0..64),
        info in proptest::collection::vec(any::<u8>(), 0..64),
        out_len in 0usize..128,
    ) {
        let _ = kdf::derive_key_hkdf(&master, &info, out_len);
    }
}

proptest! {
    // Fewer cases than the properties above, deliberately — Argon2 is
    // designed to be expensive per call, so 256 iterations would cost
    // minutes of CI time for marginal extra coverage over 20; the
    // property being checked (no panic across the input-length space)
    // saturates quickly since Argon2's own internals don't branch on
    // input content in ways that would need more samples to reach.
    #![proptest_config(ProptestConfig::with_cases(20))]

    /// Argon2 must never panic regardless of input/salt length,
    /// including zero-length inputs.
    #[test]
    fn argon2_kdf_never_panics_on_arbitrary_input_and_salt(
        input in proptest::collection::vec(any::<u8>(), 0..64),
        salt in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let _ = kdf::derive_kek_argon2(&input, &salt);
    }
}