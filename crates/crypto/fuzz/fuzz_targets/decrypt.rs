#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use sentinel_crypto::envelope::{self, EnvelopeCiphertext, NONCE_LEN};
use sentinel_crypto::SecretBytes;

/// Mirrors `EnvelopeCiphertext`'s fields exactly, but derives `Arbitrary`
/// itself (the real type intentionally doesn't need to — only test/fuzz
/// harnesses construct it from raw untrusted bytes; production code
/// only ever gets one back from `envelope::encrypt`).
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    kek_bytes: Vec<u8>,
    encrypted_dek: Vec<u8>,
    dek_nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    data_nonce: [u8; NONCE_LEN],
}

// The property under test: decrypting attacker-controlled bytes must
// NEVER panic, regardless of length or content — it must fail closed
// with `Err`. This is the single highest-value fuzz target in the
// entire project: `envelope::decrypt` is reachable from any client that
// can read a stored secret blob (Phase 7's `get_secret` deserializes
// exactly this type from storage before decrypting), so a panic here
// would be a remotely triggerable denial of service.
fuzz_target!(|input: FuzzInput| {
    let kek = SecretBytes::new(input.kek_bytes);
    let env = EnvelopeCiphertext {
        encrypted_dek: input.encrypted_dek,
        dek_nonce: input.dek_nonce,
        ciphertext: input.ciphertext,
        data_nonce: input.data_nonce,
    };
    let _ = envelope::decrypt(&kek, &env);
});