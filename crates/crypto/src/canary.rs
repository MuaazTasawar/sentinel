//! Key canary: a tiny known-plaintext blob encrypted under the KEK.
//!
//! Shamir secret sharing has no integrity check of its own. Combining the
//! wrong shares, or too few of them, silently returns *some* byte string of
//! the right length, so without a canary a node would happily "unseal" with
//! garbage and then fail on every secret in a confusing way (or, worse,
//! write new secrets under the wrong key). The canary lets a node prove,
//! before it accepts a reconstructed KEK, that this really is the key the
//! vault was initialised with.

use crate::envelope::{self, EnvelopeCiphertext};
use crate::{CryptoError, SecretBytes};

/// Fixed, non-secret plaintext. Its only job is to make "decrypts to
/// exactly this" a yes/no test for key correctness.
const CANARY_PLAINTEXT: &[u8] = b"sentinel-kek-canary-v1";

/// Creates a canary under `kek`. Store the result durably; it is not secret.
pub fn create(kek: &SecretBytes) -> Result<EnvelopeCiphertext, CryptoError> {
    envelope::encrypt(kek, CANARY_PLAINTEXT)
}

/// True only if `kek` decrypts `canary` to the expected plaintext. Any
/// failure (wrong key, wrong length, tampered blob) is simply `false`.
pub fn verify(kek: &SecretBytes, canary: &EnvelopeCiphertext) -> bool {
    match envelope::decrypt(kek, canary) {
        Ok(plain) => plain.as_slice() == CANARY_PLAINTEXT,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::KEY_LEN;

    fn kek(byte: u8) -> SecretBytes {
        SecretBytes::new(vec![byte; KEY_LEN])
    }

    #[test]
    fn the_right_key_verifies() {
        let canary = create(&kek(1)).unwrap();
        assert!(verify(&kek(1), &canary));
    }

    #[test]
    fn a_different_key_does_not_verify() {
        let canary = create(&kek(1)).unwrap();
        assert!(!verify(&kek(2), &canary));
    }

    #[test]
    fn a_wrong_length_key_does_not_verify_and_does_not_panic() {
        let canary = create(&kek(1)).unwrap();
        assert!(!verify(&SecretBytes::new(vec![1u8; 5]), &canary));
        assert!(!verify(&SecretBytes::new(vec![]), &canary));
    }

    #[test]
    fn a_tampered_canary_does_not_verify() {
        let mut canary = create(&kek(1)).unwrap();
        canary.ciphertext[0] ^= 0xFF;
        assert!(!verify(&kek(1), &canary));
    }

    #[test]
    fn a_canary_for_other_plaintext_does_not_verify() {
        // Right key, but a blob that decrypts to something else must not pass.
        let other = envelope::encrypt(&kek(1), b"not the canary").unwrap();
        assert!(!verify(&kek(1), &other));
    }
}