use aes_gcm::aead::{rand_core::RngCore, OsRng};
use argon2::Argon2;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::{secret::SecretBytes, CryptoError};

pub const SALT_LEN: usize = 16;

/// Derives a Key Encryption Key from a low-entropy input (e.g. a value
/// reconstructed from the hardware-unseal quorum) using Argon2id, which
/// is deliberately memory-hard to resist offline brute-forcing if that
/// input ever has less than full entropy.
pub fn derive_kek_argon2(input: &[u8], salt: &[u8]) -> Result<SecretBytes, CryptoError> {
    let argon2 = Argon2::default();
    let mut out = vec![0u8; crate::envelope::KEY_LEN];
    argon2
        .hash_password_into(input, salt, &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(SecretBytes::new(out))
}

/// Expands a high-entropy master secret (e.g. the reconstructed Shamir
/// secret) into a per-purpose key using HKDF, so the same root secret can
/// safely produce independent keys for different contexts (e.g.
/// "dek-wrapping" vs "audit-log-hmac") without those keys being related
/// in an exploitable way.
pub fn derive_key_hkdf(master: &[u8], info: &[u8], out_len: usize) -> Result<SecretBytes, CryptoError> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = vec![0u8; out_len];
    hk.expand(info, &mut out).map_err(|_| CryptoError::KdfFailed)?;
    Ok(SecretBytes::new(out))
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_is_deterministic_given_same_salt() {
        let salt = random_salt();
        let a = derive_kek_argon2(b"low-entropy-input", &salt).unwrap();
        let b = derive_kek_argon2(b"low-entropy-input", &salt).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    #[test]
    fn different_salts_produce_different_keys() {
        let a = derive_kek_argon2(b"same-input", &random_salt()).unwrap();
        let b = derive_kek_argon2(b"same-input", &random_salt()).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn hkdf_contexts_produce_independent_keys() {
        let master = b"32-byte-master-secret-material!!";
        let k1 = derive_key_hkdf(master, b"dek-wrapping", 32).unwrap();
        let k2 = derive_key_hkdf(master, b"audit-log-hmac", 32).unwrap();
        assert_ne!(k1.expose(), k2.expose());
    }
}