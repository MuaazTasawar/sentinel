use aes_gcm::{
    aead::{rand_core::RngCore, Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};

use crate::{secret::SecretBytes, CryptoError};

pub const NONCE_LEN: usize = 12;
pub const KEY_LEN: usize = 32;

/// Result of an envelope-encryption operation: a Data Encryption Key
/// (DEK) that was generated fresh, encrypted under the caller's Key
/// Encryption Key, plus the ciphertext that DEK protects.
pub struct EnvelopeCiphertext {
    pub encrypted_dek: Vec<u8>,
    pub dek_nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
    pub data_nonce: [u8; NONCE_LEN],
}

/// Encrypts `plaintext` under a freshly generated DEK, then wraps that
/// DEK under the supplied KEK. This is the standard envelope-encryption
/// pattern: the KEK (derived from the unseal quorum) never directly
/// touches secret data, and rotating the KEK later only means re-wrapping
/// DEKs, not re-encrypting every stored secret.
pub fn encrypt(kek: &SecretBytes, plaintext: &[u8]) -> Result<EnvelopeCiphertext, CryptoError> {
    if kek.len() != KEY_LEN {
        return Err(CryptoError::EncryptionFailed);
    }

    let dek = SecretBytes::new(random_bytes(KEY_LEN));
    let data_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.expose()));
    let data_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = data_cipher
        .encrypt(&data_nonce, plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let kek_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.expose()));
    let dek_nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted_dek = kek_cipher
        .encrypt(&dek_nonce, dek.expose())
        .map_err(|_| CryptoError::EncryptionFailed)?;

    Ok(EnvelopeCiphertext {
        encrypted_dek,
        dek_nonce: dek_nonce.into(),
        ciphertext,
        data_nonce: data_nonce.into(),
    })
}

/// Reverses `encrypt`: unwraps the DEK with the KEK, then decrypts the
/// ciphertext. The unwrapped DEK lives in a `SecretBytes` for its entire
/// lifetime and is zeroized the instant it goes out of scope.
pub fn decrypt(kek: &SecretBytes, env: &EnvelopeCiphertext) -> Result<Vec<u8>, CryptoError> {
    if kek.len() != KEY_LEN {
        return Err(CryptoError::DecryptionFailed);
    }

    let kek_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek.expose()));
    let dek_nonce = Nonce::from_slice(&env.dek_nonce);
    let dek_bytes = kek_cipher
        .decrypt(dek_nonce, env.encrypted_dek.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)?;
    let dek = SecretBytes::new(dek_bytes);

    let data_cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(dek.expose()));
    let data_nonce = Nonce::from_slice(&env.data_nonce);
    data_cipher
        .decrypt(data_nonce, env.ciphertext.as_ref())
        .map_err(|_| CryptoError::DecryptionFailed)
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kek() -> SecretBytes {
        SecretBytes::new(random_bytes(KEY_LEN))
    }

    #[test]
    fn round_trips_plaintext() {
        let kek = test_kek();
        let plaintext = b"db-password-hunter2";
        let env = encrypt(&kek, plaintext).unwrap();
        let decrypted = decrypt(&kek, &env).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_kek_fails_closed() {
        let kek = test_kek();
        let wrong_kek = test_kek();
        let env = encrypt(&kek, b"secret").unwrap();
        assert!(decrypt(&wrong_kek, &env).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let kek = test_kek();
        let mut env = encrypt(&kek, b"secret").unwrap();
        env.ciphertext[0] ^= 0xFF;
        assert!(decrypt(&kek, &env).is_err());
    }

    #[test]
    fn wrong_key_length_rejected() {
        let bad_kek = SecretBytes::new(vec![0u8; 16]);
        assert!(encrypt(&bad_kek, b"secret").is_err());
    }
}