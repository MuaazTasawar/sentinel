#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed: authentication tag mismatch")]
    DecryptionFailed,
    #[error("key derivation failed")]
    KdfFailed,
    #[error("insufficient shares to reconstruct secret: got {got}, need {need}")]
    InsufficientShares { got: usize, need: usize },
}