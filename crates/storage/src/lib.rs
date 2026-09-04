use async_trait::async_trait;

#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("key not found: {0}")]
    NotFound(String),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Pluggable storage backend for encrypted secret blobs. The vault only
/// ever stores ciphertext through this trait — encryption/decryption
/// happens one layer up (in the `api` crate, using `sentinel-crypto`),
/// so a storage backend can never see plaintext even if it's compromised.
#[async_trait]
pub trait Storage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Vec<u8>, StorageError>;
    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), StorageError>;
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError>;
}

mod sled_backend;
pub use sled_backend::SledStorage;