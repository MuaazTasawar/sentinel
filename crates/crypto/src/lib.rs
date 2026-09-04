mod error;
pub mod envelope;
pub mod kdf;
pub mod secret;

pub use error::CryptoError;
pub use secret::SecretBytes;

// mod shamir;   // Phase 2