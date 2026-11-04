mod error;
pub mod canary;
pub mod envelope;
pub mod kdf;
pub mod secret;
pub mod shamir;

pub use error::CryptoError;
pub use secret::SecretBytes;