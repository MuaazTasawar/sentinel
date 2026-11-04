mod quorum;
pub use quorum::{HardwareError, QuorumUnseal, UnsealFragment};

// Needs the PC/SC smart-card stack and is unverified on real hardware; see the
// `yubikey` feature in Cargo.toml.
#[cfg(feature = "yubikey")]
mod yubikey_piv;
#[cfg(feature = "yubikey")]
pub use yubikey_piv::YubiKeyUnsealer;