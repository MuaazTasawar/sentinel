use crate::quorum::HardwareError;

/// Decrypts a single Shamir share using a PIV private key stored on a
/// physical YubiKey. Each key holder provisions their share once (at
/// setup time, encrypted to their YubiKey's PIV public key in the key-
/// management slot); from then on, reconstructing it requires the
/// physical device, its PIN, and — depending on the slot's touch
/// policy — a physical touch confirmation. None of that state is
/// recoverable in software alone.
pub struct YubiKeyUnsealer {
    slot: yubikey::piv::SlotId,
}

impl YubiKeyUnsealer {
    /// `slot` is the PIV slot holding this holder's decryption key —
    /// typically `SlotId::KeyManagement` (9d), matching Yubico's
    /// convention for a private key used for decryption rather than
    /// signing.
    pub fn new(slot: yubikey::piv::SlotId) -> Self {
        Self { slot }
    }

    /// Opens the first connected YubiKey, verifies the PIN, and decrypts
    /// `encrypted_share`. Blocks on the physical touch prompt if the
    /// slot's policy requires it (Yubico's PIV applet handles the
    /// touch-and-timeout mechanics at the device level; this call simply
    /// waits for the device to respond or return its own timeout error).
    pub fn decrypt_share(&self, pin: &[u8], encrypted_share: &[u8]) -> Result<Vec<u8>, HardwareError> {
        let mut yk = yubikey::YubiKey::open().map_err(|_| HardwareError::NoDeviceFound)?;

        yk.verify_pin(pin).map_err(|_| HardwareError::IncorrectPin)?;

        let decrypted = yubikey::piv::decrypt_data(
            &mut yk,
            encrypted_share,
            yubikey::piv::AlgorithmId::EccP256,
            self.slot,
        )
        .map_err(|e| HardwareError::PivError(e.to_string()))?;

        Ok(decrypted.to_vec())
    }
}

// NOTE ON VERIFICATION: everything in this file talks directly to a
// physical YubiKey over PC/SC (via the `yubikey` crate, which wraps the
// `pcsc` crate). It cannot be exercised by an automated test in a
// sandbox with no smart-card reader attached, and I have not run it —
// unlike every other file in this project, which was compiled and
// tested before being handed over. Treat this file as reviewed-against-
// documentation, not verified-by-execution. The seam is intentional:
// `quorum.rs` (which *is* fully tested) accepts already-decrypted
// `ShamirShare` bytes and never touches `yubikey` types directly, so a
// bug here is contained to "PIV decryption doesn't work" rather than
// "quorum logic is wrong."