#[derive(thiserror::Error, Debug)]
pub enum HardwareError {
    #[error("no compatible hardware key detected")]
    NoDeviceFound,
    #[error("PIV touch confirmation timed out")]
    TouchTimeout,
}

// mod yubikey_piv;   // Phase 4