use sentinel_crypto::shamir::{self, ShamirShare};

#[derive(thiserror::Error, Debug)]
pub enum HardwareError {
    #[error("no compatible hardware key detected")]
    NoDeviceFound,
    #[error("PIV touch confirmation timed out")]
    TouchTimeout,
    #[error("PIV operation failed: {0}")]
    PivError(String),
    #[error("incorrect PIN")]
    IncorrectPin,
    #[error("share reconstruction failed: {0}")]
    ShamirError(#[from] shamir::ShamirError),
    #[error("this key holder already contributed a fragment this session")]
    DuplicateHolder(String),
}

/// One quorum member's contribution: a Shamir share that this specific
/// physical key has decrypted (via `YubiKeyUnsealer::decrypt_share` on
/// real hardware, or supplied directly in tests). `holder_id` is a
/// human label ("alice-yubikey", "bob-yubikey") purely for audit-log
/// context — it plays no role in the cryptography.
#[derive(Debug, Clone)]
pub struct UnsealFragment {
    pub holder_id: String,
    pub share: ShamirShare,
}

/// Accumulates fragments as key holders touch their hardware keys one at
/// a time, and reconstructs the KEK the moment `threshold` distinct
/// holders have contributed. This is deliberately holder-order-
/// independent: it doesn't matter which two of the three key holders
/// show up, only that some `threshold`-sized subset does.
#[derive(Debug, Default)]
pub struct QuorumUnseal {
    threshold: u8,
    fragments: Vec<UnsealFragment>,
}

impl QuorumUnseal {
    pub fn new(threshold: u8) -> Self {
        Self { threshold, fragments: Vec::new() }
    }

    /// Records one holder's fragment. Rejects a second contribution from
    /// the same `holder_id` in the same session — a compromised or
    /// confused single key holder touching twice must not be able to
    /// satisfy a quorum meant to require independent physical keys.
    pub fn contribute(&mut self, fragment: UnsealFragment) -> Result<(), HardwareError> {
        if self.fragments.iter().any(|f| f.holder_id == fragment.holder_id) {
            return Err(HardwareError::DuplicateHolder(fragment.holder_id));
        }
        self.fragments.push(fragment);
        Ok(())
    }

    pub fn contributed_so_far(&self) -> usize {
        self.fragments.len()
    }

    pub fn is_satisfied(&self) -> bool {
        self.fragments.len() >= self.threshold as usize
    }

    /// Attempts reconstruction. Returns the recovered KEK bytes once
    /// enough distinct holders have contributed; the caller (Phase 7's
    /// unseal handler) is responsible for verifying the result against
    /// the audit-log HMAC before trusting it, since Shamir itself gives
    /// no integrity signal on a wrong or insufficient set.
    pub fn try_reconstruct(&self) -> Result<Vec<u8>, HardwareError> {
        if !self.is_satisfied() {
            return Err(HardwareError::ShamirError(shamir::ShamirError::InsufficientSharesToCombine(
                self.fragments.len(),
            )));
        }
        let shares: Vec<ShamirShare> = self.fragments.iter().map(|f| f.share.clone()).collect();
        Ok(shamir::combine_shares(&shares)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_shares(secret: &[u8], threshold: u8, total: u8) -> Vec<ShamirShare> {
        shamir::split_secret(secret, threshold, total, &mut OsRng).unwrap()
    }

    #[test]
    fn reconstructs_once_threshold_reached() {
        let secret = b"32-byte-kek-material-goes-here!";
        let shares = make_shares(secret, 2, 3);

        let mut quorum = QuorumUnseal::new(2);
        assert!(!quorum.is_satisfied());

        quorum
            .contribute(UnsealFragment { holder_id: "alice".into(), share: shares[0].clone() })
            .unwrap();
        assert!(!quorum.is_satisfied());
        assert!(quorum.try_reconstruct().is_err());

        quorum
            .contribute(UnsealFragment { holder_id: "bob".into(), share: shares[1].clone() })
            .unwrap();
        assert!(quorum.is_satisfied());
        assert_eq!(quorum.try_reconstruct().unwrap(), secret);
    }

    #[test]
    fn any_valid_subset_of_holders_works() {
        let secret = b"quorum-holder-order-independence";
        let shares = make_shares(secret, 3, 5);

        let mut quorum = QuorumUnseal::new(3);
        quorum.contribute(UnsealFragment { holder_id: "carol".into(), share: shares[2].clone() }).unwrap();
        quorum.contribute(UnsealFragment { holder_id: "eve".into(), share: shares[4].clone() }).unwrap();
        quorum.contribute(UnsealFragment { holder_id: "alice".into(), share: shares[0].clone() }).unwrap();

        assert_eq!(quorum.try_reconstruct().unwrap(), secret);
    }

    #[test]
    fn rejects_duplicate_holder_in_same_session() {
        let secret = b"abcd";
        let shares = make_shares(secret, 2, 3);

        let mut quorum = QuorumUnseal::new(2);
        quorum
            .contribute(UnsealFragment { holder_id: "alice".into(), share: shares[0].clone() })
            .unwrap();
        let err = quorum
            .contribute(UnsealFragment { holder_id: "alice".into(), share: shares[1].clone() })
            .unwrap_err();
        assert!(matches!(err, HardwareError::DuplicateHolder(h) if h == "alice"));
        assert!(!quorum.is_satisfied());
    }

    #[test]
    fn single_holder_cannot_satisfy_a_two_of_three_quorum() {
        let secret = b"abcd";
        let shares = make_shares(secret, 2, 3);
        let mut quorum = QuorumUnseal::new(2);
        quorum
            .contribute(UnsealFragment { holder_id: "alice".into(), share: shares[0].clone() })
            .unwrap();
        assert!(!quorum.is_satisfied());
        assert!(quorum.try_reconstruct().is_err());
    }

    #[test]
    fn contributed_so_far_tracks_count() {
        let secret = b"abcd";
        let shares = make_shares(secret, 2, 3);
        let mut quorum = QuorumUnseal::new(2);
        assert_eq!(quorum.contributed_so_far(), 0);
        quorum
            .contribute(UnsealFragment { holder_id: "alice".into(), share: shares[0].clone() })
            .unwrap();
        assert_eq!(quorum.contributed_so_far(), 1);
    }
}